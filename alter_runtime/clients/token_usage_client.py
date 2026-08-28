"""TokenUsageClient - authenticated HTTP client for the token-usage audit endpoint.

Posts batches of parsed token-usage events to the ~alter backend.

Authentication
--------------

The JWT is:

1. Sourced from ``load_session()`` at adapter startup (the JWT written by
   ``alter login`` to ``~/.config/alter/session.json``).
2. Overridable at runtime via the ``ALTER_RUNTIME_SESSION_JWT`` env var (allows
   a wrapper script or systemd ``EnvironmentFile`` to inject a freshly minted
   token without restarting the daemon).
3. Passed as a ``Callable[[], str | None]`` provider so the adapter can swap
   in a proper refresh routine without changing the call site.

Expired JWTs will cause 401s. The daemon logs a warning and drops the batch
in that case; the offset is NOT advanced, so the next watchdog tick will
re-attempt.

Identification
--------------

``host_id`` is a stable, opaque identifier for the machine running the daemon,
derived from ``socket.gethostname()`` plus the first 8 chars of
``/etc/machine-id`` (Linux) or ``platform.node()`` (fallback). It is NOT a
PII field - it's a session-correlation key to group events by host when a
principal operates multiple machines.

Rate limiting
-------------

At most one POST per 5 seconds. The caller (ClaudeJsonlWatcher) enforces this
but TokenUsageClient also tracks its own last-POST timestamp as a defence-in-depth
guard. Retries use exponential backoff (1s, 2s, 4s) on 5xx, max 3 attempts.
The batch is dropped (not re-queued) after exhausting retries; the adapter's
un-advanced offset provides the re-try on the next watchdog tick.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os
import platform
import socket
import time
from typing import Callable

import httpx

__all__ = ["TokenUsageClient"]

logger = logging.getLogger("alter_runtime.clients.token_usage_client")

#: Endpoint path for posting token-usage events.
TOKEN_USAGE_EVENTS_PATH = "/api/v1/admin/token-usage/events"

#: Rate-limit: minimum seconds between successive POSTs.
MIN_POST_INTERVAL_SECONDS: float = 5.0

#: Retry configuration.
MAX_RETRIES: int = 3
RETRY_BASE_SECONDS: float = 1.0
RETRYABLE_HTTP_CODES = frozenset({429, 500, 502, 503, 504})


# ---------------------------------------------------------------------------
# host_id derivation (singleton, derived once)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _derive_host_id() -> str:
    """Return a stable, opaque identifier for the current machine.

    Composed from ``socket.gethostname()`` and the first 8 characters of
    ``/etc/machine-id`` (Linux), falling back to ``platform.node()`` when
    the machine-id file is absent or unreadable. The resulting string is
    safe to transmit (no PII) and stable across daemon restarts.
    """
    hostname = socket.gethostname()
    machine_suffix = ""
    machine_id_path = "/etc/machine-id"
    try:
        raw = open(machine_id_path).read().strip()  # noqa: WPS515
        if raw:
            machine_suffix = raw[:8]
    except OSError:
        # macOS / Windows / containers without machine-id.
        machine_suffix = platform.node()[:8]

    return f"{hostname}-{machine_suffix}" if machine_suffix else hostname


# ---------------------------------------------------------------------------
# TokenUsageClient
# ---------------------------------------------------------------------------


class TokenUsageClient:
    """Async client for the ~alter backend token-usage audit endpoint.

    Parameters
    ----------
    base_url:
        Base URL of the ~alter backend API. Reads ``ALTER_RUNTIME_API_BASE``
        env var at construction if not explicitly provided; defaults to
        ``https://api.truealter.com``.
    jwt_provider:
        Callable that returns the current session JWT string (or ``None`` if
        not yet authenticated). Called on every POST so that a future
        refresh-token flow can inject a fresh JWT without restarting the
        adapter.
    """

    def __init__(
        self,
        base_url: str | None = None,
        jwt_provider: Callable[[], str | None] | None = None,
    ) -> None:
        resolved_base = base_url or os.environ.get(
            "ALTER_RUNTIME_API_BASE", "https://api.truealter.com"
        )
        self._base_url = resolved_base.rstrip("/")
        self._jwt_provider = jwt_provider or (lambda: None)
        self._host_id: str = _derive_host_id()
        self._last_post_time: float = 0.0
        self._http: httpx.AsyncClient | None = None

    def _ensure_http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=30.0)
        return self._http

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def post_events(self, events: list[dict]) -> dict:
        """POST a batch of token-usage events to the backend.

        Parameters
        ----------
        events:
            List of parsed event dicts (output of ``parse_assistant_line``
            with ``project_slug`` added by the adapter).

        Returns
        -------
        dict
            Backend response body, e.g. ``{"inserted": N, "skipped_duplicates": M}``.

        Raises
        ------
        Exception
            On persistent HTTP failure after ``MAX_RETRIES`` attempts. The
            caller (ClaudeJsonlWatcher) catches this and withholds offset
            advancement so the next tick will re-attempt.
        """
        if not events:
            return {"inserted": 0, "skipped_duplicates": 0}

        # Self-enforced rate limit (defence-in-depth; adapter also rate-limits).
        now = time.monotonic()
        wait = MIN_POST_INTERVAL_SECONDS - (now - self._last_post_time)
        if wait > 0:
            await asyncio.sleep(wait)

        jwt = self._jwt_provider()
        if not jwt:
            logger.warning(
                "token_usage_client: no JWT available - dropping batch of %d events. "
                "Run `alter login` or set ALTER_RUNTIME_SESSION_JWT.",
                len(events),
            )
            raise RuntimeError("no JWT available for token-usage POST")

        payload = {
            "host_id": self._host_id,
            "events": events,
        }
        url = self._base_url + TOKEN_USAGE_EVENTS_PATH
        http = self._ensure_http()

        last_exc: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                # Per-request headers: Authorization + Content-Type +
                # the canonical ``X-Alter-Client-*`` identity bundle.
                # The X-Alter-* bundle is required on every authenticated
                # backend call so the server-side floor middleware can
                # identify the daemon.
                from alter_runtime.http_auth import backend_default_headers

                resp = await http.post(
                    url,
                    json=payload,
                    headers={
                        **backend_default_headers(),
                        "Authorization": f"Bearer {jwt}",
                        "Content-Type": "application/json",
                    },
                )
                if resp.status_code in RETRYABLE_HTTP_CODES and attempt < MAX_RETRIES - 1:
                    backoff = RETRY_BASE_SECONDS * (2**attempt)
                    logger.warning(
                        "token_usage_client: HTTP %d (attempt %d/%d), retrying in %.1fs",
                        resp.status_code,
                        attempt + 1,
                        MAX_RETRIES,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                resp.raise_for_status()
                self._last_post_time = time.monotonic()
                try:
                    return resp.json()
                except Exception:
                    return {"inserted": len(events), "skipped_duplicates": 0}
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in RETRYABLE_HTTP_CODES and attempt < MAX_RETRIES - 1:
                    backoff = RETRY_BASE_SECONDS * (2**attempt)
                    logger.warning(
                        "token_usage_client: HTTP %d (attempt %d/%d), retrying in %.1fs",
                        status,
                        attempt + 1,
                        MAX_RETRIES,
                        backoff,
                    )
                    last_exc = exc
                    await asyncio.sleep(backoff)
                    continue
                logger.error(
                    "token_usage_client: persistent HTTP %d - dropping batch of %d events",
                    status,
                    len(events),
                )
                raise
            except httpx.RequestError as exc:
                if attempt < MAX_RETRIES - 1:
                    backoff = RETRY_BASE_SECONDS * (2**attempt)
                    logger.warning(
                        "token_usage_client: request error (attempt %d/%d): %s, retrying in %.1fs",
                        attempt + 1,
                        MAX_RETRIES,
                        exc,
                        backoff,
                    )
                    last_exc = exc
                    await asyncio.sleep(backoff)
                    continue
                logger.error(
                    "token_usage_client: persistent request error - "
                    "dropping batch of %d events: %s",
                    len(events),
                    exc,
                )
                raise

        # Should not reach here; re-raise last captured exception.
        raise last_exc or RuntimeError("post_events exhausted retries")
