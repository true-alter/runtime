"""SessionPresenceWriter - projects cross-host editor-session presence into the shared cache.

The presence endpoint at /queries/presence aggregates session_presence
intent rows across hosts (editor session hooks emit these as
start/heartbeat/stop). This subscriber polls that endpoint on a configurable
cadence and writes the result to
``~/.local/share/org-alter/state/sessions.json``. A same-host awareness hook
merges that cache with ``/dev/shm`` sibling files to give every session a
unified view of all parallel sessions across hosts.

Designed to be the
canonical writer for this cache - the alternative was a
standalone systemd timer that would have been deprecated as soon as
the daemon caught up. Landing it here from the start avoids the churn.

Auth flow per cycle:

1. **Capability request.** ``POST {api}/api/v1/org-alter/caps`` body
   ``{"scopes":["alter_org.read"], "residual_seconds": 240}`` with
   ``Authorization: Bearer <session.jwt>``. Returns
   ``{capability, expires_at, jti, sub, aud_recipient, scopes, uses?, mode?}``.
2. **Query.** ``GET {worker}/orgs/{slug}/queries/presence`` with
   ``Authorization: Bearer <cap>`` and ``X-Cap-Use-Index: <index>``.

Caps are kept in-memory with a 30s lead refresh; bounded multi-use caps
are honoured. The reader does not subscribe to the bus -
awareness is a file-mediated handoff to bash hooks, and the bus would add
nothing useful.

Cache file shape mirrors the server's presence response so the bash hook's
``jq`` path stays simple::

    {
        "presence": [
            {"actor": "~example", "tool": "cc", "session_id": "abc...",
             "started_at": "...", "last_seen": "...", "state": "heartbeat"},
            ...
        ],
        "window_ms": 1800000,
        "now": "2026-05-07T...",
        "writer": "alter-runtime",
        "writer_at": "2026-05-07T..."
    }

Failure modes:

* No session.json - log once, idle until the next poll. The daemon never
  manages login.
* Capability-request reject (4xx, 503) - exponential back-off up to
  MAX_POLL_BACKOFF.
* Server reject - exponential back-off; cache file is left as-is so stale
  cross-host data keeps rendering for the rolling-window grace period.
* Network error - exponential back-off.

The subscriber never raises out of :meth:`run` - the supervisor's
exponential-backoff restart machinery is a last-resort safety net only.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from alter_runtime.config import DaemonConfig
from alter_runtime.daemon import Component
from alter_runtime.http_auth import backend_default_headers
from alter_runtime.subscribers.do_sse import _build_tls_context

if TYPE_CHECKING:
    from alter_runtime.config import Session, SessionRef
    from alter_runtime.subscribers.session_refresher import RefreshTrigger

__all__ = ["SessionPresenceWriter", "session_presence_cache_path"]

logger = logging.getLogger("alter_runtime.subscribers.session_presence")

#: Cap scope required for /queries/presence reads.
READ_SCOPE: str = "alter_org.read"

#: Default residual-lifetime ceiling at mint time. The backend caps this at
#: 300s for read scopes and the cache refreshes 30s before expiry, so the
#: effective re-mint cadence is ~210s.
DEFAULT_CAP_RESIDUAL_SECONDS: int = 240

#: Refresh leeway - re-mint when expiry is closer than this.
CAP_REFRESH_LEAD_SECONDS: float = 30.0

#: Upper bound on the subscriber's exponential backoff when either capability request
#: or the server query is failing.
MAX_POLL_BACKOFF_SECONDS: float = 60.0

#: Filename under the session-state directory that the same-host awareness
#: hook reads. Co-ordinated with that hook - changing this requires a paired
#: edit on the reader side.
CACHE_FILENAME: str = "sessions.json"


def session_presence_cache_path() -> Path:
    """Return the canonical sessions.json cache path.

    Honours ``ORG_ALTER_STATE_DIR`` to allow the path to be overridden by the caller.
    """
    override = os.environ.get("ORG_ALTER_STATE_DIR")
    if override:
        base = Path(override).expanduser()
    else:
        base = Path.home() / ".local" / "share" / "org-alter"
    return base / "state" / CACHE_FILENAME


# ---------------------------------------------------------------------------
# In-memory cap cache
# ---------------------------------------------------------------------------


@dataclass
class _CachedCap:
    capability: str
    expires_at_unix: float
    uses_available: int
    use_counter: int

    def is_fresh(self, now: float) -> bool:
        return self.expires_at_unix - now > CAP_REFRESH_LEAD_SECONDS

    def has_uses(self) -> bool:
        return self.use_counter < self.uses_available

    def take_use(self) -> int:
        index = self.use_counter
        self.use_counter += 1
        return index


# ---------------------------------------------------------------------------
# Subscriber state - mirrors McpFallbackSubscriber's _FallbackState pattern
# ---------------------------------------------------------------------------


@dataclass
class _PresenceState:
    """Internal state (exposed for tests)."""

    poll_count: int = 0
    write_count: int = 0
    backoff: float = 0.0
    last_response_at: float = 0.0
    history: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Component
# ---------------------------------------------------------------------------


class SessionPresenceWriter(Component):
    """Polls the presence endpoint and writes a local cache.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Reads the new
        ``session_presence_*`` and ``org_alter_*`` fields.
    session:
        Authenticated CLI :class:`Session`. Used for the bearer JWT
        when minting caps. Without a session the component idles silently
        and re-checks on every poll cycle.
    cache_path:
        Override the cache file path. Tests inject ``tmp_path``.
    http_client:
        Optional ``httpx.AsyncClient`` override for tests.
    refresh_trigger:
        Optional shared :class:`~alter_runtime.subscribers.session_refresher.RefreshTrigger`.
        A capability request 401/403 (``session.jwt`` itself rejected) calls
        ``request_refresh()`` so ``SessionRefresher`` wakes and rotates out
        of band instead of waiting for its schedule (2026-07-12 fix).
        ``None`` preserves the prior pure-backoff behaviour.
    """

    name = "session_presence"

    def __init__(
        self,
        config: DaemonConfig,
        session: "Session | SessionRef | None",
        *,
        cache_path: Path | None = None,
        http_client: httpx.AsyncClient | None = None,
        refresh_trigger: "RefreshTrigger | None" = None,
    ) -> None:
        self._config = config
        from alter_runtime.config import SessionRef as _SessionRef

        if isinstance(session, _SessionRef):
            self._session_ref: "_SessionRef | None" = session
            self._session: "Session | None" = session.current
        else:
            self._session_ref = None
            self._session = session
        self._cache_path: Path = (
            cache_path if cache_path is not None else session_presence_cache_path()
        )
        self._http_client = http_client
        self._owns_client = http_client is None
        self._refresh_trigger = refresh_trigger
        self._stop_event = asyncio.Event()
        self._state = _PresenceState()
        self._cap: _CachedCap | None = None

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        if not self._config.session_presence_enabled:
            logger.info("session_presence disabled by config - idle")
            await self._stop_event.wait()
            return

        logger.info(
            "session_presence starting cache=%s interval=%.1fs",
            self._cache_path,
            self._config.session_presence_poll_interval_seconds,
        )

        client = self._http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
            verify=_build_tls_context(),
            # Client-default headers carry the canonical
            # ``X-Alter-Client-*`` identity bundle so the floor middleware
            # can identify the daemon. The per-request Bearer JWT is
            # attached on each call below.
            headers=backend_default_headers(self._config.org_alter_presence_endpoint),
        )

        try:
            while not self._stop_event.is_set():
                await self._poll_once_safe(client)
                await self._sleep_interruptible(self._config.session_presence_poll_interval_seconds)
        finally:
            if self._owns_client:
                with contextlib.suppress(Exception):
                    await client.aclose()
            logger.info("session_presence stopped")

    async def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Poll loop
    # ------------------------------------------------------------------

    async def _poll_once_safe(self, client: httpx.AsyncClient) -> None:
        """Wrap _poll_once with backoff + last-resort exception swallowing.

        The supervisor restarts on bare exceptions, so we'd rather log and
        continue than tear down the component for a transient blip.
        """
        try:
            await self._poll_once(client)
            self._state.backoff = 0.0
        except asyncio.CancelledError:
            raise
        except _SessionMissing:
            # No alter session - log once, sleep through cycle.
            if "no_session" not in self._state.history:
                self._state.history.append("no_session")
                logger.info(
                    "session_presence: no alter session - run `alter login`. "
                    "Will retry on the next poll silently."
                )
            self._state.backoff = max(self._state.backoff, 5.0)
        except (httpx.HTTPError, _CapabilityRequestError, _WorkerQueryError) as exc:
            self._state.backoff = min(
                max(self._state.backoff * 2 if self._state.backoff else 2.0, 2.0),
                MAX_POLL_BACKOFF_SECONDS,
            )
            logger.warning(
                "session_presence poll failed: %s - backoff %.1fs",
                exc,
                self._state.backoff,
            )
        except Exception as exc:  # noqa: BLE001 - last-resort safety net
            logger.exception("session_presence poll unexpected error: %s", exc)
            self._state.backoff = MAX_POLL_BACKOFF_SECONDS

    async def _poll_once(self, client: httpx.AsyncClient) -> None:
        """Mint cap if needed, GET presence, write cache."""
        session = self._session_ref.current if self._session_ref is not None else self._session
        if session is None:
            raise _SessionMissing()

        cap, use_index = await self._get_cap(client, session)
        response = await self._fetch_presence(client, cap, use_index)
        self._write_cache(response)
        self._state.poll_count += 1
        self._state.write_count += 1
        self._state.last_response_at = time.time()

    # ------------------------------------------------------------------
    # Capability request
    # ------------------------------------------------------------------

    async def _get_cap(
        self,
        client: httpx.AsyncClient,
        session: Session,
    ) -> tuple[str, int]:
        """Return (capability, use_index). Mints a new cap if cache is stale."""
        now = time.time()
        if self._cap is not None and self._cap.is_fresh(now) and self._cap.has_uses():
            return self._cap.capability, self._cap.take_use()

        url = f"{session.api.rstrip('/')}/api/v1/org-alter/caps"
        body = {
            "scopes": [READ_SCOPE],
            "residual_seconds": DEFAULT_CAP_RESIDUAL_SECONDS,
        }
        headers = {
            "Authorization": f"Bearer {session.jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        response = await client.post(url, json=body, headers=headers)
        if response.status_code == 401 or response.status_code == 403:
            # The session JWT itself (not merely a cap) was rejected —
            # request an out-of-band SessionRefresher wake instead of
            # waiting for its scheduled lead time (2026-07-12 fix).
            if self._refresh_trigger is not None:
                self._refresh_trigger.request_refresh("capability_request_401")
            raise _CapabilityRequestError(
                f"capability request rejected (HTTP {response.status_code}): {response.text[:200]}"
            )
        response.raise_for_status()

        try:
            data = response.json()
        except ValueError as exc:
            raise _CapabilityRequestError("capability request returned non-JSON body") from exc

        if not isinstance(data, dict):
            raise _CapabilityRequestError("capability request returned non-object body")

        capability = data.get("capability")
        expires_at = data.get("expires_at")
        if not isinstance(capability, str) or not capability:
            raise _CapabilityRequestError("capability request response missing capability")
        if not isinstance(expires_at, str) or not expires_at:
            raise _CapabilityRequestError("capability request response missing expires_at")

        try:
            from datetime import datetime

            expires_at_unix = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
        except ValueError as exc:
            raise _CapabilityRequestError(
                f"capability request returned non-ISO expires_at: {expires_at}"
            ) from exc

        # The server rejects mode=stream caps via the same gate;
        # surface it as a clean error here too.
        mode = data.get("mode")
        if mode is not None and mode != "office":
            raise _CapabilityRequestError(f"capability request returned unsupported mode: {mode!r}")

        uses_raw = data.get("uses")
        uses_available = uses_raw if isinstance(uses_raw, int) and uses_raw >= 1 else 1

        cap = _CachedCap(
            capability=capability,
            expires_at_unix=expires_at_unix,
            uses_available=uses_available,
            use_counter=1,
        )
        self._cap = cap
        return capability, 0

    # ------------------------------------------------------------------
    # Server query
    # ------------------------------------------------------------------

    async def _fetch_presence(
        self,
        client: httpx.AsyncClient,
        capability: str,
        use_index: int,
    ) -> dict[str, Any]:
        """GET /queries/presence with the cap. Returns parsed JSON dict."""
        endpoint = self._config.org_alter_presence_endpoint
        headers = {
            "Authorization": f"Bearer {capability}",
            "Accept": "application/json",
            "X-Cap-Use-Index": str(use_index),
        }
        response = await client.get(endpoint, headers=headers)
        if response.status_code == 401 or response.status_code == 403:
            # Cap was rejected - drop it so the next cycle re-mints.
            self._cap = None
            raise _WorkerQueryError(
                f"presence query auth rejected (HTTP {response.status_code}): {response.text[:200]}"
            )
        response.raise_for_status()

        try:
            data = response.json()
        except ValueError as exc:
            raise _WorkerQueryError("presence query returned non-JSON body") from exc

        if not isinstance(data, dict):
            raise _WorkerQueryError("presence query returned non-object body")
        return data

    # ------------------------------------------------------------------
    # Atomic write
    # ------------------------------------------------------------------

    def _write_cache(self, worker_response: dict[str, Any]) -> None:
        """Augment the server payload with writer metadata, atomic-write to disk."""
        from datetime import datetime, timezone

        envelope = dict(worker_response)
        envelope["writer"] = "alter-runtime"
        envelope["writer_at"] = datetime.now(tz=timezone.utc).isoformat()

        self._cache_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp_path = self._cache_path.with_suffix(self._cache_path.suffix + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp_path, flags, 0o600)
        try:
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)
            payload = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, self._cache_path)
        with contextlib.suppress(OSError):
            os.chmod(self._cache_path, 0o600)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _sleep_interruptible(self, seconds: float) -> None:
        """Sleep ``seconds`` or until stop is set, whichever comes first."""
        effective = max(seconds, self._state.backoff)
        if effective <= 0:
            return
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=effective)
        except (TimeoutError, asyncio.TimeoutError):
            return

    @property
    def state(self) -> _PresenceState:
        """Current state (used by tests)."""
        return self._state

    @property
    def cache_path(self) -> Path:
        return self._cache_path


# ---------------------------------------------------------------------------
# Internal exception types - kept private so callers can't grep for them
# outside this module
# ---------------------------------------------------------------------------


class _SessionMissing(Exception):
    """Raised when the CLI session is absent."""


class _CapabilityRequestError(Exception):
    """Raised when /api/v1/org-alter/caps refuses or returns malformed body."""


class _WorkerQueryError(Exception):
    """Raised when /queries/presence refuses or returns malformed body."""
