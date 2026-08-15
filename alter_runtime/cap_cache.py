"""DaemonCapCache - machine-wide cap-JWT and query-result cache for the daemon.

One instance is created at daemon startup and shared across all Unix socket
clients. This collapses the N independent capability request calls (one per bridge
process) that previously ran against the server's 6/min/handle bucket into a
single minting identity per handle-scope set.

Design
------

*Cap cache* (``cap.get`` RPC):
    Mints once per sorted-scope-set, caches the resulting JWT in-memory.
    Refresh fires 30 s before declared ``expires_at`` (same leeway as
    :class:`~alter_runtime.subscribers.active_sessions_do_publisher._CachedCap`).
    Server TTL is clamped to [30, 300] s server-side; the client-side leeway
    means steady-state mint rate is at most once per (TTL - 30 s) window.
    On 401/403 from the caller's upstream, the caller drops the entry via
    :meth:`invalidate_cap` and the next ``cap.get`` re-mints immediately.

*Query cache* (``query.get`` RPC):
    Caches the JSON body of a ``GET /orgs/{slug}/queries/{path}`` response
    for 15 s (``QUERY_CACHE_TTL``). Keyed on ``(path, frozen_params)``.
    Stale entries are evicted on next access (read-through TTL). No push
    invalidation in v1.

Auth
----

Both RPC methods are served by the existing Unix socket auth handshake
(``{"method": "auth", "token": "<t>"}``). No new auth scheme is added.

Thread safety
-------------

All operations are synchronous reads/writes to plain dicts guarded by the
asyncio event loop. No additional locking is required because the daemon
runs in a single-threaded asyncio event loop where coroutine scheduling is
cooperative - no concurrent access to the dicts is possible.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from alter_runtime.auth_health import AuthHealth
    from alter_runtime.config import Session, SessionRef
    from alter_runtime.subscribers.session_refresher import RefreshTrigger

__all__ = [
    "CAP_CACHE_REFRESH_LEAD_SECONDS",
    "CAP_CACHE_TTL_MIN",
    "CAP_CACHE_TTL_MAX",
    "QUERY_CACHE_TTL",
    "DaemonCapCache",
]

logger = logging.getLogger("alter_runtime.cap_cache")

#: Re-mint leeway - same value as the publisher's ``CAP_REFRESH_LEAD_SECONDS``
#: so both components share one effective policy.
CAP_CACHE_REFRESH_LEAD_SECONDS: float = 30.0

#: Minimum server-declared TTL we honour. Values below this are clamped up.
CAP_CACHE_TTL_MIN: float = 30.0

#: Maximum server-declared TTL we honour. Values above this are clamped down.
CAP_CACHE_TTL_MAX: float = 300.0

#: Query result cache TTL in seconds. Fixed for v1 - no push invalidation.
QUERY_CACHE_TTL: float = 15.0


# ---------------------------------------------------------------------------
# Internal data classes
# ---------------------------------------------------------------------------


@dataclass
class _CachedCap:
    """Cached cap-JWT keyed on a sorted-scope-set."""

    capability: str
    expires_at_unix: float
    # Unlimited multi-use; the daemon never tracks per-use accounting here
    # (the server validates TTL + scope only).
    uses_available: int = sys.maxsize
    use_counter: int = 0

    def is_fresh(self, now: float) -> bool:
        return self.expires_at_unix - now > CAP_CACHE_REFRESH_LEAD_SECONDS

    def has_uses(self) -> bool:
        return self.use_counter < self.uses_available

    def take_use(self) -> None:
        self.use_counter += 1


@dataclass
class _CachedQuery:
    """Cached query-GET response body."""

    body: Any
    cached_at: float


# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------


class _CapabilityRequestError(Exception):
    """Raised when the capability request endpoint refuses or returns a malformed body."""


class _SessionMissing(Exception):
    """Raised when no session is available to mint a cap."""


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class DaemonCapCache:
    """Machine-wide cap and query cache.

    Parameters
    ----------
    session:
        Authenticated CLI :class:`~alter_runtime.config.Session`.
        Used for the Bearer JWT when minting capability tokens. Pass
        ``None`` to construct the cache in degraded mode (all ``cap.get``
        calls will fail with ``session_missing``).
    http_client:
        Optional ``httpx.AsyncClient`` override. When ``None``, the caller
        must supply the client via the ``client`` parameter on each method
        call (used by the Unix socket server which shares the daemon's
        single client instance).
    refresh_trigger:
        Optional shared :class:`~alter_runtime.subscribers.session_refresher.RefreshTrigger`.
        A capability request 401/403 (``session.jwt`` itself rejected, not merely a
        stale cap) calls ``request_refresh()`` so ``SessionRefresher`` wakes
        and rotates out of band instead of waiting for its schedule
        (2026-07-12 fix). ``None`` preserves the prior pure-backoff behaviour.
    auth_health:
        Optional shared :class:`~alter_runtime.auth_health.AuthHealth`. A
        capability request returning 200 is the daemon's most direct proof that the
        session JWT is still accepted by the backend, so it is recorded as a
        success here. Failures arrive through the refresh trigger, which is
        the single fan-in for every observed 401.
    """

    def __init__(
        self,
        session: "Session | SessionRef | None",
        *,
        http_client: httpx.AsyncClient | None = None,
        refresh_trigger: "RefreshTrigger | None" = None,
        auth_health: "AuthHealth | None" = None,
    ) -> None:
        # Accept either a frozen Session snapshot (legacy / test callers) or a
        # live SessionRef holder (daemon production path).  When a SessionRef is
        # supplied, _get_session() reads through it so a proactive token
        # rotation propagated via SessionRef.set() is immediately visible to
        # the next capability request without any separate update_session() call.
        from alter_runtime.config import SessionRef as _SessionRef

        if isinstance(session, _SessionRef):
            self._session_ref: "_SessionRef | None" = session
            self._session: "Session | None" = session.current
        else:
            self._session_ref = None
            self._session = session
        self._http_client = http_client
        self._refresh_trigger = refresh_trigger
        self._auth_health = auth_health
        # Cap cache: keyed on frozenset of scope strings.
        self._caps: dict[frozenset[str], _CachedCap] = {}
        # Query cache: keyed on (path, frozenset of sorted param items).
        self._queries: dict[tuple[str, frozenset[tuple[str, str]]], _CachedQuery] = {}

    # ------------------------------------------------------------------
    # Public interface (called from unix.py dispatch)
    # ------------------------------------------------------------------

    async def get_cap(
        self,
        scopes: list[str],
        *,
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        """Return a fresh cap-JWT for ``scopes``.

        Returns::

            {
                "ok": True,
                "capability": "<jwt>",
                "expires_at": "<iso8601>",
            }

        or::

            {
                "ok": False,
                "error": "<reason>",
            }
        """
        http = client or self._http_client
        if http is None:
            return {"ok": False, "error": "no http client available"}

        scope_key = frozenset(scopes)
        try:
            cap_jwt = await self._ensure_cap(http, scope_key)
        except _SessionMissing:
            return {"ok": False, "error": "session_missing"}
        except _CapabilityRequestError as exc:
            return {"ok": False, "error": f"capability_request_error: {exc}"}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": f"http_error: {exc}"}

        cached = self._caps.get(scope_key)
        expires_iso = ""
        if cached is not None:
            try:
                expires_iso = datetime.utcfromtimestamp(cached.expires_at_unix).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except (OSError, OverflowError, ValueError):
                expires_iso = ""

        return {"ok": True, "capability": cap_jwt, "expires_at": expires_iso}

    async def get_query(
        self,
        path: str,
        params: dict[str, Any] | None,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        """Return a cached (or freshly fetched) query result.

        Returns::

            {
                "ok": True,
                "body": <any json>,
                "cached_at": <float epoch>,
            }

        or::

            {
                "ok": False,
                "error": "<reason>",
            }
        """
        http = client or self._http_client
        if http is None:
            return {"ok": False, "error": "no http client available"}

        # Normalise params into a stable hashable key.
        frozen_params: frozenset[tuple[str, str]]
        if params:
            frozen_params = frozenset((str(k), str(v)) for k, v in sorted(params.items()))
        else:
            frozen_params = frozenset()

        cache_key = (path, frozen_params)
        now = time.time()

        # Cache hit: return immediately if within TTL.
        cached = self._queries.get(cache_key)
        if cached is not None and (now - cached.cached_at) < QUERY_CACHE_TTL:
            return {"ok": True, "body": cached.body, "cached_at": cached.cached_at}

        # Cache miss or stale: fetch fresh.
        try:
            body = await self._fetch_query(http, path, params or {})
        except _SessionMissing:
            return {"ok": False, "error": "session_missing"}
        except _CapabilityRequestError as exc:
            return {"ok": False, "error": f"capability_request_error: {exc}"}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": f"http_error: {exc}"}

        entry = _CachedQuery(body=body, cached_at=time.time())
        self._queries[cache_key] = entry
        return {"ok": True, "body": entry.body, "cached_at": entry.cached_at}

    def invalidate_cap(self, scopes: list[str]) -> None:
        """Drop the cached cap for ``scopes`` so the next ``cap.get`` re-mints.

        Called by the Unix socket server on 401/403 from the caller's upstream.
        """
        self._caps.pop(frozenset(scopes), None)

    def update_session(self, session: "Session | None") -> None:
        """Replace the session (called when the daemon reloads session.json).

        When the cache was constructed with a :class:`SessionRef`, the ref
        itself is the live source of truth and this call updates the legacy
        ``_session`` attribute only (a no-op in the read-through path, but
        harmless for callers that still use the old API).
        """
        self._session = session

    def _get_session(self) -> "Session | None":
        """Return the live session, reading through SessionRef when present."""
        if self._session_ref is not None:
            return self._session_ref.current
        return self._session

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _ensure_cap(
        self,
        http: httpx.AsyncClient,
        scope_key: frozenset[str],
    ) -> str:
        """Return a fresh capability JWT, minting if cache is stale or empty."""
        now = time.time()
        cached = self._caps.get(scope_key)
        if cached is not None and cached.is_fresh(now) and cached.has_uses():
            cached.take_use()
            return cached.capability

        session = self._get_session()
        if session is None:
            raise _SessionMissing()

        # Mint a new cap via the server's capability request endpoint. Sorted scopes
        # are sent as a list so the server can validate them all at once.
        url = f"{session.api.rstrip('/')}/api/v1/messaging/sessions-ingest-capability"
        headers = {
            "Authorization": f"Bearer {session.jwt}",
            "Accept": "application/json",
        }
        # The parameterless endpoint is used for
        # ``alter_events.sessions.ingest`` scoped caps as well as other
        # scopes; the server rejects unknown scopes with 422, which
        # surfaces as a _CapabilityRequestError.
        response = await http.post(url, headers=headers)

        if response.status_code in (401, 403):
            # The session JWT itself (not merely a cap) was rejected —
            # request an out-of-band SessionRefresher wake instead of
            # waiting for its scheduled lead time (2026-07-12 fix).
            if self._refresh_trigger is not None:
                self._refresh_trigger.request_refresh("capability_request_401")
            raise _CapabilityRequestError(
                f"capability request rejected (HTTP {response.status_code}): {response.text[:200]}"
            )
        response.raise_for_status()

        # An accepted mint is the authenticated 200 that answers "is this
        # session alive". Record it so a recovery is observable, and so a
        # failure elsewhere reports as split-brain rather than as a dead
        # session the member would be sent to re-login over.
        if self._auth_health is not None:
            self._auth_health.record_success("capability_request")

        try:
            data = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
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
            expires_at_unix = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
        except ValueError as exc:
            raise _CapabilityRequestError(
                f"capability request returned non-ISO expires_at: {expires_at}"
            ) from exc

        # Clamp TTL to [CAP_CACHE_TTL_MIN, CAP_CACHE_TTL_MAX].
        now2 = time.time()
        raw_ttl = expires_at_unix - now2
        clamped_ttl = max(CAP_CACHE_TTL_MIN, min(raw_ttl, CAP_CACHE_TTL_MAX))
        if clamped_ttl != raw_ttl:
            expires_at_unix = now2 + clamped_ttl

        cap = _CachedCap(
            capability=capability,
            expires_at_unix=expires_at_unix,
        )
        cap.take_use()
        self._caps[scope_key] = cap
        return capability

    async def _fetch_query(
        self,
        http: httpx.AsyncClient,
        path: str,
        params: dict[str, Any],
    ) -> Any:
        """Fetch ``GET /orgs/{slug}/queries/{path}`` with a fresh cap."""
        session = self._get_session()
        if session is None:
            raise _SessionMissing()

        # Use the default ingest scope to cap-gate query requests, matching
        # the server-side scope requirement. The scope key used here must
        # match what the caller registered (frozenset of the same scope list).
        scope_key = frozenset(["alter_events.sessions.ingest"])
        cap_jwt = await self._ensure_cap(http, scope_key)

        url = f"{session.api.rstrip('/')}/orgs/queries/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {cap_jwt}",
            "Accept": "application/json",
        }
        response = await http.get(url, params=params or None, headers=headers)

        if response.status_code in (401, 403):
            # Drop the cap entry so the next call re-mints.
            self._caps.pop(scope_key, None)
            raise _CapabilityRequestError(f"query cap rejected (HTTP {response.status_code})")

        response.raise_for_status()

        try:
            return response.json()
        except (ValueError, json.JSONDecodeError):
            return response.text
