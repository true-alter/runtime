"""AttunementRefresher - always-on low-frequency attunement projection.

Why this exists
---------------

Attunement (``~Alter``'s knowledge depth about the member) only reaches the
shell cache (``~/.cache/alter/identity.json``) via two paths today, and both
are dormant during normal operation:

1. The live SSE feed (``do_sse``) carries an ``attunement_transition``
   frame *only on a transition*, not on a cadence. Between transitions,
   nothing refreshes.
2. The MCP fallback poller (``mcp_fallback``) calls ``alter_attunement`` and
   merges it into its ``state_sync`` payload - but the fallback is **idle**
   whenever the SSE feed is connected (its whole job is to fill the gap
   while the edge is down). In healthy steady state the feed stays connected,
   so the fallback never runs, so attunement never gets pulled.

The net effect: during normal operation a member's attunement score in the
shell cache goes stale and never updates. This component closes that gap.

What it does
------------

A separate, lightweight supervised :class:`Component` that:

* Calls the ``alter_attunement`` MCP tool on a slow, configurable cadence
  (:attr:`DaemonConfig.attunement_refresh_interval_seconds`, default 300s),
  reusing the exact JSON-RPC 2.0 ``tools/call`` envelope, the shared
  ``mcp_fallback_endpoint``, and the Bearer-JWT auth that
  :class:`~alter_runtime.subscribers.mcp_fallback.McpFallbackSubscriber`
  already uses - so there is one wire contract, not two.
* Runs **regardless of stream connection state**. Unlike the fallback it does not
  subscribe to ``identity.connected`` / ``identity.disconnected``; it simply
  ticks on its interval for as long as the daemon is up.
* Publishes the result onto the EventBus as an ``identity.event`` with kind
  ``attunement_transition`` - a kind the existing
  :class:`~alter_runtime.subscribers.cache_writer.CacheWriter` already
  recognises and projects (it reads ``attunement_score`` into the cache's
  ``attunement`` field and ``engagement_level`` into ``level``). No cache
  writer change is needed.
* Is resilient: a failed or empty ``alter_attunement`` call backs off
  exponentially (capped) and retries on the next tick. It never raises out of
  its loop, never crashes the daemon, and never blocks other components.

Design choice - why a new component, not a do_sse heartbeat
-----------------------------------------------------------

The lowest-risk option. ``do_sse``'s connect / auth / mint path was just
stabilised in production and must not regress, so we deliberately add this as
a *separate concern* with zero coupling to ``do_sse``: it shares only the
read-only MCP wire contract (envelope + endpoint + JWT) that ``mcp_fallback``
already established. It cannot perturb the SSE connection, the subscribe-cap
mint, or the stall watchdog. The only shared surface with the rest of the
daemon is the in-process EventBus (publish-only) - the same contract every
other subscriber uses.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

from alter_runtime.config import DaemonConfig
from alter_runtime.daemon import Component
from alter_runtime.http_auth import backend_default_headers
from alter_runtime.invocation_signing import build_signed_mcp_headers
from alter_runtime.subscribers.bus import EventBus
from alter_runtime.subscribers.do_sse import _build_tls_context

if TYPE_CHECKING:
    from alter_runtime.config import Session, SessionRef

__all__ = ["AttunementRefresher", "ATTUNEMENT_KIND"]

logger = logging.getLogger("alter_runtime.subscribers.attunement_refresher")

TOPIC_EVENT = "identity.event"

#: The bus-event kind we publish. ``cache_writer.STATE_KINDS`` recognises
#: ``attunement_transition`` and projects ``attunement_score`` ->
#: cache ``attunement`` and ``engagement_level`` -> cache ``level``.
ATTUNEMENT_KIND = "attunement_transition"

#: Upper bound on the refresher's own exponential backoff when the MCP
#: endpoint (or the attunement tool) is failing. Matches the fallback's cap.
MAX_REFRESH_BACKOFF_SECONDS: float = 60.0

#: Fields we lift from the ``alter_attunement`` result. These are exactly the
#: keys ``cache_writer.project_state_to_cache`` reads.
_ATTUNEMENT_FIELDS = ("attunement_score", "engagement_level", "engagement_label")


@dataclass
class _RefresherState:
    """Internal state for the refresher (exposed for tests)."""

    poll_count: int = 0
    publish_count: int = 0
    backoff: float = 0.0
    history: list[str] = field(default_factory=list)


class AttunementRefresher(Component):
    """Periodically pulls ``alter_attunement`` into the shell cache.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Uses ``mcp_fallback_endpoint`` (shared
        read-side MCP endpoint) and ``attunement_refresh_interval_seconds``.
    session:
        Authenticated CLI :class:`Session`. Used for the Bearer JWT and
        the handle (for logging and the published event ``handle``).
    bus:
        Shared :class:`EventBus`. The refresher publishes ``identity.event``
        frames; it does not subscribe to anything.
    http_client:
        Optional ``httpx.AsyncClient`` override for tests.
    """

    name = "attunement_refresher"

    def __init__(
        self,
        config: DaemonConfig,
        session: "Session | SessionRef",
        bus: EventBus,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config
        from alter_runtime.config import SessionRef as _SessionRef

        if isinstance(session, _SessionRef):
            self._session_ref: "_SessionRef | None" = session
            self._session: "Session" = session.current
        else:
            self._session_ref = None
            self._session = session  # type: ignore[assignment]
        self._bus = bus
        self._http_client = http_client
        self._owns_client = http_client is None
        self._stop_event = asyncio.Event()
        self._state = _RefresherState()
        self._request_id_counter = 0

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Tick on the configured interval, refreshing attunement each tick."""
        logger.info(
            "attunement_refresher starting handle=%s endpoint=%s interval=%.0fs",
            self._session.handle,
            self._config.mcp_fallback_endpoint,
            self._config.attunement_refresh_interval_seconds,
        )

        client = self._http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
            # Same strict TLS posture as the SSE / MCP fallback path:
            # CERT_REQUIRED, check_hostname=True, TLS 1.2 minimum.
            verify=_build_tls_context(),
            # Canonical client-identity headers; the per-request Bearer JWT
            # and invocation signature are attached on each call below.
            headers=backend_default_headers(),
        )

        try:
            while not self._stop_event.is_set():
                try:
                    attunement = await self._poll_once(client)
                except asyncio.CancelledError:
                    raise
                except (httpx.HTTPError, ValueError) as exc:
                    await self._on_poll_error(exc)
                    await self._sleep_interruptible(self._state.backoff)
                    continue

                if attunement:
                    await self._publish_attunement(attunement)
                    # Reset backoff on a successful, non-empty refresh.
                    self._state.backoff = 0.0
                    await self._sleep_interruptible(
                        self._config.attunement_refresh_interval_seconds
                    )
                else:
                    # A well-formed-but-empty response (no score yet, or the
                    # tool returned nothing) is not an error - the member may
                    # simply have no attunement to report. Back off gently so a
                    # member at attunement=0 isn't polled every tick forever,
                    # but never escalate to the error backoff.
                    await self._sleep_interruptible(
                        self._config.attunement_refresh_interval_seconds
                    )
        finally:
            if self._owns_client:
                try:
                    await client.aclose()
                except Exception:  # pragma: no cover
                    pass
            logger.info("attunement_refresher stopped handle=%s", self._session.handle)

    async def stop(self) -> None:
        """Cooperative shutdown."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    async def _poll_once(self, client: httpx.AsyncClient) -> dict[str, Any] | None:
        """Call ``alter_attunement`` and return the trimmed attunement dict.

        Returns ``None`` when the tool reports nothing usable (JSON-RPC error,
        empty result, or no attunement fields present). Raises ``httpx.HTTPError``
        / ``ValueError`` on transport-level failures so the caller's backoff
        path engages - identical to the fallback's ``_call_tool`` contract.
        """
        result = await self._call_tool(client, "alter_attunement")
        if not result:
            return None

        trimmed: dict[str, Any] = {}
        for key in _ATTUNEMENT_FIELDS:
            value = result.get(key)
            if value is not None and value != "":
                trimmed[key] = value

        # Carry the handle through so the cache writer keys the projection to
        # the right member even if the tool result omits it.
        handle = result.get("handle") or self._session.handle
        if handle:
            trimmed.setdefault("handle", handle)

        # If there's no actual attunement signal, treat as empty rather than
        # publishing a handle-only event that would blank nothing useful.
        if not any(k in trimmed for k in _ATTUNEMENT_FIELDS):
            return None
        return trimmed

    async def _call_tool(self, client: httpx.AsyncClient, tool_name: str) -> dict[str, Any] | None:
        """Issue one JSON-RPC ``tools/call`` and return the result dict, or None.

        Mirrors ``McpFallbackSubscriber._call_tool``: raises on transport
        errors (so backoff engages) but returns ``None`` for a
        well-formed-but-empty or JSON-RPC-error response (so a single soft
        failure is tolerated without crashing the loop).

        The ``Mcp-Invocation-Signature`` ES256 header is injected via
        :func:`~alter_runtime.invocation_signing.build_signed_mcp_headers`
        when a signing key is available. When the key is absent or
        unreadable the header is omitted and a WARNING is logged.
        """
        self._request_id_counter += 1
        # These tools are called with empty arguments.
        arguments: dict[str, Any] = {}
        body = {
            "jsonrpc": "2.0",
            "id": self._request_id_counter,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        _live = self._session_ref.current if self._session_ref is not None else self._session
        base_headers = {
            "Authorization": f"Bearer {_live.jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Inject the per-invocation signature. build_signed_mcp_headers
        # returns base_headers unchanged when signing is not possible.
        headers = build_signed_mcp_headers(
            _live,
            tool_name,
            arguments,
            base_headers,
        )

        logger.debug(
            "attunement_refresher polling tool=%s endpoint=%s signed=%s",
            tool_name,
            self._config.mcp_fallback_endpoint,
            "Mcp-Invocation-Signature" in headers,
        )
        response = await client.post(
            self._config.mcp_fallback_endpoint,
            json=body,
            headers=headers,
        )
        response.raise_for_status()

        self._state.poll_count += 1

        try:
            rpc_response = response.json()
        except ValueError:
            logger.warning("attunement_refresher non-JSON response tool=%s", tool_name)
            return None

        if not isinstance(rpc_response, dict):
            return None
        if "error" in rpc_response and rpc_response.get("error"):
            err = rpc_response["error"]
            logger.warning(
                "attunement_refresher JSON-RPC error tool=%s code=%s message=%s",
                tool_name,
                err.get("code") if isinstance(err, dict) else err,
                err.get("message") if isinstance(err, dict) else err,
            )
            return None

        result = rpc_response.get("result")
        if not isinstance(result, dict):
            return None
        return result

    async def _on_poll_error(self, exc: Exception) -> None:
        """Increase backoff and log. Never raises."""
        self._state.backoff = min(
            max(self._state.backoff * 2 if self._state.backoff else 2.0, 2.0),
            MAX_REFRESH_BACKOFF_SECONDS,
        )
        logger.warning(
            "attunement_refresher poll failed: %s - backoff %.1fs",
            exc,
            self._state.backoff,
        )

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def _publish_attunement(self, attunement: dict[str, Any]) -> None:
        """Publish an ``attunement_transition`` identity.event for the cache writer.

        The event is emitted with the attunement fields at the *top level* so
        ``cache_writer.project_state_to_cache`` (which reads ``attunement_score``
        and ``engagement_level`` from the event body) projects them straight
        into ``identity.json``'s ``attunement`` / ``level`` fields.
        """
        event: dict[str, Any] = {
            "kind": ATTUNEMENT_KIND,
            "source": "attunement_refresher",
            "handle": self._session.handle,
            **attunement,
        }
        self._state.publish_count += 1
        self._state.history.append("publish")
        logger.info(
            "attunement_refresher publishing attunement poll=%d score=%s level=%s",
            self._state.poll_count,
            attunement.get("attunement_score"),
            attunement.get("engagement_level"),
        )
        await self._bus.publish(TOPIC_EVENT, event)

    async def _sleep_interruptible(self, seconds: float) -> None:
        """Wait ``seconds`` or until stopped, whichever comes first."""
        if seconds <= 0:
            return
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except (TimeoutError, asyncio.TimeoutError):
            return

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def state(self) -> _RefresherState:
        """Current refresher state (used by tests)."""
        return self._state
