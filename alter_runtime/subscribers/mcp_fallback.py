"""McpFallbackSubscriber - direct MCP polling when the DO is unreachable.

When the primary :class:`DoSseSubscriber` is connected to the edge, this
subscriber is idle. When it transitions to disconnected (via the
``identity.disconnected`` bus sentinel), the fallback starts polling the
backend MCP endpoint at :attr:`DaemonConfig.mcp_fallback_endpoint` and
publishes synthetic frames onto the bus so that local surfaces (Unix socket,
D-Bus, inbox projection) never notice the edge is down.

The fallback calls the ``alter_whoami`` MCP tool - the one stable, publicly
documented read-side call on the backend that returns the authenticated
identity's consent-tier / engagement / trait-snapshot header - and then the
``alter_attunement`` tool, which carries the attunement score that
``alter_whoami`` deliberately omits (whoami returns ``attunement: None``). The
attunement fields are merged onto the whoami result; the second call is
best-effort, so a missing attunement never blanks the identity surface. We
treat the merged response as a ``state_sync`` synthetic event, synthesise an
:class:`SSEFrame`, and publish to both ``identity.frame`` and
``identity.event`` (mirroring what the DO SSE path does).

When the DO reconnects (``identity.connected``), polling stops until the next
disconnect. Either way the local surfaces never know which path served them.

Design notes
------------

* **JSON-RPC envelope.** The backend MCP endpoint speaks JSON-RPC 2.0 over
  HTTP POST. Each poll sends two calls of the form ``{"jsonrpc": "2.0",
  "method": "tools/call", "params": {"name": <tool>, "arguments": {}}, "id":
  <counter>}`` - one for ``alter_whoami`` then one for ``alter_attunement``.
* **State deduplication.** We cache the hash of the last published state
  dict and skip publishing if the new state is identical - polling produces
  noise otherwise. Tests exercise this.
* **Auth propagation.** The server MCP tool accepts the CLI JWT as
  the ``Authorization`` bearer header.
* **Back-off.** If the fallback itself is failing (backend MCP is also down),
  we slow the poll rate with exponential backoff up to one minute between
  attempts, and never log at ERROR - the disconnected state is already
  logged by ``DoSseSubscriber``.
* **Cold start.** The fallback starts in *idle* mode. If the DO has never
  connected, it waits for the first explicit ``identity.disconnected``
  signal before polling. There is a separate cold-start timer in
  :meth:`run` that activates the fallback if no ``identity.connected`` arrives
  within ``fallback_trigger_after_seconds * 3`` of startup, which covers the
  case where the primary subscriber can never establish a connection at all.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
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
from alter_runtime.subscribers.sse import SSEFrame

if TYPE_CHECKING:
    from alter_runtime.config import Session, SessionRef

__all__ = ["McpFallbackSubscriber"]

logger = logging.getLogger("alter_runtime.subscribers.mcp_fallback")

TOPIC_CONNECTED = "identity.connected"
TOPIC_DISCONNECTED = "identity.disconnected"
TOPIC_FRAME = "identity.frame"
TOPIC_EVENT = "identity.event"

#: Upper bound on the fallback's own exponential backoff when the MCP
#: endpoint is also failing.
MAX_POLL_BACKOFF_SECONDS: float = 60.0


@dataclass
class _FallbackState:
    """Internal state for the fallback subscriber (exposed for tests)."""

    active: bool = False
    poll_count: int = 0
    last_state_hash: str | None = None
    backoff: float = 0.0
    history: list[str] = field(default_factory=list)


class McpFallbackSubscriber(Component):
    """Polls the backend MCP endpoint while the DO is unreachable.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Uses ``mcp_fallback_endpoint``,
        ``fallback_poll_interval_seconds``, and ``fallback_trigger_after_seconds``.
    session:
        Authenticated CLI :class:`Session`. Used for the bearer JWT and
        the handle (for logging and the synthetic frame ``id``).
    bus:
        Shared :class:`EventBus`. The fallback subscribes to connect/disconnect
        sentinels and publishes synthetic frames/events.
    http_client:
        Optional ``httpx.AsyncClient`` override for tests.
    """

    name = "mcp_fallback"

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
        self._state = _FallbackState()
        self._activate_event = asyncio.Event()
        self._request_id_counter = 0

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Subscribe to bus sentinels and drive the polling loop."""
        logger.info(
            "mcp_fallback starting handle=%s endpoint=%s",
            self._session.handle,
            self._config.mcp_fallback_endpoint,
        )

        self._bus.subscribe(TOPIC_CONNECTED, self._on_do_connected)
        self._bus.subscribe(TOPIC_DISCONNECTED, self._on_do_disconnected)

        # Cold-start: if the DO never connects, activate the fallback after
        # fallback_trigger_after_seconds * 3 so local surfaces still have
        # something to render.
        cold_start_deadline = max(self._config.fallback_trigger_after_seconds * 3.0, 10.0)
        cold_start_task = asyncio.create_task(self._cold_start_timer(cold_start_deadline))

        client = self._http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
            # Same strict TLS posture as the DO SSE path - CERT_REQUIRED,
            # check_hostname=True, TLS 1.2 minimum.
            verify=_build_tls_context(),
            # Backend default headers: the canonical ``X-Alter-Client-*``
            # identity headers so the server-side floor middleware can
            # identify the daemon.
            headers=backend_default_headers(),
        )

        try:
            while not self._stop_event.is_set():
                # Idle until someone activates us.
                try:
                    await asyncio.wait_for(
                        self._activate_event.wait(),
                        timeout=None,
                    )
                except asyncio.CancelledError:
                    raise

                if self._stop_event.is_set():
                    return

                await self._poll_loop(client)
        finally:
            cold_start_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await cold_start_task

            self._bus.unsubscribe(TOPIC_CONNECTED, self._on_do_connected)
            self._bus.unsubscribe(TOPIC_DISCONNECTED, self._on_do_disconnected)

            if self._owns_client:
                try:
                    await client.aclose()
                except Exception:  # pragma: no cover
                    pass
            logger.info("mcp_fallback stopped handle=%s", self._session.handle)

    async def stop(self) -> None:
        """Cooperative shutdown."""
        self._stop_event.set()
        self._activate_event.set()  # unwedge the idle wait

    # ------------------------------------------------------------------
    # Bus callbacks
    # ------------------------------------------------------------------

    async def _on_do_disconnected(self, payload: dict[str, Any]) -> None:
        """Primary subscriber reported a disconnect - activate polling."""
        if self._state.active:
            return
        self._state.active = True
        self._state.history.append("activate")
        logger.info(
            "mcp_fallback activating handle=%s reason=%s",
            self._session.handle,
            payload.get("reason"),
        )
        self._activate_event.set()

    async def _on_do_connected(self, payload: dict[str, Any]) -> None:
        """Primary subscriber reconnected - stand down."""
        if not self._state.active:
            return
        self._state.active = False
        self._state.history.append("deactivate")
        logger.info(
            "mcp_fallback standing down handle=%s (DO reconnected)",
            self._session.handle,
        )
        # Clear the activate event so the next wait_for blocks again.
        self._activate_event.clear()

    async def _cold_start_timer(self, seconds: float) -> None:
        """Activate the fallback if the DO never connected at startup."""
        try:
            await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            return
        if self._stop_event.is_set():
            return
        if not self._state.active and self._state.poll_count == 0:
            logger.warning(
                "mcp_fallback cold-start: DO has not connected in %.0fs - "
                "activating fallback polling",
                seconds,
            )
            self._state.active = True
            self._state.history.append("cold_start")
            self._activate_event.set()

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------

    async def _poll_loop(self, client: httpx.AsyncClient) -> None:
        """While active, poll MCP every N seconds and publish synthetic frames."""
        while self._state.active and not self._stop_event.is_set():
            try:
                state = await self._poll_once(client)
            except asyncio.CancelledError:
                raise
            except (httpx.HTTPError, ValueError) as exc:
                await self._on_poll_error(exc)
                await self._sleep_interruptible(self._state.backoff)
                continue

            if state is not None:
                await self._publish_state(state)

            # Reset backoff on success
            self._state.backoff = 0.0
            await self._sleep_interruptible(self._config.fallback_poll_interval_seconds)

    async def _poll_once(self, client: httpx.AsyncClient) -> dict[str, Any] | None:
        """Poll the MCP endpoint and return the merged identity state, or None.

        Issues two JSON-RPC ``tools/call`` requests against the same endpoint:

        1. ``alter_whoami`` - the authoritative identity header (handle,
           consent_tier, engagement level, trait snapshot). This is the
           critical call; if it fails the whole poll fails.
        2. ``alter_attunement`` - the attunement score plus engagement
           level/label. ``alter_whoami`` deliberately omits the attunement
           score (it returns ``attunement: None``), so when the live SSE feed
           is down this second call is the only path that carries attunement to
           the cache writer. It is best-effort: if it fails or comes back empty
           we still publish the whoami state rather than dropping the poll, so
           a missing attunement never blanks out the identity surface.

        The attunement fields (``attunement_score``, ``engagement_level``,
        ``engagement_label``) are merged onto the whoami result dict so the
        cache writer (which reads ``attunement_score`` + ``engagement_level``)
        receives them under the keys it already expects.
        """
        whoami = await self._call_tool(client, "alter_whoami")
        if whoami is None:
            return None

        attunement = await self._call_tool(client, "alter_attunement")
        if attunement:
            for key in ("attunement_score", "engagement_level", "engagement_label"):
                value = attunement.get(key)
                if value is not None and value != "":
                    whoami[key] = value

        return whoami

    async def _call_tool(self, client: httpx.AsyncClient, tool_name: str) -> dict[str, Any] | None:
        """Issue one JSON-RPC ``tools/call`` and return the result dict, or None.

        Raises on transport errors (``httpx.HTTPError``) so the caller's
        backoff path engages; returns ``None`` for a well-formed-but-empty or
        JSON-RPC-error response so a single soft failure (e.g. a missing
        attunement) can be tolerated without aborting the poll.

        The ``Mcp-Invocation-Signature`` ES256 header is injected via
        :func:`~alter_runtime.invocation_signing.build_signed_mcp_headers`
        when a signing key is available. When the key is absent or
        unreadable the header is omitted and a WARNING is logged; the server
        will reject with -32002 (same as before this change).
        """
        self._request_id_counter += 1
        # These two subscribers call tools with empty arguments; the canonical
        # hash of ``{}`` is stable and does not change between calls.
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
        _live_session = (
            self._session_ref.current if self._session_ref is not None else self._session
        )
        base_headers = {
            "Authorization": f"Bearer {_live_session.jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Inject the per-invocation signature. build_signed_mcp_headers
        # returns base_headers unchanged when signing is not possible.
        headers = build_signed_mcp_headers(
            _live_session,
            tool_name,
            arguments,
            base_headers,
        )

        logger.debug(
            "mcp_fallback polling tool=%s endpoint=%s signed=%s",
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
            logger.warning("mcp_fallback non-JSON response from MCP endpoint tool=%s", tool_name)
            return None

        if not isinstance(rpc_response, dict):
            return None
        if "error" in rpc_response and rpc_response.get("error"):
            err = rpc_response["error"]
            logger.warning(
                "mcp_fallback JSON-RPC error tool=%s code=%s message=%s",
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
        """Increase backoff and log. Does not change the active flag."""
        self._state.backoff = min(
            max(self._state.backoff * 2 if self._state.backoff else 2.0, 2.0),
            MAX_POLL_BACKOFF_SECONDS,
        )
        logger.warning(
            "mcp_fallback poll failed: %s - backoff %.1fs",
            exc,
            self._state.backoff,
        )

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def _publish_state(self, state: dict[str, Any]) -> None:
        """Dedupe against the last published state and publish a synthetic frame."""
        digest = _stable_hash(state)
        if digest == self._state.last_state_hash:
            logger.debug("mcp_fallback state unchanged - skip publish")
            return
        self._state.last_state_hash = digest

        synthetic_event: dict[str, Any] = {
            "kind": "state_sync",
            "source": "mcp_fallback",
            "handle": self._session.handle,
            "payload": state,
        }
        frame = SSEFrame(
            event="state_sync",
            data=json.dumps(synthetic_event, separators=(",", ":")),
            id=f"fallback-{self._state.poll_count}",
        )
        logger.info(
            "mcp_fallback publishing state_sync poll=%d keys=%s",
            self._state.poll_count,
            sorted(state.keys())[:8],
        )
        await self._bus.publish(TOPIC_FRAME, frame)
        await self._bus.publish(TOPIC_EVENT, synthetic_event)

    async def _sleep_interruptible(self, seconds: float) -> None:
        """Wait ``seconds`` or until stopped / deactivated."""
        if seconds <= 0:
            return
        try:
            # Wake early if either shutdown or reconnect fires.
            await asyncio.wait_for(self._wait_stop_or_inactive(), timeout=seconds)
        except (TimeoutError, asyncio.TimeoutError):
            return

    async def _wait_stop_or_inactive(self) -> None:
        """Return as soon as either the component stops or the fallback is deactivated."""
        while not self._stop_event.is_set() and self._state.active:
            await asyncio.sleep(0.05)

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def state(self) -> _FallbackState:
        """Current fallback state (used by tests)."""
        return self._state


def _stable_hash(state: dict[str, Any]) -> str:
    """SHA-256 of a canonicalised JSON encoding of ``state`` (for dedupe)."""
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
