"""UnixSocketServer - local JSON-RPC surface for the runtime daemon.

Binds an ``asyncio`` Unix-domain socket at :attr:`DaemonConfig.unix_socket`
(typically ``$XDG_RUNTIME_DIR/alter.sock`` on Linux) with mode ``0o600`` and
speaks line-delimited JSON to connected clients.

Wire protocol
-------------

Every message (request or response) is a single UTF-8 line terminated with
``\\n``. Requests are JSON-RPC 2.0-ish - we keep it minimal:

::

    {"method": "ping"}                  -> {"ok": true, "pong": true}
    {"method": "auth", "token": "<t>"}  -> {"ok": true, "authenticated": true}
    {"method": "subscribe"}             -> streams live events as they arrive
    {"method": "ingest", "kind": "vault_consent_grant", "payload": {...}}
    {"method": "whoami"}                -> {"ok": true, "handle": "<handle>"}
    {"method": "agent/roster"}          -> {"ok": true, "roster": [...instruments...]}
    {"method": "send", "to": "<handle>", "body": "<md>"}
                                        -> {"ok": true, "sent": true, "to": "<handle>"}

Streaming events (from a live ``subscribe``) are pushed as server-originated
frames of the form::

    {"event": "identity.frame", "data": {...SSEFrame fields...}}

Closing the client socket ends the subscription. Disconnects during write
are swallowed.

Security
--------

The socket is created with the process umask tightened to ``0o077`` and then
``os.chmod()``'d to ``0o600`` to keep every other UID off it. POSIX peer-cred
inspection is not required for cross-UID isolation - the ``0o600`` mode alone
is sufficient on Linux and macOS because neither permits other users to open
a socket they cannot read/write. Windows Named Pipe support is planned.

Beyond the cross-UID gate, the server requires a token-based auth handshake
*within* the same UID - every method except ``ping`` is refused until the
client has presented the daemon's startup token. The token is minted at
``run()`` and written to ``<socket_parent>/alter-daemon-token`` mode ``0o600``;
same-UID clients read the file and present the value as
``{"method":"auth","token":"<t>"}`` immediately after connect. Auth failures
close the connection. This narrows the attack surface from "any same-UID
process can ingest events" to "any same-UID process that has read the token
file" - still bounded by the same trust floor as ``~/.ssh/id_rsa`` but with
an explicit audit boundary, an ``ingest`` ``kind`` whitelist, and rejection
of accidental connections from misconfigured tools.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from alter_runtime.cap_cache import DaemonCapCache
from alter_runtime.config import DaemonConfig
from alter_runtime.daemon import Component
from alter_runtime.floor_loop import FloorState, is_safety_critical_call
from alter_runtime.messaging import DEFAULT_CONTENT_TYPE, SendError, send_member_message
from alter_runtime.subscribers.bus import EventBus
from alter_runtime.subscribers.sse import SSEFrame

if TYPE_CHECKING:
    from alter_runtime.auth_health import AuthHealth
    from alter_runtime.config import Session, SessionRef
    from alter_runtime.subscribers.agent_frames import AgentFrameSubscriber
    from alter_runtime.subscribers.session_refresher import RefreshTrigger

__all__ = ["UnixSocketServer"]

logger = logging.getLogger("alter_runtime.sockets.unix")

#: Maximum length of a single JSON-RPC request line. Large enough for a
#: typical ingest payload but small enough to prevent a runaway client from
#: exhausting memory.
MAX_LINE_BYTES: int = 256 * 1024

#: Topics to forward to subscribed clients.
FORWARDED_TOPICS: tuple[str, ...] = (
    "identity.frame",
    "identity.event",
    "identity.connected",
    "identity.disconnected",
)

#: Topic used for egress - clients that call ``ingest`` publish here for the
#: eventual ``LocalSignalForwarder`` to POST to the Durable Object.
EGRESS_TOPIC: str = "local.signal"

#: Filename (relative to the socket's parent directory) of the daemon-minted
#: auth token. Written ``0o600`` at server startup; same-UID clients read it
#: and present the value via ``{"method":"auth","token":"<t>"}``.
TOKEN_FILENAME: str = "alter-daemon-token"

#: ``ingest`` kinds external clients may publish onto the bus. Internal
#: subscribers (``GitWatcher``, ``EbpfSubscriber``, etc.) publish directly via
#: the in-process bus and never traverse this socket; the whitelist here is
#: scoped to what plugins / external clients are permitted to inject.
INGEST_KIND_WHITELIST: frozenset[str] = frozenset(
    {
        "vault_consent_grant",
        "vault_consent_revoke",
        "vault_inference_emit",
    }
)


@dataclass(eq=False)
class _ClientConnection:
    """Per-client book-keeping.

    ``eq=False`` keeps the default ``__hash__`` (object identity) so that
    instances can live in a ``set()``. Structural equality between client
    sessions has no meaning here - each connection is its own identity.
    """

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    subscribed: bool = False
    #: ``True`` once the client has presented the daemon token via the
    #: ``auth`` method. ``ping`` is the only method allowed before this flips;
    #: every other method short-circuits with ``{"ok": false, "error":
    #: "auth required"}`` and the connection is closed.
    authenticated: bool = False
    #: Queue used to fan out bus events to this specific client without
    #: blocking the bus publisher.
    queue: asyncio.Queue[dict[str, Any]] = field(default_factory=lambda: asyncio.Queue(maxsize=256))

    def peer(self) -> str:
        """Human-readable identifier for log lines."""
        try:
            info = self.writer.get_extra_info("sockname")
            return str(info) if info else "<unix>"
        except Exception:  # pragma: no cover
            return "<unix>"


class UnixSocketServer(Component):
    """Local JSON-RPC server on a Unix-domain socket.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig` - only ``unix_socket`` is consulted.
    bus:
        Shared :class:`EventBus`. The server subscribes to identity topics
        for fan-out and publishes to ``local.signal`` on ingest.
    session:
        Authenticated CLI :class:`Session` - used for the ``whoami``
        method. Optional so tests can start the server without a session.
    socket_path:
        Optional override for the socket path (tests inject a ``tmp_path``
        location so they don't collide with a real daemon).
    auth_token:
        Optional explicit auth token. When ``None`` (the production default),
        :meth:`run` mints a fresh ``secrets.token_urlsafe(32)`` value at
        startup and writes it next to the socket as ``alter-daemon-token``
        (mode ``0o600``). Tests may inject a deterministic value to avoid
        the disk write - when provided, no token file is created.
    session_ref:
        Optional live :class:`~alter_runtime.config.SessionRef` holder.
        When present, forwarded to the lazily-constructed
        :class:`DaemonCapCache` INSTEAD OF ``session`` so capability request reads
        through a proactive/reactive token rotation rather than the
        boot-time JWT forever (2026-07-12 fix). ``session`` itself keeps
        its existing frozen-snapshot meaning for ``whoami`` and is
        unaffected either way.
    refresh_trigger:
        Optional shared :class:`~alter_runtime.subscribers.session_refresher.RefreshTrigger`,
        forwarded to the lazily-constructed :class:`DaemonCapCache` so a
        capability request 401 wakes ``SessionRefresher`` out of band (2026-07-12 fix).
    auth_health:
        Optional shared :class:`~alter_runtime.auth_health.AuthHealth`,
        forwarded to the same lazily-constructed :class:`DaemonCapCache` so an
        accepted capability request is recorded as proof the session is still alive.
    """

    name = "unix_socket"

    def __init__(
        self,
        config: DaemonConfig,
        bus: EventBus,
        session: Session | None = None,
        *,
        socket_path: Path | None = None,
        auth_token: str | None = None,
        agent_frames_subscriber: AgentFrameSubscriber | None = None,
        floor_state: FloorState | None = None,
        cap_cache: DaemonCapCache | None = None,
        http_client: Any | None = None,
        session_ref: "SessionRef | None" = None,
        refresh_trigger: "RefreshTrigger | None" = None,
        auth_health: "AuthHealth | None" = None,
    ) -> None:
        self._config = config
        self._bus = bus
        self._session = session
        self._session_ref = session_ref
        self._refresh_trigger = refresh_trigger
        self._auth_health = auth_health
        self._socket_path: Path = socket_path if socket_path is not None else config.unix_socket
        # Optional reference to the AgentFrameSubscriber that maintains the
        # in-memory instrument roster.  When present, the ``agent/roster``
        # method returns the live roster without a server round-trip.  When absent,
        # ``agent/roster`` returns an empty list so the daemon starts cleanly
        # even when the subscriber has not been registered yet.
        self._agent_frames_subscriber: AgentFrameSubscriber | None = agent_frames_subscriber
        # Shared floor state: when the
        # FloorLoop reports below floor, every authenticated method except
        # the ping/auth handshake and safety-critical carve-outs
        # short-circuits with the canonical ``client_below_floor`` envelope.
        # When ``None`` (tests / degraded daemon) the gate is effectively
        # a no-op; the server-side backend gate remains authoritative.
        self._floor_state: FloorState | None = floor_state
        self._auth_token: str | None = auth_token
        self._token_path: Path | None = None
        self._token_minted: bool = False
        self._server: asyncio.base_events.Server | None = None
        self._clients: set[_ClientConnection] = set()
        self._stop_event = asyncio.Event()
        # Callback handles registered on the bus - kept so we can unsubscribe
        # cleanly on stop.
        self._bus_handlers: dict[str, Any] = {}
        # Machine-wide capability and query cache shared across all clients.
        # When ``None`` a fresh instance is created on first use. Tests may
        # inject a pre-configured instance.
        self._cap_cache: DaemonCapCache | None = cap_cache
        # Optional HTTP client for cap_cache use.  When provided the
        # cap_cache's own client is overridden by passing it explicitly on
        # each call so tests can inject a mock transport.
        self._http_client: Any | None = http_client

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Bind the socket and serve clients until stop() is called."""
        parent = self._socket_path.parent

        # Hardening: the parent directory holds the socket
        # AND the daemon token file. mkdir(mode=0o700) only sets the mode
        # on creation, not when the parent already exists. We must (a)
        # create with 0o700, AND (b) chmod-fix any pre-existing parent so
        # an inherited 0o755 from a non-XDG fallback (like /tmp/alter-1000/)
        # cannot leak the token to other UIDs. Refuse outright when the
        # fallback root is /tmp and XDG_RUNTIME_DIR is unset - /tmp itself
        # is 1777 and a per-user subdir there is the wrong trust posture
        # for shipping signed-frame credentials.
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        else:
            with contextlib.suppress(OSError):
                os.chmod(parent, 0o700)
        self._validate_parent_dir(parent)

        # If a stale socket file exists (daemon crashed without cleanup),
        # remove it. We only do this if it's an actual socket - never a
        # regular file.
        if self._socket_path.exists():
            try:
                mode = os.stat(self._socket_path).st_mode
            except FileNotFoundError:
                mode = 0
            import stat as _stat

            if _stat.S_ISSOCK(mode):
                logger.info("unix_socket removing stale socket at %s", self._socket_path)
                with contextlib.suppress(OSError):
                    self._socket_path.unlink()

        logger.info("unix_socket binding path=%s", self._socket_path)

        # Tighten the umask so the socket is created mode 0o600 even if the
        # inherited shell umask is 0o022.
        previous_umask = os.umask(0o077)
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_client,
                path=str(self._socket_path),
            )
        finally:
            os.umask(previous_umask)

        # Post-bind chmod in case the kernel / fs didn't honour umask.
        with contextlib.suppress(OSError):
            os.chmod(self._socket_path, 0o600)

        # Mint and persist the auth token if the caller didn't provide one.
        # Same-UID clients read this file and present its value via the
        # ``auth`` method before any other call is accepted.
        if self._auth_token is None:
            self._auth_token = secrets.token_urlsafe(32)
            self._token_minted = True
            self._token_path = self._socket_path.parent / TOKEN_FILENAME
            previous_token_umask = os.umask(0o077)
            try:
                self._token_path.write_text(self._auth_token, encoding="utf-8")
            finally:
                os.umask(previous_token_umask)
            with contextlib.suppress(OSError):
                os.chmod(self._token_path, 0o600)
            logger.info("unix_socket auth token written path=%s", self._token_path)

        # Subscribe to the identity topics we fan out.
        for topic in FORWARDED_TOPICS:
            handler = self._make_forwarder(topic)
            self._bus.subscribe(topic, handler)
            self._bus_handlers[topic] = handler

        try:
            await self._stop_event.wait()
        finally:
            logger.info("unix_socket stopping path=%s", self._socket_path)
            await self._shutdown()

    async def stop(self) -> None:
        """Cooperative shutdown."""
        self._stop_event.set()

    @staticmethod
    def _validate_parent_dir(parent: Path) -> None:
        """Refuse to bind the socket if the parent directory is unsafe.

        Hardening: the daemon token file lives next to the
        socket - if its parent isn't user-owned and 0o700-or-tighter, any
        same-UID-or-higher process can read the token and impersonate a
        legitimate client. The XDG_RUNTIME_DIR location is already
        per-user 0o700 by systemd convention; the legacy fallback
        ``/tmp/alter-<uid>.sock`` puts the token directly in /tmp (1777)
        which is the wrong trust posture for shipping. Refuse outright in
        that case so operators see the misconfiguration instead of
        silently inheriting a world-readable token directory.
        """
        # /tmp itself is 1777 by design - never permit it as the parent.
        # Tests use tmp_path (/tmp/pytest-of-<user>/...) which has its
        # own per-user owner; that case is allowed because the parent
        # we check is the socket's *direct* parent, not /tmp.
        if str(parent) == "/tmp":
            raise PermissionError(
                "unix_socket refusing to bind under /tmp directly - set "
                "XDG_RUNTIME_DIR (e.g. /run/user/$UID) or override "
                "ALTER_RUNTIME_SOCKET to a user-owned 0o700 directory."
            )
        if hasattr(os, "getuid"):
            try:
                stat_result = os.stat(parent)
            except OSError as exc:
                raise PermissionError(f"unix_socket cannot stat parent {parent}: {exc}") from exc
            if stat_result.st_uid != os.getuid():
                raise PermissionError(
                    f"unix_socket refusing to bind: parent {parent} is owned "
                    f"by uid={stat_result.st_uid}, expected uid={os.getuid()}."
                )
            mode_bits = stat_result.st_mode & 0o777
            if mode_bits & 0o077:
                raise PermissionError(
                    f"unix_socket refusing to bind: parent {parent} mode is "
                    f"{mode_bits:#o}, expected 0o700 (group/other bits unset)."
                )

    async def _shutdown(self) -> None:
        """Close the server, drop subscribers, kick connected clients."""
        for topic, handler in list(self._bus_handlers.items()):
            self._bus.unsubscribe(topic, handler)
        self._bus_handlers.clear()

        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None

        for client in list(self._clients):
            with contextlib.suppress(Exception):
                client.writer.close()

        # Remove the socket file so the next run() call starts clean.
        with contextlib.suppress(FileNotFoundError, OSError):
            self._socket_path.unlink()

        # Remove the daemon-minted token file. Tokens injected via the
        # constructor (tests, embedders) are not on disk and not our problem.
        if self._token_minted and self._token_path is not None:
            with contextlib.suppress(FileNotFoundError, OSError):
                self._token_path.unlink()
            self._token_minted = False
            self._token_path = None

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Per-client coroutine - serves one connection until it closes."""
        client = _ClientConnection(reader=reader, writer=writer)
        self._clients.add(client)
        logger.debug("unix_socket client connected peer=%s", client.peer())

        # Kick off the fan-out pump in parallel; it drains `client.queue`.
        pump_task = asyncio.create_task(self._pump_queue(client))

        try:
            while not self._stop_event.is_set():
                try:
                    line = await reader.readuntil(b"\n")
                except asyncio.IncompleteReadError:
                    break
                except asyncio.LimitOverrunError:
                    # Client sent > 64KB without a newline - drain the rest
                    # of the stream and hang up.
                    logger.warning("unix_socket client line too long peer=%s", client.peer())
                    break
                if not line or len(line) > MAX_LINE_BYTES:
                    break
                await self._dispatch_line(client, line)
        except ConnectionError:
            pass
        finally:
            pump_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await pump_task
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            self._clients.discard(client)
            logger.debug("unix_socket client disconnected peer=%s", client.peer())

    async def _dispatch_line(self, client: _ClientConnection, line: bytes) -> None:
        """Parse one JSON-RPC request line and dispatch it."""
        try:
            request = json.loads(line.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            await self._write(client, {"ok": False, "error": f"invalid json: {exc}"})
            return

        if not isinstance(request, dict):
            await self._write(client, {"ok": False, "error": "request must be a JSON object"})
            return

        method = request.get("method")

        # ``ping`` is the only method allowed pre-auth; it serves as a
        # liveness probe for clients that haven't read the token yet.
        if method == "ping":
            await self._write(client, {"ok": True, "pong": True})
            return

        # ``auth`` performs the token handshake. Constant-time compare so a
        # malicious same-UID process can't time-side-channel the token.
        if method == "auth":
            token = request.get("token")
            expected = self._auth_token
            if (
                not isinstance(token, str)
                or expected is None
                or not secrets.compare_digest(token, expected)
            ):
                logger.warning(
                    "unix_socket auth failed peer=%s - closing connection",
                    client.peer(),
                )
                await self._write(client, {"ok": False, "error": "auth: invalid token"})
                with contextlib.suppress(Exception):
                    client.writer.close()
                return
            client.authenticated = True
            await self._write(client, {"ok": True, "authenticated": True})
            return

        # Every other method requires prior auth. Refuse and close on first
        # offence - a same-UID process that doesn't speak the protocol is
        # almost certainly misconfigured rather than malicious, but either
        # way it has no business holding the connection open.
        if not client.authenticated:
            await self._write(client, {"ok": False, "error": "auth required"})
            with contextlib.suppress(Exception):
                client.writer.close()
            return

        # Floor gate: check client version before allowing the request.
        #
        # Locked → emit the canonical ``client_below_floor`` envelope on
        # every authenticated method, except the safety-critical
        # carve-out (``ingest`` with ``urgency: critical|emergency``). The
        # response body is byte-shape-equal to the server-side floor
        # reject envelope:
        # ``{"error": {"code": "client_below_floor", "message": "...",
        # "client_version": "...", "min_version": "...", "upgrade_cmd":
        # "...", "channel": "..."}}``.
        #
        # The handshake (``ping``, ``auth``) is permitted regardless of
        # floor state; analogous to the MCP ``initialize`` permitted in
        # so callers see a clean error envelope rather than a TCP
        # reset. Both methods exited above this point.
        if self._floor_state is not None and self._floor_state.is_locked():
            if not is_safety_critical_call(method, request):
                envelope = self._floor_state.envelope_payload()
                if envelope is not None:
                    floor_response: dict[str, Any] = {"ok": False, **envelope}
                    await self._write(client, floor_response)
                    return

        if method == "whoami":
            await self._write(
                client,
                {
                    "ok": True,
                    "handle": self._session.handle if self._session else None,
                    "consent_tier": self._session.consent_tier if self._session else None,
                },
            )
        elif method == "agent/roster":
            # Local read of current online instruments
            # without a server round-trip.  Delegates to the AgentFrameSubscriber's
            # in-memory roster which is populated from observed agent_frame
            # deliveries.  Returns an empty list when the subscriber has not
            # been wired (daemon degraded mode or subscriber not yet registered).
            roster: list[Any] = []
            if self._agent_frames_subscriber is not None:
                try:
                    roster = self._agent_frames_subscriber.get_roster()
                except Exception as exc:  # noqa: BLE001 - defensive
                    logger.warning("unix_socket agent/roster: roster read failed: %s", exc)
            await self._write(client, {"ok": True, "roster": roster})
        elif method == "subscribe":
            client.subscribed = True
            await self._write(client, {"ok": True, "subscribed": True})
        elif method == "unsubscribe":
            client.subscribed = False
            await self._write(client, {"ok": True, "subscribed": False})
        elif method == "ingest":
            kind = request.get("kind")
            payload = request.get("payload", {})
            if not isinstance(kind, str) or not isinstance(payload, dict):
                await self._write(
                    client,
                    {"ok": False, "error": "ingest requires kind:str and payload:dict"},
                )
                return
            if kind not in INGEST_KIND_WHITELIST:
                await self._write(
                    client,
                    {"ok": False, "error": f"ingest kind not permitted: {kind!r}"},
                )
                return
            # Mint per-kind side-effects (event_id / revocation_token /
            # timestamps) before publishing so the bus payload carries the
            # same identifiers the client receives in the response. The
            # plaintext revocation_token is rendered ONCE in the plugin's
            # Notice modal - only its SHA-256 hash is persisted client-side
            # and in the backend ledger. The daemon forwards the plaintext
            # to the backend so the ledger can compute the hash on receipt.
            response: dict[str, Any] = {"ok": True, "ingested": True}
            enriched_payload: dict[str, Any] = dict(payload)
            if kind == "vault_consent_grant":
                event_id = "evt-" + secrets.token_hex(8)
                revocation_token = secrets.token_urlsafe(32)
                granted_at = datetime.now(tz=timezone.utc).isoformat()
                response["event_id"] = event_id
                response["revocation_token"] = revocation_token
                response["granted_at"] = granted_at
                enriched_payload["event_id"] = event_id
                enriched_payload["revocation_token"] = revocation_token
                enriched_payload["granted_at"] = granted_at
            elif kind == "vault_consent_revoke":
                revoked_at = datetime.now(tz=timezone.utc).isoformat()
                response["revoked"] = True
                response["revoked_at"] = revoked_at
                enriched_payload["revoked_at"] = revoked_at
            await self._bus.publish(
                EGRESS_TOPIC,
                {
                    "kind": kind,
                    "payload": enriched_payload,
                    "source": "unix_socket",
                },
            )
            await self._write(client, response)
        elif method == "cap.get":
            # Machine-wide cap-JWT cache. Collapses N client-bridge capability request
            # calls into one minting identity per handle-scope set.
            #
            # Request:  {"method": "cap.get", "scopes": ["scope1", ...]}
            # Response: {"ok": true, "capability": "<jwt>", "expires_at": "<iso>"}
            #        or {"ok": false, "error": "<reason>"}
            scopes = request.get("scopes")
            if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
                await self._write(
                    client,
                    {"ok": False, "error": "cap.get requires scopes: string[]"},
                )
                return
            cache = self._ensure_cap_cache()
            http = self._http_client
            result = await cache.get_cap(scopes, client=http)
            await self._write(client, result)
        elif method == "query.get":
            # Cap-gated query cache. Single GET per (path, params) every 15 s.
            #
            # Request:  {"method": "query.get", "path": "<str>", "params": {...}}
            # Response: {"ok": true, "body": <any>, "cached_at": <float>}
            #        or {"ok": false, "error": "<reason>"}
            path = request.get("path")
            params = request.get("params")
            if not isinstance(path, str) or not path:
                await self._write(
                    client,
                    {"ok": False, "error": "query.get requires path: str"},
                )
                return
            if params is not None and not isinstance(params, dict):
                await self._write(
                    client,
                    {"ok": False, "error": "query.get params must be an object or absent"},
                )
                return
            cache = self._ensure_cap_cache()
            http = self._http_client
            result = await cache.get_query(path, params, client=http)
            await self._write(client, result)
        elif method == "send":
            # Outbound member-to-member message. Reuses the daemon's CLI
            # session bearer + per-invocation signature (the same auth as the
            # read-only polling tools) to issue one signed alter_message_send.
            #
            # Request:  {"method": "send", "to": "~handle", "body": "<md>",
            #            "content_type": "<optional>"}
            # Response: {"ok": true, "sent": true, "to": "~handle", ...}
            #        or {"ok": false, "error": "<reason>"}
            #
            # Default-closed at the backend: the recipient must have
            # granted this sender messaging permission, else the send is
            # rejected and surfaced as ok:false. Delivery is HUMAN-class (no
            # drafted_with tag) so the recipient's app raises a heads-up.
            to = request.get("to")
            body = request.get("body")
            if not isinstance(to, str) or not to:
                await self._write(client, {"ok": False, "error": "send requires to: str"})
                return
            if not isinstance(body, str) or not body:
                await self._write(client, {"ok": False, "error": "send requires body: str"})
                return
            if self._session is None:
                await self._write(
                    client,
                    {"ok": False, "error": "no session (run `alter login`)"},
                )
                return
            content_type = request.get("content_type") or DEFAULT_CONTENT_TYPE
            if not isinstance(content_type, str):
                await self._write(
                    client,
                    {"ok": False, "error": "content_type must be a string"},
                )
                return
            try:
                send_result = await send_member_message(
                    self._session,
                    self._config.mcp_fallback_endpoint,
                    to=to,
                    body=body,
                    content_type=content_type,
                    http_client=self._http_client,
                )
            except SendError as exc:
                await self._write(client, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # noqa: BLE001 - transport / unexpected
                logger.warning("unix_socket send failed to=%s: %s", to, exc)
                await self._write(client, {"ok": False, "error": f"send failed: {exc}"})
                return
            send_response: dict[str, Any] = {"ok": True, "sent": True, "to": to}
            for key in ("message_id", "id", "thread_id", "status"):
                value = send_result.get(key)
                if value is not None:
                    send_response[key] = value
            await self._write(client, send_response)
        else:
            await self._write(
                client,
                {"ok": False, "error": f"unknown method: {method!r}"},
            )

    async def _write(self, client: _ClientConnection, obj: dict[str, Any]) -> None:
        """Serialise ``obj`` as a single JSON line and send it."""
        try:
            body = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
            client.writer.write(body)
            await client.writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            # Client went away - swallow, the reader loop will clean up.
            pass

    async def _pump_queue(self, client: _ClientConnection) -> None:
        """Drain the client's fan-out queue onto the wire."""
        while True:
            frame = await client.queue.get()
            if not client.subscribed:
                continue
            await self._write(client, frame)

    # ------------------------------------------------------------------
    # Bus fan-out
    # ------------------------------------------------------------------

    def _make_forwarder(self, topic: str):
        """Return a bus subscriber that enqueues events for every client."""

        async def _forwarder(payload: Any) -> None:
            frame: dict[str, Any]
            if isinstance(payload, SSEFrame):
                frame = {
                    "event": topic,
                    "data": {
                        "event": payload.event,
                        "data": payload.data,
                        "id": payload.id,
                    },
                }
            else:
                frame = {"event": topic, "data": payload}
            for client in list(self._clients):
                if not client.subscribed:
                    continue
                try:
                    client.queue.put_nowait(frame)
                except asyncio.QueueFull:
                    logger.warning(
                        "unix_socket client queue full - dropping frame peer=%s",
                        client.peer(),
                    )

        return _forwarder

    # ------------------------------------------------------------------
    # Cap/query cache helpers
    # ------------------------------------------------------------------

    def _ensure_cap_cache(self) -> DaemonCapCache:
        """Return the shared :class:`DaemonCapCache`, constructing it on first call.

        Prefers ``self._session_ref`` (live read-through holder) over the
        frozen ``self._session`` snapshot when both are available, so
        capability request sees a proactively/reactively rotated JWT rather than the
        boot-time token forever (2026-07-12 fix).
        """
        if self._cap_cache is None:
            self._cap_cache = DaemonCapCache(
                self._session_ref or self._session,
                refresh_trigger=self._refresh_trigger,
                auth_health=self._auth_health,
            )
        return self._cap_cache

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    @property
    def token_path(self) -> Path | None:
        """Filesystem path of the daemon-minted token, or ``None`` if the
        token was injected via the constructor (tests / embedders) and never
        written to disk."""
        return self._token_path

    @property
    def auth_token(self) -> str | None:
        """The current auth token. Exposed for tests and same-process
        embedders; production clients read it from :attr:`token_path`."""
        return self._auth_token

    @property
    def client_count(self) -> int:
        return len(self._clients)
