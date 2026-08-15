"""DoSseSubscriber - primary inbound stream via Cloudflare Durable Object SSE.

Opens a long-lived Server-Sent Events connection against
``https://mcp.truealter.com/events/{handle}/stream`` (templated from
:class:`DaemonConfig.do_sse_endpoint`) authenticated with the CLI session
JWT, parses frames via :func:`parse_sse_frames`, and publishes:

* ``identity.frame``  - the raw :class:`SSEFrame` (for subscribers that need the
  event name or the raw payload string).
* ``identity.event``  - the parsed JSON body as a ``dict`` (convenience for
  99% of consumers; skipped when the payload isn't valid JSON).
* ``identity.connected``    - sentinel published once the first byte of a new
  connection lands. Payload: ``{"handle": str, "reconnect_count": int}``.
* ``identity.disconnected`` - sentinel published when the connection drops or
  stalls past :attr:`DaemonConfig.fallback_trigger_after_seconds`. Payload:
  ``{"handle": str, "reason": str, "reconnect_count": int}``.

The subscriber is the only component that talks to the network on the hot
path; every other component reads from the bus. That separation is deliberate
so the fallback path (:class:`McpFallbackSubscriber`) can take over without
the fan-out layer noticing.

Reconnection semantics:

* The SSE ``id:`` field from the most recently parsed frame is remembered
  across reconnects and sent back as the ``Last-Event-ID`` HTTP header so the
  DO can replay anything we missed.
* Transient errors (``httpx.TransportError``, 502/503/504, socket reset) are
  logged at warning level and retried with exponential backoff capped at
  ``MAX_BACKOFF_SECONDS``.
* Authentication errors (401/403) are logged at error level and retried more
  slowly - the JWT may have been rotated and the daemon does not own
  re-authentication; the operator is expected to run ``alter login``.
* Cancellation (``asyncio.CancelledError``) propagates so the supervisor can
  shut the component down cleanly.

The subscriber never raises out of :meth:`run` - the supervisor's
exponential-backoff restart machinery is kept as a last-resort safety net for
truly unexpected exceptions.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import ssl
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

from alter_runtime.config import ConfigError, DaemonConfig
from alter_runtime.daemon import Component
from alter_runtime.http_auth import backend_default_headers
from alter_runtime.subscribers.sse import SSEFrame, parse_sse_frames

if TYPE_CHECKING:
    from alter_runtime.config import Session, SessionRef
    from alter_runtime.subscribers.bus import EventBus
    from alter_runtime.subscribers.session_refresher import RefreshTrigger

__all__ = ["DoSseSubscriber"]

logger = logging.getLogger("alter_runtime.subscribers.do_sse")

#: Topic published once per successful connection start.
TOPIC_CONNECTED = "identity.connected"
#: Topic published when the connection drops or the stream stalls.
TOPIC_DISCONNECTED = "identity.disconnected"
#: Topic published per raw SSE frame.
TOPIC_FRAME = "identity.frame"
#: Topic published with the parsed JSON event body (skipped on parse failure).
TOPIC_EVENT = "identity.event"

#: Initial back-off in seconds after a transient network error.
BASE_BACKOFF_SECONDS: float = 1.0
#: Upper bound on exponential back-off.
MAX_BACKOFF_SECONDS: float = 60.0
#: Slow back-off for authentication failures - the user probably needs to
#: run ``alter login`` to fix the session, so we don't want to hammer the edge.
AUTH_ERROR_BACKOFF_SECONDS: float = 300.0
#: A connection that survives at least this long is treated as "healthy" - the
#: next reconnect starts the backoff fresh; a connection that dies sooner is a
#: flap and the backoff keeps climbing.
STABLE_CONNECTION_SECONDS: float = 30.0

#: Maximum number of recently-seen SSE frame IDs retained for dedup. 256 is
#: large enough to absorb an SSE replay burst (Last-Event-ID resume after a
#: transient drop usually replays the tail of the backlog) while staying
#: cheap to keep in-memory.
FRAME_DEDUP_WINDOW: int = 256

#: Max age (seconds) of a JWT ``iat`` claim before we refuse to use the
#: bearer. Startup guard: if the session.json is ancient we'd rather
#: fail loud than let a leaked long-lived bearer ferry events into a
#: connected client session. A ~30s window is too tight for the CLI's
#: current session lifecycle (JWTs live for hours); 24h is the practical
#: middle ground and still catches the stolen-laptop scenario where a
#: dormant session.json is replayed weeks later. A tighter check will
#: apply to per-frame freshness in a later revision.
MAX_BEARER_AGE_SECONDS: float = 24 * 60 * 60


def _build_tls_context() -> ssl.SSLContext:
    """Construct a strict TLS context for the DO SSE client.

    No ``CERT_NONE``, no hostname-check disable. Explicit construction so
    that any future attempt to weaken the client's TLS posture has to edit
    this function and trigger review, rather than silently flipping a
    kwarg on the httpx.AsyncClient constructor.
    """
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # Minimum TLS 1.2 - matches Cloudflare's edge minimum. Setting
    # ``minimum_version`` instead of deprecated options= flags keeps us on
    # the modern OpenSSL path.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _peek_jwt_iat(jwt: str) -> float | None:
    """Return the ``iat`` (issued-at) claim of ``jwt`` as a UNIX timestamp.

    Best-effort parse - no signature verification (the DO does that). We
    only read ``iat`` so we can reject dormant session bearers at start-up.
    Returns ``None`` if the token doesn't carry a readable payload.
    """
    try:
        parts = jwt.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        # base64url requires padding in fours; pad up before decoding.
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    iat = payload.get("iat")
    if isinstance(iat, (int, float)):
        return float(iat)
    return None


#: Length in bytes of a valid Ed25519 signature (RFC 8032).
ED25519_SIGNATURE_BYTES: int = 64
#: Length in bytes of a valid Ed25519 public key (RFC 8032).
ED25519_PUBKEY_BYTES: int = 32
#: Prefix on :attr:`DaemonConfig.frame_signature_pubkey` and on the
#: ``pubkey`` field emitted by the DO. Matches the canonical envelope
#: convention for signed frames.
ED25519_PUBKEY_PREFIX: str = "ed25519:"


def _b64url_decode(value: str) -> bytes:
    """Decode a base64url-encoded value, tolerating missing padding.

    Matches the server's encoding convention (``bufToBase64Url``
    strips trailing ``=``). Raises :class:`ValueError` on malformed input
    so the caller can treat the frame as malformed-signature.
    """
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _canonical_bytes_without_signature(payload: dict) -> bytes:
    """Return the canonical JSON bytes of ``payload`` with ``signature`` removed.

    Uses stable key ordering (``sort_keys=True``) and the most compact
    separator set so the output matches the server's ``canonicalise``
    routine. The
    ``signature`` field is excluded before serialisation so both signer
    and verifier compute bytes over the same logical object.
    """
    stripped = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(
        stripped,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


class _FrameSignatureOutcome(str):  # noqa: N801 - sentinel-style enum
    """Structured outcome classes emitted by :func:`_verify_frame_signature`.

    Kept as string constants (not :class:`enum.Enum`) so they can double as
    log fields without extra serialisation and so ``_ConnectionState``
    counter attribute names derive directly from the value.
    """

    OK = "ok"
    UNSIGNED = "unsigned"
    MALFORMED_SIG = "malformed_sig"
    WRONG_KEY = "wrong_key"
    BAD_SIG = "bad_sig"


def _verify_frame_signature(payload: dict, pinned_pubkey_b64: str) -> str:
    """Verify an Ed25519 signature on a parsed SSE frame payload.

    Expected wire contract (the DO emitter MUST adopt this - see follow-up
    note in :attr:`DaemonConfig.require_frame_signature`)::

        {
          "signature": "<base64url>",          # 64-byte Ed25519 signature
          "pubkey":    "ed25519:<base64url>",  # 32-byte public key
          "kind":      "...",                  # event kind
          "payload":   { ... },                # opaque event body
          ...                                  # any other top-level fields
        }

    The signature is computed over the canonical (``sort_keys=True``,
    compact-separator) JSON bytes of the object with the ``signature``
    field removed. This matches ``canonicalise()`` in
    the server's signing convention so the DO can
    re-use the existing Web Crypto signer.

    Parameters
    ----------
    payload:
        The parsed JSON object from ``frame.data``. MUST be a ``dict``;
        non-dict payloads should be treated as unsigned by the caller.
    pinned_pubkey_b64:
        The base64url-encoded 32-byte Ed25519 public key (without the
        ``ed25519:`` prefix) that the daemon trusts. Frames declaring any
        other ``pubkey`` are rejected as ``wrong_key`` - this is the
        self-certifying-frame defence.

    Returns
    -------
    str
        One of the :class:`_FrameSignatureOutcome` constants:
        ``"ok"``, ``"unsigned"``, ``"malformed_sig"``, ``"wrong_key"``, or
        ``"bad_sig"``. Never raises.
    """
    # Lazy import so the cryptography dependency is only loaded when
    # enforcement is actually invoked. Keeps start-up cold cost minimal
    # on systems where require_frame_signature stays False.
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:  # pragma: no cover - dependency declared in pyproject.toml
        logger.error(
            "do_sse: `cryptography` package is missing but require_frame_signature=True; "
            "treating all frames as malformed_sig until the dependency is installed."
        )
        return _FrameSignatureOutcome.MALFORMED_SIG

    signature_b64 = payload.get("signature")
    declared_pubkey = payload.get("pubkey")
    if not isinstance(signature_b64, str) or not isinstance(declared_pubkey, str):
        return _FrameSignatureOutcome.UNSIGNED

    # Normalise the declared pubkey - strip the ``ed25519:`` prefix if
    # present so the comparison is encoding-agnostic.
    if declared_pubkey.startswith(ED25519_PUBKEY_PREFIX):
        declared_pubkey_b64 = declared_pubkey[len(ED25519_PUBKEY_PREFIX) :]
    else:
        declared_pubkey_b64 = declared_pubkey

    if declared_pubkey_b64 != pinned_pubkey_b64:
        return _FrameSignatureOutcome.WRONG_KEY

    # Decode the signature; malformed base64 or wrong length → drop.
    try:
        signature_bytes = _b64url_decode(signature_b64)
    except (ValueError, Exception):  # noqa: BLE001 - base64 can raise binascii.Error
        return _FrameSignatureOutcome.MALFORMED_SIG
    if len(signature_bytes) != ED25519_SIGNATURE_BYTES:
        return _FrameSignatureOutcome.MALFORMED_SIG

    # Decode + load the pinned pubkey. Malformed pinned key is a
    # configuration bug; surface it as malformed_sig so the daemon's
    # structured log shows the failure class clearly without taking down
    # the subscriber.
    try:
        pubkey_bytes = _b64url_decode(pinned_pubkey_b64)
        if len(pubkey_bytes) != ED25519_PUBKEY_BYTES:
            return _FrameSignatureOutcome.MALFORMED_SIG
        pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    except (ValueError, Exception):  # noqa: BLE001
        return _FrameSignatureOutcome.MALFORMED_SIG

    canonical = _canonical_bytes_without_signature(payload)
    try:
        pubkey.verify(signature_bytes, canonical)
    except InvalidSignature:
        return _FrameSignatureOutcome.BAD_SIG
    except Exception:  # noqa: BLE001 - defensive; crypto lib shouldn't raise here
        return _FrameSignatureOutcome.BAD_SIG
    return _FrameSignatureOutcome.OK


@dataclass
class _ConnectionState:
    """Internal book-keeping for the DO SSE connection.

    Kept on the subscriber instance so tests can assert on reconnect counts
    and the current ``Last-Event-ID`` checkpoint.
    """

    reconnect_count: int = 0
    last_event_id: str | None = None
    was_connected: bool = False
    backoff: float = BASE_BACKOFF_SECONDS
    # Monotonic timestamp of the most recent successful connect, or None
    # when not connected.
    connected_at: float | None = None
    # Records for debugging / tests
    history: list[str] = field(default_factory=list)

    # --- Frame-signature enforcement counters -------------
    #: Frames that passed Ed25519 verification (``require_frame_signature``
    #: is ``True`` and the signature was valid against the pinned pubkey).
    frames_verified_ok: int = 0
    #: Frames dropped because the ``signature`` (or ``pubkey``) field was
    #: absent while enforcement is on.
    frames_dropped_unsigned: int = 0
    #: Frames dropped because the declared signature could not be decoded
    #: or was not 64 bytes (Ed25519 signature length).
    frames_dropped_malformed_sig: int = 0
    #: Frames dropped because the frame's declared ``pubkey`` differs from
    #: the daemon's pinned :attr:`DaemonConfig.frame_signature_pubkey`.
    frames_dropped_wrong_key: int = 0
    #: Frames dropped because Ed25519 verification failed against the
    #: pinned pubkey (decoded signature was the right shape but the
    #: cryptographic check did not pass).
    frames_dropped_bad_sig: int = 0
    #: Frames that arrived without a signature while enforcement is still
    #: ``False``. Not dropped - counted so operators can see the baseline
    #: signature-coverage deficit before flipping the switch on.
    frames_warned_unsigned: int = 0


class DoSseSubscriber(Component):
    """Tails the per-handle DO SSE stream and publishes frames onto the bus.

    Parameters
    ----------
    config:
        Loaded :class:`DaemonConfig`. Used for ``do_sse_endpoint`` and the
        fallback trigger threshold.
    session:
        Authenticated CLI :class:`Session`. Supplies ``handle`` and
        ``jwt``.
    bus:
        The shared :class:`EventBus` instance.
    http_client:
        Optional override for the HTTP client. Tests pass an
        ``httpx.AsyncClient(transport=httpx.MockTransport(...))`` here so they
        don't need the network.
    refresh_trigger:
        Optional shared :class:`~alter_runtime.subscribers.session_refresher.RefreshTrigger`.
        A 401/403 on the DO SSE stream itself (``session.jwt`` rejected, not
        merely a stale subscribe-cap) calls ``request_refresh()`` so
        ``SessionRefresher`` wakes and rotates out of band instead of waiting
        for its schedule (closes the gap left by the 2026-07-12 fix, which
        wired every other hot JWT consumer but not this one). ``None``
        preserves the prior pure-backoff behaviour.
    """

    name = "do_sse"

    def __init__(
        self,
        config: DaemonConfig,
        session: "Session | SessionRef",
        bus: EventBus,
        *,
        http_client: httpx.AsyncClient | None = None,
        refresh_trigger: "RefreshTrigger | None" = None,
    ) -> None:
        # --- SessionRef unwrap -------------------------------------------
        # Accept either a frozen Session snapshot (legacy / test callers) or a
        # live SessionRef holder (daemon production path). Resolve the initial
        # Session for the bearer invariant checks; store the ref for ongoing
        # JWT reads.
        from alter_runtime.config import SessionRef as _SessionRef

        if isinstance(session, _SessionRef):
            self._session_ref: "_SessionRef | None" = session
            _initial_session: "Session" = session.current
        else:
            self._session_ref = None
            _initial_session = session  # type: ignore[assignment]

        # --- Startup guard: bearer + scheme invariants ---------------
        # If there's no session bearer, the daemon would happily open an
        # unauthenticated SSE stream - and the DO would (correctly) bounce
        # it, but we'd still log + reconnect forever. Refuse at construct
        # time instead so operator sees a clear error and runs ``alter login``.
        if not getattr(_initial_session, "jwt", None):
            raise ConfigError(
                "do_sse: session has no bearer JWT - run `alter login` before starting the runtime."
            )
        # Defence-in-depth: reject non-https even though config.load()
        # already checks. The subscriber is the hot-path component; a
        # weakened config that bypasses load() should still not be able
        # to drive an http:// stream.
        endpoint = getattr(config, "do_sse_endpoint", "") or ""
        if not endpoint.lower().startswith("https://"):
            raise ConfigError(
                f"do_sse: do_sse_endpoint={endpoint!r} is not https:// - refusing to start."
            )
        # Freshness sanity check - if the bearer's ``iat`` is older than
        # MAX_BEARER_AGE_SECONDS, refuse to use it. Logged-not-raised when
        # ``iat`` is absent because some deployments mint opaque tokens.
        iat = _peek_jwt_iat(_initial_session.jwt)
        if iat is not None:
            age = time.time() - iat
            if age > MAX_BEARER_AGE_SECONDS:
                raise ConfigError(
                    f"do_sse: bearer JWT iat is {age:.0f}s old (>"
                    f"{MAX_BEARER_AGE_SECONDS:.0f}s) - refusing to use a "
                    "dormant session. Run `alter login` to refresh."
                )
        elif not getattr(session, "jwt_expires_at", None):
            # No iat *and* no expiry - opaque or stripped token. Log, don't
            # crash; follow-up PR adds mandatory expiry metadata end-to-end.
            logger.warning(
                "do_sse: bearer has no parseable iat and no jwt_expires_at; "
                "proceeding but freshness cannot be verified."
            )

        # --- Startup guard: enforcement requires a pinned trust root ----
        # When frame-signature enforcement is on, we MUST have a pinned
        # Ed25519 public key to verify against - otherwise the verifier
        # would trust whatever ``pubkey`` the frame itself declared, which
        # is a self-certifying (i.e. useless) check. Refuse to construct so
        # the operator sees the misconfiguration before the daemon fans out
        # unverified events. Interim pin is the env var
        # ``ALTER_RUNTIME_FRAME_SIG_PUBKEY``; follow-up PR replaces this
        # with a DO ``/state`` fetch on start-up.
        if getattr(config, "require_frame_signature", False):
            pinned = getattr(config, "frame_signature_pubkey", None)
            if not pinned:
                raise ConfigError(
                    "do_sse: require_frame_signature=True but "
                    "frame_signature_pubkey is unset - refusing to start. "
                    "Set ALTER_RUNTIME_FRAME_SIG_PUBKEY to the DO's pinned "
                    "Ed25519 public key (`ed25519:<base64url>`)."
                )
            # validate pubkey format at construct
            # time so operators see a clear ConfigError instead of silent
            # frame-drops caused by malformed_sig later.
            import re as _re

            # 32-byte Ed25519 public key encodes to 43 base64url chars
            # without padding (ceil(32 * 4 / 3) = 43) or 44 with an
            # ``=`` pad byte. The pre-pentest regex (`+=*`) accepted
            # arbitrarily-short keys that decoded to <32 bytes - those
            # were caught further downstream but the failure was a
            # silent ``frames_dropped_malformed_sig`` deficit instead
            # of a clear refusal-to-start. Tighten the shape gate so
            # the operator sees the misconfiguration at construct time.
            if not _re.match(r"^ed25519:[A-Za-z0-9_-]{43,}=*$", pinned):
                raise ConfigError(
                    f"do_sse: frame_signature_pubkey={pinned!r} is not in the "
                    "expected `ed25519:<base64url>` format - refusing to start."
                )
            _raw_pubkey = pinned[len(ED25519_PUBKEY_PREFIX) :]
            _padding = "=" * (-len(_raw_pubkey) % 4)
            try:
                _decoded = base64.urlsafe_b64decode(_raw_pubkey + _padding)
            except Exception as _exc:
                raise ConfigError(
                    f"do_sse: frame_signature_pubkey base64url decode failed: {_exc}"
                ) from _exc
            if len(_decoded) != ED25519_PUBKEY_BYTES:
                raise ConfigError(
                    f"do_sse: frame_signature_pubkey decoded to {len(_decoded)} bytes; "
                    f"Ed25519 public keys must be exactly {ED25519_PUBKEY_BYTES} bytes."
                )

        self._config = config
        # Keep a frozen snapshot for handle / handle-only attributes (never
        # changes after login). Hot JWT reads go through _get_session().jwt.
        self._session = _initial_session
        self._bus = bus
        self._http_client = http_client
        self._owns_client = http_client is None
        self._refresh_trigger = refresh_trigger
        self._stop_event = asyncio.Event()
        # Read the module-level constant at __init__ time (not at class-def
        # time) so tests that monkeypatch the constant see the patched value.
        self._state = _ConnectionState(backoff=BASE_BACKOFF_SECONDS)
        # the DO SSE gate requires a
        # scope=alter_events.subscribe capability JWT, not session.jwt.
        # Cache (token, expires_epoch); re-mint within 30s of expiry.
        self._subscribe_cap: tuple[str, float] | None = None
        # Bounded LRU of recently-seen frame IDs - prevents a DO replay from
        # being fanned out to every local surface twice.
        self._seen_frame_ids: OrderedDict[str, None] = OrderedDict()

    def _get_session(self) -> "Session":
        """Return the live session, reading through SessionRef when present."""
        if self._session_ref is not None:
            return self._session_ref.current
        return self._session

    # ------------------------------------------------------------------
    # Component lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Long-lived reconnect loop. Never raises except on cancellation."""
        url = self._config.do_sse_endpoint.format(handle=self._session.handle)
        logger.info(
            "do_sse starting handle=%s url=%s",
            self._session.handle,
            url,
        )

        # Owned client uses a strict TLS context - no CERT_NONE, hostname
        # verification on, TLS 1.2+. Tests can still inject a MockTransport
        # via ``http_client=`` to bypass the network entirely.
        # Client-default headers carry only the canonical ``X-Alter-Client-*``
        # identity bundle, required on every
        # authenticated backend call so the floor middleware can identify the
        # daemon (else HTTP 426 ``client_identification_required``).
        client = self._http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=10.0,
                read=None,  # SSE holds the connection open indefinitely
                write=10.0,
                pool=10.0,
            ),
            verify=_build_tls_context(),
            headers=backend_default_headers(url),
        )

        try:
            while not self._stop_event.is_set():
                try:
                    await self._run_one_connection(client, url)
                    # Clean EOF: treat as disconnect + backoff. Every other
                    # branch in this loop calls _backoff_then_retry() after
                    # _on_disconnect(); this one didn't, so a server (or
                    # test mock) returning a clean empty-body EOF repeatedly
                    # reconnected with zero delay - a tight busy loop that
                    # never truly suspends and starves the event loop of any
                    # other task, hanging the whole process (observed
                    # 2026-08-15: test_do_sse.py spun in state R forever).
                    await self._on_disconnect("stream_closed")
                    await self._backoff_then_retry()
                except asyncio.CancelledError:
                    raise
                except httpx.HTTPStatusError as exc:
                    await self._handle_http_status_error(exc)
                except (httpx.TransportError, httpx.RequestError) as exc:
                    await self._on_disconnect(f"transport_error: {type(exc).__name__}")
                    await self._backoff_then_retry()
                except Exception as exc:
                    logger.exception("do_sse unexpected error: %s", exc)
                    await self._on_disconnect(f"unexpected: {type(exc).__name__}")
                    await self._backoff_then_retry()
        finally:
            if self._owns_client:
                try:
                    await client.aclose()
                except Exception:  # pragma: no cover - defensive
                    pass
            logger.info("do_sse stopped handle=%s", self._session.handle)

    async def stop(self) -> None:
        """Cooperative shutdown - releases the reconnect loop."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    async def _run_one_connection(self, client: httpx.AsyncClient, url: str) -> None:
        """Open one SSE stream and dispatch frames until it closes or stalls."""
        cap = await self._ensure_subscribe_cap(client)
        headers = {
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {cap}",
            "Cache-Control": "no-cache",
            "User-Agent": f"alter-runtime/{_package_version()}",
        }
        if self._state.last_event_id is not None:
            headers["Last-Event-ID"] = self._state.last_event_id

        logger.debug(
            "do_sse connecting url=%s last_event_id=%s",
            url,
            self._state.last_event_id,
        )

        async with client.stream("GET", url, headers=headers) as response:
            if response.status_code != 200:
                # Read a small body preview for error logs, then surface the
                # status so the outer loop can decide on a backoff policy.
                try:
                    body_preview = (await response.aread())[:256].decode("utf-8", errors="replace")
                except Exception:
                    body_preview = "<body unreadable>"
                logger.warning(
                    "do_sse non-200 status=%d url=%s body=%r",
                    response.status_code,
                    url,
                    body_preview,
                )
                raise httpx.HTTPStatusError(
                    f"do_sse got HTTP {response.status_code}",
                    request=response.request,
                    response=response,
                )

            await self._on_connect()
            await self._consume_stream(response)

    async def _ensure_subscribe_cap(self, client: httpx.AsyncClient) -> str:
        """Return a cached or freshly-minted subscribe-scope capability JWT.

        The per-handle DO stream
        requires a capability with scope ``alter_events.subscribe`` and
        ``aud_recipient == sub == <handle>``. We acquire it from the server
        using ``session.jwt`` as bearer, cache until 30s before
        expiry, and re-mint on each reconnect afterwards.
        """
        now = time.time()
        if self._subscribe_cap is not None:
            token, exp = self._subscribe_cap
            if exp - now > 30.0:
                return token

        _live = self._get_session()
        mint_url = f"{_live.api.rstrip('/')}/api/v1/messaging/subscribe-capability"
        headers = {
            "Authorization": f"Bearer {_live.jwt}",
            "Accept": "application/json",
            "User-Agent": f"alter-runtime/{_package_version()}",
        }
        # Short timeout - a 5xx here drops into the outer reconnect/backoff
        # path in run() via httpx.HTTPStatusError, which is the same
        # degradation channel as any other auth failure.
        resp = await client.post(mint_url, headers=headers, timeout=10.0)
        resp.raise_for_status()
        body = resp.json()
        token = body["capability"]
        exp_iso = body.get("expires_at") or ""
        try:
            # datetime.fromisoformat accepts +HH:MM offsets; the backend
            # returns UTC with 'Z' in FastAPI's default JSON encoder.
            from datetime import datetime as _dt

            exp_dt = _dt.fromisoformat(exp_iso.replace("Z", "+00:00"))
            exp_epoch = exp_dt.timestamp()
        except Exception:
            # Conservative fallback if the timestamp can't be parsed.
            # The server ceiling is 60s
            # (SUBSCRIBE_CAP_MAX_LIFETIME_SECONDS); the server
            # mints with SUBSCRIBE_CAPABILITY_TTL_SECONDS clamped to 60s.
            # Assuming 300s here caused the client to hold an already-
            # rejected cap for 235s before reconnect - set to 60s to
            # match the shipped ceiling.
            exp_epoch = now + 60.0
        self._subscribe_cap = (token, exp_epoch)
        logger.debug(
            "do_sse minted subscribe cap handle=%s exp=%.0f",
            self._session.handle,
            exp_epoch,
        )
        return token

    async def _consume_stream(self, response: httpx.Response) -> None:
        """Read chunks from ``response``, parse SSE, dispatch each frame.

        Uses a stall watchdog: if no bytes arrive for
        ``fallback_trigger_after_seconds``, the iteration unblocks and the
        caller treats this as a disconnect (fallback will pick up).
        """
        buffer = ""
        stall_seconds = max(self._config.fallback_trigger_after_seconds, 1.0)

        # ``aiter_text`` yields decoded str chunks as they arrive. We wrap each
        # chunk fetch in a timeout so a stalled keepalive doesn't wedge us.
        iterator = response.aiter_text()
        while not self._stop_event.is_set():
            try:
                chunk = await asyncio.wait_for(iterator.__anext__(), timeout=stall_seconds)
            except (TimeoutError, asyncio.TimeoutError):
                logger.warning(
                    "do_sse stream stalled > %.1fs - treating as disconnect", stall_seconds
                )
                return
            except StopAsyncIteration:
                return

            if not chunk:
                continue
            buffer += chunk
            frames, buffer = parse_sse_frames(buffer)
            for frame in frames:
                await self._dispatch_frame(frame)

    # ------------------------------------------------------------------
    # Frame dispatch + connection state publishing
    # ------------------------------------------------------------------

    async def _dispatch_frame(self, frame: SSEFrame) -> None:
        """Publish a parsed frame to the bus and advance Last-Event-ID.

        Frame-signature enforcement happens BEFORE any publish: if
        ``require_frame_signature=True`` and the frame fails verification
        against the pinned pubkey, it is dropped with a structured warning
        log and the matching ``_ConnectionState`` counter is incremented.
        """
        if frame.id is not None:
            # Frame-ID dedup - drops duplicates within FRAME_DEDUP_WINDOW so
            # a DO replay after a transient drop doesn't fan out twice. Raw
            # untagged frames (`frame.id is None`) skip the check because the
            # DO does not emit untagged payloads on the hot path; this is a
            # test-fixture escape hatch.
            if frame.id in self._seen_frame_ids:
                logger.debug("do_sse duplicate frame id=%s - dropping", frame.id)
                return
            self._seen_frame_ids[frame.id] = None
            if len(self._seen_frame_ids) > FRAME_DEDUP_WINDOW:
                self._seen_frame_ids.popitem(last=False)
            self._state.last_event_id = frame.id

        # Parse payload once - used for both signature verification and
        # the convenience TOPIC_EVENT publish below. Non-JSON / non-dict
        # payloads are opaque to the signature check (the wire contract
        # always wraps signed bodies in a top-level object).
        parsed_payload: dict | None = None
        try:
            candidate = frame.json
            if isinstance(candidate, dict):
                parsed_payload = candidate
        except (ValueError, json.JSONDecodeError):
            parsed_payload = None

        # --- Frame-signature enforcement ---------------------------
        if self._config.require_frame_signature:
            if parsed_payload is None:
                # Enforcement is on but the frame isn't a signable object.
                # Drop as unsigned rather than silently letting opaque
                # payloads bypass the check.
                self._state.frames_dropped_unsigned += 1
                logger.warning(
                    "do_sse dropping non-dict frame under signature enforcement id=%s event=%s",
                    frame.id,
                    frame.event,
                )
                return
            pinned = self._config.frame_signature_pubkey or ""
            if pinned.startswith(ED25519_PUBKEY_PREFIX):
                pinned = pinned[len(ED25519_PUBKEY_PREFIX) :]
            outcome = _verify_frame_signature(parsed_payload, pinned)
            if outcome == _FrameSignatureOutcome.OK:
                self._state.frames_verified_ok += 1
            else:
                # Structured log + counter increment + drop. Keep the log
                # at WARNING (not ERROR) - enforcement drops are expected
                # during the DO-signer rollout and flooding ERROR would
                # desensitise operators before the migration completes.
                counter_attr = f"frames_dropped_{outcome}"
                current = getattr(self._state, counter_attr, 0)
                setattr(self._state, counter_attr, current + 1)
                logger.warning(
                    "do_sse dropping frame under signature enforcement id=%s event=%s outcome=%s",
                    frame.id,
                    frame.event,
                    outcome,
                )
                return
        else:
            # Enforcement off - count unsigned frames so operators can see
            # the signature-coverage deficit in metrics before flipping
            # the switch. Does NOT alter dispatch behaviour.
            if parsed_payload is None or "signature" not in parsed_payload:
                self._state.frames_warned_unsigned += 1

        await self._bus.publish(TOPIC_FRAME, frame)

        if parsed_payload is not None:
            await self._bus.publish(TOPIC_EVENT, parsed_payload)
        else:
            logger.debug("do_sse frame not JSON event=%s", frame.event)

    async def _on_connect(self) -> None:
        """Publish an ``identity.connected`` sentinel."""
        self._state.was_connected = True
        self._state.connected_at = time.monotonic()
        self._state.history.append("connect")
        logger.info(
            "do_sse connected handle=%s reconnect_count=%d",
            self._session.handle,
            self._state.reconnect_count,
        )
        await self._bus.publish(
            TOPIC_CONNECTED,
            {
                "handle": self._session.handle,
                "reconnect_count": self._state.reconnect_count,
            },
        )

    async def _on_disconnect(self, reason: str) -> None:
        """Publish an ``identity.disconnected`` sentinel (only if we were connected)."""
        self._state.history.append(f"disconnect:{reason}")
        # Don't emit spurious disconnect events if we never managed to connect
        # in the first place - the fallback listens for transitions from
        # connected→disconnected; a cold start is handled separately by the
        # config-driven start-up delay in McpFallbackSubscriber.
        if not self._state.was_connected:
            return
        self._state.was_connected = False
        dwell = time.monotonic() - (self._state.connected_at or 0.0)
        self._state.connected_at = None
        if dwell >= STABLE_CONNECTION_SECONDS:
            # Connection was healthy; treat the next reconnect as a fresh start.
            self._state.backoff = BASE_BACKOFF_SECONDS
        # else: short-lived connection - a flap. Leave self._state.backoff
        # climbing so _backoff_then_retry keeps escalating toward MAX_BACKOFF.
        self._state.reconnect_count += 1
        logger.warning(
            "do_sse disconnected handle=%s reason=%s reconnect_count=%d",
            self._session.handle,
            reason,
            self._state.reconnect_count,
        )
        await self._bus.publish(
            TOPIC_DISCONNECTED,
            {
                "handle": self._session.handle,
                "reason": reason,
                "reconnect_count": self._state.reconnect_count,
            },
        )

    # ------------------------------------------------------------------
    # Error handling + backoff
    # ------------------------------------------------------------------

    async def _handle_http_status_error(self, exc: httpx.HTTPStatusError) -> None:
        status = exc.response.status_code if exc.response is not None else 0
        await self._on_disconnect(f"http_status:{status}")
        if status in (401, 403):
            logger.error(
                "do_sse auth failure status=%d - sleeping %.0fs; run `alter login` to refresh",
                status,
                AUTH_ERROR_BACKOFF_SECONDS,
            )
            # Belt-and-braces: if a SessionRef is live, reload it now so the
            # next reconnect after the sleep uses the freshest available token.
            # Also drop the cached subscribe-cap so it is re-minted with the
            # updated JWT rather than replaying the rejected one.
            if self._session_ref is not None:
                self._session_ref.reload()
            self._subscribe_cap = None
            # The DO SSE gate rejected the session bearer itself (not a
            # separately-scoped cap), which is the strongest possible signal
            # that the JWT is dead - request an out-of-band SessionRefresher
            # wake instead of waiting out its scheduled lead time (closes the
            # gap this subscriber was left out of by the 2026-07-12 fix).
            if self._refresh_trigger is not None:
                self._refresh_trigger.request_refresh("do_sse_401")
            await self._sleep_interruptible(AUTH_ERROR_BACKOFF_SECONDS)
            return
        await self._backoff_then_retry()

    async def _backoff_then_retry(self) -> None:
        """Sleep a jittered fraction of the current backoff ceiling, then
        double the ceiling for next time (capped at MAX_BACKOFF_SECONDS).

        Full Jitter (AWS "Exponential Backoff and Jitter"): the actual sleep is
        uniform(0, ceiling). This decorrelates reconnects across daemons so a
        shared-cause outage doesn't produce a synchronised thundering herd, and
        bounds the worst-case wait at the current ceiling.
        """
        ceiling = self._state.backoff
        delay = random.uniform(0.0, ceiling)
        self._state.backoff = min(ceiling * 2, MAX_BACKOFF_SECONDS)
        logger.info("do_sse reconnecting in %.1fs (ceiling %.1fs)", delay, ceiling)
        await self._sleep_interruptible(delay)

    async def _sleep_interruptible(self, seconds: float) -> None:
        """Wait ``seconds`` or until ``stop()`` is called, whichever is first."""
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except (TimeoutError, asyncio.TimeoutError):
            return

    # ------------------------------------------------------------------
    # Test introspection
    # ------------------------------------------------------------------

    @property
    def state(self) -> _ConnectionState:
        """Current connection state (used by tests)."""
        return self._state


def _package_version() -> str:
    """Best-effort version string for the User-Agent header."""
    try:
        from alter_runtime import __version__

        return __version__
    except Exception:  # pragma: no cover
        return "unknown"
