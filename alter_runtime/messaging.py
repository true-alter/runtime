"""Outbound member-to-member messaging for the runtime daemon.

Member-self write tools (messaging) authenticate with the long-lived member
API key (``alt_memb_…``) sent as the ``X-ALTER-API-Key`` header, plus the
per-invocation ES256 signature: this matches how the local MCP bridge reaches
``alter_message_send``. The short-lived login JWT is NOT used here on purpose:
it carries only ``identity_read`` scope and the backend rejects a send made
with it (``connector was not granted the scope required``), whereas the member
key carries the ``member_self`` scope the tool requires and does not expire on
the JWT's ~24h clock.

This module is the outbound counterpart to the inbound notifier subsystem.
It makes no decision about content: the caller supplies the recipient and
body. Delivery is default-closed at the backend: the recipient must have
granted the sender messaging permission first, or the send is rejected.

Delivery is HUMAN-class on purpose. The Claude-Code bridge stamps a
``drafted_with`` tag (so a recipient's messenger can distinguish AI-drafted
posts from the sovereign's own voice); a direct daemon send deliberately
omits it, so the recipient's app surfaces the message as a normal heads-up
rather than suppressing it as agent chatter. Any provenance the caller needs
belongs in the body text it supplies.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any

import httpx

from alter_runtime import __version__ as RUNTIME_VERSION
from alter_runtime.http_auth import backend_default_headers
from alter_runtime.invocation_signing import build_signed_mcp_headers

if TYPE_CHECKING:
    from alter_runtime.config import Session

logger = logging.getLogger("alter_runtime.messaging")

#: Default content type for a member message body.
DEFAULT_CONTENT_TYPE: str = "text/markdown"

#: Network timeout for one send, seconds. A member send does a Durable-Object
#: round-trip on the backend that can take well over the poll timeout, so this
#: is set generously and applied per-request (so an injected client's shorter
#: default does not clip the send).
SEND_TIMEOUT_SECONDS: float = 60.0


def _agent_version_hash() -> str:
    """Stable version hash identifying this runtime as the calling agent.

    Elevated-trust tools (alter_message_send) require an ``X-Agent-Version-Hash``
    so the backend can detect a version change for the caller. Mirrors the local
    bridge's scheme (``sha256:`` + first 32 hex of a sha256 over the client's
    own release identifier), keyed on the runtime version so the daemon
    identifies honestly as itself, not as the bridge.
    """
    digest = hashlib.sha256(f"alter-runtime@{RUNTIME_VERSION}".encode()).hexdigest()[:32]
    return f"sha256:{digest}"


class SendError(Exception):
    """A member-message send was rejected by the backend or malformed."""


def _tool_error(result: dict[str, Any]) -> str | None:
    """Return a human reason when an MCP tool result signals its OWN failure.

    A tool-level failure rides INSIDE a successful JSON-RPC envelope: HTTP 200,
    no top-level ``error``, and ``isError: true`` on the result, with the reason
    in ``result["error"]`` and mirrored into ``content`` and ``_meta``. Observed
    against the live backend for an unresolvable recipient (``do_rejected``,
    DO 403 "consent denied") and for a non-handle string (``invalid_recipient``)
    against a live backend. Reading only the JSON-RPC ``error`` made both
    indistinguishable from a delivered send at every layer above this one.

    Either signal alone is treated as a failure: a structured ``error`` payload
    is authoritative even if ``isError`` is absent, and ``isError`` is honoured
    even when the reason cannot be parsed. Returns ``None`` only when the result
    carries no failure signal at all.
    """
    error = result.get("error")
    if not result.get("isError") and not error:
        return None
    if isinstance(error, dict):
        message = str(error.get("message") or "").strip()
        details = error.get("details")
        if isinstance(details, dict) and details.get("message"):
            detail = str(details["message"]).strip()
            message = f"{message}: {detail}" if message else detail
        code = error.get("code")
        if message:
            return f"{message} ({code})" if code else message
    elif isinstance(error, str) and error.strip():
        return error.strip()
    # ``isError`` with no readable error object: fall back to the text content,
    # which by MCP convention carries the tool's own account of the failure.
    content = result.get("content")
    texts = (
        [
            str(part.get("text") or "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        ]
        if isinstance(content, list)
        else []
    )
    joined = " ".join(text for text in texts if text.strip()).strip()
    return joined or "tool reported a failure with no reason given"


async def send_member_message(
    session: Session,
    endpoint: str,
    *,
    to: str,
    body: str,
    content_type: str = DEFAULT_CONTENT_TYPE,
    http_client: httpx.AsyncClient | None = None,
    request_id: int = 1,
) -> dict[str, Any]:
    """Send one member-to-member message via a signed ``alter_message_send``.

    Issues a single stateless JSON-RPC ``tools/call`` (the same shape the
    read-only pollers use, which the endpoint accepts without an
    ``initialize`` handshake) authenticated with the member API key plus the
    per-invocation ``Mcp-Invocation-Signature``.

    Returns the parsed MCP tool ``result`` dict on success. Raises
    :class:`SendError` on a missing member key, a JSON-RPC error, a TOOL-level
    failure inside a successful envelope (see :func:`_tool_error`), or a
    malformed response, and propagates :class:`httpx.HTTPError` for transport
    failures so the caller decides backoff vs fail-open. A return is therefore
    the only truthful basis for the ``delivered`` claim every layer above makes.
    """
    member_key = getattr(session, "member_api_key", None)
    if not member_key:
        raise SendError(
            "no member API key in session; member-self tools need a session "
            "minted with one (re-run `alter login`)"
        )
    tool_name = "alter_message_send"
    arguments: dict[str, Any] = {"to": to, "body": body, "content_type": content_type}
    rpc_body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    # Auth: the member API key as X-ALTER-API-Key (carries member_self scope);
    # the short-lived JWT is deliberately NOT sent. The X-Alter-Client-*
    # identity bundle the floor middleware expects is attached per-request, so
    # the send is correct whether it runs on the daemon's shared client or a
    # one-off client.
    base_headers = {
        **backend_default_headers(endpoint),
        "X-ALTER-API-Key": member_key,
        "X-Agent-Version-Hash": _agent_version_hash(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    # Returns base_headers unchanged when signing is not possible; the backend
    # then rejects with -32002, surfaced below as a SendError.
    headers = build_signed_mcp_headers(session, tool_name, arguments, base_headers)

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=SEND_TIMEOUT_SECONDS)
    try:
        # Per-request timeout so an injected client's shorter default never
        # clips the slower-than-a-poll member send.
        response = await client.post(
            endpoint, json=rpc_body, headers=headers, timeout=SEND_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        try:
            rpc = response.json()
        except ValueError as exc:
            raise SendError("malformed MCP response (non-JSON)") from exc
    finally:
        if owns_client:
            await client.aclose()

    if not isinstance(rpc, dict):
        raise SendError("malformed MCP response (not an object)")
    if rpc.get("error"):
        err = rpc["error"]
        msg = err.get("message") if isinstance(err, dict) else err
        raise SendError(f"alter_message_send rejected: {msg}")
    result = rpc.get("result")
    if not isinstance(result, dict):
        raise SendError("alter_message_send returned no result object")
    tool_error = _tool_error(result)
    if tool_error is not None:
        raise SendError(f"alter_message_send rejected: {tool_error}")
    return result
