"""AlterClient - async JSON-RPC 2.0 client for the ~alter identity MCP server.

Key behaviours:

1. **Dual-source discovery** - ``AlterClient.auto_discover()`` first tries
   to reach the local daemon's Unix socket and falls back to direct MCP
   polling at ``api.truealter.com/api/v1/mcp`` when the socket is unavailable.

2. **JSON-RPC 2.0 envelope, retry/backoff, session management** via the
   ``Mcp-Session-Id`` header, and typed tool methods.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from itertools import count
from typing import Any

import httpx

__all__ = ["AlterClient", "MCPResponse"]

logger = logging.getLogger("alter_runtime.sdk")

_request_counter = count(1)

# Retry configuration
MAX_RETRIES = 2
RETRY_BACKOFF_BASE = 1.0  # seconds
RETRYABLE_HTTP_CODES = frozenset({429, 502, 503, 504})

# Default endpoint - the public MCP HTTP endpoint
DEFAULT_MCP_ENDPOINT = "https://api.truealter.com/api/v1/mcp"

# MCP protocol version
MCP_PROTOCOL_VERSION = "2025-03-26"


# ---------------------------------------------------------------------------
# MCPResponse - typed JSON-RPC 2.0 response wrapper
# ---------------------------------------------------------------------------


@dataclass
class MCPResponse:
    """Typed wrapper for a JSON-RPC 2.0 response."""

    result: Any | None = None
    error: dict[str, Any] | None = None
    request_id: int | str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def extract_text(self) -> str | None:
        """Extract the ``content[0].text`` field from an MCP tools/call result."""
        if not self.ok or not isinstance(self.result, dict):
            return None
        content = self.result.get("content")
        if not isinstance(content, list) or not content:
            return None
        first = content[0]
        if isinstance(first, dict) and isinstance(first.get("text"), str):
            return first["text"]
        return None


# ---------------------------------------------------------------------------
# AlterClient
# ---------------------------------------------------------------------------


class AlterClient:
    """Async HTTP client for ~alter's MCP server (Streamable HTTP transport).

    Handles JSON-RPC 2.0 request/response over HTTP POST, with optional
    session management via ``Mcp-Session-Id`` headers. Includes automatic
    retry for transient failures and rate limiting.

    Usage::

        async with AlterClient(api_key="alt_xxx") as client:  # pragma: allowlist secret
            resp = await client.whoami()
            print(resp.extract_text())

    For the graceful-fallback discovery path used by the local daemon, use
    ``AlterClient.auto_discover()`` which tries the local unix socket first.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_MCP_ENDPOINT,
        api_key: str | None = None,
        bearer_token: str | None = None,
        timeout: float = 30.0,
        client_name: str = "alter-runtime",
        client_version: str = "0.3.1",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.bearer_token = bearer_token
        self.timeout = timeout
        self.client_name = client_name
        self.client_version = client_version
        self.session_id: str | None = None
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> AlterClient:
        self._ensure_http()
        await self.initialize()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    def _ensure_http(self) -> None:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=self.timeout,
                headers=self._build_headers(),
            )

    def _build_headers(self) -> dict[str, str]:
        # Canonical X-Alter-Client-* identity bundle
        # bundle. The SDK is the most-likely third-party touchpoint and
        # honours its ``client_name`` / ``client_version`` constructor args
        # so embedded callers (local MCP bridges and third
        # parties using AlterClient directly) identify themselves to the
        # server-side floor middleware. The ``binary`` channel is the
        # closest match for an SDK-shipped client; callers may override
        # by setting headers post-construction.
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Alter-Client-Id": self.client_name,
            "X-Alter-Client-Version": self.client_version,
            "X-Alter-Client-Channel": "binary",
        }
        if self.api_key:
            headers["X-ALTER-API-Key"] = self.api_key
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers

    async def close(self) -> None:
        """Close the MCP session and HTTP client."""
        if self._http is None:
            return
        if self.session_id:
            try:
                await self._http.delete(
                    self.base_url,
                    headers={"Mcp-Session-Id": self.session_id},
                )
            except httpx.RequestError:
                pass
        await self._http.aclose()
        self._http = None

    # ------------------------------------------------------------------
    # JSON-RPC core
    # ------------------------------------------------------------------

    async def _rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        retries: int = MAX_RETRIES,
    ) -> MCPResponse:
        """Send a JSON-RPC 2.0 request with automatic retry for transient failures."""
        self._ensure_http()
        assert self._http is not None

        request_id = next(_request_counter)
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "id": request_id,
        }
        if params is not None:
            payload["params"] = params

        headers: dict[str, str] = {}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        last_error: MCPResponse | None = None

        for attempt in range(1 + retries):
            try:
                resp = await self._http.post(
                    self.base_url,
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in RETRYABLE_HTTP_CODES and attempt < retries:
                    wait = RETRY_BACKOFF_BASE * (2**attempt)
                    logger.warning(
                        "MCP HTTP %s (attempt %d/%d), retrying in %.1fs",
                        status,
                        attempt + 1,
                        1 + retries,
                        wait,
                    )
                    last_error = MCPResponse(
                        error={"code": status, "message": str(exc)},
                        request_id=request_id,
                    )
                    await asyncio.sleep(wait)
                    continue
                logger.error("MCP HTTP error: %s %s", status, exc.response.text[:200])
                return MCPResponse(
                    error={"code": status, "message": str(exc)},
                    request_id=request_id,
                )
            except httpx.RequestError as exc:
                if attempt < retries:
                    wait = RETRY_BACKOFF_BASE * (2**attempt)
                    logger.warning(
                        "MCP request error (attempt %d/%d): %s, retrying in %.1fs",
                        attempt + 1,
                        1 + retries,
                        exc,
                        wait,
                    )
                    last_error = MCPResponse(
                        error={"code": -1, "message": str(exc)},
                        request_id=request_id,
                    )
                    await asyncio.sleep(wait)
                    continue
                logger.error("MCP request failed: %s", exc)
                return MCPResponse(
                    error={"code": -1, "message": str(exc)},
                    request_id=request_id,
                )

            data = resp.json()

            # Capture session ID from response headers
            if sid := resp.headers.get("Mcp-Session-Id"):
                self.session_id = sid

            return MCPResponse(
                result=data.get("result"),
                error=data.get("error"),
                request_id=data.get("id", request_id),
            )

        # Should not reach here, but return last error if it does
        return last_error or MCPResponse(
            error={"code": -1, "message": "Exhausted retries"},
            request_id=request_id,
        )

    async def _call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> MCPResponse:
        """Invoke an MCP tool via tools/call."""
        return await self._rpc(
            "tools/call",
            {"name": tool_name, "arguments": arguments or {}},
        )

    # ------------------------------------------------------------------
    # MCP protocol - session management
    # ------------------------------------------------------------------

    async def initialize(self) -> MCPResponse:
        """Initialise the MCP session. Called automatically by ``__aenter__``."""
        return await self._rpc(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": self.client_name,
                    "version": self.client_version,
                },
            },
        )

    async def list_tools(self) -> MCPResponse:
        """List available tools on the MCP server."""
        return await self._rpc("tools/list")

    # ------------------------------------------------------------------
    # Ergonomic wrappers around the free identity tools. These three are the
    # minimum viable surface for the MCP fallback path when the local daemon
    # is unavailable.
    # ------------------------------------------------------------------

    async def whoami(self) -> MCPResponse:
        """Return the authenticated caller's handle + session metadata."""
        return await self._call_tool("alter_whoami")

    async def attunement(self) -> MCPResponse:
        """Return the caller's current engagement level and attunement score."""
        return await self._call_tool("alter_attunement")

    async def portfolio(self) -> MCPResponse:
        """Return the caller's identity portfolio (earnings, achievements, style)."""
        return await self._call_tool("alter_portfolio")

    async def style(self) -> MCPResponse:
        """Return the caller's trait-derived style profile."""
        return await self._call_tool("alter_style")

    async def consent(self) -> MCPResponse:
        """Return the caller's current consent configuration."""
        return await self._call_tool("alter_consent")

    async def login_status(self) -> MCPResponse:
        """Return the caller's login status (reads local session file)."""
        return await self._call_tool("alter_login_status")

    # ------------------------------------------------------------------
    # Identity layer free tools (network building)
    # ------------------------------------------------------------------

    async def verify_identity(
        self,
        *,
        candidate_id: str | None = None,
        email: str | None = None,
    ) -> MCPResponse:
        """Check if a human is registered. The viral trigger."""
        args: dict[str, Any] = {}
        if candidate_id:
            args["candidate_id"] = candidate_id
        if email:
            args["email"] = email
        return await self._call_tool("verify_identity", args)

    async def get_profile(self, candidate_id: str) -> MCPResponse:
        """Fetch a public profile by candidate id."""
        return await self._call_tool("get_profile", {"candidate_id": candidate_id})

    async def get_engagement_level(self, candidate_id: str) -> MCPResponse:
        """Get the engagement level (L1-L4) for a candidate."""
        return await self._call_tool("get_engagement_level", {"candidate_id": candidate_id})

    # ------------------------------------------------------------------
    # Generic passthrough for tools without a typed wrapper
    # ------------------------------------------------------------------

    async def call(self, tool_name: str, **kwargs: Any) -> MCPResponse:
        """Call any MCP tool by name with keyword arguments."""
        return await self._call_tool(tool_name, kwargs)

    # ------------------------------------------------------------------
    # Discovery: local daemon first, direct MCP as fallback
    # ------------------------------------------------------------------

    @classmethod
    def auto_discover(
        cls,
        *,
        api_key: str | None = None,
        bearer_token: str | None = None,
        mcp_endpoint: str = DEFAULT_MCP_ENDPOINT,
    ) -> AlterClient:
        """Construct a client that prefers the local daemon over direct MCP.

        Returns a direct MCP client. A future release wires the local socket
        detection path so consumers can call :meth:`auto_discover` today and
        switch transparently.
        """
        # TODO: probe unix_socket_path() and return a socket-backed
        # client if reachable. For now, return a direct MCP client.
        return cls(
            base_url=mcp_endpoint,
            api_key=api_key,
            bearer_token=bearer_token,
        )
