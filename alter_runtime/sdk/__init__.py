"""alter_runtime.sdk - Python SDK for the ~alter identity MCP server.

Exports ``AlterClient``, the async HTTP client for the ~alter identity MCP
server. The PyPI package is ``alter-runtime``.
"""

from alter_runtime.sdk.client import AlterClient, MCPResponse

__all__ = ["AlterClient", "MCPResponse"]
