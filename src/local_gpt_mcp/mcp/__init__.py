"""Official MCP SDK v2 transport, local stdio only."""

from local_gpt_mcp.mcp.server import create_server, serve_stdio

__all__ = ["create_server", "serve_stdio"]
