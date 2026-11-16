"""Local-only MCP v2 tools. No HTTP listener or device input commands."""

from __future__ import annotations

from collections.abc import Callable

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from local_gpt_mcp.pairing.local_approval import ConsoleApproval
from local_gpt_mcp.pairing.sessions import SessionBroker, SessionDenied
from local_gpt_mcp.policy import AccessDenied, Capability, PolicyAuthority


def _safe_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except (AccessDenied, SessionDenied, ValueError, TypeError):
        # Do not leak caller IDs, targets, grant tokens or credentials in errors.
        raise ToolError("Local authority denied the request") from None


def create_server(broker: SessionBroker) -> MCPServer:
    """Register scoped session tools on the official spec-compatible MCP server."""
    server = MCPServer("Local GPT MCP")

    @server.resource("local-gpt://about")
    def about() -> str:
        """Public, non-sensitive server capability summary."""
        return "Local GPT MCP: stdio only; no desktop or browser operations are enabled."

    @server.tool()
    def session_open(user_id: str, device_id: str, client_nonce: str) -> dict[str, str | int]:
        """Request a new session after a separate, on-device pairing approval."""
        return _safe_call(lambda: broker.open(user_id, device_id, client_nonce))

    @server.tool()
    def session_status(session_token: str, client_nonce: str) -> dict[str, bool | int]:
        """Check an authenticated session using a fresh client nonce."""
        return _safe_call(lambda: broker.status(session_token, client_nonce))

    @server.tool()
    def session_request_grant(
        session_token: str,
        client_nonce: str,
        target: str,
        capabilities: list[str],
        ttl_seconds: int,
    ) -> dict[str, str | int]:
        """Ask the local human to approve specific capabilities on one target."""
        return _safe_call(
            lambda: broker.request_grant(
                session_token,
                client_nonce,
                target,
                frozenset(Capability(name) for name in capabilities),
                ttl_seconds,
            )
        )

    @server.tool()
    def session_revoke_grant(session_token: str, client_nonce: str, grant_token: str) -> dict[str, bool]:
        """Immediately invalidate a grant owned by this session."""
        _safe_call(lambda: broker.revoke_grant(session_token, client_nonce, grant_token))
        return {"revoked": True}

    @server.tool()
    def session_close(session_token: str, client_nonce: str) -> dict[str, bool]:
        """Expire the MCP session and revoke all grants associated with it."""
        _safe_call(lambda: broker.close(session_token, client_nonce))
        return {"closed": True}

    @server.tool()
    def session_emergency_stop(session_token: str, client_nonce: str) -> dict[str, bool]:
        """Permanently stop this instance and revoke all local authority."""
        _safe_call(lambda: broker.stop(session_token, client_nonce))
        return {"stopped": True}

    return server


def serve_stdio() -> None:
    """Stdio is intentionally the only exposed transport in this release slice."""
    authority = PolicyAuthority(ConsoleApproval())
    create_server(SessionBroker(authority)).run(transport="stdio")
