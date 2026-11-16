"""Local-only MCP v2 tools. No HTTP listener or device input commands."""

from __future__ import annotations

import base64
from collections.abc import Callable

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from local_gpt_mcp.desktop.controller import DesktopController, DesktopDenied
from local_gpt_mcp.pairing.local_approval import ConsoleApproval
from local_gpt_mcp.pairing.sessions import SessionBroker, SessionDenied
from local_gpt_mcp.policy import AccessDenied, Capability, PolicyAuthority


def _safe_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except (AccessDenied, SessionDenied, DesktopDenied, ValueError, TypeError, OSError):
        # Do not leak caller IDs, targets, grant tokens or credentials in errors.
        raise ToolError("Local authority denied the request") from None


def create_server(broker: SessionBroker, desktop: DesktopController | None = None) -> MCPServer:
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

    if desktop is not None:

        @server.tool()
        def desktop_window_info(
            session_token: str, client_nonce: str, grant_token: str, handle: int
        ) -> dict[str, str | int]:
            """Read an explicitly approved foreground window's title and dimensions."""

            def inspect() -> dict[str, str | int]:
                info = desktop.describe(session_token, client_nonce, grant_token, handle)
                return {
                    "handle": info.identity.handle,
                    "title": info.title,
                    "width": info.rect.width,
                    "height": info.rect.height,
                }

            return _safe_call(inspect)

        @server.tool()
        def desktop_capture(
            session_token: str, client_nonce: str, grant_token: str, handle: int
        ) -> dict[str, str]:
            """Read a PNG of only the approved window, never the entire screen."""

            def grab() -> dict[str, str]:
                data = desktop.capture(session_token, client_nonce, grant_token, handle)
                return {"mime_type": "image/png", "base64": base64.b64encode(data).decode("ascii")}

            return _safe_call(grab)

        @server.tool()
        def desktop_controls(
            session_token: str, client_nonce: str, grant_token: str, handle: int
        ) -> list[dict[str, str | int]]:
            """Read a bounded UI Automation tree without editable field contents."""

            def inspect() -> list[dict[str, str | int]]:
                nodes = desktop.inspect(session_token, client_nonce, grant_token, handle)
                return [{"role": n.role, "name": n.name, "depth": n.depth} for n in nodes]

            return _safe_call(inspect)

        @server.tool()
        def desktop_click(
            session_token: str, client_nonce: str, grant_token: str, handle: int, x: int, y: int
        ) -> dict[str, bool]:
            """Click one absolute pixel inside the approved, foreground window."""
            _safe_call(lambda: desktop.click(session_token, client_nonce, grant_token, handle, x, y))
            return {"executed": True}

        @server.tool()
        def desktop_type(
            session_token: str, client_nonce: str, grant_token: str, handle: int, text: str
        ) -> dict[str, bool]:
            """Type at most 256 printable characters without modifiers or Enter."""
            _safe_call(lambda: desktop.type_text(session_token, client_nonce, grant_token, handle, text))
            return {"executed": True}

        @server.tool()
        def desktop_scroll(
            session_token: str, client_nonce: str, grant_token: str, handle: int, steps: int
        ) -> dict[str, bool]:
            """Send at most three scroll steps to the approved window."""
            _safe_call(lambda: desktop.scroll(session_token, client_nonce, grant_token, handle, steps))
            return {"executed": True}

        @server.tool()
        def desktop_key(
            session_token: str, client_nonce: str, grant_token: str, handle: int, key: str
        ) -> dict[str, bool]:
            """Press a restricted navigation key; no Alt, Ctrl, Win or Enter."""
            _safe_call(lambda: desktop.press_key(session_token, client_nonce, grant_token, handle, key))
            return {"executed": True}

    return server


def serve_stdio(allow_windows: tuple[int, ...] = ()) -> None:
    """Local-only stdio; no window can be granted without explicit local selection."""
    authority = PolicyAuthority(ConsoleApproval())
    broker = SessionBroker(authority)
    desktop = None
    if allow_windows:
        from local_gpt_mcp.desktop.windows import WindowsBackend

        backend = WindowsBackend(stopped=lambda: authority.stopped)
        allowed = backend.trust_local(allow_windows)
        desktop = DesktopController(broker, backend, allowed)
    create_server(broker, desktop).run(transport="stdio")
