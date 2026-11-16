"""Local-only MCP v2 tools. No HTTP listener or device input commands."""

from __future__ import annotations

import asyncio
import base64
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from playwright.async_api import Error as PlaywrightError

from local_gpt_mcp.browser import BrowserController, BrowserDenied
from local_gpt_mcp.desktop.controller import DesktopController, DesktopDenied
from local_gpt_mcp.orchestrator.driver import ScopedDriver
from local_gpt_mcp.orchestrator.engine import ActionApproval, DenyAllActions, WorkflowEngine, WorkflowFailure
from local_gpt_mcp.orchestrator.local_approval import ConsoleActionApproval
from local_gpt_mcp.orchestrator.models import Action, SessionGrants, Step, WorkflowPlan
from local_gpt_mcp.orchestrator.store import FileCheckpointStore, MemoryCheckpointStore
from local_gpt_mcp.pairing.local_approval import ConsoleApproval
from local_gpt_mcp.pairing.sessions import SessionBroker, SessionDenied
from local_gpt_mcp.policy import AccessDenied, Capability, PolicyAuthority
from local_gpt_mcp.policy.authority import LocalApproval
from local_gpt_mcp.ui.panel import LocalSafetyPanel


def _safe_call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except (AccessDenied, SessionDenied, DesktopDenied, ValueError, TypeError, OSError):
        # Do not leak caller IDs, targets, grant tokens or credentials in errors.
        raise ToolError("Local authority denied the request") from None


async def _safe_async[T](operation: Callable[[], Awaitable[T]]) -> T:
    try:
        return await operation()
    except (AccessDenied, SessionDenied, BrowserDenied, PlaywrightError, ValueError, TypeError, OSError):
        raise ToolError("Local authority denied the browser request") from None


def create_server(
    broker: SessionBroker,
    desktop: DesktopController | None = None,
    browser: BrowserController | None = None,
    lifespan: Any = None,
    workflows: WorkflowEngine | None = None,
    *,
    direct_action_approval: ActionApproval | None = None,
) -> MCPServer:
    """Register scoped local tools, optionally with a temporary browser lifespan."""
    server = MCPServer("Local GPT MCP", lifespan=lifespan)
    local_approval = direct_action_approval if direct_action_approval is not None else DenyAllActions()

    def approve_direct(step: Step) -> None:
        try:
            approved = local_approval.approve(step)
        except Exception:
            raise ToolError("Fresh local action approval is required") from None
        if not approved:
            raise ToolError("Fresh local action approval is required")

    async def approve_direct_async(step: Step) -> None:
        try:
            approved = await asyncio.wait_for(
                asyncio.to_thread(local_approval.approve, step), timeout=46
            )
        except Exception:
            raise ToolError("Fresh local action approval is required") from None
        if not approved:
            raise ToolError("Fresh local action approval is required")

    @server.resource("local-gpt://about")
    def about() -> str:
        """Public, non-sensitive server capability summary."""
        return "Local GPT MCP: stdio only; desktop and browser tools require local authorization."

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
            _safe_call(
                lambda: approve_direct(Step("direct", Action.DESKTOP_CLICK, f"window:{handle}", x=x, y=y))
            )
            _safe_call(lambda: desktop.click(session_token, client_nonce, grant_token, handle, x, y))
            return {"executed": True}

        @server.tool()
        def desktop_type(
            session_token: str, client_nonce: str, grant_token: str, handle: int, text: str
        ) -> dict[str, bool]:
            """Type at most 256 printable characters without modifiers or Enter."""
            _safe_call(
                lambda: approve_direct(Step("direct", Action.DESKTOP_TYPE, f"window:{handle}", text=text))
            )
            _safe_call(lambda: desktop.type_text(session_token, client_nonce, grant_token, handle, text))
            return {"executed": True}

        @server.tool()
        def desktop_scroll(
            session_token: str, client_nonce: str, grant_token: str, handle: int, steps: int
        ) -> dict[str, bool]:
            """Send at most three scroll steps to the approved window."""
            _safe_call(
                lambda: approve_direct(
                    Step("direct", Action.DESKTOP_SCROLL, f"window:{handle}", amount=steps)
                )
            )
            _safe_call(lambda: desktop.scroll(session_token, client_nonce, grant_token, handle, steps))
            return {"executed": True}

        @server.tool()
        def desktop_key(
            session_token: str, client_nonce: str, grant_token: str, handle: int, key: str
        ) -> dict[str, bool]:
            """Press a restricted navigation key; no Alt, Ctrl, Win or Enter."""
            _safe_call(
                lambda: approve_direct(Step("direct", Action.DESKTOP_KEY, f"window:{handle}", text=key))
            )
            _safe_call(lambda: desktop.press_key(session_token, client_nonce, grant_token, handle, key))
            return {"executed": True}

    if browser is not None:

        @server.tool()
        def browser_selected_tabs(session_token: str, client_nonce: str) -> dict[str, list[dict[str, str]]]:
            """List only the isolated tabs selected at local startup, after pairing."""
            _safe_call(lambda: broker.status(session_token, client_nonce))
            return {"tabs": [{"tab_id": tab.tab_id, "origin": tab.origin} for tab in browser.selected_tabs()]}

        @server.tool()
        async def browser_navigate(
            session_token: str, client_nonce: str, grant_token: str, tab_id: str, url: str
        ) -> dict[str, str]:
            """Navigate within the exact approved HTTPS origin."""
            await _safe_async(
                lambda: approve_direct_async(Step("direct", Action.BROWSER_NAVIGATE, tab_id, text=url))
            )
            destination = await _safe_async(
                lambda: browser.navigate(session_token, client_nonce, grant_token, tab_id, url)
            )
            return {"url": destination}

        @server.tool()
        async def browser_read(
            session_token: str, client_nonce: str, grant_token: str, tab_id: str, selector: str
        ) -> dict[str, str]:
            """Read bounded visible text, never editable control values."""
            value = await _safe_async(
                lambda: browser.read(session_token, client_nonce, grant_token, tab_id, selector)
            )
            return {"text": value}

        @server.tool()
        async def browser_click(
            session_token: str, client_nonce: str, grant_token: str, tab_id: str, selector: str
        ) -> dict[str, bool]:
            """Click one visible, nonsensitive element in the approved tab."""
            await _safe_async(
                lambda: approve_direct_async(
                    Step("direct", Action.BROWSER_CLICK, tab_id, selector=selector)
                )
            )
            await _safe_async(
                lambda: browser.click(session_token, client_nonce, grant_token, tab_id, selector)
            )
            return {"executed": True}

        @server.tool()
        async def browser_fill(
            session_token: str,
            client_nonce: str,
            grant_token: str,
            tab_id: str,
            selector: str,
            text: str,
        ) -> dict[str, bool]:
            """Fill a non-sensitive visible input; password/payment fields are prohibited."""
            await _safe_async(
                lambda: approve_direct_async(
                    Step("direct", Action.BROWSER_FILL, tab_id, selector=selector, text=text)
                )
            )
            await _safe_async(
                lambda: browser.fill(session_token, client_nonce, grant_token, tab_id, selector, text)
            )
            return {"executed": True}

        @server.tool()
        async def browser_scroll(
            session_token: str, client_nonce: str, grant_token: str, tab_id: str, steps: int
        ) -> dict[str, bool]:
            """Scroll only within the approved browser tab."""
            await _safe_async(
                lambda: approve_direct_async(
                    Step("direct", Action.BROWSER_SCROLL, tab_id, amount=steps)
                )
            )
            await _safe_async(lambda: browser.scroll(session_token, client_nonce, grant_token, tab_id, steps))
            return {"executed": True}

        @server.tool()
        async def browser_capture(
            session_token: str, client_nonce: str, grant_token: str, tab_id: str
        ) -> dict[str, str]:
            """Screenshot selected tab with all editable controls masked."""
            data = await _safe_async(
                lambda: browser.capture(session_token, client_nonce, grant_token, tab_id)
            )
            return {"mime_type": "image/png", "base64": base64.b64encode(data).decode("ascii")}

    if workflows is not None:

        @server.tool()
        async def workflow_execute(
            session_token: str,
            client_nonce: str,
            read_grant_token: str,
            input_grant_token: str,
            plan_id: str,
            steps: list[Step],
            resume: bool = False,
        ) -> dict[str, Any]:
            """Run at most eight typed actions; each mutation requires local human confirmation."""
            # This nonce is consumed immediately; each adapter action uses its
            # own cryptographically random nonce through the trusted broker.
            _safe_call(lambda: broker.status(session_token, client_nonce))
            try:
                plan = WorkflowPlan(plan_id, tuple(steps))
                result = await workflows.run(
                    plan,
                    SessionGrants(session_token, read_grant_token, input_grant_token),
                    resume=resume,
                )
            except (WorkflowFailure, AccessDenied, SessionDenied, ValueError, PermissionError):
                raise ToolError("Workflow denied, stopped, or requires manual reconciliation") from None
            return {
                "plan_id": result.plan_id,
                "completed": result.completed,
                "finished": result.finished,
                "results": [{"step_id": value.step_id, "result": value.result} for value in result.outputs],
            }

    return server


def serve_stdio(
    allow_windows: tuple[int, ...] = (),
    browser_origin: str | None = None,
    workflow_state_dir: Path | None = None,
) -> None:
    """Local-only stdio; UI/browser scopes and persistence selected locally."""
    # The Windows safety panel is mandatory whenever an adapter is enabled:
    # a missing/headless window fails closed, with no silent console fallback.
    panel = LocalSafetyPanel() if sys.platform == "win32" and (allow_windows or browser_origin) else None
    approval: LocalApproval = panel if panel is not None else ConsoleApproval()
    authority = PolicyAuthority(approval)
    if panel is not None:
        panel.bind_authority(authority)
        panel.start()
    broker = SessionBroker(authority)
    desktop = None
    if allow_windows:
        from local_gpt_mcp.desktop.windows import WindowsBackend

        backend = WindowsBackend(stopped=lambda: authority.stopped)
        allowed = backend.trust_local(allow_windows)
        desktop = DesktopController(broker, backend, allowed)
    browser = BrowserController(broker) if browser_origin else None
    lifespan = None
    if browser is not None and browser_origin is not None:
        from local_gpt_mcp.browser.playwright_driver import IsolatedBrowserSession

        @asynccontextmanager
        async def browser_lifespan(_server: MCPServer) -> AsyncIterator[None]:
            async with IsolatedBrowserSession(browser_origin, browser):
                yield

        lifespan = browser_lifespan
    workflows = None
    if desktop is not None or browser is not None:
        store = (
            FileCheckpointStore(workflow_state_dir)
            if workflow_state_dir is not None
            else MemoryCheckpointStore()
        )
        workflows = WorkflowEngine(
            broker,
            ScopedDriver(browser=browser, desktop=desktop),
            store,
            panel if panel is not None else ConsoleActionApproval(),
        )
    try:
        create_server(
            broker,
            desktop,
            browser,
            lifespan,
            workflows,
            direct_action_approval=panel if panel is not None else ConsoleActionApproval(),
        ).run(transport="stdio")
    finally:
        if panel is not None:
            panel.stop()
