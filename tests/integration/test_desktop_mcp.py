"""Real MCP SDK client proves unpaired clients cannot use Windows tools."""

from __future__ import annotations

from typing import Any

import pytest
from mcp import Client

from local_gpt_mcp.desktop import (
    ControlInfo,
    DesktopController,
    Rect,
    WindowIdentity,
    WindowInfo,
)
from local_gpt_mcp.mcp.server import create_server
from local_gpt_mcp.orchestrator.models import Step
from local_gpt_mcp.pairing import SessionBroker
from local_gpt_mcp.policy import GrantRequest, PairingRequest, PolicyAuthority


class Approval:
    def approve_pairing(self, request: PairingRequest) -> bool:
        return True

    def approve_grant(self, request: GrantRequest) -> bool:
        return True

    def approve(self, step: Step) -> bool:
        return True


class Native:
    def __init__(self) -> None:
        self.effects: list[str] = []
        self.info = WindowInfo(
            WindowIdentity(41, 1001, 987654),
            "Test window",
            Rect(0, 0, 300, 200),
            True,
            True,
            True,
            False,
            True,
            True,
            False,
        )

    def desktop_ready(self) -> bool:
        return True

    def windows(self) -> tuple[WindowInfo, ...]:
        return (self.info,)

    def window(self, handle: int) -> WindowInfo | None:
        return self.info if handle == 41 else None

    def capture(self, handle: int) -> bytes:
        return b"\x89PNG"

    def controls(self, handle: int, max_depth: int, max_nodes: int) -> tuple[ControlInfo, ...]:
        return (ControlInfo("Button", "OK", 1),)

    def click(self, handle: int, x: int, y: int) -> None:
        self.effects.append("click")

    def type_text(self, handle: int, text: str) -> None:
        self.effects.append("type")

    def scroll(self, handle: int, steps: int) -> None:
        self.effects.append("scroll")

    def press_key(self, handle: int, key: str) -> None:
        self.effects.append("key")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_desktop_tools_not_present_without_local_allowlist() -> None:
    async with Client(create_server(SessionBroker(PolicyAuthority()))) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert "session_open" in names
        assert not any(name.startswith("desktop_") for name in names)


@pytest.mark.anyio
async def test_mcp_requires_pairing_and_separate_grant_for_every_effect() -> None:
    native = Native()
    broker = SessionBroker(PolicyAuthority(Approval()))
    controller = DesktopController(broker, native, [native.info.identity])
    sequence = 0

    def nonce() -> str:
        nonlocal sequence
        sequence += 1
        return f"{sequence:032x}"

    async with Client(create_server(broker, controller, direct_action_approval=Approval())) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert "desktop_window_info" in names
        assert "desktop_click" in names
        assert "desktop_capture" in names
        assert not any("shell" in name for name in names)

        base: dict[str, Any] = {"handle": 41}
        unauthorized = await client.call_tool(
            "desktop_click",
            {
                **base,
                "session_token": "invalid",
                "client_nonce": nonce(),
                "grant_token": "invalid",
                "x": 50,
                "y": 50,
            },
        )
        assert unauthorized.is_error
        assert native.effects == []

        paired = await client.call_tool(
            "session_open", {"user_id": "user", "device_id": "device", "client_nonce": nonce()}
        )
        assert not paired.is_error
        assert paired.structured_content is not None
        session = paired.structured_content["session_token"]
        grant_result = await client.call_tool(
            "session_request_grant",
            {
                "session_token": session,
                "client_nonce": nonce(),
                "target": "window:41",
                "capabilities": ["window.read", "window.input"],
                "ttl_seconds": 60,
            },
        )
        assert not grant_result.is_error
        assert grant_result.structured_content is not None
        grant = grant_result.structured_content["grant_token"]
        authorized = {**base, "session_token": session, "grant_token": grant}

        observation = await client.call_tool("desktop_window_info", {**authorized, "client_nonce": nonce()})
        assert not observation.is_error
        assert observation.structured_content is not None
        assert observation.structured_content["width"] == 300

        image = await client.call_tool("desktop_capture", {**authorized, "client_nonce": nonce()})
        assert not image.is_error
        uia = await client.call_tool("desktop_controls", {**authorized, "client_nonce": nonce()})
        assert not uia.is_error

        for tool, fields in (
            ("desktop_click", {"x": 50, "y": 50}),
            ("desktop_type", {"text": "hello"}),
            ("desktop_scroll", {"steps": 1}),
            ("desktop_key", {"key": "tab"}),
        ):
            result = await client.call_tool(tool, {**authorized, **fields, "client_nonce": nonce()})
            assert not result.is_error
        assert native.effects == ["click", "type", "scroll", "key"]

        stopped = await client.call_tool(
            "session_emergency_stop", {"session_token": session, "client_nonce": nonce()}
        )
        assert not stopped.is_error
        denied = await client.call_tool(
            "desktop_click", {**authorized, "client_nonce": nonce(), "x": 50, "y": 50}
        )
        assert denied.is_error
        assert native.effects == ["click", "type", "scroll", "key"]
