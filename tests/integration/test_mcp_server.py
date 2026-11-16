"""Actual MCP SDK Client exercises published tools, schemas and access rejection."""

from __future__ import annotations

import pytest
from mcp import Client

from local_gpt_mcp.mcp.server import create_server
from local_gpt_mcp.pairing.sessions import SessionBroker
from local_gpt_mcp.policy import GrantRequest, PairingRequest, PolicyAuthority


class LocalApproval:
    def __init__(self, approved: bool = True) -> None:
        self.approved = approved

    def approve_pairing(self, request: PairingRequest) -> bool:
        return self.approved

    def approve_grant(self, request: GrantRequest) -> bool:
        return self.approved


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_mcp_tool_discovery_does_not_expose_device_actions() -> None:
    broker = SessionBroker(PolicyAuthority())
    async with Client(create_server(broker)) as client:
        tools = await client.list_tools()
        names = {tool.name for tool in tools.tools}
        assert "session_open" in names
        assert "session_request_grant" in names
        assert "session_emergency_stop" in names
        assert "desktop_click" not in names
        assert "shell_execute" not in names


@pytest.mark.anyio
async def test_unauthorized_client_cannot_create_session_or_read_status() -> None:
    broker = SessionBroker(PolicyAuthority())
    async with Client(create_server(broker)) as client:
        denied = await client.call_tool(
            "session_open",
            {"user_id": "person", "device_id": "pc", "client_nonce": "aa" * 16},
        )
        assert denied.is_error
        status = await client.call_tool(
            "session_status",
            {"session_token": "unpaired", "client_nonce": "bb" * 16},
        )
        assert status.is_error


@pytest.mark.anyio
async def test_locally_paired_client_can_get_status_and_stop() -> None:
    broker = SessionBroker(PolicyAuthority(LocalApproval()))
    async with Client(create_server(broker)) as client:
        result = await client.call_tool(
            "session_open",
            {"user_id": "person", "device_id": "pc", "client_nonce": "aa" * 16},
        )
        assert not result.is_error
        content = result.structured_content
        assert content is not None
        token = content["session_token"]
        status = await client.call_tool("session_status", {"session_token": token, "client_nonce": "bb" * 16})
        assert not status.is_error
        stopped = await client.call_tool(
            "session_emergency_stop", {"session_token": token, "client_nonce": "cc" * 16}
        )
        assert not stopped.is_error
        denied = await client.call_tool("session_status", {"session_token": token, "client_nonce": "dd" * 16})
        assert denied.is_error
