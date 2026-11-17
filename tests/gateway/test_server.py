"""Real MCP tools and HTTP OAuth discovery/denial contracts."""

from __future__ import annotations

import httpx
import pytest
from mcp import Client
from mcp.server.auth.provider import AccessToken

from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.gateway.registry import DeviceDirectory
from local_gpt_mcp.gateway.server import create_gateway, create_gateway_server

CONFIG = GatewayConfig(
    resource_url="https://gateway.example.com/mcp",
    issuer_url="https://login.example.com",
    jwks_url="https://login.example.com/keys",
)


class StubVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        return None


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_http_oauth_discovery_and_unauthenticated_denial() -> None:
    app = create_gateway(CONFIG, verifier=StubVerifier())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://gateway.example.com") as client:
        metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        document = metadata.json()
        assert document["resource"] == CONFIG.resource_url
        assert CONFIG.issuer_url in document["authorization_servers"]
        denied = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert denied.status_code == 401
        assert "resource_metadata=" in denied.headers["www-authenticate"]


@pytest.mark.anyio
async def test_account_scoped_tools_never_expose_remote_mutations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = DeviceDirectory()
    directory.enroll_trusted("alice", "alice-pc", "Personal PC")
    directory.enroll_trusted("bob", "bob-pc", "Private Bob PC")
    principal = AccessToken(
        token="fixture",
        client_id="test-client",
        scopes=["devices:read"],
        resource=CONFIG.resource_url,
        subject="alice",
    )
    monkeypatch.setattr("local_gpt_mcp.gateway.server.get_access_token", lambda: principal)
    server = create_gateway_server(CONFIG, directory=directory, verifier=StubVerifier())
    async with Client(server) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert names == {"list_my_devices", "device_status", "read_from_device"}
        own = await client.call_tool("list_my_devices", {})
        assert not own.is_error
        assert own.structured_content == {
            "devices": [{"device_id": "alice-pc", "label": "Personal PC", "online": False}]
        }
        foreign = await client.call_tool("device_status", {"device_id": "bob-pc"})
        assert foreign.is_error
        offline = await client.call_tool(
            "read_from_device",
            {"device_id": "alice-pc", "kind": "desktop_window_info", "target": "window:41"},
        )
        assert offline.is_error


@pytest.mark.anyio
async def test_contextless_and_unscoped_requests_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = create_gateway_server(CONFIG, verifier=StubVerifier())
    monkeypatch.setattr("local_gpt_mcp.gateway.server.get_access_token", lambda: None)
    async with Client(server) as client:
        assert (await client.call_tool("list_my_devices", {})).is_error
