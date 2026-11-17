"""Real outbound-only HTTP agent against a tenant-authenticated MCP gateway."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping

import httpx2 as httpx
import pytest
from mcp.server.auth.provider import AccessToken

from local_gpt_mcp.agent.identity import MAX_BODY, DeviceIdentity, sign_request
from local_gpt_mcp.agent.outbound import OutboundAgent
from local_gpt_mcp.gateway.agent_relay import AgentRelay
from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.gateway.registry import DeviceDirectory, DeviceUnavailable, ReadRequest
from local_gpt_mcp.gateway.server import create_gateway

CONFIG = GatewayConfig(
    resource_url="https://gateway.example.com/mcp",
    issuer_url="https://login.example.com",
    jwks_url="https://login.example.com/jwks",
)


class StubVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        if token not in {"alice", "bob"}:
            return None
        return AccessToken(
            token=token,
            client_id="owner-browser",
            scopes=["devices:read", "devices:manage"],
            subject=token,
            resource=CONFIG.resource_url,
        )


class ApprovedRead:
    def __init__(self) -> None:
        self.calls: list[ReadRequest] = []

    async def read(self, request: ReadRequest) -> Mapping[str, str | int | bool]:
        self.calls.append(request)
        return {"title": "Locally approved disposable window"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_owner_pairing_signed_poll_and_scoped_result() -> None:
    relay = AgentRelay()
    directory = DeviceDirectory(relay)
    app = create_gateway(CONFIG, directory=directory, relay=relay, verifier=StubVerifier())
    approved = ApprovedRead()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
        ) as client,
    ):
        assert (await client.post("/api/owner/enrollments", json={"label": "My PC"})).status_code == 403
        created = await client.post(
            "/api/owner/enrollments",
            json={"label": "My PC"},
            headers={"Authorization": "Bearer alice"},
        )
        assert created.status_code == 200
        claim = created.json()
        identity = DeviceIdentity.generate(claim["device_id"])
        agent = OutboundAgent(identity, "https://gateway.example.com", client=client, executor=approved)
        await agent.enroll(claim["enrollment_code"])
        assert directory.list_owned("alice") == [
            {"device_id": identity.device_id, "label": "My PC", "online": False}
        ]
        assert directory.list_owned("bob") == []
        assert (
            await client.post(
                "/api/agent/enroll",
                json={
                    "device_id": identity.device_id,
                    "enrollment_code": claim["enrollment_code"],
                    "public_key": identity.public_key,
                },
            )
        ).status_code == 403

        assert not await agent.tick()  # authenticated heartbeat, no pending work
        request = ReadRequest("desktop_window_info", "window:41")
        pending = asyncio.create_task(directory.read("alice", identity.device_id, request))
        await asyncio.sleep(0)
        assert await agent.tick()
        assert await pending == {"title": "Locally approved disposable window"}
        assert approved.calls == [request]
        assert directory.status("alice", identity.device_id)["online"] is True

        assert (
            await client.post(
                "/api/owner/revoke",
                json={"device_id": identity.device_id},
                headers={"Authorization": "Bearer bob"},
            )
        ).status_code == 403
        assert (
            await client.post(
                "/api/owner/revoke",
                json={"device_id": identity.device_id},
                headers={"Authorization": "Bearer alice"},
            )
        ).status_code == 200
        assert directory.status("alice", identity.device_id)["online"] is False
        with pytest.raises(DeviceUnavailable):
            await directory.read("alice", identity.device_id, request)
        with pytest.raises(DeviceUnavailable):
            await agent.tick()


@pytest.mark.anyio
async def test_signed_nonce_replay_and_payload_tampering_are_denied() -> None:
    relay = AgentRelay()
    directory = DeviceDirectory(relay)
    app = create_gateway(CONFIG, directory=directory, relay=relay, verifier=StubVerifier())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        code = await client.post(
            "/api/owner/enrollments",
            json={"label": "Test"},
            headers={"Authorization": "Bearer alice"},
        )
        claim = code.json()
        identity = DeviceIdentity.generate(claim["device_id"])
        agent = OutboundAgent(identity, "https://gateway.example.com", client=client)
        await agent.enroll(claim["enrollment_code"])
        raw = b"{}"
        headers = sign_request(identity.private_key, identity.device_id, "/api/agent/poll", raw)
        assert (await client.post("/api/agent/poll", content=raw, headers=headers)).status_code == 200
        assert (await client.post("/api/agent/poll", content=raw, headers=headers)).status_code == 403
        assert (
            await client.post("/api/agent/poll", content=b'{"forged":true}', headers=headers)
        ).status_code == 403
        wrong_path = sign_request(identity.private_key, identity.device_id, "/api/agent/result", raw)
        assert (await client.post("/api/agent/poll", content=raw, headers=wrong_path)).status_code == 403


@pytest.mark.anyio
async def test_default_agent_never_releases_unapproved_pc_data() -> None:
    relay = AgentRelay()
    directory = DeviceDirectory(relay)
    app = create_gateway(CONFIG, directory=directory, relay=relay, verifier=StubVerifier())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        code = await client.post(
            "/api/owner/enrollments",
            json={"label": "Deny"},
            headers={"Authorization": "Bearer alice"},
        )
        claim = code.json()
        agent = OutboundAgent(
            DeviceIdentity.generate(claim["device_id"]), "https://gateway.example.com", client=client
        )
        await agent.enroll(claim["enrollment_code"])
        assert not await agent.tick()
        pending = asyncio.create_task(
            directory.read("alice", agent.identity.device_id, ReadRequest("desktop_window_info", "window:41"))
        )
        await asyncio.sleep(0)
        assert await agent.tick()
        with pytest.raises(DeviceUnavailable):
            await pending


@pytest.mark.anyio
async def test_owner_and_agent_routes_reject_foreign_host_and_browser_origin() -> None:
    relay = AgentRelay()
    directory = DeviceDirectory(relay)
    app = create_gateway(CONFIG, directory=directory, relay=relay, verifier=StubVerifier())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        for headers in (
            {"Host": "untrusted.example.com"},
            {"Origin": "https://untrusted.example.com"},
            {"Origin": "null"},
        ):
            denied = await client.post(
                "/api/owner/enrollments",
                json={"label": "Never enrolled"},
                headers={"Authorization": "Bearer alice", **headers},
            )
            assert denied.status_code == 403

        # A signed request cannot bypass the public Host boundary.
        identity = DeviceIdentity.generate("pc-test")
        signed = sign_request(identity.private_key, identity.device_id, "/api/agent/poll", b"{}")
        denied_poll = await client.post(
            "/api/agent/poll",
            content=b"{}",
            headers={**signed, "Host": "untrusted.example.com"},
        )
        assert denied_poll.status_code == 403


@pytest.mark.anyio
async def test_streaming_body_bounds_and_missing_content_length() -> None:
    relay = AgentRelay()
    directory = DeviceDirectory(relay)
    app = create_gateway(CONFIG, directory=directory, relay=relay, verifier=StubVerifier())

    async def valid_stream() -> AsyncIterator[bytes]:
        yield b'{"label":"Streaming PC"}'

    async def oversized_stream() -> AsyncIterator[bytes]:
        yield b'{"label":"'
        yield b"A" * MAX_BODY
        yield b'"}'

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        permitted = await client.post(
            "/api/owner/enrollments",
            content=valid_stream(),
            headers={"Authorization": "Bearer alice"},
        )
        assert permitted.status_code == 200
        assert permitted.json()["device_id"].startswith("pc-")

        denied = await client.post(
            "/api/owner/enrollments",
            content=oversized_stream(),
            headers={"Authorization": "Bearer alice"},
        )
        assert denied.status_code == 403
