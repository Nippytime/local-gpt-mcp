"""Signed fake-cloud transport never dispatches without separate owner UV approval."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from mcp.server.auth.provider import AccessToken

from local_gpt_mcp.agent.identity import DeviceIdentity, sign_request
from local_gpt_mcp.agent.outbound import OutboundAgent
from local_gpt_mcp.gateway.action_relay import RemoteActionRelay
from local_gpt_mcp.gateway.agent_relay import AgentRelay
from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.gateway.registry import DeviceDirectory
from local_gpt_mcp.gateway.server import create_gateway
from local_gpt_mcp.policy import Caller, Capability
from local_gpt_mcp.policy.approval_queue import OwnerApprovalQueue
from local_gpt_mcp.policy.owner_presence import OwnerPresence
from local_gpt_mcp.policy.remote_receipts import (
    RemoteApprovalVerifier,
    ScopedAction,
    SQLiteConsumptionStore,
    action_fingerprint,
)

CONFIG = GatewayConfig(
    resource_url="https://gateway.example.com/mcp",
    issuer_url="https://login.example.com",
    jwks_url="https://login.example.com/jwks",
)
CREDENTIAL = "credential-alice-0001"


class OwnerTokens:
    async def verify_token(self, token: str) -> AccessToken | None:
        if token != "alice":
            return None
        return AccessToken(
            token=token,
            client_id="trusted-browser",
            scopes=["devices:read", "devices:manage", "approvals:manage"],
            subject="alice",
            resource=CONFIG.resource_url,
        )


async def signed_post(
    client: httpx.AsyncClient, identity: DeviceIdentity, path: str, body: dict[str, object]
) -> httpx.Response:
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    return await client.post(
        path,
        content=raw,
        headers=sign_request(identity.private_key, identity.device_id, path, raw),
    )


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_signed_agent_receives_one_webauthed_job_and_acks_only_its_own(tmp_path: Path) -> None:
    device_relay = AgentRelay()
    directory = DeviceDirectory(device_relay)
    signer = ed25519.Ed25519PrivateKey.generate()
    passkey = ec.generate_private_key(ec.SECP256R1())
    presence = OwnerPresence(
        origin="https://gateway.example.com", receipt_signer=signer, stopped=lambda: False
    )
    presence.register_trusted("alice", CREDENTIAL, passkey.public_key())
    approvals = OwnerApprovalQueue(presence)
    actions = RemoteActionRelay(approvals, connected=device_relay.connected)
    app = create_gateway(
        CONFIG,
        directory=directory,
        relay=device_relay,
        approvals=approvals,
        actions=actions,
        verifier=OwnerTokens(),
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
        ) as client,
    ):
        claim = await client.post(
            "/api/owner/enrollments",
            json={"label": "My PC"},
            headers={"Authorization": "Bearer alice"},
        )
        assert claim.status_code == 200 and claim.headers["cache-control"] == "no-store"
        identity = DeviceIdentity.generate(claim.json()["device_id"])
        agent = OutboundAgent(identity, "https://gateway.example.com", client=client)
        await agent.enroll(claim.json()["enrollment_code"])
        assert not await agent.tick()
        pending = asyncio.create_task(
            actions.request_trusted(
                "alice", identity.device_id, "session-1", "window:41", "window.click", {"x": 18, "y": 35}
            )
        )
        await asyncio.sleep(0)
        before = await signed_post(client, identity, "/api/agent/actions/poll", {})
        assert before.status_code == 200
        assert before.json() == {"job_id": None}
        forged_device = DeviceIdentity.generate("pc-other")
        assert (await signed_post(client, forged_device, "/api/agent/actions/poll", {})).status_code == 403

        queued = (await client.get("/api/owner/approvals", headers={"Authorization": "Bearer alice"})).json()[
            "approvals"
        ][0]
        begin = await client.post(
            "/api/owner/approvals/begin",
            headers={"Authorization": "Bearer alice"},
            json={"job_id": queued["job_id"], "credential_id": CREDENTIAL},
        )
        assert begin.status_code == 200
        challenge = begin.json()["challenge"]
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "origin": "https://gateway.example.com",
                "challenge": challenge,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        auth_data = hashlib.sha256(b"gateway.example.com").digest() + b"\x05" + (1).to_bytes(4, "big")
        signature = passkey.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        verified = await client.post(
            "/api/owner/approvals/finish",
            headers={"Authorization": "Bearer alice"},
            json={
                "job_id": queued["job_id"],
                "credential_id": CREDENTIAL,
                "challenge": challenge,
                "client_data": encoded(client_data),
                "authenticator_data": encoded(auth_data),
                "signature": encoded(signature),
            },
        )
        assert verified.status_code == 200
        assert "receipt" not in verified.text

        delivery = await signed_post(client, identity, "/api/agent/actions/poll", {})
        assert delivery.status_code == 200 and delivery.headers["cache-control"] == "no-store"
        body = delivery.json()
        assert body["job_id"] == queued["job_id"]
        assert body["operation"] == "window.click"
        assert body["parameters"] == {"x": 18, "y": 35}
        assert (await signed_post(client, identity, "/api/agent/actions/poll", {})).json() == {"job_id": None}
        expected = ScopedAction(
            Caller("alice", identity.device_id, "session-1"),
            "window:41",
            Capability.WINDOW_INPUT,
            action_fingerprint("window.click", {"x": 18, "y": 35}),
            body["job_id"],
        )
        verifier = RemoteApprovalVerifier(
            signer.public_key(),
            SQLiteConsumptionStore(tmp_path / "spent.sqlite"),
            stopped=lambda: False,
        )
        verifier.verify(body["receipt"], expected)
        reject = await signed_post(
            client,
            forged_device,
            "/api/agent/actions/result",
            {"job_id": body["job_id"], "result": {"ok": True}},
        )
        assert reject.status_code == 403
        accepted = await signed_post(
            client,
            identity,
            "/api/agent/actions/result",
            {"job_id": body["job_id"], "result": {"ok": True}},
        )
        assert accepted.status_code == 200
        assert await pending == {"ok": True}
        assert (
            await signed_post(
                client,
                identity,
                "/api/agent/actions/result",
                {"job_id": body["job_id"], "result": {"ok": True}},
            )
        ).status_code == 403


@pytest.mark.anyio
async def test_action_endpoints_not_enabled_by_default() -> None:
    relay = AgentRelay()
    app = create_gateway(CONFIG, relay=relay, verifier=OwnerTokens())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        assert (await client.post("/api/agent/actions/poll", json={})).status_code in {404, 405}
