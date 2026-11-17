"""Owner HTTP API never lets OAuth bearer or a model mint its own consent."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from mcp.server.auth.provider import AccessToken
from starlette.applications import Starlette

from local_gpt_mcp.gateway.approval_api import install_approval_routes
from local_gpt_mcp.policy import Caller, Capability
from local_gpt_mcp.policy.approval_queue import OwnerApprovalQueue
from local_gpt_mcp.policy.owner_presence import OwnerPresence
from local_gpt_mcp.policy.remote_receipts import (
    RemoteApprovalDenied,
    RemoteApprovalVerifier,
    ScopedAction,
    SQLiteConsumptionStore,
    action_fingerprint,
)

RESOURCE = "https://gateway.example.com/mcp"
CREDENTIAL = "Y3JlZGVudGlhbC1hbGljZS0wMDAx"
JOB_ID = "a" * 32


class Verifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        identities = {
            "alice-owner": ("alice", ["approvals:manage"]),
            "bob-owner": ("bob", ["approvals:manage"]),
            "model": ("alice", ["devices:read"]),
        }
        identity = identities.get(token)
        if identity is None:
            return None
        return AccessToken(
            token=token,
            client_id="approval-browser",
            scopes=identity[1],
            subject=identity[0],
            resource=RESOURCE,
        )


def _signed(key: ec.EllipticCurvePrivateKey, challenge: str) -> dict[str, str]:
    client = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": "https://gateway.example.com",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    auth = hashlib.sha256(b"gateway.example.com").digest() + b"\x05" + (1).to_bytes(4, "big")
    signature = key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "client_data": base64.urlsafe_b64encode(client).rstrip(b"=").decode(),
        "authenticator_data": base64.urlsafe_b64encode(auth).rstrip(b"=").decode(),
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    }


def _fixture() -> tuple[
    Starlette, OwnerApprovalQueue, ScopedAction, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey
]:
    def clock() -> float:
        return 2_000_000_000.0

    signer = ed25519.Ed25519PrivateKey.generate()
    key = ec.generate_private_key(ec.SECP256R1())
    presence = OwnerPresence(
        origin="https://gateway.example.com", receipt_signer=signer, stopped=lambda: False, clock=clock
    )
    presence.register_trusted("alice", CREDENTIAL, key.public_key())
    approvals = OwnerApprovalQueue(presence, clock=clock)
    action = ScopedAction(
        Caller("alice", "pc-alice", "session-1"),
        "window:41",
        Capability.WINDOW_INPUT,
        action_fingerprint("window.click", {"x": 18, "y": 35}),
        JOB_ID,
    )
    approvals.offer_trusted(action, operation="window.click", parameters={"x": 18, "y": 35})
    app = Starlette()
    install_approval_routes(app, approvals, Verifier(), RESOURCE)
    return app, approvals, action, key, signer


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_owner_passkey_confirm_is_one_job_and_device_only(tmp_path: Path) -> None:
    app, approvals, action, key, signer = _fixture()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        assert (await client.get("/api/owner/approvals")).status_code == 403
        assert (
            await client.get("/api/owner/approvals", headers={"Authorization": "Bearer model"})
        ).status_code == 403
        bob = await client.get("/api/owner/approvals", headers={"Authorization": "Bearer bob-owner"})
        assert bob.json() == {"approvals": []}
        denied = await client.post(
            "/api/owner/approvals/begin",
            headers={"Authorization": "Bearer bob-owner"},
            json={"job_id": JOB_ID, "credential_id": CREDENTIAL},
        )
        assert denied.status_code == 403
        alice = {"Authorization": "Bearer alice-owner"}
        listing = await client.get("/api/owner/approvals", headers=alice)
        assert listing.status_code == 200
        assert listing.headers["cache-control"] == "no-store"
        assert listing.json()["approvals"][0]["parameters"] == {"x": 18, "y": 35}
        assert "receipt" not in listing.text
        begin = await client.post(
            "/api/owner/approvals/begin",
            headers=alice,
            json={"job_id": JOB_ID, "credential_id": CREDENTIAL},
        )
        assert begin.status_code == 200
        challenge = begin.json()["challenge"]
        assert challenge
        data = {
            "job_id": JOB_ID,
            "credential_id": CREDENTIAL,
            "challenge": challenge,
            **_signed(key, challenge),
        }
        approved = await client.post("/api/owner/approvals/finish", headers=alice, json=data)
        assert approved.status_code == 200
        assert approved.json() == {"approved": True}
        assert "receipt" not in approved.text
        assert (await client.post("/api/owner/approvals/finish", headers=alice, json=data)).status_code == 403
        with pytest.raises(RemoteApprovalDenied):
            approvals.take_trusted("bob", action.caller.device_id, action)
        with pytest.raises(RemoteApprovalDenied):
            approvals.take_trusted("alice", "pc-bob", action)
        receipt = approvals.take_trusted("alice", action.caller.device_id, action)
        verifier = RemoteApprovalVerifier(
            signer.public_key(),
            SQLiteConsumptionStore(tmp_path / "spent.sqlite"),
            stopped=lambda: False,
            clock=lambda: 2_000_000_000.0,
        )
        verifier.verify(receipt, action)
        with pytest.raises(RemoteApprovalDenied):
            approvals.take_trusted("alice", action.caller.device_id, action)


@pytest.mark.anyio
async def test_model_cannot_enqueue_forge_or_approve_its_own_job() -> None:
    app, approvals, action, _key, _signer = _fixture()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        headers = {"Authorization": "Bearer alice-owner"}
        assert (
            await client.post(
                "/api/owner/approvals",
                json={"job_id": "b" * 32, "operation": "window.click"},
                headers=headers,
            )
        ).status_code in {404, 405}
        assert (
            await client.post(
                "/api/owner/approvals/begin",
                json={"job_id": "b" * 32, "credential_id": CREDENTIAL},
                headers=headers,
            )
        ).status_code == 403
        begin = await client.post(
            "/api/owner/approvals/begin",
            json={"job_id": JOB_ID, "credential_id": CREDENTIAL},
            headers=headers,
        )
        challenge = begin.json()["challenge"]
        forged = {
            "job_id": JOB_ID,
            "credential_id": CREDENTIAL,
            "challenge": challenge,
            "client_data": "AAAA",
            "authenticator_data": "BBBB",
            "signature": "CCCC",
        }
        assert (
            await client.post("/api/owner/approvals/finish", json=forged, headers=headers)
        ).status_code == 403
        with pytest.raises(RemoteApprovalDenied):
            approvals.take_trusted("alice", action.caller.device_id, action)
        assert (
            await client.post("/api/owner/approvals/halt", headers={"Authorization": "Bearer model"})
        ).status_code == 403
        assert (await client.post("/api/owner/approvals/halt", headers=headers)).status_code == 200
        with pytest.raises(RemoteApprovalDenied):
            approvals.offer_trusted(action, operation="window.click", parameters={"x": 18, "y": 35})


@pytest.mark.anyio
async def test_cross_origin_host_and_revoked_job_denied() -> None:
    app, _queue, _action, _key, _signer = _fixture()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        headers = {"Authorization": "Bearer alice-owner"}
        for bad in ({"Host": "evil.example.com"}, {"Origin": "https://evil.example.com"}):
            assert (await client.get("/api/owner/approvals", headers={**headers, **bad})).status_code == 403
        deny = await client.post("/api/owner/approvals/deny", headers=headers, json={"job_id": JOB_ID})
        assert deny.status_code == 200
        assert (
            await client.post(
                "/api/owner/approvals/begin",
                headers=headers,
                json={"job_id": JOB_ID, "credential_id": CREDENTIAL},
            )
        ).status_code == 403
