"""Remote action relay releases only passkey-approved exact jobs."""

from __future__ import annotations

import asyncio
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from local_gpt_mcp.gateway.action_relay import RemoteActionRelay
from local_gpt_mcp.gateway.registry import DeviceUnavailable
from local_gpt_mcp.policy.approval_queue import OwnerApprovalQueue
from local_gpt_mcp.policy.owner_presence import OwnerPresence
from local_gpt_mcp.policy.remote_receipts import RemoteApprovalDenied

CREDENTIAL = "credential-alice-0001"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_approved_job_dispatches_once_and_is_exactly_bound() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    signer = ed25519.Ed25519PrivateKey.generate()
    clock = [2_000_000_000.0]
    presence = OwnerPresence(
        origin="https://approval.example.com",
        receipt_signer=signer,
        stopped=lambda: False,
        clock=lambda: clock[0],
    )
    presence.register_trusted("alice", CREDENTIAL, key.public_key())
    approvals = OwnerApprovalQueue(presence, clock=lambda: clock[0])
    relay = RemoteActionRelay(
        approvals,
        connected=lambda owner, device: owner == "alice" and device == "pc-alice",
        clock=lambda: clock[0],
    )
    pending = asyncio.create_task(
        relay.request_trusted(
            "alice", "pc-alice", "session-1", "window:41", "window.click", {"x": 18, "y": 35}
        )
    )
    await asyncio.sleep(0)
    listing = approvals.list_owned("alice")
    assert len(listing) == 1
    assert approvals.list_owned("bob") == []
    assert relay.poll_trusted("alice", "pc-alice") == {"job_id": None}
    with pytest.raises(DeviceUnavailable):
        relay.poll_trusted("bob", "pc-alice")
    request = listing[0]
    challenge = approvals.begin("alice", str(request["job_id"]), CREDENTIAL)
    client = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge.challenge,
            "origin": "https://approval.example.com",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    auth = hashlib.sha256(b"approval.example.com").digest() + b"\x05" + (1).to_bytes(4, "big")
    signature = key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    approvals.finish(
        "alice",
        str(request["job_id"]),
        CREDENTIAL,
        challenge.challenge,
        client_data=client,
        authenticator_data=auth,
        signature=signature,
    )
    delivered = relay.poll_trusted("alice", "pc-alice")
    assert delivered["job_id"] == request["job_id"]
    assert delivered["target"] == "window:41"
    assert delivered["parameters"] == {"x": 18, "y": 35}
    assert isinstance(delivered["receipt"], str)
    assert relay.poll_trusted("alice", "pc-alice") == {"job_id": None}
    with pytest.raises(DeviceUnavailable):
        relay.reply_trusted("bob", "pc-alice", str(request["job_id"]), {"ok": True})
    relay.reply_trusted("alice", "pc-alice", str(request["job_id"]), {"ok": True})
    assert await pending == {"ok": True}
    with pytest.raises(DeviceUnavailable):
        relay.reply_trusted("alice", "pc-alice", str(request["job_id"]), {"ok": True})


@pytest.mark.anyio
async def test_denied_unconnected_bad_action_and_stop_never_dispatch() -> None:
    signer = ed25519.Ed25519PrivateKey.generate()
    presence = OwnerPresence(
        origin="https://approval.example.com",
        receipt_signer=signer,
        stopped=lambda: False,
    )
    approvals = OwnerApprovalQueue(presence)
    relay = RemoteActionRelay(approvals, connected=lambda owner, device: device == "pc-a")
    with pytest.raises(DeviceUnavailable):
        await relay.request_trusted("alice", "pc-offline", "s", "window:41", "window.click", {"x": 1, "y": 1})
    with pytest.raises(DeviceUnavailable):
        await relay.request_trusted("alice", "pc-a", "s", "window:41", "window.type", {"text": "secret"})
    with pytest.raises(DeviceUnavailable):
        await relay.request_trusted("alice", "pc-a", "s", "window:41", "window.click", {"x": True, "y": 1})
    pending = asyncio.create_task(
        relay.request_trusted("alice", "pc-a", "s", "window:41", "window.click", {"x": 1, "y": 1})
    )
    await asyncio.sleep(0)
    assert relay.poll_trusted("alice", "pc-a") == {"job_id": None}
    relay.halt_owner("alice")
    with pytest.raises(DeviceUnavailable):
        await pending
    with pytest.raises(DeviceUnavailable):
        relay.poll_trusted("alice", "pc-a")
    with pytest.raises(DeviceUnavailable):
        await relay.request_trusted("alice", "pc-a", "s", "window:41", "window.click", {"x": 1, "y": 1})
    assert approvals.list_owned("alice") == []
