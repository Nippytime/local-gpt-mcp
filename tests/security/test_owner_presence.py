"""Real P-256/WebAuthn user-verification checks before owner receipt signing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from local_gpt_mcp.policy import Caller, Capability
from local_gpt_mcp.policy.owner_presence import OwnerPresence
from local_gpt_mcp.policy.remote_receipts import (
    RemoteApprovalDenied,
    RemoteApprovalVerifier,
    ScopedAction,
    SQLiteConsumptionStore,
    action_fingerprint,
)


def _action() -> ScopedAction:
    return ScopedAction(
        Caller("alice", "pc-alice", "session-1"),
        "window:41",
        Capability.WINDOW_INPUT,
        action_fingerprint("window.click", {"x": 34, "y": 75}),
        "a" * 32,
    )


def _signed_assertion(
    key: ec.EllipticCurvePrivateKey,
    challenge: str,
    *,
    origin: str = "https://approval.example.com",
    rp: str = "approval.example.com",
    flags: int = 0x05,
    counter: int = 1,
) -> tuple[bytes, bytes, bytes]:
    client = json.dumps(
        {"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": False},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    authenticator = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")
    signature = key.sign(authenticator + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    return client, authenticator, signature


def _service() -> tuple[OwnerPresence, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, list[float]]:
    clock = [2_000_000_000.0]
    signer = ed25519.Ed25519PrivateKey.generate()
    passkey = ec.generate_private_key(ec.SECP256R1())
    service = OwnerPresence(
        origin="https://approval.example.com",
        receipt_signer=signer,
        stopped=lambda: False,
        clock=lambda: clock[0],
    )
    service.register_trusted("alice", "credential-alice-0001", passkey.public_key())
    return service, passkey, signer, clock


def test_real_verified_passkey_mints_one_device_verifiable_receipt(tmp_path: Path) -> None:
    service, passkey, signer, clock = _service()
    pending = service.begin("alice", "credential-alice-0001", _action())
    client, authenticator, signature = _signed_assertion(passkey, pending.challenge)
    receipt = service.finish(
        "alice",
        "credential-alice-0001",
        pending.challenge,
        client_data=client,
        authenticator_data=authenticator,
        signature=signature,
    )
    device = RemoteApprovalVerifier(
        signer.public_key(),
        SQLiteConsumptionStore(tmp_path / "spent.sqlite"),
        stopped=lambda: False,
        clock=lambda: clock[0],
    )
    device.verify(receipt, _action())
    with pytest.raises(RemoteApprovalDenied, match="consumed"):
        device.verify(receipt, _action())
    with pytest.raises(RemoteApprovalDenied, match="challenge"):
        service.finish(
            "alice",
            "credential-alice-0001",
            pending.challenge,
            client_data=client,
            authenticator_data=authenticator,
            signature=signature,
        )


@pytest.mark.parametrize(
    "origin,rp,flags",
    [
        ("https://attacker.example.com", "approval.example.com", 0x05),
        ("https://approval.example.com", "attacker.example.com", 0x05),
        ("https://approval.example.com", "approval.example.com", 0x01),
        ("https://approval.example.com", "approval.example.com", 0x04),
    ],
)
def test_wrong_origin_rp_or_missing_user_verification_denied(origin: str, rp: str, flags: int) -> None:
    service, passkey, _signer, _clock = _service()
    pending = service.begin("alice", "credential-alice-0001", _action())
    client, auth, signature = _signed_assertion(passkey, pending.challenge, origin=origin, rp=rp, flags=flags)
    with pytest.raises(RemoteApprovalDenied):
        service.finish(
            "alice",
            "credential-alice-0001",
            pending.challenge,
            client_data=client,
            authenticator_data=auth,
            signature=signature,
        )


def test_other_owner_wrong_signature_expiry_and_replay_fail_closed() -> None:
    service, passkey, _signer, clock = _service()
    with pytest.raises(RemoteApprovalDenied):
        service.begin("bob", "credential-alice-0001", _action())
    pending = service.begin("alice", "credential-alice-0001", _action())
    client, auth, _signature = _signed_assertion(passkey, pending.challenge)
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    forged = wrong_key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    with pytest.raises(RemoteApprovalDenied, match="signature"):
        service.finish(
            "alice",
            "credential-alice-0001",
            pending.challenge,
            client_data=client,
            authenticator_data=auth,
            signature=forged,
        )
    with pytest.raises(RemoteApprovalDenied):
        service.finish(
            "alice",
            "credential-alice-0001",
            pending.challenge,
            client_data=client,
            authenticator_data=auth,
            signature=forged,
        )
    later = service.begin("alice", "credential-alice-0001", _action())
    clock[0] += 61
    new_client, new_auth, new_sig = _signed_assertion(passkey, later.challenge)
    with pytest.raises(RemoteApprovalDenied):
        service.finish(
            "alice",
            "credential-alice-0001",
            later.challenge,
            client_data=new_client,
            authenticator_data=new_auth,
            signature=new_sig,
        )


def test_sign_counter_and_stop_denial() -> None:
    service, passkey, _signer, _clock = _service()
    first = service.begin("alice", "credential-alice-0001", _action())
    client, auth, sig = _signed_assertion(passkey, first.challenge, counter=10)
    service.finish(
        "alice",
        "credential-alice-0001",
        first.challenge,
        client_data=client,
        authenticator_data=auth,
        signature=sig,
    )
    second = service.begin("alice", "credential-alice-0001", _action())
    client, auth, sig = _signed_assertion(passkey, second.challenge, counter=9)
    with pytest.raises(RemoteApprovalDenied, match="counter"):
        service.finish(
            "alice",
            "credential-alice-0001",
            second.challenge,
            client_data=client,
            authenticator_data=auth,
            signature=sig,
        )
    third = service.begin("alice", "credential-alice-0001", _action())
    client, auth, sig = _signed_assertion(passkey, third.challenge, counter=0)
    with pytest.raises(RemoteApprovalDenied, match="counter"):
        service.finish(
            "alice",
            "credential-alice-0001",
            third.challenge,
            client_data=client,
            authenticator_data=auth,
            signature=sig,
        )
    signer = ed25519.Ed25519PrivateKey.generate()
    stopped = OwnerPresence(
        origin="https://approval.example.com",
        receipt_signer=signer,
        stopped=lambda: True,
    )
    stopped.register_trusted("alice", "credential-alice-0001", passkey.public_key())
    with pytest.raises(RemoteApprovalDenied, match="authorized"):
        stopped.begin("alice", "credential-alice-0001", _action())
