"""Remote owner receipts bind one action and remain single-use after process restart."""

from __future__ import annotations

import base64
import json
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from local_gpt_mcp.policy import Caller, Capability
from local_gpt_mcp.policy.remote_receipts import (
    RemoteApprovalDenied,
    RemoteApprovalVerifier,
    ScopedAction,
    SQLiteConsumptionStore,
    action_fingerprint,
    issue_testable_receipt,
)


def action() -> ScopedAction:
    return ScopedAction(
        Caller("alice", "pc-a", "session-1"),
        "window:41",
        Capability.WINDOW_INPUT,
        action_fingerprint("window.click", {"x": 12, "y": 34}),
    )


def test_signed_receipt_is_exact_and_persistently_single_use(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    clock = [2_000_000_000.0]
    db = tmp_path / "spent.sqlite"
    target = action()
    proof = issue_testable_receipt(key, target, issued_at=int(clock[0]))
    verifier = RemoteApprovalVerifier(
        key.public_key(),
        SQLiteConsumptionStore(db),
        stopped=lambda: False,
        clock=lambda: clock[0],
    )
    verifier.verify(proof, target)
    with pytest.raises(RemoteApprovalDenied, match="consumed"):
        verifier.verify(proof, target)
    after_restart = RemoteApprovalVerifier(
        key.public_key(),
        SQLiteConsumptionStore(db),
        stopped=lambda: False,
        clock=lambda: clock[0],
    )
    with pytest.raises(RemoteApprovalDenied, match="consumed"):
        after_restart.verify(proof, target)


def test_wrong_owner_device_session_target_capability_and_action_denied(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    target = action()
    proof = issue_testable_receipt(key, target, issued_at=2_000_000_000)
    verifier = RemoteApprovalVerifier(
        key.public_key(),
        SQLiteConsumptionStore(tmp_path / "spent.sqlite"),
        stopped=lambda: False,
        clock=lambda: 2_000_000_000.0,
    )
    others = [
        replace(target, caller=replace(target.caller, user_id="bob")),
        replace(target, caller=replace(target.caller, device_id="pc-b")),
        replace(target, caller=replace(target.caller, session_id="session-2")),
        replace(target, target="window:42"),
        replace(target, capability=Capability.WINDOW_READ),
        replace(target, action_sha256=action_fingerprint("window.click", {"x": 13, "y": 34})),
    ]
    for changed in others:
        with pytest.raises(RemoteApprovalDenied, match="exact action"):
            verifier.verify(proof, changed)
    verifier.verify(proof, target)


def test_expired_forged_and_stopped_receipts_never_execute(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    foreign = Ed25519PrivateKey.generate()
    target = action()
    proof = issue_testable_receipt(key, target, issued_at=2_000_000_000, ttl_seconds=10)
    clock = [2_000_000_011.0]
    stopped = threading.Event()
    verifier = RemoteApprovalVerifier(
        key.public_key(),
        SQLiteConsumptionStore(tmp_path / "spent.sqlite"),
        stopped=stopped.is_set,
        clock=lambda: clock[0],
    )
    with pytest.raises(RemoteApprovalDenied, match="Expired"):
        verifier.verify(proof, target)
    clock[0] = 2_000_000_000
    with pytest.raises(RemoteApprovalDenied, match="signature"):
        verifier.verify(issue_testable_receipt(foreign, target, issued_at=int(clock[0])), target)
    stopped.set()
    with pytest.raises(RemoteApprovalDenied, match="stopped"):
        verifier.verify(proof, target)


def test_approval_has_no_editable_authority_and_malformed_proofs_fail(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    target = action()
    verifier = RemoteApprovalVerifier(
        key.public_key(),
        SQLiteConsumptionStore(tmp_path / "spent.sqlite"),
        stopped=lambda: False,
        clock=lambda: 2_000_000_000.0,
    )
    proof = issue_testable_receipt(key, target, issued_at=2_000_000_000)
    encoded, signature = proof.split(".")
    payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    payload["target"] = "window:999"
    forged = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).rstrip(b"=").decode("ascii")
    for candidate in ["", "bad", "!!!." + signature, forged + "." + signature, "x" * 5000]:
        with pytest.raises(RemoteApprovalDenied):
            verifier.verify(candidate, target)
    with pytest.raises(RemoteApprovalDenied):
        ScopedAction(target.caller, "window:0", target.capability, target.action_sha256)
    with pytest.raises(RemoteApprovalDenied):
        action_fingerprint("window.click", {"text": "x" * 5000})
