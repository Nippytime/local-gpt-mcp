"""Remote signed approval alone never bypasses local pairing or STOP."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from local_gpt_mcp.agent.remote_actions import AuthorizedActionRunner
from local_gpt_mcp.gateway.registry import DeviceUnavailable
from local_gpt_mcp.policy.authority import (
    Caller,
    Capability,
    GrantRequest,
    PairingRequest,
    PolicyAuthority,
)
from local_gpt_mcp.policy.remote_receipts import (
    RemoteApprovalVerifier,
    ScopedAction,
    SQLiteConsumptionStore,
    action_fingerprint,
    issue_testable_receipt,
)


class LocalPairing:
    def approve_pairing(self, request: PairingRequest) -> bool:
        return True

    def approve_grant(self, request: GrantRequest) -> bool:
        return False


class FakeNative:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def execute(self, target: str, operation: str, parameters: Mapping[str, int]) -> dict[str, bool]:
        self.calls.append((target, operation))
        return {"ok": True}


def fixture(tmp_path: Path) -> tuple[AuthorizedActionRunner, PolicyAuthority, Ed25519PrivateKey, FakeNative]:
    def clock() -> float:
        return 2_000_000_000.0

    issuer = Ed25519PrivateKey.generate()
    policy = PolicyAuthority(LocalPairing())
    local = FakeNative()
    verifier = RemoteApprovalVerifier(
        issuer.public_key(),
        SQLiteConsumptionStore(tmp_path / "spent.sqlite"),
        stopped=lambda: policy.stopped,
        clock=clock,
    )
    return AuthorizedActionRunner("pc-a", verifier, policy, executor=local), policy, issuer, local


def delivery(issuer: Ed25519PrivateKey, *, job_id: str = "a" * 32) -> dict[str, object]:
    action = ScopedAction(
        Caller("alice", "pc-a", "session-1"),
        "window:41",
        Capability.WINDOW_INPUT,
        action_fingerprint("window.click", {"x": 18, "y": 35}),
        job_id,
    )
    return {
        "job_id": action.job_id,
        "user_id": action.caller.user_id,
        "device_id": action.caller.device_id,
        "session_id": action.caller.session_id,
        "target": action.target,
        "capability": action.capability.value,
        "operation": "window.click",
        "parameters": {"x": 18, "y": 35},
        "action_sha256": action.action_sha256,
        "receipt": issue_testable_receipt(issuer, action, issued_at=2_000_000_000),
    }


@pytest.mark.anyio
async def test_real_receipt_requires_pairing_then_consumes_once(tmp_path: Path) -> None:
    runner, policy, issuer, local = fixture(tmp_path)
    first = delivery(issuer)
    with pytest.raises(DeviceUnavailable):
        await runner.execute(first)
    assert local.calls == []
    policy.pair(PairingRequest("alice", "pc-a"))
    # The denied receipt was consumed; an owner must approve a new job.
    with pytest.raises(DeviceUnavailable):
        await runner.execute(first)
    second = delivery(issuer, job_id="b" * 32)
    assert await runner.execute(second) == {"ok": True}
    assert local.calls == [("window:41", "window.click")]
    with pytest.raises(DeviceUnavailable):
        await runner.execute(second)
    assert len(local.calls) == 1


@pytest.mark.anyio
async def test_mismatched_device_parameters_and_stopped_pc_deny(tmp_path: Path) -> None:
    runner, policy, issuer, local = fixture(tmp_path)
    policy.pair(PairingRequest("alice", "pc-a"))
    body = delivery(issuer)
    for mutation in (
        {"device_id": "pc-other"},
        {"parameters": {"x": 19, "y": 35}},
        {"operation": "window.type"},
        {"parameters": {"x": True, "y": 35}},
    ):
        with pytest.raises(DeviceUnavailable):
            await runner.execute({**body, **mutation})
    assert local.calls == []
    policy.emergency_stop()
    with pytest.raises(DeviceUnavailable):
        await runner.execute(body)
    assert local.calls == []


@pytest.mark.anyio
async def test_default_native_executor_is_disabled(tmp_path: Path) -> None:
    runner, policy, issuer, _local = fixture(tmp_path)
    policy.pair(PairingRequest("alice", "pc-a"))
    disabled = AuthorizedActionRunner("pc-a", runner.verifier, policy)
    with pytest.raises(DeviceUnavailable):
        await disabled.execute(delivery(issuer))
