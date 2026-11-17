"""Signed outbound read actions obey durable owner and device STOP decisions."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from local_gpt_mcp.agent.identity import DeviceIdentity, sign_request
from local_gpt_mcp.gateway.agent_relay import AgentRelay
from local_gpt_mcp.gateway.registry import DeviceDirectory, DeviceUnavailable, ReadRequest
from local_gpt_mcp.policy.stop_ledger import SQLiteStopLedger, StopDenied


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def ledger(tmp_path: Path) -> SQLiteStopLedger:
    folder = tmp_path / "private"
    folder.mkdir(mode=0o700)
    return SQLiteStopLedger(folder / "stop.sqlite")


def enrolled(guard: SQLiteStopLedger) -> tuple[AgentRelay, DeviceIdentity]:
    relay = AgentRelay(stops=guard)
    relay.bind(DeviceDirectory(relay))
    code, device_id = relay.issue_code("alice", "Local PC")
    identity = DeviceIdentity.generate(device_id)
    relay.enroll(code, device_id, identity.public_key)
    signed = sign_request(identity.private_key, device_id, "/api/agent/poll", b"{}")
    assert relay.authenticate(device_id, "/api/agent/poll", b"{}", signed) == "alice"
    return relay, identity


@pytest.mark.anyio
async def test_revoked_device_cannot_reconnect_poll_or_read(tmp_path: Path) -> None:
    guard = ledger(tmp_path)
    relay, identity = enrolled(guard)
    device_id = identity.device_id
    assert relay.connected("alice", device_id)
    SQLiteStopLedger(guard._path).revoke_device("alice", device_id)
    assert not relay.connected("alice", device_id)
    with pytest.raises(StopDenied):
        relay.authenticate(
            device_id,
            "/api/agent/poll",
            b"{}",
            sign_request(identity.private_key, device_id, "/api/agent/poll", b"{}"),
        )
    with pytest.raises(StopDenied):
        relay.poll("alice", device_id)
    with pytest.raises(StopDenied):
        await relay.read("alice", device_id, ReadRequest("desktop_window_info", "window:41"))
    assert relay.issue_code("bob", "Other PC")[1].startswith("pc-")


@pytest.mark.anyio
async def test_owner_halt_cancels_queued_read_and_blocks_reenrollment(tmp_path: Path) -> None:
    guard = ledger(tmp_path)
    relay, identity = enrolled(guard)
    pending = asyncio.create_task(
        relay.read("alice", identity.device_id, ReadRequest("desktop_window_info", "window:41"))
    )
    await asyncio.sleep(0)
    relay.halt_owner("alice")
    with pytest.raises(DeviceUnavailable):
        await pending
    assert not relay.connected("alice", identity.device_id)
    with pytest.raises(StopDenied):
        relay.issue_code("alice", "New PC")
    with pytest.raises(StopDenied):
        SQLiteStopLedger(guard._path).require_allowed("alice")
    with pytest.raises(StopDenied):
        relay.reply("alice", identity.device_id, "missing", {"ok": True})


def test_halt_not_reported_success_without_durable_storage() -> None:
    with pytest.raises(StopDenied):
        AgentRelay().halt_owner("alice")
