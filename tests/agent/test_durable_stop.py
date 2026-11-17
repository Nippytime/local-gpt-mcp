"""Signed outbound read actions obey durable owner and device STOP decisions."""

from __future__ import annotations

import asyncio
import os
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
    return SQLiteStopLedger.provision(folder / "stop.sqlite")


def enrolled(guard: SQLiteStopLedger) -> tuple[AgentRelay, DeviceIdentity]:
    relay = AgentRelay(stops=guard)
    relay.bind(DeviceDirectory(relay))
    code, device_id = relay.issue_code("alice", "Local PC")
    identity = DeviceIdentity.generate(device_id)
    relay.enroll(code, device_id, identity.public_key)
    signed = sign_request(identity.private_key, device_id, "/api/agent/poll", b"{}")
    headers = {name.lower(): value for name, value in signed.items()}
    assert relay.authenticate(device_id, "/api/agent/poll", b"{}", headers) == "alice"
    return relay, identity


@pytest.mark.anyio
async def test_revoked_device_cannot_reconnect_poll_or_read(tmp_path: Path) -> None:
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            ledger(tmp_path)
        return
    guard = ledger(tmp_path)
    relay, identity = enrolled(guard)
    device_id = identity.device_id
    assert relay.connected("alice", device_id)
    SQLiteStopLedger(tmp_path / "private" / "stop.sqlite").revoke_device("alice", device_id)
    assert not relay.connected("alice", device_id)
    with pytest.raises(StopDenied):
        relay.authenticate(
            device_id,
            "/api/agent/poll",
            b"{}",
            {
                name.lower(): value
                for name, value in sign_request(
                    identity.private_key, device_id, "/api/agent/poll", b"{}"
                ).items()
            },
        )
    with pytest.raises(StopDenied):
        relay.poll("alice", device_id)
    with pytest.raises(StopDenied):
        await relay.read("alice", device_id, ReadRequest("desktop_window_info", "window:41"))
    assert relay.issue_code("bob", "Other PC")[1].startswith("pc-")


@pytest.mark.anyio
async def test_owner_halt_cancels_queued_read_and_blocks_reenrollment(tmp_path: Path) -> None:
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            ledger(tmp_path)
        return
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
        SQLiteStopLedger(tmp_path / "private" / "stop.sqlite").require_allowed("alice")
    with pytest.raises(StopDenied):
        relay.reply("alice", identity.device_id, "missing", {"ok": True})


def test_halt_not_reported_success_without_durable_storage() -> None:
    with pytest.raises(StopDenied):
        AgentRelay().halt_owner("alice")


@pytest.mark.anyio
@pytest.mark.parametrize("decision", ["halt", "revoke", "missing"])
async def test_remote_worker_stop_interrupts_outstanding_read(tmp_path: Path, decision: str) -> None:
    """An in-flight read fails before its normal timeout when a second worker denies it."""
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            ledger(tmp_path)
        return
    guard = ledger(tmp_path)
    relay, identity = enrolled(guard)
    pending = asyncio.create_task(
        relay.read("alice", identity.device_id, ReadRequest("desktop_window_info", "window:41"))
    )
    await asyncio.sleep(0)
    assert len(relay._jobs) == 1
    path = tmp_path / "private" / "stop.sqlite"
    if decision == "halt":
        SQLiteStopLedger(path).halt_owner("alice")
    elif decision == "revoke":
        SQLiteStopLedger(path).revoke_device("alice", identity.device_id)
    else:
        path.unlink()  # destroyed/inaccessible security state must also deny
    with pytest.raises(DeviceUnavailable, match="cancelled"):
        await asyncio.wait_for(pending, timeout=2)
    assert not relay._jobs
    assert not relay.connected("alice", identity.device_id)


@pytest.mark.anyio
async def test_live_read_still_returns_before_stop_poll_interval(tmp_path: Path) -> None:
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            ledger(tmp_path)
        return
    relay, identity = enrolled(ledger(tmp_path))
    pending = asyncio.create_task(
        relay.read("alice", identity.device_id, ReadRequest("desktop_window_info", "window:41"))
    )
    await asyncio.sleep(0)
    job = relay.poll("alice", identity.device_id)
    job_id = job["job_id"]
    assert isinstance(job_id, str)
    relay.reply("alice", identity.device_id, job_id, {"title": "Approved"})
    assert await asyncio.wait_for(pending, timeout=1) == {"title": "Approved"}
    assert not relay._jobs
