"""Only a trusted owner's device public-key enrollment survives a gateway restart."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from local_gpt_mcp.agent.identity import DeviceAuthenticationError, DeviceIdentity, sign_request
from local_gpt_mcp.gateway.agent_relay import AgentRelay
from local_gpt_mcp.gateway.registry import DeviceDirectory
from local_gpt_mcp.policy.stop_ledger import SQLiteStopLedger, StopDenied


def private_db(tmp_path: Path) -> Path:
    folder = tmp_path / "private"
    folder.mkdir(mode=0o700)
    return folder / "stop.sqlite"


def fresh_relay(path: Path) -> tuple[AgentRelay, DeviceDirectory]:
    relay = AgentRelay(stops=SQLiteStopLedger(path))
    directory = DeviceDirectory(relay)
    relay.bind(directory)
    return relay, directory


def pair(relay: AgentRelay, owner: str, label: str) -> DeviceIdentity:
    code, device_id = relay.issue_code(owner, label)
    identity = DeviceIdentity.generate(device_id)
    relay.enroll(code, device_id, identity.public_key)
    return identity


def heartbeat(relay: AgentRelay, identity: DeviceIdentity) -> str:
    payload = b"{}"
    path = "/api/agent/poll"
    signed = sign_request(identity.private_key, identity.device_id, path, payload)
    return relay.authenticate(identity.device_id, path, payload, {k.lower(): v for k, v in signed.items()})


def test_restart_restores_offline_device_and_requires_fresh_signed_poll(tmp_path: Path) -> None:
    path = private_db(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            SQLiteStopLedger.provision(path)
        return
    store = SQLiteStopLedger.provision(path)
    first, directory = fresh_relay(path)
    alice = pair(first, "alice", "Office PC")
    assert heartbeat(first, alice) == "alice"
    assert directory.status("alice", alice.device_id)["online"]
    restarted, restored = fresh_relay(path)
    assert restored.list_owned("alice") == [
        {"device_id": alice.device_id, "label": "Office PC", "online": False}
    ]
    assert not restarted.connected("alice", alice.device_id)
    with pytest.raises(DeviceAuthenticationError):
        heartbeat(restarted, DeviceIdentity.generate(alice.device_id))
    assert not restored.status("alice", alice.device_id)["online"]
    assert heartbeat(restarted, alice) == "alice"
    assert restored.status("alice", alice.device_id)["online"]
    assert store.list_trusted_devices()[0][:3] == ("alice", alice.device_id, "Office PC")


def test_restart_cannot_resurrect_revoked_or_stopped_devices(tmp_path: Path) -> None:
    path = private_db(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied):
            SQLiteStopLedger.provision(path)
        return
    store = SQLiteStopLedger.provision(path)
    first, _directory = fresh_relay(path)
    alice = pair(first, "alice", "Stopped PC")
    bob = pair(first, "bob", "Revoked PC")
    carol = pair(first, "carol", "Allowed PC")
    store.halt_owner("alice")
    store.revoke_device("bob", bob.device_id)
    restarted, restored = fresh_relay(path)
    assert restored.list_owned("alice") == []
    assert restored.list_owned("bob") == []
    assert restored.list_owned("carol") == [
        {"device_id": carol.device_id, "label": "Allowed PC", "online": False}
    ]
    with pytest.raises(DeviceAuthenticationError):
        heartbeat(restarted, alice)
    with pytest.raises(DeviceAuthenticationError):
        heartbeat(restarted, bob)
    assert heartbeat(restarted, carol) == "carol"


def test_duplicate_ids_foreign_owner_and_bad_public_keys_are_denied(tmp_path: Path) -> None:
    path = private_db(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied):
            SQLiteStopLedger.provision(path)
        return
    store = SQLiteStopLedger.provision(path)
    owner, _directory = fresh_relay(path)
    alice = pair(owner, "alice", "PC")
    with pytest.raises(StopDenied):
        store.register_trusted_device("bob", alice.device_id, "Stolen PC", alice.public_key)
    with pytest.raises(StopDenied):
        store.register_trusted_device("alice", "pc-other", "Bad PC", "not-a-key")
    with pytest.raises(StopDenied):
        store.register_trusted_device("alice", "pc-other", "", alice.public_key)
    store.revoke_device("alice", alice.device_id)
    with pytest.raises(StopDenied):
        store.register_trusted_device("alice", alice.device_id, "Reissued PC", alice.public_key)
    restored, directory = fresh_relay(path)
    assert directory.list_owned("alice") == []
    with pytest.raises(DeviceAuthenticationError):
        heartbeat(restored, alice)


def test_explicit_upgrade_preserves_stop_and_replay_history(tmp_path: Path) -> None:
    path = private_db(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied):
            SQLiteStopLedger.provision(path)
        return
    ledger = SQLiteStopLedger.provision(path)
    ledger.halt_owner("alice")
    ledger.revoke_device("bob", "pc-revoked")
    assert ledger.consume_device_nonce("pc-allowed", "a" * 32, now=1000, expires_at=1045)
    # Simulate the v1 schema shipped before durable public-key enrollment.
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE trusted_devices")
        db.execute("PRAGMA user_version = 1")
    with pytest.raises(StopDenied, match="upgrade"):
        SQLiteStopLedger(path)
    migrated = SQLiteStopLedger.upgrade_device_store(path)
    with pytest.raises(StopDenied):
        migrated.require_allowed("alice")
    with pytest.raises(StopDenied):
        migrated.require_allowed("bob", "pc-revoked")
    assert not migrated.consume_device_nonce("pc-allowed", "a" * 32, now=1000, expires_at=1045)
    with pytest.raises(StopDenied):
        SQLiteStopLedger.upgrade_device_store(path)
    assert migrated.list_trusted_devices() == []


def test_corrupt_enrollment_record_and_missing_file_fail_startup(tmp_path: Path) -> None:
    path = private_db(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied):
            SQLiteStopLedger.provision(path)
        return
    SQLiteStopLedger.provision(path)
    first, _directory = fresh_relay(path)
    device = pair(first, "alice", "PC")
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE trusted_devices SET public_key = ? WHERE device_id = ?", ("tampered", device.device_id)
        )
    with pytest.raises(StopDenied):
        fresh_relay(path)
    path.unlink()
    with pytest.raises(StopDenied):
        fresh_relay(path)


def test_unconfigured_developer_mode_does_not_persist_enrollments() -> None:
    first = AgentRelay()
    first_directory = DeviceDirectory(first)
    first.bind(first_directory)
    pair(first, "alice", "Temporary PC")
    restarted = AgentRelay()
    directory = DeviceDirectory(restarted)
    restarted.bind(directory)
    assert directory.list_owned("alice") == []
