"""A validated signed agent nonce may only be consumed once per protected host."""

from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from local_gpt_mcp.agent.identity import (
    DeviceAuthenticationError,
    DeviceIdentity,
    DeviceReplayGuard,
    sign_request,
)
from local_gpt_mcp.policy.stop_ledger import SQLiteStopLedger, StopDenied


def _path(tmp_path: Path) -> Path:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    return private / "stop.sqlite"


def _headers(identity: DeviceIdentity, *, timestamp: int) -> dict[str, str]:
    return {
        key.lower(): value
        for key, value in sign_request(
            identity.private_key, identity.device_id, "/api/agent/poll", b"{}", timestamp=timestamp
        ).items()
    }


def test_valid_signature_consumed_once_across_independent_guards(tmp_path: Path) -> None:
    path = _path(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            SQLiteStopLedger.provision(path)
        return
    first = SQLiteStopLedger.provision(path)
    other = SQLiteStopLedger(path)
    alice = DeviceIdentity.generate("pc-alice")
    now = 2_000_000_000
    signed = _headers(alice, timestamp=now)
    forged = dict(signed)
    forged["x-device-signature"] = "A" * 88
    one = DeviceReplayGuard(clock=lambda: now, store=first)
    two = DeviceReplayGuard(clock=lambda: now, store=other)
    with pytest.raises(DeviceAuthenticationError):
        one.verify(alice.private_key.public_key(), alice.device_id, "/api/agent/poll", b"{}", forged)
    one.verify(alice.private_key.public_key(), alice.device_id, "/api/agent/poll", b"{}", signed)
    with pytest.raises(DeviceAuthenticationError, match="Replayed"):
        two.verify(alice.private_key.public_key(), alice.device_id, "/api/agent/poll", b"{}", signed)
    with pytest.raises(DeviceAuthenticationError, match="Replayed"):
        DeviceReplayGuard(clock=lambda: now, store=SQLiteStopLedger(path)).verify(
            alice.private_key.public_key(), alice.device_id, "/api/agent/poll", b"{}", signed
        )
    fresh = _headers(alice, timestamp=now)
    two.verify(alice.private_key.public_key(), alice.device_id, "/api/agent/poll", b"{}", fresh)
    expired = DeviceReplayGuard(clock=lambda: now + 46, store=other)
    with pytest.raises(DeviceAuthenticationError, match="Expired"):
        expired.verify(alice.private_key.public_key(), alice.device_id, "/api/agent/poll", b"{}", signed)


def test_concurrent_claims_are_atomic_and_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _path(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied):
            SQLiteStopLedger.provision(path)
        return
    SQLiteStopLedger.provision(path)
    nonce = "a" * 32
    def claim(_: int) -> bool:
        return SQLiteStopLedger(path).consume_device_nonce("pc-alice", nonce, now=1000, expires_at=1001)

    with ThreadPoolExecutor(max_workers=8) as executor:
        claimed = list(executor.map(claim, range(8)))
    assert claimed.count(True) == 1
    assert claimed.count(False) == 7
    assert SQLiteStopLedger(path).consume_device_nonce("pc-bob", nonce, now=1000, expires_at=1001)

    monkeypatch.setattr("local_gpt_mcp.policy.stop_ledger.MAX_NONCES", 2)
    with pytest.raises(StopDenied, match="capacity"):
        SQLiteStopLedger(path).consume_device_nonce("pc-alice", "b" * 32, now=1000, expires_at=1001)
    assert SQLiteStopLedger(path).consume_device_nonce("pc-alice", "c" * 32, now=1002, expires_at=1045)


def test_explicit_migration_preserves_stop_and_does_not_reset_nonce_state(tmp_path: Path) -> None:
    path = _path(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied):
            SQLiteStopLedger.provision(path)
        return
    original = SQLiteStopLedger.provision(path)
    original.halt_owner("alice")
    original.revoke_device("bob", "pc-one")
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE device_nonces")
        db.execute("PRAGMA user_version = 0")
    with pytest.raises(StopDenied, match="upgrade"):
        SQLiteStopLedger(path)
    upgraded = SQLiteStopLedger.upgrade_nonce_store(path)
    with pytest.raises(StopDenied):
        upgraded.require_allowed("alice")
    with pytest.raises(StopDenied):
        upgraded.require_allowed("bob", "pc-one")
    upgraded.require_allowed("bob", "pc-two")
    with pytest.raises(StopDenied):
        SQLiteStopLedger.upgrade_nonce_store(path)
    assert upgraded.consume_device_nonce("pc-two", "d" * 32, now=1000, expires_at=1045)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE device_nonces")
    with pytest.raises(StopDenied):
        SQLiteStopLedger(path)
    with pytest.raises(StopDenied):
        SQLiteStopLedger.upgrade_nonce_store(path)


def test_corrupt_or_missing_store_never_falls_back_to_memory(tmp_path: Path) -> None:
    path = _path(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied):
            SQLiteStopLedger.provision(path)
        return
    store = SQLiteStopLedger.provision(path)
    alice = DeviceIdentity.generate("pc-alice")
    signed = _headers(alice, timestamp=1000)
    guard = DeviceReplayGuard(clock=lambda: 1000.0, store=store)
    path.unlink()
    with pytest.raises(StopDenied):
        guard.verify(alice.private_key.public_key(), alice.device_id, "/api/agent/poll", b"{}", signed)
    with pytest.raises(StopDenied):
        SQLiteStopLedger(path)


def test_unconfigured_in_memory_guard_still_denies_replay() -> None:
    alice = DeviceIdentity.generate("pc-alice")
    signed = _headers(alice, timestamp=1000)
    guard = DeviceReplayGuard(clock=lambda: 1000.0)
    guard.verify(alice.private_key.public_key(), alice.device_id, "/api/agent/poll", b"{}", signed)
    with pytest.raises(DeviceAuthenticationError, match="Replayed"):
        guard.verify(alice.private_key.public_key(), alice.device_id, "/api/agent/poll", b"{}", signed)
