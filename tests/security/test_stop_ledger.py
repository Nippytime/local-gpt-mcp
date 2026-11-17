"""Private owner STOP decisions survive restarts and deny unsafe gateway storage."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from local_gpt_mcp.policy.stop_ledger import SQLiteStopLedger, StopDenied


def private_db(tmp_path: Path) -> Path:
    folder = tmp_path / "private"
    folder.mkdir(mode=0o700)
    return folder / "stop.sqlite"


def test_persistent_tenant_scoped_revocation_and_irreversible_halt(tmp_path: Path) -> None:
    path = private_db(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            SQLiteStopLedger.provision(path)
        return
    first = SQLiteStopLedger.provision(path)
    second = SQLiteStopLedger(path)
    with pytest.raises(StopDenied):
        SQLiteStopLedger.provision(path)
    first.require_allowed("alice", "pc-one")
    first.require_allowed("bob", "pc-one")
    first.revoke_device("alice", "pc-one")
    with pytest.raises(StopDenied):
        second.require_allowed("alice", "pc-one")
    second.require_allowed("alice", "pc-two")
    second.require_allowed("bob", "pc-one")
    second.halt_owner("alice")
    second.halt_owner("alice")  # durable, idempotent; no unhalt API
    with pytest.raises(StopDenied):
        SQLiteStopLedger(path).require_allowed("alice")
    with pytest.raises(StopDenied):
        first.require_allowed("alice", "pc-two")
    first.require_allowed("bob", "pc-one")


@pytest.mark.parametrize("owner,device", [("", None), ("alice", ""), ("alice", "pc with space")])
def test_invalid_stop_identity_is_denied(tmp_path: Path, owner: str, device: str | None) -> None:
    path = private_db(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            SQLiteStopLedger.provision(path)
        return
    ledger = SQLiteStopLedger.provision(path)
    with pytest.raises(StopDenied):
        ledger.require_allowed(owner, device)


def test_missing_corrupt_or_repermissioned_store_fails_closed(tmp_path: Path) -> None:
    path = private_db(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            SQLiteStopLedger.provision(path)
        return
    ledger = SQLiteStopLedger.provision(path)
    os.chmod(path, 0o644)
    with pytest.raises(StopDenied):
        ledger.require_allowed("alice", "pc-one")
    os.chmod(path, 0o600)
    path.unlink()
    with pytest.raises(StopDenied):
        ledger.require_allowed("alice", "pc-one")
    with pytest.raises(StopDenied):
        SQLiteStopLedger(path)  # restart cannot silently recreate an erased STOP decision
    path.write_bytes(b"not-a-sqlite-database")
    os.chmod(path, 0o600)
    with pytest.raises(StopDenied):
        ledger.require_allowed("alice", "pc-one")


def test_reject_world_accessible_directory_and_linked_database(tmp_path: Path) -> None:
    path = private_db(tmp_path)
    if os.name == "nt":
        with pytest.raises(StopDenied, match="POSIX"):
            SQLiteStopLedger.provision(path)
        return
    os.chmod(path.parent, 0o755)
    with pytest.raises(StopDenied):
        SQLiteStopLedger(path)
    os.chmod(path.parent, 0o700)
    target = tmp_path / "outside"
    target.write_bytes(b"fake")
    path.symlink_to(target)
    with pytest.raises(StopDenied):
        SQLiteStopLedger(path)
