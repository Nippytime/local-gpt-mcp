"""Operator-only bootstrap: verified WebAuthn creation and one-use durable codes."""

from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from local_gpt_mcp.policy.bootstrap import (
    BootstrapDenied,
    SQLiteBootstrapPermits,
    first_owner_registration,
    main,
)
from local_gpt_mcp.policy.credential_store import SQLiteCredentialStore
from local_gpt_mcp.policy.registration import RegistrationDenied
from security.test_registration import ORIGIN, fixture


def private_paths(tmp_path: Path) -> tuple[Path, Path]:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    return private / "permits.sqlite", private / "credentials.sqlite"


def test_real_first_passkey_creation_consumes_operator_code(tmp_path: Path) -> None:
    permit_path, credential_path = private_paths(tmp_path)
    if os.name == "nt":
        with pytest.raises(BootstrapDenied, match="POSIX"):
            SQLiteBootstrapPermits.provision(permit_path)
        return
    permits = SQLiteBootstrapPermits.provision(permit_path)
    credentials = SQLiteCredentialStore.provision(credential_path)
    code = permits.issue_local("alice")
    registrar = first_owner_registration(
        owner="alice", code=code, origin=ORIGIN, permits=permits, credentials=credentials
    )
    start = registrar.begin("alice")
    private = ec.generate_private_key(ec.SECP256R1())
    credential = fixture(start, private)
    cid = registrar.finish("alice", start.challenge, credential)
    saved = SQLiteCredentialStore(credential_path).get(cid)
    assert saved is not None
    assert saved.owner == "alice"
    assert saved.key.public_numbers() == private.public_key().public_numbers()
    assert not SQLiteBootstrapPermits(permit_path).authorized("alice", code)
    with pytest.raises(RegistrationDenied):
        registrar.finish("alice", start.challenge, credential)
    with pytest.raises(RegistrationDenied):
        first_owner_registration(
            owner="alice", code=code, origin=ORIGIN, permits=permits, credentials=credentials
        )


def test_owner_mismatch_expired_replaced_and_revoked_permits(tmp_path: Path) -> None:
    permit_path, credentials_path = private_paths(tmp_path)
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            SQLiteBootstrapPermits.provision(permit_path)
        return
    now = [1_000.0]
    SQLiteBootstrapPermits.provision(permit_path)
    permits = SQLiteBootstrapPermits(permit_path, clock=lambda: now[0])
    credentials = SQLiteCredentialStore.provision(credentials_path)
    first = permits.issue_local("alice")
    assert not permits.authorized("bob", first)
    assert not permits.authorized("alice", "a" * 43)
    with pytest.raises(RegistrationDenied):
        first_owner_registration(
            owner="bob", code=first, origin=ORIGIN, permits=permits, credentials=credentials
        )
    second = permits.issue_local("alice")
    assert not permits.authorized("alice", first)
    assert permits.authorized("alice", second)
    permits.revoke_local("alice")
    assert not permits.authorized("alice", second)
    expiring = permits.issue_local("alice")
    now[0] += 180
    assert not permits.authorized("alice", expiring)
    with pytest.raises(BootstrapDenied):
        permits.consume("alice", expiring)


def test_concurrent_workers_only_one_consumes_permit(tmp_path: Path) -> None:
    path, _ = private_paths(tmp_path)
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            SQLiteBootstrapPermits.provision(path)
        return
    permits = SQLiteBootstrapPermits.provision(path)
    code = permits.issue_local("alice")

    def consume(_: int) -> bool:
        try:
            SQLiteBootstrapPermits(path).consume("alice", code)
        except BootstrapDenied:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(consume, range(8)))
    assert results.count(True) == 1
    assert results.count(False) == 7
    assert not permits.authorized("alice", code)


def test_failed_registration_burns_permit_and_disallows_second_passkey(tmp_path: Path) -> None:
    permit_path, credential_path = private_paths(tmp_path)
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            SQLiteBootstrapPermits.provision(permit_path)
        return
    permits = SQLiteBootstrapPermits.provision(permit_path)
    credentials = SQLiteCredentialStore.provision(credential_path)
    code = permits.issue_local("alice")
    registrar = first_owner_registration(
        owner="alice", code=code, origin=ORIGIN, permits=permits, credentials=credentials
    )
    begin = registrar.begin("alice")
    key = ec.generate_private_key(ec.SECP256R1())
    bad = fixture(begin, key, origin="https://attacker.example.com")
    with pytest.raises(RegistrationDenied):
        registrar.finish("alice", begin.challenge, bad)
    assert permits.authorized("alice", code)  # rejected attestation was never stored
    start = registrar.begin("alice")
    cid = registrar.finish("alice", start.challenge, fixture(start, key))
    assert credentials.get(cid) is not None
    newer = permits.issue_local("alice")
    with pytest.raises(RegistrationDenied):
        first_owner_registration(
            owner="alice", code=newer, origin=ORIGIN, permits=permits, credentials=credentials
        ).begin("alice")


def test_missing_corrupt_and_unsafe_storage_denies_without_reprovision(tmp_path: Path) -> None:
    path, _ = private_paths(tmp_path)
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            SQLiteBootstrapPermits.provision(path)
        return
    with pytest.raises(BootstrapDenied):
        SQLiteBootstrapPermits(path)
    SQLiteBootstrapPermits.provision(path)
    with pytest.raises(BootstrapDenied):
        SQLiteBootstrapPermits.provision(path)
    linked = path.parent / "linked.sqlite"
    linked.symlink_to(path)
    with pytest.raises(BootstrapDenied):
        SQLiteBootstrapPermits(linked)
    hard = path.parent / "hard.sqlite"
    os.link(path, hard)
    with pytest.raises(BootstrapDenied):
        SQLiteBootstrapPermits(hard)
    hard.unlink()
    os.chmod(path, 0o644)
    with pytest.raises(BootstrapDenied):
        SQLiteBootstrapPermits(path)
    os.chmod(path, 0o600)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE permits")
    with pytest.raises(BootstrapDenied):
        SQLiteBootstrapPermits(path)
    path.unlink()
    with pytest.raises(BootstrapDenied):
        SQLiteBootstrapPermits(path)


def test_terminal_command_issues_one_code_without_storing_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, _ = private_paths(tmp_path)
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            main(["provision", str(path)])
        return
    assert main(["provision", str(path)]) == 0
    assert main(["issue", str(path), "alice"]) == 0
    code = capsys.readouterr().out.strip()
    assert len(code) == 43
    assert SQLiteBootstrapPermits(path).authorized("alice", code)
    assert code.encode() not in path.read_bytes()
    assert main(["revoke", str(path), "alice"]) == 0
    assert not SQLiteBootstrapPermits(path).authorized("alice", code)
