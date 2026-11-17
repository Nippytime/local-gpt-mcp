"""Durable server-side passkey keys and replay counters persist across restarts."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from local_gpt_mcp.policy import Caller, Capability
from local_gpt_mcp.policy.credential_store import CredentialStoreDenied, SQLiteCredentialStore
from local_gpt_mcp.policy.owner_presence import OwnerPresence
from local_gpt_mcp.policy.passkey_store import SQLitePasskeys
from local_gpt_mcp.policy.remote_receipts import RemoteApprovalDenied, ScopedAction, action_fingerprint

CREDENTIAL_ID = "credential-alice-0001"


def _provision(tmp_path: Path) -> Path:
    private = tmp_path / "operator"
    private.mkdir(mode=0o700)
    path = private / "passkeys.sqlite"
    SQLiteCredentialStore.provision(path)
    return path


def _windows_denies(tmp_path: Path) -> bool:
    if os.name != "nt":
        return False
    with pytest.raises(CredentialStoreDenied, match="POSIX"):
        SQLiteCredentialStore.provision(tmp_path / "passkeys.sqlite")
    return True


def _action() -> ScopedAction:
    return ScopedAction(
        Caller("alice", "pc-alice", "session-1"),
        "window:41",
        Capability.WINDOW_INPUT,
        action_fingerprint("window.click", {"x": 15, "y": 24}),
        "a" * 32,
    )


def test_trusted_credential_survives_restart_and_is_owner_isolated(tmp_path: Path) -> None:
    if _windows_denies(tmp_path):
        return
    db_path = _provision(tmp_path)
    key = ec.generate_private_key(ec.SECP256R1())
    first = SQLitePasskeys(db_path)
    first.register_trusted("alice", CREDENTIAL_ID, key.public_key())
    with pytest.raises(RemoteApprovalDenied, match="unavailable"):
        first.register_trusted("bob", CREDENTIAL_ID, key.public_key())
    restart = SQLitePasskeys(db_path)
    stored = restart.get(CREDENTIAL_ID)
    assert stored is not None
    assert stored.owner == "alice"
    assert stored.sign_count == 0
    assert stored.key.public_numbers() == key.public_key().public_numbers()
    assert restart.list_owned("alice") == [CREDENTIAL_ID]
    assert restart.list_owned("bob") == []
    with pytest.raises(RemoteApprovalDenied, match="unavailable"):
        restart.advance("bob", CREDENTIAL_ID, 1)
    if os.name != "nt":
        assert db_path.stat().st_mode & 0o077 == 0


def test_atomic_counter_replay_and_downgrade_after_restart(tmp_path: Path) -> None:
    if _windows_denies(tmp_path):
        return
    path = _provision(tmp_path)
    key = ec.generate_private_key(ec.SECP256R1())
    store = SQLitePasskeys(path)
    store.register_trusted("alice", CREDENTIAL_ID, key.public_key())
    store.advance("alice", CREDENTIAL_ID, 10)
    restarted = SQLitePasskeys(path)
    for count in (10, 9, 0):
        with pytest.raises(RemoteApprovalDenied, match="unavailable"):
            restarted.advance("alice", CREDENTIAL_ID, count)
    restarted.advance("alice", CREDENTIAL_ID, 11)
    stored = store.get(CREDENTIAL_ID)
    assert stored is not None
    assert stored.sign_count == 11


def test_owner_presence_uses_durable_passkey_and_revocation(tmp_path: Path) -> None:
    if _windows_denies(tmp_path):
        return
    path = _provision(tmp_path)
    key = ec.generate_private_key(ec.SECP256R1())
    issuer = ed25519.Ed25519PrivateKey.generate()
    store = SQLitePasskeys(path)
    store.register_trusted("alice", CREDENTIAL_ID, key.public_key())
    presence = OwnerPresence(
        origin="https://approval.example.com",
        receipt_signer=issuer,
        stopped=lambda: False,
        credential_store=SQLitePasskeys(path),
    )
    challenge = presence.begin("alice", CREDENTIAL_ID, _action())
    assert challenge.challenge
    with pytest.raises(RemoteApprovalDenied):
        presence.begin("bob", CREDENTIAL_ID, _action())
    store.revoke_trusted("alice", CREDENTIAL_ID)
    assert store.list_owned("alice") == []
    with pytest.raises(RemoteApprovalDenied):
        presence.begin("alice", CREDENTIAL_ID, _action())
    # An outstanding challenge must also be invalid after key revocation.
    with pytest.raises(RemoteApprovalDenied):
        presence.finish(
            "alice",
            CREDENTIAL_ID,
            challenge.challenge,
            client_data=b"{}",
            authenticator_data=b"0" * 37,
            signature=b"x",
        )


def test_symlink_and_relative_passkey_database_paths_rejected(tmp_path: Path) -> None:
    if _windows_denies(tmp_path):
        return
    with pytest.raises(RemoteApprovalDenied):
        SQLitePasskeys(Path("relative.sqlite"))
    target = _provision(tmp_path)
    linked = target.parent / "shortcut.sqlite"
    linked.symlink_to(target)
    with pytest.raises(RemoteApprovalDenied):
        SQLitePasskeys(linked)


def test_database_contains_no_signing_private_keys(tmp_path: Path) -> None:
    if _windows_denies(tmp_path):
        return
    path = _provision(tmp_path)
    key = ec.generate_private_key(ec.SECP256R1())
    SQLitePasskeys(path).register_trusted("alice", CREDENTIAL_ID, key.public_key())
    with sqlite3.connect(path) as db:
        columns = {entry[1] for entry in db.execute("PRAGMA table_info(passkeys)")}
        row = db.execute("SELECT owner, length(public_key), sign_count FROM passkeys").fetchone()
    assert columns == {"credential_id", "owner", "public_key", "sign_count"}
    assert row == ("alice", 65, 0)


def test_explicit_provisioning_and_permanent_revocation_fail_closed(tmp_path: Path) -> None:
    if _windows_denies(tmp_path):
        return
    private = tmp_path / "operator"
    private.mkdir(mode=0o700)
    path = private / "passkeys.sqlite"
    with pytest.raises(RemoteApprovalDenied, match="unavailable"):
        SQLitePasskeys(path)
    SQLiteCredentialStore.provision(path)
    key = ec.generate_private_key(ec.SECP256R1())
    store = SQLitePasskeys(path)
    store.register_trusted("alice", CREDENTIAL_ID, key.public_key())
    store.revoke_trusted("alice", CREDENTIAL_ID)
    with pytest.raises(RemoteApprovalDenied, match="unavailable"):
        SQLitePasskeys(path).register_trusted("alice", CREDENTIAL_ID, key.public_key())
    with pytest.raises(RemoteApprovalDenied, match="unavailable"):
        SQLitePasskeys(path).register_trusted("bob", CREDENTIAL_ID, key.public_key())
    path.unlink()
    with pytest.raises(RemoteApprovalDenied, match="unavailable"):
        SQLitePasskeys(path)
