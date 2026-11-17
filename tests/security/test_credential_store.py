"""Secure owner credential store with real WebAuthn creation and cross-process counters."""

from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from local_gpt_mcp.policy.credential_store import CredentialStoreDenied, SQLiteCredentialStore
from local_gpt_mcp.policy.registration import OperatorAuthorizedRegistration
from tests.security.test_registration import ORIGIN, fixture

CREDENTIAL_ID = "registered-credential-00000000000001"


def path_for(tmp_path: Path) -> Path:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    return private / "owner.sqlite"


def test_verified_webauthn_creation_persists_public_p256_key(tmp_path: Path) -> None:
    path = path_for(tmp_path)
    if os.name == "nt":
        with pytest.raises(CredentialStoreDenied, match="POSIX"):
            SQLiteCredentialStore.provision(path)
        return
    store = SQLiteCredentialStore.provision(path)
    registrar = OperatorAuthorizedRegistration(
        origin=ORIGIN, store=store, operator_authorized=lambda owner: owner == "alice"
    )
    start = registrar.begin("alice")
    private = ec.generate_private_key(ec.SECP256R1())
    credential_id = registrar.finish("alice", start.challenge, fixture(start, private))
    restarted = SQLiteCredentialStore(path)
    record = restarted.get(credential_id)
    assert record is not None
    assert record.owner == "alice"
    assert record.sign_count == 0
    assert record.key.public_numbers() == private.public_key().public_numbers()
    assert restarted.list_owned("alice") == [credential_id]
    assert restarted.list_owned("bob") == []
    with pytest.raises(CredentialStoreDenied, match="already registered"):
        restarted.register_trusted("bob", credential_id, private.public_key())


def test_atomic_counter_denies_cross_worker_replay_and_revocation(tmp_path: Path) -> None:
    path = path_for(tmp_path)
    if os.name == "nt":
        with pytest.raises(CredentialStoreDenied):
            SQLiteCredentialStore.provision(path)
        return
    first = SQLiteCredentialStore.provision(path)
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    first.register_trusted("alice", CREDENTIAL_ID, key)

    def advance(_: int) -> bool:
        try:
            SQLiteCredentialStore(path).advance("alice", CREDENTIAL_ID, 1)
        except CredentialStoreDenied:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(advance, range(8)))
    assert results.count(True) == 1
    assert results.count(False) == 7
    with pytest.raises(CredentialStoreDenied):
        first.advance("bob", CREDENTIAL_ID, 2)
    SQLiteCredentialStore(path).advance("alice", CREDENTIAL_ID, 2)
    assert first.get(CREDENTIAL_ID).sign_count == 2  # type: ignore[union-attr]
    first.revoke_trusted("alice", CREDENTIAL_ID)
    assert SQLiteCredentialStore(path).get(CREDENTIAL_ID) is None
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore(path).register_trusted("alice", CREDENTIAL_ID, key)
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore(path).register_trusted("bob", CREDENTIAL_ID, key)
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore(path).advance("alice", CREDENTIAL_ID, 3)


def test_untrusted_paths_missing_file_and_corrupt_schema_fail_closed(tmp_path: Path) -> None:
    path = path_for(tmp_path)
    if os.name == "nt":
        with pytest.raises(CredentialStoreDenied):
            SQLiteCredentialStore.provision(path)
        return
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore(path)
    store = SQLiteCredentialStore.provision(path)
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore.provision(path)
    os.chmod(path, 0o644)
    with pytest.raises(CredentialStoreDenied):
        store.list_owned("alice")
    os.chmod(path, 0o600)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE revoked_ids")
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore(path)
    path.unlink()
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore(path)
    with pytest.raises(CredentialStoreDenied):
        store.get(CREDENTIAL_ID)


def test_reject_symlink_hardlink_and_insecure_parent(tmp_path: Path) -> None:
    path = path_for(tmp_path)
    if os.name == "nt":
        with pytest.raises(CredentialStoreDenied):
            SQLiteCredentialStore.provision(path)
        return
    SQLiteCredentialStore.provision(path)
    linked = path.parent / "linked.sqlite"
    linked.symlink_to(path)
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore(linked)
    hardlink = path.parent / "hardlink.sqlite"
    os.link(path, hardlink)
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore(hardlink)
    hardlink.unlink()
    os.chmod(path.parent, 0o755)
    with pytest.raises(CredentialStoreDenied):
        SQLiteCredentialStore(path)


def test_invalid_owner_key_and_counters_denied(tmp_path: Path) -> None:
    path = path_for(tmp_path)
    if os.name == "nt":
        with pytest.raises(CredentialStoreDenied):
            SQLiteCredentialStore.provision(path)
        return
    store = SQLiteCredentialStore.provision(path)
    good_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(CredentialStoreDenied):
        store.register_trusted("other owner", CREDENTIAL_ID, good_key)
    with pytest.raises(CredentialStoreDenied):
        store.register_trusted("alice", "tiny", good_key)
    with pytest.raises(CredentialStoreDenied):
        store.register_trusted("alice", CREDENTIAL_ID, ec.generate_private_key(ec.SECP384R1()).public_key())
    store.register_trusted("alice", CREDENTIAL_ID, good_key)
    for value in (True, -1, 0x1_0000_0000):
        with pytest.raises(CredentialStoreDenied):
            store.advance("alice", CREDENTIAL_ID, value)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE passkeys SET public_key = ? WHERE credential_id = ?", (b"corrupt", CREDENTIAL_ID))
    with pytest.raises(CredentialStoreDenied):
        store.get(CREDENTIAL_ID)
