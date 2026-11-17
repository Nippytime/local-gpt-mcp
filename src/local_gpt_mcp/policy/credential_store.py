"""Private, explicitly provisioned owner passkey public-key database.

This is a single-host POSIX credential store, not an enrollment authorization API.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from local_gpt_mcp.policy.authority import AccessDenied, valid_identifier

CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9_-]{16,512}$")
MAX_CREDENTIALS = 10_000


class CredentialStoreDenied(AccessDenied):
    """Untrusted or unavailable credential storage, without leaking internal state."""


@dataclass(frozen=True, slots=True)
class StoredCredential:
    owner: str
    key: ec.EllipticCurvePublicKey
    sign_count: int


def _uid() -> int:
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        raise CredentialStoreDenied("A POSIX service owner is required")
    return int(getuid())


def _check_id(owner: str, credential_id: str) -> None:
    if (
        not valid_identifier(owner)
        or not isinstance(credential_id, str)
        or CREDENTIAL_ID.fullmatch(credential_id) is None
    ):
        raise CredentialStoreDenied("Invalid owner credential identity")


def _encode(key: ec.EllipticCurvePublicKey) -> bytes:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise CredentialStoreDenied("Only P-256 owner credentials are allowed")
    return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


class SQLiteCredentialStore:
    """Owner-isolated P-256 keys, irreversible ID revocation, atomic counters."""

    def __init__(self, path: Path) -> None:
        if os.name == "nt" or not path.is_absolute():
            raise CredentialStoreDenied("A private absolute POSIX database is required")
        self._path = path
        with self._session() as db:
            if db.execute("PRAGMA user_version").fetchone() != (1,):
                raise CredentialStoreDenied("Explicit owner credential database provisioning required")
            db.execute("SELECT credential_id, owner, public_key, sign_count FROM passkeys LIMIT 1")
            db.execute("SELECT credential_id FROM revoked_ids LIMIT 1")

    @classmethod
    def provision(cls, path: Path) -> SQLiteCredentialStore:
        """Exclusive first install only; restart never recreates missing security history."""
        if os.name == "nt" or not path.is_absolute():
            raise CredentialStoreDenied("A private absolute POSIX database is required")
        fresh = cls.__new__(cls)
        fresh._path = path
        fresh._check_parent()
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise CredentialStoreDenied("Safe no-follow file creation unavailable")
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | nofollow, 0o600)
        except OSError as error:
            raise CredentialStoreDenied("Credential database must be provisioned once") from error
        else:
            os.close(fd)
        with fresh._session() as db, db:
            db.execute(
                "CREATE TABLE passkeys (credential_id TEXT PRIMARY KEY, owner TEXT NOT NULL, "
                "public_key BLOB NOT NULL, sign_count INTEGER NOT NULL)"
            )
            db.execute("CREATE TABLE revoked_ids (credential_id TEXT PRIMARY KEY)")
            db.execute("PRAGMA user_version = 1")
        return cls(path)

    def _check_parent(self) -> None:
        try:
            parent = self._path.parent
            mode = parent.stat()
            if (
                parent.is_symlink()
                or parent.resolve() != parent
                or not stat.S_ISDIR(mode.st_mode)
                or mode.st_uid != _uid()
                or stat.S_IMODE(mode.st_mode) & 0o077
            ):
                raise CredentialStoreDenied("Credential directory must be private")
        except OSError as error:
            raise CredentialStoreDenied("Credential directory unavailable") from error

    def _check_file(self) -> None:
        self._check_parent()
        try:
            mode = self._path.lstat()
            if (
                not stat.S_ISREG(mode.st_mode)
                or mode.st_nlink != 1
                or mode.st_uid != _uid()
                or stat.S_IMODE(mode.st_mode) & 0o077
            ):
                raise CredentialStoreDenied("Credential database file is unsafe")
        except OSError as error:
            raise CredentialStoreDenied("Credential database file unavailable") from error

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        self._check_file()
        try:
            with closing(sqlite3.connect(f"{self._path.as_uri()}?mode=rw", uri=True, timeout=5)) as db:
                yield db
        except CredentialStoreDenied:
            raise
        except (sqlite3.Error, OSError) as error:
            raise CredentialStoreDenied("Credential database unavailable") from error

    @staticmethod
    def _decode(row: tuple[str, bytes, int]) -> StoredCredential:
        owner, encoded, counter = row
        if (
            not valid_identifier(owner)
            or not isinstance(encoded, bytes)
            or len(encoded) != 65
            or type(counter) is not int
            or not 0 <= counter <= 0xFFFFFFFF
        ):
            raise CredentialStoreDenied("Invalid persisted owner credential")
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)
        except ValueError as error:
            raise CredentialStoreDenied("Invalid persisted owner credential") from error
        return StoredCredential(owner, key, counter)

    def register_trusted(self, owner: str, credential_id: str, key: ec.EllipticCurvePublicKey) -> None:
        """Called only after independently authorized WebAuthn verification."""
        _check_id(owner, credential_id)
        public = _encode(key)
        with self._session() as db, db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute("SELECT COUNT(*) FROM passkeys").fetchone()
            if active is None or active[0] >= MAX_CREDENTIALS:
                raise CredentialStoreDenied("Credential capacity exhausted")
            blocked = db.execute(
                "SELECT EXISTS(SELECT 1 FROM revoked_ids WHERE credential_id = ?)", (credential_id,)
            ).fetchone()
            if blocked is None or blocked[0]:
                raise CredentialStoreDenied("Credential permanently revoked")
            inserted = db.execute(
                "INSERT OR IGNORE INTO passkeys(credential_id, owner, public_key, sign_count) "
                "VALUES (?, ?, ?, 0)",
                (credential_id, owner, public),
            )
            if inserted.rowcount != 1:
                raise CredentialStoreDenied("Credential already registered")

    def get(self, credential_id: str) -> StoredCredential | None:
        if not isinstance(credential_id, str) or CREDENTIAL_ID.fullmatch(credential_id) is None:
            raise CredentialStoreDenied("Invalid credential identifier")
        with self._session() as db:
            row = db.execute(
                "SELECT owner, public_key, sign_count FROM passkeys WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
        return None if row is None else self._decode(row)

    def list_owned(self, owner: str) -> list[str]:
        if not valid_identifier(owner):
            raise CredentialStoreDenied("Invalid owner identity")
        with self._session() as db:
            rows = db.execute(
                "SELECT credential_id FROM passkeys WHERE owner = ? ORDER BY credential_id", (owner,)
            ).fetchall()
        ids = [row[0] for row in rows]
        if any(not isinstance(cid, str) or CREDENTIAL_ID.fullmatch(cid) is None for cid in ids):
            raise CredentialStoreDenied("Invalid persisted owner credential")
        return ids

    def advance(self, owner: str, credential_id: str, sign_count: int) -> None:
        _check_id(owner, credential_id)
        if type(sign_count) is not int or not 0 <= sign_count <= 0xFFFFFFFF:
            raise CredentialStoreDenied("Invalid signature counter")
        with self._session() as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT sign_count FROM passkeys WHERE credential_id = ? AND owner = ?",
                (credential_id, owner),
            ).fetchone()
            if row is None or type(row[0]) is not int or not 0 <= row[0] <= 0xFFFFFFFF:
                raise CredentialStoreDenied("Owner passkey revoked or unavailable")
            if row[0] > 0 and sign_count <= row[0]:
                raise CredentialStoreDenied("Passkey signature counter replay")
            db.execute(
                "UPDATE passkeys SET sign_count = ? WHERE credential_id = ? AND owner = ?",
                (sign_count, credential_id, owner),
            )

    def revoke_trusted(self, owner: str, credential_id: str) -> None:
        """Remember revoked IDs so deletion cannot silently restore trusted identity."""
        _check_id(owner, credential_id)
        with self._session() as db, db:
            db.execute("BEGIN IMMEDIATE")
            deleted = db.execute(
                "DELETE FROM passkeys WHERE owner = ? AND credential_id = ?", (owner, credential_id)
            )
            if deleted.rowcount != 1:
                raise CredentialStoreDenied("Owner passkey revoked or unavailable")
            db.execute("INSERT INTO revoked_ids(credential_id) VALUES (?)", (credential_id,))
