"""Operator-trusted owner passkey public keys and monotonic counters; never private keys."""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from local_gpt_mcp.policy.authority import valid_identifier
from local_gpt_mcp.policy.remote_receipts import RemoteApprovalDenied


@dataclass(frozen=True, slots=True)
class PasskeyCredential:
    owner: str
    key: ec.EllipticCurvePublicKey
    sign_count: int


class PasskeyStore(Protocol):
    def register_trusted(self, owner: str, credential_id: str, key: ec.EllipticCurvePublicKey) -> None: ...

    def get(self, credential_id: str) -> PasskeyCredential | None: ...

    def list_owned(self, owner: str) -> list[str]: ...

    def advance(self, owner: str, credential_id: str, sign_count: int) -> None: ...


def _check(owner: str, credential_id: str, key: ec.EllipticCurvePublicKey) -> None:
    if (
        not valid_identifier(owner)
        or not isinstance(credential_id, str)
        or not 16 <= len(credential_id) <= 512
        or not isinstance(key, ec.EllipticCurvePublicKey)
        or not isinstance(key.curve, ec.SECP256R1)
    ):
        raise RemoteApprovalDenied("Invalid trusted owner passkey")


def _counter(previous: int, incoming: int) -> None:
    if (
        type(incoming) is not int
        or not 0 <= incoming <= 0xFFFFFFFF
        or (previous > 0 and incoming <= previous)
    ):
        raise RemoteApprovalDenied("Passkey sign counter replay or downgrade")


class MemoryPasskeys:
    def __init__(self) -> None:
        self._entries: dict[str, PasskeyCredential] = {}
        self._lock = threading.RLock()

    def register_trusted(self, owner: str, credential_id: str, key: ec.EllipticCurvePublicKey) -> None:
        _check(owner, credential_id, key)
        with self._lock:
            if credential_id in self._entries:
                raise RemoteApprovalDenied("Passkey already registered")
            self._entries[credential_id] = PasskeyCredential(owner, key, 0)

    def get(self, credential_id: str) -> PasskeyCredential | None:
        with self._lock:
            return self._entries.get(credential_id)

    def list_owned(self, owner: str) -> list[str]:
        with self._lock:
            return sorted(key for key, entry in self._entries.items() if entry.owner == owner)

    def advance(self, owner: str, credential_id: str, sign_count: int) -> None:
        with self._lock:
            current = self._entries.get(credential_id)
            if current is None or current.owner != owner:
                raise RemoteApprovalDenied("Passkey revoked or belongs to another owner")
            _counter(current.sign_count, sign_count)
            self._entries[credential_id] = PasskeyCredential(owner, current.key, sign_count)


class SQLitePasskeys:
    def __init__(self, path: Path) -> None:
        if (
            not path.is_absolute()
            or path.is_symlink()
            or path.parent.is_symlink()
            or not path.parent.is_dir()
            or (path.exists() and not path.is_file())
        ):
            raise RemoteApprovalDenied("A safe absolute passkey database path is required")
        self._path = path
        with closing(self._connect()) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS passkeys ("
                "credential_id TEXT PRIMARY KEY, owner TEXT NOT NULL, "
                "public_key BLOB NOT NULL, sign_count INTEGER NOT NULL)"
            )
            db.commit()
        if os.name != "nt":
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def _connect(self) -> sqlite3.Connection:
        if self._path.is_symlink() or self._path.parent.is_symlink():
            raise RemoteApprovalDenied("Linked passkey database path refused")
        return sqlite3.connect(self._path, timeout=5)

    def register_trusted(self, owner: str, credential_id: str, key: ec.EllipticCurvePublicKey) -> None:
        _check(owner, credential_id, key)
        encoded = key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        try:
            with closing(self._connect()) as db, db:
                db.execute(
                    "INSERT INTO passkeys (credential_id, owner, public_key, sign_count) VALUES (?, ?, ?, 0)",
                    (credential_id, owner, encoded),
                )
        except sqlite3.IntegrityError as error:
            raise RemoteApprovalDenied("Passkey already registered") from error

    def get(self, credential_id: str) -> PasskeyCredential | None:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT owner, public_key, sign_count FROM passkeys WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
        if row is None:
            return None
        owner, encoded, counter = row
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)
        except ValueError as error:
            raise RemoteApprovalDenied("Stored owner passkey is invalid") from error
        return PasskeyCredential(owner, key, counter)

    def list_owned(self, owner: str) -> list[str]:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT credential_id FROM passkeys WHERE owner = ? ORDER BY credential_id",
                (owner,),
            ).fetchall()
        return [str(row[0]) for row in rows]

    def advance(self, owner: str, credential_id: str, sign_count: int) -> None:
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT sign_count FROM passkeys WHERE credential_id = ? AND owner = ?",
                (credential_id, owner),
            ).fetchone()
            if row is None:
                raise RemoteApprovalDenied("Passkey revoked or belongs to another owner")
            _counter(int(row[0]), sign_count)
            db.execute(
                "UPDATE passkeys SET sign_count = ? WHERE credential_id = ? AND owner = ?",
                (sign_count, credential_id, owner),
            )

    def revoke_trusted(self, owner: str, credential_id: str) -> None:
        with closing(self._connect()) as db, db:
            deleted = db.execute(
                "DELETE FROM passkeys WHERE credential_id = ? AND owner = ?",
                (credential_id, owner),
            )
            if deleted.rowcount != 1:
                raise RemoteApprovalDenied("Passkey unavailable for this owner")
