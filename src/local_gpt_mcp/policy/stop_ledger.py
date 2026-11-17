"""Durable single-host deny ledger for an authenticated outbound gateway.

This is not a Windows-wide STOP or a distributed deployment mechanism.
"""

from __future__ import annotations

import math
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from local_gpt_mcp.policy.authority import AccessDenied, valid_identifier

MAX_NONCES = 20_000
NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")


class StopDenied(AccessDenied):
    """Remote access denied; database internals are not exposed to clients."""


def _uid() -> int:
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        raise StopDenied("POSIX owner identity is unavailable")
    return int(getuid())


class SQLiteStopLedger:
    """Irreversible owner/device denial, shared across local worker processes."""

    def __init__(self, path: Path) -> None:
        if os.name == "nt" or not path.is_absolute():
            raise StopDenied("A private POSIX stop database is required")
        self._path = path
        with self._session() as db:
            if db.execute("PRAGMA user_version").fetchone() != (1,):
                raise StopDenied("Explicit durable nonce schema upgrade required")
            db.execute("SELECT owner FROM halted_owners LIMIT 1")
            db.execute("SELECT owner FROM revoked_devices LIMIT 1")
            db.execute("SELECT device_id, nonce, expires_at FROM device_nonces LIMIT 1")

    @classmethod
    def provision(cls, path: Path) -> SQLiteStopLedger:
        """Explicit first install only; ordinary restarts never reset a missing ledger."""
        if os.name == "nt" or not path.is_absolute():
            raise StopDenied("A private POSIX stop database is required")
        fresh = cls.__new__(cls)
        fresh._path = path
        fresh._check_parent()
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None:
            raise StopDenied("Safe POSIX no-follow creation is required")
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | no_follow, 0o600)
        except OSError as error:
            raise StopDenied("STOP state must be provisioned exactly once") from error
        else:
            os.close(fd)
        with fresh._session() as db, db:
            db.execute("CREATE TABLE halted_owners (owner TEXT PRIMARY KEY)")
            db.execute(
                "CREATE TABLE revoked_devices ("
                "owner TEXT NOT NULL, device_id TEXT NOT NULL, "
                "PRIMARY KEY(owner, device_id))"
            )
            cls._create_nonce_table(db)
        return cls(path)

    @staticmethod
    def _create_nonce_table(db: sqlite3.Connection) -> None:
        db.execute(
            "CREATE TABLE device_nonces ("
            "device_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at REAL NOT NULL, "
            "PRIMARY KEY(device_id, nonce))"
        )
        db.execute("CREATE INDEX device_nonces_expiry ON device_nonces(expires_at)")
        db.execute("PRAGMA user_version = 1")

    @classmethod
    def upgrade_nonce_store(cls, path: Path) -> SQLiteStopLedger:
        """Explicit once-only upgrade of an old stop ledger; never reset nonce history."""
        if os.name == "nt" or not path.is_absolute():
            raise StopDenied("A private POSIX stop database is required")
        legacy = cls.__new__(cls)
        legacy._path = path
        with legacy._session() as db, db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("PRAGMA user_version").fetchone() != (0,):
                raise StopDenied("STOP state already upgraded or invalid")
            db.execute("SELECT owner FROM halted_owners LIMIT 1")
            db.execute("SELECT owner FROM revoked_devices LIMIT 1")
            cls._create_nonce_table(db)
        return cls(path)

    def _check_parent(self) -> None:
        try:
            parent = self._path.parent
            meta = parent.stat()
            if (
                parent.is_symlink()
                or parent.resolve() != parent
                or not stat.S_ISDIR(meta.st_mode)
                or meta.st_uid != _uid()
                or stat.S_IMODE(meta.st_mode) & 0o077
            ):
                raise StopDenied("STOP state directory must be private")
        except OSError as error:
            raise StopDenied("STOP state directory unavailable") from error

    def _check_file(self) -> None:
        self._check_parent()
        try:
            meta = self._path.lstat()
            if (
                not stat.S_ISREG(meta.st_mode)
                or meta.st_nlink != 1
                or meta.st_uid != _uid()
                or stat.S_IMODE(meta.st_mode) & 0o077
            ):
                raise StopDenied("STOP state file is unsafe")
        except OSError as error:
            raise StopDenied("STOP state file unavailable") from error

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        self._check_file()
        try:
            with closing(sqlite3.connect(f"{self._path.as_uri()}?mode=rw", uri=True, timeout=5)) as db:
                yield db
        except StopDenied:
            raise
        except (sqlite3.Error, OSError) as error:
            raise StopDenied("STOP state unavailable") from error

    @staticmethod
    def _identity(owner: str, device_id: str | None = None) -> None:
        if not valid_identifier(owner) or (device_id is not None and not valid_identifier(device_id)):
            raise StopDenied("Invalid STOP scope")

    def halt_owner(self, owner: str) -> None:
        """Idempotent, permanent deny for an owner; no unhalt endpoint exists."""
        self._identity(owner)
        with self._session() as db, db:
            db.execute("INSERT OR IGNORE INTO halted_owners(owner) VALUES (?)", (owner,))

    def revoke_device(self, owner: str, device_id: str) -> None:
        self._identity(owner, device_id)
        with self._session() as db, db:
            db.execute(
                "INSERT OR IGNORE INTO revoked_devices(owner, device_id) VALUES (?, ?)",
                (owner, device_id),
            )

    def require_allowed(self, owner: str, device_id: str | None = None) -> None:
        """Check the persisted decision for each admission, never cache a permit."""
        self._identity(owner, device_id)
        with self._session() as db:
            blocked = db.execute(
                "SELECT EXISTS(SELECT 1 FROM halted_owners WHERE owner = ?) OR "
                "EXISTS(SELECT 1 FROM revoked_devices WHERE owner = ? AND device_id = ?)",
                (owner, owner, device_id),
            ).fetchone()
        if blocked is None or blocked[0]:
            raise StopDenied("Owner or device is stopped")

    def consume_device_nonce(self, device_id: str, nonce: str, *, now: float, expires_at: float) -> bool:
        """Atomically reject duplicate valid Ed25519 nonces across local processes."""
        if (
            not valid_identifier(device_id)
            or not isinstance(nonce, str)
            or NONCE_PATTERN.fullmatch(nonce) is None
            or type(now) not in (int, float)
            or type(expires_at) not in (int, float)
            or not math.isfinite(now)
            or not math.isfinite(expires_at)
            or expires_at < now
        ):
            raise StopDenied("Invalid device nonce claim")
        with self._session() as db, db:
            db.execute("BEGIN IMMEDIATE")
            # Equality is still valid for the Ed25519 clock-skew boundary.
            db.execute("DELETE FROM device_nonces WHERE expires_at < ?", (now,))
            count = db.execute("SELECT COUNT(*) FROM device_nonces").fetchone()
            if count is None or count[0] >= MAX_NONCES:
                raise StopDenied("Durable device nonce capacity exhausted")
            inserted = db.execute(
                "INSERT OR IGNORE INTO device_nonces(device_id, nonce, expires_at) VALUES (?, ?, ?)",
                (device_id, nonce, expires_at),
            )
            return inserted.rowcount == 1
