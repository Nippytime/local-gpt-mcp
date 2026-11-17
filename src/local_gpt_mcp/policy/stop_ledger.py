"""Durable single-host deny ledger for an authenticated outbound gateway.

This is not a Windows-wide STOP or a distributed deployment mechanism.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator

from local_gpt_mcp.policy.authority import AccessDenied, valid_identifier


class StopDenied(AccessDenied):
    """Remote access denied; database internals are not exposed to clients."""


class SQLiteStopLedger:
    """Irreversible owner/device denial, shared across local worker processes."""

    def __init__(self, path: Path) -> None:
        if os.name == "nt" or not path.is_absolute():
            raise StopDenied("A private POSIX stop database is required")
        self._path = path
        self._check_parent()
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        except OSError as error:
            raise StopDenied("Cannot provision trusted STOP state") from error
        else:
            os.close(fd)
        with self._session() as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS halted_owners (owner TEXT PRIMARY KEY)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS revoked_devices ("
                "owner TEXT NOT NULL, device_id TEXT NOT NULL, "
                "PRIMARY KEY(owner, device_id))"
            )

    def _check_parent(self) -> None:
        try:
            parent = self._path.parent
            meta = parent.stat()
            if (
                parent.is_symlink()
                or parent.resolve() != parent
                or not stat.S_ISDIR(meta.st_mode)
                or meta.st_uid != os.getuid()
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
                or meta.st_uid != os.getuid()
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
