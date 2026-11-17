"""Operator-local, one-use owner bootstrap permits; never an MCP or HTTP tool.

Issued only by a trusted POSIX service account on its own terminal. The owner
must independently present the code to the authenticated enrollment client.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from local_gpt_mcp.policy.authority import AccessDenied, valid_identifier
from local_gpt_mcp.policy.credential_store import SQLiteCredentialStore
from local_gpt_mcp.policy.registration import OperatorAuthorizedRegistration, RegistrationDenied

MAX_PERMITS = 256
PERMIT_SECONDS = 180
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class BootstrapDenied(AccessDenied):
    """No valid local operator bootstrap authorization exists."""


class SQLiteBootstrapPermits:
    """Single-host operator-issued secrets; persist digests, not raw bearer codes."""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        if os.name == "nt" or not path.is_absolute():
            raise BootstrapDenied("A private absolute POSIX permit database is required")
        self._path = path
        self._clock = clock
        with self._session() as db:
            if db.execute("PRAGMA user_version").fetchone() != (1,):
                raise BootstrapDenied("Explicit operator permit provisioning is required")
            rows = db.execute(
                "SELECT owner, digest, expires_at FROM permits LIMIT ?", (MAX_PERMITS + 1,)
            ).fetchall()
            if len(rows) > MAX_PERMITS:
                raise BootstrapDenied("Operator permit capacity exceeded")
            for owner, digest, expires_at in rows:
                if (
                    not valid_identifier(owner)
                    or not isinstance(digest, bytes)
                    or len(digest) != 32
                    or type(expires_at) not in (float, int)
                    or not 0 < expires_at < 10_000_000_000
                ):
                    raise BootstrapDenied("Invalid operator permit database")

    @classmethod
    def provision(cls, path: Path) -> SQLiteBootstrapPermits:
        """Exclusive first install; normal startup cannot reset a consumed permit."""
        if os.name == "nt" or not path.is_absolute():
            raise BootstrapDenied("A private absolute POSIX permit database is required")
        initial = cls.__new__(cls)
        initial._path = path
        initial._clock = time.time
        initial._check_parent()
        flag = getattr(os, "O_NOFOLLOW", None)
        if flag is None:
            raise BootstrapDenied("Safe no-follow file creation unavailable")
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | flag, 0o600)
        except OSError as error:
            raise BootstrapDenied("Permit store must be explicitly provisioned once") from error
        else:
            os.close(fd)
        with initial._session() as db, db:
            db.execute(
                "CREATE TABLE permits (owner TEXT PRIMARY KEY, digest BLOB NOT NULL, "
                "expires_at REAL NOT NULL)"
            )
            db.execute("PRAGMA user_version = 1")
        return cls(path)

    def _check_parent(self) -> None:
        try:
            parent = self._path.parent
            mode = parent.stat()
            uid = getattr(os, "getuid", None)
            if (
                uid is None
                or parent.is_symlink()
                or parent.resolve() != parent
                or not stat.S_ISDIR(mode.st_mode)
                or mode.st_uid != uid()
                or stat.S_IMODE(mode.st_mode) & 0o077
            ):
                raise BootstrapDenied("Operator permit directory must be private")
        except OSError as error:
            raise BootstrapDenied("Operator permit directory unavailable") from error

    def _check_file(self) -> None:
        self._check_parent()
        try:
            mode = self._path.lstat()
            uid = getattr(os, "getuid", None)
            if (
                uid is None
                or not stat.S_ISREG(mode.st_mode)
                or mode.st_nlink != 1
                or mode.st_uid != uid()
                or stat.S_IMODE(mode.st_mode) & 0o077
            ):
                raise BootstrapDenied("Operator permit file is unsafe")
        except OSError as error:
            raise BootstrapDenied("Operator permit file unavailable") from error

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        self._check_file()
        try:
            with closing(sqlite3.connect(f"{self._path.as_uri()}?mode=rw", uri=True, timeout=5)) as db:
                yield db
        except BootstrapDenied:
            raise
        except (sqlite3.Error, OSError) as error:
            raise BootstrapDenied("Operator permit storage unavailable") from error

    @staticmethod
    def _digest(code: str) -> bytes:
        if not isinstance(code, str) or TOKEN_PATTERN.fullmatch(code) is None:
            raise BootstrapDenied("Invalid operator permit")
        return hashlib.sha256(code.encode("ascii")).digest()

    def issue_local(self, owner: str) -> str:
        """Trusted terminal only. Caller must NEVER expose this as an HTTP/MCP action."""
        if not valid_identifier(owner):
            raise BootstrapDenied("Invalid owner identity")
        code = secrets.token_urlsafe(32)
        digest = self._digest(code)
        now = self._clock()
        with self._session() as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM permits WHERE expires_at <= ?", (now,))
            count = db.execute("SELECT COUNT(*) FROM permits").fetchone()
            existing = db.execute("SELECT 1 FROM permits WHERE owner = ?", (owner,)).fetchone()
            if count is None or (count[0] >= MAX_PERMITS and existing is None):
                raise BootstrapDenied("Operator permit capacity exceeded")
            db.execute(
                "INSERT INTO permits(owner, digest, expires_at) VALUES (?, ?, ?) "
                "ON CONFLICT(owner) DO UPDATE SET digest=excluded.digest, expires_at=excluded.expires_at",
                (owner, digest, now + PERMIT_SECONDS),
            )
        return code

    def authorized(self, owner: str, code: str) -> bool:
        if not valid_identifier(owner):
            return False
        try:
            digest = self._digest(code)
            with self._session() as db:
                row = db.execute(
                    "SELECT digest, expires_at FROM permits WHERE owner = ?", (owner,)
                ).fetchone()
            if row is None or not isinstance(row[0], bytes) or len(row[0]) != 32:
                return False
            return (
                type(row[1]) in (float, int)
                and row[1] > self._clock()
                and hmac.compare_digest(row[0], digest)
            )
        except BootstrapDenied:
            return False

    def consume(self, owner: str, code: str) -> None:
        """Atomically consume before credential insertion: failures burn the permit."""
        if not valid_identifier(owner):
            raise BootstrapDenied("Operator authorization unavailable")
        digest = self._digest(code)
        with self._session() as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT digest, expires_at FROM permits WHERE owner = ?", (owner,)).fetchone()
            if (
                row is None
                or not isinstance(row[0], bytes)
                or len(row[0]) != 32
                or type(row[1]) not in (float, int)
                or row[1] <= self._clock()
                or not hmac.compare_digest(row[0], digest)
            ):
                raise BootstrapDenied("Operator authorization unavailable")
            db.execute("DELETE FROM permits WHERE owner = ?", (owner,))

    def revoke_local(self, owner: str) -> None:
        if not valid_identifier(owner):
            raise BootstrapDenied("Invalid owner identity")
        with self._session() as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM permits WHERE owner = ?", (owner,))


class _FirstCredentialOnly:
    """Registration's trusted store adapter; issuer authorization is one use."""

    def __init__(
        self,
        owner: str,
        code: str,
        permits: SQLiteBootstrapPermits,
        credentials: SQLiteCredentialStore,
    ) -> None:
        self._owner = owner
        self._code = code
        self._permits = permits
        self._credentials = credentials

    def register_trusted(self, owner: str, credential_id: str, key: ec.EllipticCurvePublicKey) -> None:
        if owner != self._owner or self._credentials.list_owned(owner):
            raise BootstrapDenied("First owner credential only")
        self._permits.consume(owner, self._code)
        self._credentials.register_trusted(owner, credential_id, key)


def first_owner_registration(
    *,
    owner: str,
    code: str,
    origin: str,
    permits: SQLiteBootstrapPermits,
    credentials: SQLiteCredentialStore,
    clock: Callable[[], float] = time.time,
) -> OperatorAuthorizedRegistration:
    """Bind one independently supplied code to one OAuth-verified owner.

    The caller MUST derive `owner` from independent browser OAuth; never MCP.
    """
    if not valid_identifier(owner) or not permits.authorized(owner, code):
        raise RegistrationDenied("Operator permit required")
    store = _FirstCredentialOnly(owner, code, permits, credentials)
    return OperatorAuthorizedRegistration(
        origin=origin,
        store=store,
        operator_authorized=lambda account: (
            account == owner and not credentials.list_owned(owner) and permits.authorized(owner, code)
        ),
        clock=clock,
    )


def main(argv: list[str] | None = None) -> int:
    """Trusted service-account terminal command, not loaded by gateway routes."""
    parser = argparse.ArgumentParser(description="Operator-only first passkey bootstrap")
    parser.add_argument("command", choices=("provision", "issue", "revoke"))
    parser.add_argument("path", type=Path, help="Absolute private POSIX permit SQLite path")
    parser.add_argument("owner", nargs="?")
    args = parser.parse_args(argv)
    if args.command == "provision":
        if args.owner is not None:
            parser.error("provision does not accept an owner")
        SQLiteBootstrapPermits.provision(args.path)
        return 0
    if args.owner is None:
        parser.error("issue/revoke requires owner")
    store = SQLiteBootstrapPermits(args.path)
    if args.command == "issue":
        # Only show the token on the trusted terminal; do not persist or log it.
        print(store.issue_local(args.owner))
    else:
        store.revoke_local(args.owner)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
