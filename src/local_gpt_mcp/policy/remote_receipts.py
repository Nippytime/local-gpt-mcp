"""Device-local verification of independently signed, single-use remote consent.

This verifier cannot approve itself: the pinned issuer key and trusted replay
database are supplied by the local owner, not by MCP tool arguments.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from local_gpt_mcp.policy.authority import AccessDenied, Caller, Capability, valid_identifier, valid_target

MAX_PROOF_BYTES = 4096
MAX_ACTION_BYTES = 4096
MAX_TTL_SECONDS = 60
CLOCK_SKEW_SECONDS = 5
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
HEX_NONCE = re.compile(r"^[0-9a-f]{32}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

RECEIPT_FIELDS = frozenset(
    {
        "version",
        "user_id",
        "device_id",
        "session_id",
        "target",
        "capability",
        "action_sha256",
        "nonce",
        "issued_at",
        "expires_at",
    }
)


class RemoteApprovalDenied(AccessDenied):
    """A remote owner receipt was invalid, stale, consumed or stopped."""


@dataclass(frozen=True, slots=True)
class ScopedAction:
    caller: Caller
    target: str
    capability: Capability
    action_sha256: str

    def __post_init__(self) -> None:
        if (
            not all(
                valid_identifier(value)
                for value in (self.caller.user_id, self.caller.device_id, self.caller.session_id)
            )
            or not isinstance(self.capability, Capability)
            or not valid_target(self.target, frozenset({self.capability}))
            or not isinstance(self.action_sha256, str)
            or HEX_DIGEST.fullmatch(self.action_sha256) is None
        ):
            raise RemoteApprovalDenied("Invalid scoped action")


class ConsumptionStore(Protocol):
    def consume(self, nonce: str, expiry: int, now: int) -> None: ...


class SQLiteConsumptionStore:
    """Transactional, process-restart-safe nonce store in a trusted owner-owned path."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute() or path.is_symlink() or path.parent.is_symlink():
            raise RemoteApprovalDenied("A safe absolute owner-scoped replay database is required")
        self._path = path
        with closing(sqlite3.connect(self._path, timeout=3)) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS spent (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
            )
            db.commit()

    def consume(self, nonce: str, expiry: int, now: int) -> None:
        with closing(sqlite3.connect(self._path, timeout=3)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM spent WHERE expires_at <= ?", (now,))
            try:
                db.execute("INSERT INTO spent (nonce, expires_at) VALUES (?, ?)", (nonce, expiry))
            except sqlite3.IntegrityError as error:
                raise RemoteApprovalDenied("Remote approval already consumed") from error


def action_fingerprint(operation: str, parameters: Mapping[str, str | int | bool]) -> str:
    """Hash exact bounded action parameters; never persist typed text in consent logs."""
    if not isinstance(operation, str) or re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", operation) is None:
        raise RemoteApprovalDenied("Invalid requested operation")
    if (
        not isinstance(parameters, Mapping)
        or len(parameters) > 16
        or any(
            not isinstance(key, str) or not 0 < len(key) <= 80 or not isinstance(value, str | int | bool)
            for key, value in parameters.items()
        )
    ):
        raise RemoteApprovalDenied("Invalid bounded action parameters")
    raw = json.dumps(
        {"operation": operation, "parameters": dict(parameters)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    if len(raw) > MAX_ACTION_BYTES:
        raise RemoteApprovalDenied("Action exceeds consent size")
    return hashlib.sha256(raw).hexdigest()


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or BASE64URL.fullmatch(value) is None:
        raise RemoteApprovalDenied("Invalid approval encoding")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise RemoteApprovalDenied("Invalid approval encoding") from error


def issue_testable_receipt(
    private_key: Ed25519PrivateKey,
    action: ScopedAction,
    *,
    issued_at: int,
    ttl_seconds: int = 30,
) -> str:
    """Issuer-side primitive; a separate owner-presence service must gate its use."""
    if (
        type(issued_at) is not int
        or issued_at <= 0
        or type(ttl_seconds) is not int
        or not (0 < ttl_seconds <= MAX_TTL_SECONDS)
    ):
        raise RemoteApprovalDenied("Invalid approval lifetime")
    payload = {
        "version": 1,
        "user_id": action.caller.user_id,
        "device_id": action.caller.device_id,
        "session_id": action.caller.session_id,
        "target": action.target,
        "capability": action.capability.value,
        "action_sha256": action.action_sha256,
        "nonce": secrets.token_hex(16),
        "issued_at": issued_at,
        "expires_at": issued_at + ttl_seconds,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    return _encode(body) + "." + _encode(private_key.sign(body))


class RemoteApprovalVerifier:
    """A receipt never replaces local pairing, target checks or executor policy."""

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        store: ConsumptionStore,
        *,
        stopped: Callable[[], bool],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._key = public_key
        self._store = store
        self._stopped = stopped
        self._clock = clock

    def verify(self, proof: str, expected: ScopedAction) -> None:
        """Consume once before acting; the native executor must recheck STOP and scope."""
        if self._stopped():
            raise RemoteApprovalDenied("Remote approvals stopped")
        if not isinstance(proof, str) or not 0 < len(proof) <= MAX_PROOF_BYTES:
            raise RemoteApprovalDenied("Missing or oversized owner approval")
        fragments = proof.split(".")
        if len(fragments) != 2:
            raise RemoteApprovalDenied("Invalid signed approval format")
        body, signature = _decode(fragments[0]), _decode(fragments[1])
        if len(body) > MAX_PROOF_BYTES or len(signature) != 64:
            raise RemoteApprovalDenied("Invalid signed approval size")
        try:
            self._key.verify(signature, body)
        except InvalidSignature as error:
            raise RemoteApprovalDenied("Untrusted approval signature") from error
        try:
            claims: object = json.loads(body)
        except (UnicodeError, ValueError) as error:
            raise RemoteApprovalDenied("Invalid approval claims") from error
        if not isinstance(claims, dict) or set(claims) != RECEIPT_FIELDS:
            raise RemoteApprovalDenied("Invalid approval claims")
        issued_at = claims["issued_at"]
        expires_at = claims["expires_at"]
        nonce = claims["nonce"]
        now = int(self._clock())
        if (
            type(claims["version"]) is not int
            or claims["version"] != 1
            or type(issued_at) is not int
            or type(expires_at) is not int
            or not isinstance(nonce, str)
            or HEX_NONCE.fullmatch(nonce) is None
            or issued_at <= 0
            or not 0 < expires_at - issued_at <= MAX_TTL_SECONDS
            or issued_at > now + CLOCK_SKEW_SECONDS
            or now >= expires_at
        ):
            raise RemoteApprovalDenied("Expired or malformed owner approval")
        if (
            claims["user_id"] != expected.caller.user_id
            or claims["device_id"] != expected.caller.device_id
            or claims["session_id"] != expected.caller.session_id
            or claims["target"] != expected.target
            or claims["capability"] != expected.capability.value
            or claims["action_sha256"] != expected.action_sha256
        ):
            raise RemoteApprovalDenied("Approval does not match the exact action")
        if self._stopped():
            raise RemoteApprovalDenied("Remote approvals stopped")
        self._store.consume(nonce, expires_at, now)
        if self._stopped():
            raise RemoteApprovalDenied("Remote approvals stopped")
