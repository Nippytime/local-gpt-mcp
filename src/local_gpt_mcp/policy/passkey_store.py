"""Owner passkey adapter backed by explicitly provisioned private credentials."""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric import ec

from local_gpt_mcp.policy.authority import valid_identifier
from local_gpt_mcp.policy.credential_store import (
    CredentialStoreDenied,
    SQLiteCredentialStore,
    StoredCredential,
)
from local_gpt_mcp.policy.remote_receipts import RemoteApprovalDenied

PasskeyCredential = StoredCredential


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


def _trusted[_Result](operation: Callable[[], _Result]) -> _Result:
    try:
        return operation()
    except CredentialStoreDenied as error:
        raise RemoteApprovalDenied("Trusted owner credentials unavailable") from error


class SQLitePasskeys:
    """Compatibility only; database creation, chmod and schema repair are never implicit."""

    def __init__(self, path: Path) -> None:
        self._store = _trusted(lambda: SQLiteCredentialStore(path))

    def register_trusted(self, owner: str, credential_id: str, key: ec.EllipticCurvePublicKey) -> None:
        _trusted(lambda: self._store.register_trusted(owner, credential_id, key))

    def get(self, credential_id: str) -> PasskeyCredential | None:
        return _trusted(lambda: self._store.get(credential_id))

    def list_owned(self, owner: str) -> list[str]:
        return _trusted(lambda: self._store.list_owned(owner))

    def advance(self, owner: str, credential_id: str, sign_count: int) -> None:
        _trusted(lambda: self._store.advance(owner, credential_id, sign_count))

    def revoke_trusted(self, owner: str, credential_id: str) -> None:
        _trusted(lambda: self._store.revoke_trusted(owner, credential_id))
