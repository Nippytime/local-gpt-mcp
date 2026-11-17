"""Device-bound Ed25519 request authentication with replay and TTL checks."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

NONCE = re.compile(r"^[0-9a-f]{32}$")
DEVICE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
MAX_BODY = 16_384
SKEW_SECONDS = 45


class DeviceAuthenticationError(PermissionError):
    """A device signature, identity, freshness or nonce failed authentication."""


def public_key_text(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_public_key(value: str) -> Ed25519PublicKey:
    if not isinstance(value, str) or len(value) != 44:
        raise DeviceAuthenticationError("Invalid device public key")
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        if len(raw) != 32:
            raise ValueError("Unexpected key length")
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError, UnicodeError, binascii.Error) as error:
        raise DeviceAuthenticationError("Invalid device public key") from error


def _payload(device_id: str, method: str, path: str, timestamp: int, nonce: str, body: bytes) -> bytes:
    if (
        not isinstance(device_id, str)
        or DEVICE.fullmatch(device_id) is None
        or method != "POST"
        or not path.startswith("/api/agent/")
        or path.count("?")
        or type(timestamp) is not int
        or not isinstance(nonce, str)
        or NONCE.fullmatch(nonce) is None
        or len(body) > MAX_BODY
    ):
        raise DeviceAuthenticationError("Invalid signed device request")
    return json.dumps(
        {
            "device_id": device_id,
            "method": method,
            "path": path,
            "timestamp": timestamp,
            "nonce": nonce,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def sign_request(
    private: Ed25519PrivateKey, device_id: str, path: str, body: bytes, *, timestamp: int | None = None
) -> dict[str, str]:
    when = int(time.time()) if timestamp is None else timestamp
    nonce = secrets.token_hex(16)
    signed = _payload(device_id, "POST", path, when, nonce, body)
    return {
        "X-Device-Id": device_id,
        "X-Device-Time": str(when),
        "X-Device-Nonce": nonce,
        "X-Device-Signature": base64.urlsafe_b64encode(private.sign(signed)).decode("ascii"),
    }


class NonceStore(Protocol):
    """Atomic single-host durable nonce consumption; called only after signature validation."""

    def consume_device_nonce(self, device_id: str, nonce: str, *, now: float, expires_at: float) -> bool: ...


class DeviceReplayGuard:
    """Bounded replay protection: private shared ledger when configured, otherwise in-memory."""

    def __init__(self, *, clock: Callable[[], float] = time.time, store: NonceStore | None = None) -> None:
        self._clock = clock
        self._store = store
        self._lock = threading.Lock()
        self._seen: dict[tuple[str, str], float] = {}

    def verify(
        self,
        public_key: Ed25519PublicKey,
        device_id: str,
        path: str,
        body: bytes,
        headers: Mapping[str, str],
    ) -> None:
        try:
            nonce = headers["x-device-nonce"]
            timestamp = int(headers["x-device-time"])
            signature = base64.urlsafe_b64decode(headers["x-device-signature"])
            if abs(self._clock() - timestamp) > SKEW_SECONDS or len(signature) != 64:
                raise DeviceAuthenticationError("Expired or malformed device signature")
            signed = _payload(device_id, "POST", path, timestamp, nonce, body)
            public_key.verify(signature, signed)
        except (KeyError, ValueError, InvalidSignature, TypeError, UnicodeError, binascii.Error) as error:
            raise DeviceAuthenticationError("Invalid device authentication") from error
        now = self._clock()
        if self._store is not None:
            if not self._store.consume_device_nonce(
                device_id, nonce, now=now, expires_at=timestamp + SKEW_SECONDS
            ):
                raise DeviceAuthenticationError("Replayed or exhausted device nonce budget")
            return
        with self._lock:
            self._seen = {key: expiry for key, expiry in self._seen.items() if expiry > now}
            key = (device_id, nonce)
            if key in self._seen or len(self._seen) >= 20_000:
                raise DeviceAuthenticationError("Replayed or exhausted device nonce budget")
            self._seen[key] = now + SKEW_SECONDS * 2


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """Private key must remain on the Windows user device, never uploaded."""

    device_id: str
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, device_id: str) -> DeviceIdentity:
        if DEVICE.fullmatch(device_id) is None:
            raise ValueError("Invalid device identifier")
        return cls(device_id, Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> str:
        return public_key_text(self.private_key)
