"""Trusted server-side passkey assertion gate for remote owner consent.

Not an MCP tool. Only a separately authenticated, owner-controlled web UI
may call this service; registration is an internal trusted operation.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from local_gpt_mcp.policy.authority import valid_identifier
from local_gpt_mcp.policy.remote_receipts import (
    RemoteApprovalDenied,
    ScopedAction,
    issue_testable_receipt,
)

MAX_ASSERTION_BYTES = 4096
MAX_PENDING = 1024
CHALLENGE_SECONDS = 60
USER_PRESENT = 0x01
USER_VERIFIED = 0x04


@dataclass(frozen=True, slots=True)
class PresenceChallenge:
    """Opaque challenge, scoped to a specific owner, passkey and pending action."""

    challenge: str
    expires_at: int


@dataclass(slots=True)
class _Credential:
    owner: str
    key: ec.EllipticCurvePublicKey
    sign_count: int = 0


@dataclass(frozen=True, slots=True)
class _Pending:
    owner: str
    credential_id: str
    action: ScopedAction
    expiry: int


class OwnerPresence:
    """Prove actual UV/UP with a pinned passkey before minting a receipt.

    The trusted issuer private key must not be placed in the browser or MCP
    runtime; the Windows device separately pins its public verification key.
    """

    def __init__(
        self,
        *,
        origin: str,
        receipt_signer: Ed25519PrivateKey,
        stopped: Callable[[], bool],
        clock: Callable[[], float] = time.time,
    ) -> None:
        parts = urlsplit(origin)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.path
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
            or parts.port not in (None, 443)
            or "." not in parts.hostname
            or parts.hostname.endswith((".local", ".internal"))
        ):
            raise ValueError("A pinned public HTTPS owner approval origin is required")
        self.origin = origin
        self.rp_id = parts.hostname
        self._issuer = receipt_signer
        self._clock = clock
        self._stopped = stopped
        self._lock = threading.RLock()
        self._credentials: dict[str, _Credential] = {}
        self._pending: dict[str, _Pending] = {}

    def register_trusted(
        self, owner: str, credential_id: str, public_key: ec.EllipticCurvePublicKey
    ) -> None:
        """INTERNAL pre-enrollment only, never exposed to MCP or public HTTP."""
        if (
            not valid_identifier(owner)
            or not isinstance(credential_id, str)
            or not 16 <= len(credential_id) <= 512
            or not isinstance(public_key, ec.EllipticCurvePublicKey)
            or not isinstance(public_key.curve, ec.SECP256R1)
        ):
            raise RemoteApprovalDenied("Invalid pre-registered owner passkey")
        with self._lock:
            if credential_id in self._credentials:
                raise RemoteApprovalDenied("Passkey already registered")
            self._credentials[credential_id] = _Credential(owner, public_key)

    def begin(self, owner: str, credential_id: str, action: ScopedAction) -> PresenceChallenge:
        """Caller MUST have been authenticated independently of the MCP tool."""
        with self._lock:
            credential = self._credentials.get(credential_id)
            if (
                self._stopped()
                or not isinstance(action, ScopedAction)
                or credential is None
                or credential.owner != owner
                or action.caller.user_id != owner
            ):
                raise RemoteApprovalDenied("Owner presence not authorized")
            now = int(self._clock())
            self._pending = {
                key: request for key, request in self._pending.items() if request.expiry > now
            }
            if len(self._pending) >= MAX_PENDING:
                raise RemoteApprovalDenied("Pending approval limit reached")
            challenge = secrets.token_urlsafe(32)
            expiry = now + CHALLENGE_SECONDS
            self._pending[challenge] = _Pending(owner, credential_id, action, expiry)
            return PresenceChallenge(challenge, expiry)

    def finish(
        self,
        owner: str,
        credential_id: str,
        challenge: str,
        *,
        client_data: bytes,
        authenticator_data: bytes,
        signature: bytes,
    ) -> str:
        """Verify WebAuthn ES256 assertion, consume challenge, then sign one receipt."""
        with self._lock:
            if self._stopped() or not isinstance(challenge, str):
                raise RemoteApprovalDenied("Owner approval stopped or invalid")
            # A challenge is single-attempt; bad proofs cannot be brute-forced.
            pending = self._pending.pop(challenge, None)
            credential = self._credentials.get(credential_id)
            now = int(self._clock())
            if (
                pending is None
                or pending.expiry <= now
                or pending.owner != owner
                or pending.credential_id != credential_id
                or credential is None
                or credential.owner != owner
            ):
                raise RemoteApprovalDenied("Missing or expired owner challenge")
            if (
                not isinstance(client_data, bytes)
                or not 0 < len(client_data) <= MAX_ASSERTION_BYTES
                or not isinstance(authenticator_data, bytes)
                or not 37 <= len(authenticator_data) <= MAX_ASSERTION_BYTES
                or not isinstance(signature, bytes)
                or not 0 < len(signature) <= 256
            ):
                raise RemoteApprovalDenied("Malformed passkey assertion")
            try:
                data: object = json.loads(client_data)
            except (ValueError, UnicodeError) as error:
                raise RemoteApprovalDenied("Invalid passkey client data") from error
            if (
                not isinstance(data, dict)
                or data.get("type") != "webauthn.get"
                or data.get("challenge") != challenge
                or data.get("origin") != self.origin
                or data.get("crossOrigin", False) is not False
                or "topOrigin" in data
            ):
                raise RemoteApprovalDenied("Passkey challenge or origin mismatch")
            rp_hash = hashlib.sha256(self.rp_id.encode("ascii")).digest()
            flags = authenticator_data[32]
            counter = int.from_bytes(authenticator_data[33:37], "big")
            if (
                authenticator_data[:32] != rp_hash
                or flags & (USER_PRESENT | USER_VERIFIED) != USER_PRESENT | USER_VERIFIED
                or (credential.sign_count > 0 and counter > 0 and counter <= credential.sign_count)
            ):
                raise RemoteApprovalDenied("Passkey RP, user verification or counter rejected")
            signed = authenticator_data + hashlib.sha256(client_data).digest()
            try:
                credential.key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError, TypeError) as error:
                raise RemoteApprovalDenied("Untrusted passkey signature") from error
            if self._stopped():
                raise RemoteApprovalDenied("Remote approvals stopped")
            credential.sign_count = max(credential.sign_count, counter)
            receipt = issue_testable_receipt(self._issuer, pending.action, issued_at=now, ttl_seconds=30)
            if self._stopped():
                raise RemoteApprovalDenied("Remote approvals stopped")
            return receipt
