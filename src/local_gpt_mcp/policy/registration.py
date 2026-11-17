"""Operator-authorized WebAuthn registration verifier, never an MCP/API enrollment route.

The injecting caller must independently authorize the owner before issuing a challenge.
Verification alone does not establish device ownership or provision an OAuth identity.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import ec
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import bytes_to_base64url, decode_credential_public_key
from webauthn.helpers.cose import COSECRV, COSEAlgorithmIdentifier
from webauthn.helpers.decode_credential_public_key import DecodedEC2PublicKey
from webauthn.helpers.decoded_public_key_to_cryptography import decoded_public_key_to_cryptography
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AttestationFormat,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from local_gpt_mcp.policy.authority import AccessDenied, valid_identifier

CHALLENGE_TTL_SECONDS = 60
MAX_PENDING_REGISTRATIONS = 128
MAX_CREDENTIAL_RESPONSE_BYTES = 12_000


class RegistrationDenied(AccessDenied):
    """Untrusted, unauthorized, expired or malformed registration."""


class TrustedPasskeyStore(Protocol):
    def register_trusted(self, owner: str, credential_id: str, key: ec.EllipticCurvePublicKey) -> None: ...


@dataclass(frozen=True, slots=True)
class RegistrationStart:
    challenge: str
    options_json: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class _Pending:
    owner: str
    expected: bytes
    expires_at: float


class OperatorAuthorizedRegistration:
    """Single-use, browser-verifiable registration ceremony with an independent owner gate."""

    def __init__(
        self,
        *,
        origin: str,
        store: TrustedPasskeyStore,
        operator_authorized: Callable[[str], bool],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        parsed = urlsplit(origin)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("Invalid WebAuthn HTTPS origin") from error
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or port not in (None, 443)
            or parsed.path
            or parsed.query
            or parsed.fragment
            or "." not in parsed.hostname
            or parsed.hostname.endswith((".local", ".internal"))
        ):
            raise ValueError("A pinned public HTTPS WebAuthn origin is required")
        self._origin = origin
        self._rp_id = parsed.hostname
        self._store = store
        self._authorized = operator_authorized
        self._clock = clock
        self._lock = threading.RLock()
        self._pending: dict[str, _Pending] = {}

    def _require_operator(self, owner: str) -> None:
        if not valid_identifier(owner) or self._authorized(owner) is not True:
            raise RegistrationDenied("Trusted operator registration approval required")

    def begin(self, owner: str) -> RegistrationStart:
        """Only a separately trusted operator can authorize a browser creation challenge."""
        with self._lock:
            self._require_operator(owner)
            now = self._clock()
            self._pending = {key: p for key, p in self._pending.items() if p.expires_at > now}
            if len(self._pending) >= MAX_PENDING_REGISTRATIONS:
                raise RegistrationDenied("Registration challenge capacity exhausted")
            challenge_bytes = secrets.token_bytes(32)
            challenge = bytes_to_base64url(challenge_bytes)
            self._pending[challenge] = _Pending(owner, challenge_bytes, now + CHALLENGE_TTL_SECONDS)
            options = generate_registration_options(
                rp_id=self._rp_id,
                rp_name="Local GPT MCP",
                user_id=hashlib.sha256(owner.encode("utf-8")).digest(),
                user_name=owner,
                user_display_name=owner,
                challenge=challenge_bytes,
                timeout=CHALLENGE_TTL_SECONDS * 1000,
                attestation=AttestationConveyancePreference.NONE,
                supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
            )
            return RegistrationStart(challenge, options_to_json(options), now + CHALLENGE_TTL_SECONDS)

    def finish(self, owner: str, challenge: str, credential: Mapping[str, object]) -> str:
        """Consume the challenge once, validate a real WebAuthn creation and store only P-256 public data."""
        with self._lock:
            if not isinstance(challenge, str):
                raise RegistrationDenied("Registration challenge unavailable")
            pending = self._pending.pop(challenge, None)
            if pending is None or pending.owner != owner or self._clock() >= pending.expires_at:
                raise RegistrationDenied("Registration challenge unavailable")
            self._require_operator(owner)
            try:
                import json

                supplied = json.dumps(credential, separators=(",", ":"))
                if len(supplied) > MAX_CREDENTIAL_RESPONSE_BYTES:
                    raise RegistrationDenied("Registration payload too large")
                result = verify_registration_response(
                    credential=supplied,
                    expected_challenge=pending.expected,
                    expected_origin=self._origin,
                    expected_rp_id=self._rp_id,
                    require_user_presence=True,
                    require_user_verification=True,
                    supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
                )
                decoded = decode_credential_public_key(result.credential_public_key)
                if (
                    result.fmt != AttestationFormat.NONE
                    or not result.user_verified
                    or not isinstance(decoded, DecodedEC2PublicKey)
                    or decoded.alg != COSEAlgorithmIdentifier.ECDSA_SHA_256
                    or decoded.crv != COSECRV.P256
                    or not 16 <= len(result.credential_id) <= 384
                ):
                    raise RegistrationDenied("Unsupported or unverified passkey credential")
                public_key = decoded_public_key_to_cryptography(decoded)
                if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
                    public_key.curve, ec.SECP256R1
                ):
                    raise RegistrationDenied("Only P-256 owner passkeys are permitted")
                credential_id = bytes_to_base64url(result.credential_id)
                self._require_operator(owner)
                self._store.register_trusted(owner, credential_id, public_key)
                return credential_id
            except RegistrationDenied:
                raise
            except Exception as error:
                raise RegistrationDenied("Untrusted registration response or credential store") from error
