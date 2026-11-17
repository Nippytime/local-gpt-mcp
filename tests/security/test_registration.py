"""Real WebAuthn fmt:none creation fixtures and independently authorized owner registration."""

from __future__ import annotations

import hashlib
import json

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import bytes_to_base64url

from local_gpt_mcp.policy.registration import (
    OperatorAuthorizedRegistration,
    RegistrationDenied,
    RegistrationStart,
)

ORIGIN = "https://owner.example.com"
RP_ID = "owner.example.com"


class Store:
    def __init__(self) -> None:
        self.credentials: dict[str, tuple[str, ec.EllipticCurvePublicKey]] = {}

    def register_trusted(self, owner: str, credential_id: str, key: ec.EllipticCurvePublicKey) -> None:
        if credential_id in self.credentials:
            raise ValueError("Duplicate credential ID")
        self.credentials[credential_id] = (owner, key)


def fixture(
    start: RegistrationStart,
    private: ec.EllipticCurvePrivateKey,
    *,
    origin: str = ORIGIN,
    rp: str = RP_ID,
    flags: int = 0x45,
    alg: int = -7,
) -> dict[str, object]:
    identifier = b"real-demo-credential-id-00000001"
    numbers = private.public_key().public_numbers()
    cose = cbor2.dumps(
        {
            1: 2,
            3: alg,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )
    authenticator = (
        hashlib.sha256(rp.encode("ascii")).digest()
        + bytes([flags])
        + (0).to_bytes(4, "big")
        + bytes(16)
        + len(identifier).to_bytes(2, "big")
        + identifier
        + cose
    )
    attestation = cbor2.dumps({"fmt": "none", "authData": authenticator, "attStmt": {}})
    client = json.dumps(
        {"type": "webauthn.create", "challenge": start.challenge, "origin": origin, "crossOrigin": False}
    ).encode("utf-8")
    cid = bytes_to_base64url(identifier)
    return {
        "id": cid,
        "rawId": cid,
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client),
            "attestationObject": bytes_to_base64url(attestation),
        },
        "clientExtensionResults": {},
    }


def service(
    *,
    allowed: set[str] | None = None,
) -> tuple[OperatorAuthorizedRegistration, Store, list[float], set[str]]:
    clock = [1000.0]
    authorized = {"alice"} if allowed is None else allowed
    store = Store()
    registrar = OperatorAuthorizedRegistration(
        origin=ORIGIN,
        store=store,
        operator_authorized=lambda owner: owner in authorized,
        clock=lambda: clock[0],
    )
    return registrar, store, clock, authorized


def test_real_creation_verifies_and_stores_only_owner_p256_public_key() -> None:
    registrar, store, _clock, _auth = service()
    start = registrar.begin("alice")
    options = json.loads(start.options_json)
    assert options["rp"]["id"] == RP_ID
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["pubKeyCredParams"] == [{"alg": -7, "type": "public-key"}]
    key = ec.generate_private_key(ec.SECP256R1())
    credential = fixture(start, key)
    cid = registrar.finish("alice", start.challenge, credential)
    assert cid == credential["id"]
    assert store.credentials[cid][0] == "alice"
    assert store.credentials[cid][1].public_numbers() == key.public_key().public_numbers()
    with pytest.raises(RegistrationDenied):
        registrar.finish("alice", start.challenge, credential)


@pytest.mark.parametrize(
    "origin,rp,flags,alg",
    [
        ("https://attacker.example.com", RP_ID, 0x45, -7),
        (ORIGIN, "attacker.example.com", 0x45, -7),
        (ORIGIN, RP_ID, 0x41, -7),  # UP but no UV
        (ORIGIN, RP_ID, 0x44, -7),  # UV but no UP
        (ORIGIN, RP_ID, 0x45, -257),  # unsupported RSA alg marker on EC2 key
    ],
)
def test_malformed_or_wrong_origin_rp_uv_algorithm_is_rejected(
    origin: str, rp: str, flags: int, alg: int
) -> None:
    registrar, store, _clock, _auth = service()
    start = registrar.begin("alice")
    key = ec.generate_private_key(ec.SECP256R1())
    credential = fixture(start, key, origin=origin, rp=rp, flags=flags, alg=alg)
    with pytest.raises(RegistrationDenied):
        registrar.finish("alice", start.challenge, credential)
    assert not store.credentials


def test_wrong_owner_expiry_and_revoked_operator_deny_without_storage() -> None:
    registrar, store, clock, approved = service()
    begin = registrar.begin("alice")
    credential = fixture(begin, ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(RegistrationDenied):
        registrar.finish("bob", begin.challenge, credential)
    with pytest.raises(RegistrationDenied):
        registrar.finish("alice", begin.challenge, credential)
    fresh = registrar.begin("alice")
    approved.clear()
    with pytest.raises(RegistrationDenied):
        registrar.finish("alice", fresh.challenge, fixture(fresh, ec.generate_private_key(ec.SECP256R1())))
    approved.add("alice")
    expired = registrar.begin("alice")
    clock[0] += 60.0
    with pytest.raises(RegistrationDenied):
        registrar.finish(
            "alice", expired.challenge, fixture(expired, ec.generate_private_key(ec.SECP256R1()))
        )
    assert not store.credentials


def test_operator_preapproval_mandatory_and_https_origin_pinned() -> None:
    registrar, _store, _clock, _authorized = service(allowed=set())
    with pytest.raises(RegistrationDenied):
        registrar.begin("alice")
    with pytest.raises(RegistrationDenied):
        registrar.begin("owner with spaces")
    for origin in ("http://owner.example.com", "https://owner.example.com/unsafe", "https://localhost"):
        with pytest.raises(ValueError):
            OperatorAuthorizedRegistration(
                origin=origin,
                store=Store(),
                operator_authorized=lambda _owner: True,
            )


def test_duplicate_ids_oversized_response_and_tamper_rejected() -> None:
    registrar, store, _clock, _authorized = service()
    key = ec.generate_private_key(ec.SECP256R1())
    first = registrar.begin("alice")
    registrar.finish("alice", first.challenge, fixture(first, key))
    second = registrar.begin("alice")
    with pytest.raises(RegistrationDenied):
        registrar.finish("alice", second.challenge, fixture(second, key))
    third = registrar.begin("alice")
    forged = fixture(third, key)
    forged["response"] = {"clientDataJSON": "bad", "attestationObject": "bad"}
    with pytest.raises(RegistrationDenied):
        registrar.finish("alice", third.challenge, forged)
    fourth = registrar.begin("alice")
    oversized = fixture(fourth, key)
    oversized["junk"] = "x" * 12_001
    with pytest.raises(RegistrationDenied):
        registrar.finish("alice", fourth.challenge, oversized)
    assert len(store.credentials) == 1


def test_pending_challenge_budget_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("local_gpt_mcp.policy.registration.MAX_PENDING_REGISTRATIONS", 2)
    registrar, _store, clock, _allowed = service()
    registrar.begin("alice")
    registrar.begin("alice")
    with pytest.raises(RegistrationDenied):
        registrar.begin("alice")
    clock[0] += 61
    registrar.begin("alice")
