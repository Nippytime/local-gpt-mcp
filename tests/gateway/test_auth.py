"""Verify signed OAuth access tokens and reject untrusted token claims."""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from local_gpt_mcp.gateway.auth import GatewayConfig, JWTVerifier

CONFIG = GatewayConfig(
    resource_url="https://gateway.example.com/mcp",
    issuer_url="https://login.example.com",
    jwks_url="https://login.example.com/keys",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def signed(monkeypatch: pytest.MonkeyPatch) -> tuple[JWTVerifier, rsa.RSAPrivateKey]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = JWTVerifier(CONFIG)
    signing_key = SimpleNamespace(key=private.public_key())
    monkeypatch.setattr(
        verifier, "_keys", SimpleNamespace(get_signing_key_from_jwt=lambda token: signing_key)
    )
    return verifier, private


def make_token(key: rsa.RSAPrivateKey, **updates: object) -> str:
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": CONFIG.issuer_url,
        "aud": CONFIG.resource_url,
        "sub": "alice",
        "client_id": "https://chatgpt.com/oauth/client.json",
        "scope": "devices:read",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    claims.update(updates)
    return jwt.encode(claims, key, algorithm="RS256")


@pytest.mark.anyio
async def test_valid_signature_binds_subject_client_resource_and_issuer(
    signed: tuple[JWTVerifier, rsa.RSAPrivateKey],
) -> None:
    verifier, key = signed
    value = await verifier.verify_token(make_token(key))
    assert value is not None
    assert value.subject == "alice"
    assert value.scopes == ["devices:read"]
    assert value.resource == CONFIG.resource_url
    assert value.claims == {"iss": CONFIG.issuer_url}


@pytest.mark.anyio
@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "https://other.example.com/mcp"},
        {"iss": "https://evil.example.com"},
        {"sub": ""},
        {"exp": 0},
        {"nbf": 4_102_444_800},
        {"scope": ""},
        {"client_id": ""},
        {"scope": "devices:read " + "x" * 200},
    ],
)
async def test_invalid_identity_audience_and_scope_are_rejected(
    signed: tuple[JWTVerifier, rsa.RSAPrivateKey], changes: dict[str, object]
) -> None:
    verifier, key = signed
    assert await verifier.verify_token(make_token(key, **changes)) is None


@pytest.mark.anyio
async def test_forged_signatures_and_unsigned_tokens_are_rejected(
    signed: tuple[JWTVerifier, rsa.RSAPrivateKey],
) -> None:
    verifier, _ = signed
    foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await verifier.verify_token(make_token(foreign)) is None
    assert await verifier.verify_token("not-a-jwt") is None
    assert await verifier.verify_token("a" * 8193) is None
    assert await verifier.verify_token(jwt.encode({"sub": "alice"}, key="", algorithm="none")) is None


def test_operator_urls_require_public_https_and_pinned_jwks_host() -> None:
    with pytest.raises(ValueError):
        GatewayConfig("http://localhost:8000/mcp", CONFIG.issuer_url, CONFIG.jwks_url)
    with pytest.raises(ValueError):
        GatewayConfig(CONFIG.resource_url, "http://login.example.com", CONFIG.jwks_url)
    with pytest.raises(ValueError):
        GatewayConfig(CONFIG.resource_url, CONFIG.issuer_url, "https://evil.example.com/key")
    with pytest.raises(ValueError):
        GatewayConfig("https://gateway.example.com/mcp?token=x", CONFIG.issuer_url, CONFIG.jwks_url)
