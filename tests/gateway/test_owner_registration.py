"""Owner-only first WebAuthn registration HTTP contract; no model self-enrollment."""

from __future__ import annotations

import os
from pathlib import Path

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from mcp.server.auth.provider import AccessToken

from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.gateway.owner_registration import OwnerEnrollmentAPI
from local_gpt_mcp.gateway.server import create_gateway
from local_gpt_mcp.policy.bootstrap import BootstrapDenied, SQLiteBootstrapPermits
from local_gpt_mcp.policy.credential_store import SQLiteCredentialStore
from security.test_registration import ORIGIN, fixture

CONFIG = GatewayConfig(
    resource_url="https://owner.example.com/mcp",
    issuer_url="https://login.example.com",
    jwks_url="https://login.example.com/keys",
)
BROWSER_CLIENT = "independent-owner-browser-client"
HEADERS = {
    "Origin": ORIGIN,
    "Sec-Fetch-Site": "same-origin",
    "Authorization": "Bearer owner-session",
}


class Verifier:
    async def verify_token(self, raw: str) -> AccessToken | None:
        if raw not in ("owner-session", "owner-refresh", "model-session", "bob-session", "read-session"):
            return None
        model = raw == "model-session"
        return AccessToken(
            token=raw,
            client_id="chatgpt-model" if model else BROWSER_CLIENT,
            scopes=["devices:read"] if raw == "read-session" else ["owner:enroll"],
            resource=CONFIG.resource_url,
            subject="bob" if raw == "bob-session" else "alice",
        )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def stores(tmp_path: Path) -> tuple[SQLiteBootstrapPermits, SQLiteCredentialStore]:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    return (
        SQLiteBootstrapPermits.provision(private / "permits.sqlite"),
        SQLiteCredentialStore.provision(private / "credentials.sqlite"),
    )


@pytest.mark.anyio
async def test_first_owner_http_registration_verifies_real_webauthn_and_replay(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            stores(tmp_path)
        return
    permits, credentials = stores(tmp_path)
    code = permits.issue_local("alice")
    verifier = Verifier()
    enrolled = OwnerEnrollmentAPI(
        config=CONFIG,
        verifier=verifier,
        permits=permits,
        credentials=credentials,
        browser_client_id=BROWSER_CLIENT,
    )
    app = create_gateway(CONFIG, verifier=verifier, owner_enrollment=enrolled)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ORIGIN, headers=HEADERS
    ) as client:
        begin = await client.post("/api/owner/passkey/begin", json={"operator_code": code})
        assert begin.status_code == 200
        assert begin.headers["cache-control"] == "no-store"
        entry = begin.json()
        assert entry["options"]["rp"]["id"] == "owner.example.com"
        challenge = entry["options"]["challenge"]
        from local_gpt_mcp.policy.registration import RegistrationStart

        start = RegistrationStart(challenge, "", 0)
        private = ec.generate_private_key(ec.SECP256R1())
        payload = {
            "ceremony_id": entry["ceremony_id"],
            "challenge": challenge,
            "credential": fixture(start, private),
        }
        completed = await client.post("/api/owner/passkey/finish", json=payload)
        assert completed.status_code == 200
        saved = SQLiteCredentialStore(credentials._path).get(completed.json()["credential_id"])
        assert saved is not None
        assert saved.owner == "alice"
        assert saved.key.public_numbers() == private.public_key().public_numbers()
        assert (await client.post("/api/owner/passkey/finish", json=payload)).status_code == 403
        assert (
            await client.post("/api/owner/passkey/begin", json={"operator_code": code})
        ).status_code == 403


@pytest.mark.anyio
async def test_enrollment_requires_separate_client_scope_origin_token_and_owner(tmp_path: Path) -> None:
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            stores(tmp_path)
        return
    permits, credentials = stores(tmp_path)
    code = permits.issue_local("alice")
    verify = Verifier()
    api = OwnerEnrollmentAPI(
        config=CONFIG,
        verifier=verify,
        permits=permits,
        credentials=credentials,
        browser_client_id=BROWSER_CLIENT,
    )
    app = create_gateway(CONFIG, verifier=verify, owner_enrollment=api)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        for overrides in (
            {"Authorization": "Bearer model-session"},
            {"Authorization": "Bearer read-session"},
            {"Authorization": "Bearer bob-session"},
            {"Origin": "https://attacker.example.com"},
            {"Sec-Fetch-Site": "cross-site"},
            {"Sec-Fetch-Site": ""},
            {"Authorization": "Bearer forged"},
        ):
            headers = {**HEADERS, **overrides}
            result = await client.post(
                "/api/owner/passkey/begin", headers=headers, json={"operator_code": code}
            )
            assert result.status_code == 403
            assert result.headers["cache-control"] == "no-store"
        absent = await client.post("/api/owner/passkey/begin", headers=HEADERS, json={})
        assert absent.status_code == 403
        begin = await client.post("/api/owner/passkey/begin", headers=HEADERS, json={"operator_code": code})
        assert begin.status_code == 200
        entry = begin.json()
        key = ec.generate_private_key(ec.SECP256R1())
        from local_gpt_mcp.policy.registration import RegistrationStart

        payload = {
            "ceremony_id": entry["ceremony_id"],
            "challenge": entry["options"]["challenge"],
            "credential": fixture(RegistrationStart(entry["options"]["challenge"], "", 0), key),
        }
        changed = {**HEADERS, "Authorization": "Bearer owner-refresh"}
        assert (
            await client.post("/api/owner/passkey/finish", headers=changed, json=payload)
        ).status_code == 403
        # The first rejected finish burns the pending ceremony, including the original token.
        assert (
            await client.post("/api/owner/passkey/finish", headers=HEADERS, json=payload)
        ).status_code == 403
        assert not credentials.list_owned("alice")


@pytest.mark.anyio
async def test_default_gateway_does_not_expose_first_enrollment_routes() -> None:
    app = create_gateway(CONFIG, verifier=Verifier())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ORIGIN, headers=HEADERS
    ) as client:
        begin = await client.post("/api/owner/passkey/begin", json={"operator_code": "secret"})
        assert begin.status_code in (404, 405)


@pytest.mark.anyio
async def test_oversized_malformed_and_duplicate_fields_rejected(tmp_path: Path) -> None:
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            stores(tmp_path)
        return
    permits, credentials = stores(tmp_path)
    verifier = Verifier()
    api = OwnerEnrollmentAPI(
        config=CONFIG,
        verifier=verifier,
        permits=permits,
        credentials=credentials,
        browser_client_id=BROWSER_CLIENT,
    )
    app = create_gateway(CONFIG, verifier=verifier, owner_enrollment=api)
    code = permits.issue_local("alice")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ORIGIN, headers=HEADERS
    ) as client:
        for raw in ('{"operator_code":"a","operator_code":"b"}', '{"operator_code":}', "[]"):
            response = await client.post(
                "/api/owner/passkey/begin", content=raw, headers={"Content-Type": "application/json"}
            )
            assert response.status_code == 403
        too_long = await client.post(
            "/api/owner/passkey/begin", json={"operator_code": code, "junk": "x" * 17_000}
        )
        assert too_long.status_code == 403
        correct = await client.post("/api/owner/passkey/begin", json={"operator_code": code})
        assert correct.status_code == 200
