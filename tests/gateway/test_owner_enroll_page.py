"""Opt-in owner-browser WebAuthn registration page security and packaged assets."""

from __future__ import annotations

import os
from importlib.resources import files
from pathlib import Path

import httpx2 as httpx
import pytest

from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.gateway.owner_enroll_page import OwnerEnrollmentPageConfig
from local_gpt_mcp.gateway.owner_registration import OwnerEnrollmentAPI
from local_gpt_mcp.gateway.server import create_gateway
from local_gpt_mcp.policy.bootstrap import BootstrapDenied, SQLiteBootstrapPermits
from local_gpt_mcp.policy.credential_store import SQLiteCredentialStore

CONFIG = GatewayConfig(
    resource_url="https://owner.example.com/mcp",
    issuer_url="https://login.example.com",
    jwks_url="https://login.example.com/keys",
)
PAGE = OwnerEnrollmentPageConfig(
    client_id="trusted-owner-browser",
    authorization_endpoint="https://login.example.com/oauth/authorize",
    token_endpoint="https://login.example.com/oauth/token",
)


class NoBearerVerifier:
    async def verify_token(self, token: str) -> None:
        return None


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def service(tmp_path: Path, verifier: NoBearerVerifier) -> OwnerEnrollmentAPI:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    permits = SQLiteBootstrapPermits.provision(private / "permits.sqlite")
    credentials = SQLiteCredentialStore.provision(private / "credentials.sqlite")
    return OwnerEnrollmentAPI(
        config=CONFIG,
        verifier=verifier,
        permits=permits,
        credentials=credentials,
        browser_client_id=PAGE.client_id,
    )


@pytest.mark.anyio
async def test_opt_in_page_has_strict_origin_csp_and_token_free_public_config(tmp_path: Path) -> None:
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            service(tmp_path, NoBearerVerifier())
        return
    verifier = NoBearerVerifier()
    app = create_gateway(
        CONFIG, verifier=verifier, owner_enrollment=service(tmp_path, verifier), enrollment_page=PAGE
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://owner.example.com"
    ) as client:
        document = await client.get("/owner/enroll")
        assert document.status_code == 200
        assert "Register your owner passkey" in document.text
        assert '<script type="module" src="/owner/enroll.js"></script>' in document.text
        assert 'type="password"' in document.text
        assert "inline" not in document.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in document.headers["content-security-policy"]
        assert "publickey-credentials-create=(self)" in document.headers["permissions-policy"]
        assert document.headers["cache-control"] == "no-store"
        assert document.headers["x-frame-options"] == "DENY"
        assert "operator_code" not in document.text
        public = await client.get("/owner/enroll-config")
        assert public.status_code == 200
        assert public.json()["redirect_uri"] == "https://owner.example.com/owner/enroll"
        assert public.json()["client_id"] == PAGE.client_id
        assert "client_secret" not in public.text
        js = await client.get("/owner/enroll.js")
        assert js.status_code == 200
        for required in (
            "code_challenge_method",
            "S256",
            "parseCreationOptionsFromJSON",
            "navigator.credentials.create",
            "credential.toJSON()",
            "sessionStorage.removeItem",
            "history.replaceState",
        ):
            assert required in js.text
        for dangerous in ("localStorage", "innerHTML", "console.log", "document.write"):
            assert dangerous not in js.text
        assert "accessToken = token.access_token" in js.text
        css = await client.get("/owner/enroll.css")
        assert css.status_code == 200
        for headers in (
            {"Host": "attacker.example.com"},
            {"Origin": "https://attacker.example.com"},
        ):
            for url in ("/owner/enroll", "/owner/enroll-config", "/owner/enroll.js"):
                assert (await client.get(url, headers=headers)).status_code == 403


@pytest.mark.anyio
async def test_default_gateway_has_no_owner_enrollment_page() -> None:
    app = create_gateway(CONFIG, verifier=NoBearerVerifier())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://owner.example.com"
    ) as client:
        assert (await client.get("/owner/enroll")).status_code in (404, 405)


def test_owner_page_refuses_untrusted_identity_issuer_and_unbound_service(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires"):
        create_gateway(CONFIG, verifier=NoBearerVerifier(), enrollment_page=PAGE)
    if os.name == "nt":
        with pytest.raises(BootstrapDenied):
            service(tmp_path, NoBearerVerifier())
        return
    verifier = NoBearerVerifier()
    enroll = service(tmp_path, verifier)
    with pytest.raises(ValueError, match="client ID"):
        create_gateway(
            CONFIG,
            verifier=verifier,
            owner_enrollment=enroll,
            enrollment_page=OwnerEnrollmentPageConfig(
                "foreign-owner-app", PAGE.authorization_endpoint, PAGE.token_endpoint
            ),
        )
    with pytest.raises(ValueError, match="issuer"):
        create_gateway(
            CONFIG,
            verifier=verifier,
            owner_enrollment=enroll,
            enrollment_page=OwnerEnrollmentPageConfig(
                PAGE.client_id, "https://evil.example.com/oauth/authorize", PAGE.token_endpoint
            ),
        )
    with pytest.raises(ValueError, match="issuer"):
        create_gateway(
            CONFIG,
            verifier=verifier,
            owner_enrollment=enroll,
            enrollment_page=OwnerEnrollmentPageConfig(
                PAGE.client_id, PAGE.authorization_endpoint, "http://login.example.com/token"
            ),
        )
    with pytest.raises(ValueError, match="reuse"):
        create_gateway(CONFIG, verifier=NoBearerVerifier(), owner_enrollment=enroll, enrollment_page=PAGE)


def test_packaged_browser_assets_are_present() -> None:
    assets = files("local_gpt_mcp.gateway").joinpath("assets")
    for name in ("enroll.html", "enroll.js", "enroll.css"):
        assert assets.joinpath(name).read_text(encoding="utf-8")
