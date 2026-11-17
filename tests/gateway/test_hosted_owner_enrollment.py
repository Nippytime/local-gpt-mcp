"""Hosted first-passkey enrollment is explicit, one-worker and deny-first."""

from __future__ import annotations

import os
from pathlib import Path

import httpx2 as httpx
import pytest
from mcp.server.auth.provider import AccessToken

from local_gpt_mcp.gateway import server
from local_gpt_mcp.gateway.server import create_from_env
from local_gpt_mcp.policy.bootstrap import SQLiteBootstrapPermits
from local_gpt_mcp.policy.credential_store import SQLiteCredentialStore

RESOURCE = "https://owner.example.com/mcp"
ORIGIN = "https://owner.example.com"


@pytest.fixture(autouse=True)
def gateway_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "LOCAL_MCP_STOP_DB",
        "LOCAL_MCP_OWNER_CLIENT_ID",
        "LOCAL_MCP_OWNER_ENROLLMENT",
        "LOCAL_MCP_OWNER_SINGLE_PROCESS_ACK",
        "LOCAL_MCP_OWNER_AUTHORIZE_URL",
        "LOCAL_MCP_OWNER_TOKEN_URL",
        "LOCAL_MCP_OWNER_PERMIT_DB",
        "LOCAL_MCP_PASSKEY_DB",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("LOCAL_MCP_RESOURCE_URL", RESOURCE)
    monkeypatch.setenv("LOCAL_MCP_ISSUER_URL", "https://login.example.com")
    monkeypatch.setenv("LOCAL_MCP_JWKS_URL", "https://login.example.com/jwks")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def configure(monkeypatch: pytest.MonkeyPatch, private: Path) -> None:
    monkeypatch.setenv("LOCAL_MCP_OWNER_ENROLLMENT", "1")
    monkeypatch.setenv("LOCAL_MCP_OWNER_SINGLE_PROCESS_ACK", "1")
    monkeypatch.setenv("LOCAL_MCP_OWNER_CLIENT_ID", "separate-owner-browser")
    monkeypatch.setenv("LOCAL_MCP_OWNER_AUTHORIZE_URL", "https://login.example.com/authorize")
    monkeypatch.setenv("LOCAL_MCP_OWNER_TOKEN_URL", "https://login.example.com/token")
    monkeypatch.setenv("LOCAL_MCP_OWNER_PERMIT_DB", str(private / "permits.sqlite"))
    monkeypatch.setenv("LOCAL_MCP_PASSKEY_DB", str(private / "passkeys.sqlite"))


def provision(private: Path) -> SQLiteBootstrapPermits:
    private.mkdir(mode=0o700)
    permits = SQLiteBootstrapPermits.provision(private / "permits.sqlite")
    SQLiteCredentialStore.provision(private / "passkeys.sqlite")
    return permits


class FakeVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        if token not in ("owner", "wrong-client", "model", "wrong-scope"):
            return None
        return AccessToken(
            token=token,
            client_id="model-client" if token in ("model", "wrong-client") else "separate-owner-browser",
            scopes=["devices:read"] if token == "wrong-scope" else ["owner:enroll"],
            resource=RESOURCE,
            subject="alice",
        )


@pytest.mark.anyio
async def test_default_hosting_exposes_no_owner_registration_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Leftover config never activates the enrollment page without the explicit switch.
    monkeypatch.setenv("LOCAL_MCP_OWNER_CLIENT_ID", "separate-owner-browser")
    monkeypatch.setenv("LOCAL_MCP_OWNER_PERMIT_DB", "/missing/private/permits.sqlite")
    app = create_from_env()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        assert (await client.get("/owner/enroll")).status_code in (404, 405)
        assert (await client.post("/api/owner/passkey/begin", json={})).status_code in (404, 405)


@pytest.mark.anyio
async def test_explicit_hosting_wires_real_private_stores_and_exact_oauth_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "private"
    if os.name == "nt":
        configure(monkeypatch, private)
        with pytest.raises(Exception, match="POSIX|private|unavailable"):
            create_from_env()
        return
    permits = provision(private)
    configure(monkeypatch, private)
    code = permits.issue_local("alice")
    monkeypatch.setattr(server, "JWTVerifier", lambda _config: FakeVerifier())
    app = create_from_env()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        page = await client.get("/owner/enroll")
        assert page.status_code == 200
        assert page.headers["cache-control"] == "no-store"
        config = (await client.get("/owner/enroll-config")).json()
        assert config["client_id"] == "separate-owner-browser"
        assert config["resource"] == RESOURCE
        assert "operator_code" not in str(config)
        for token in ("model", "wrong-client", "wrong-scope"):
            denied = await client.post(
                "/api/owner/passkey/begin",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Origin": ORIGIN,
                    "Sec-Fetch-Site": "same-origin",
                },
                json={"operator_code": code},
            )
            assert denied.status_code == 403
        begun = await client.post(
            "/api/owner/passkey/begin",
            headers={
                "Authorization": "Bearer owner",
                "Origin": ORIGIN,
                "Sec-Fetch-Site": "same-origin",
            },
            json={"operator_code": code},
        )
        assert begun.status_code == 200
        assert begun.headers["cache-control"] == "no-store"
        assert begun.json()["options"]["rp"]["id"] == "owner.example.com"
        assert (await client.get("/owner/enroll", headers={"Host": "evil.example.com"})).status_code == 403


def test_enabled_hosting_rejects_incomplete_and_untrusted_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for bad in ("true", "", "2"):
        monkeypatch.setenv("LOCAL_MCP_OWNER_ENROLLMENT", bad)
        with pytest.raises(RuntimeError, match="explicitly enabled"):
            create_from_env()
    private = tmp_path / "private"
    configure(monkeypatch, private)
    monkeypatch.delenv("LOCAL_MCP_OWNER_SINGLE_PROCESS_ACK")
    with pytest.raises(RuntimeError, match="single-worker"):
        create_from_env()
    monkeypatch.setenv("LOCAL_MCP_OWNER_SINGLE_PROCESS_ACK", "1")
    with pytest.raises(RuntimeError, match="independent OAuth client"):
        monkeypatch.delenv("LOCAL_MCP_OWNER_CLIENT_ID")
        create_from_env()
    monkeypatch.setenv("LOCAL_MCP_OWNER_CLIENT_ID", "separate-owner-browser")
    if os.name == "nt":
        with pytest.raises(Exception, match="POSIX|private|unavailable"):
            create_from_env()
        return
    with pytest.raises(Exception, match="unavailable"):
        create_from_env()  # missing database is never silently created
    provision(private)
    monkeypatch.setenv("LOCAL_MCP_OWNER_TOKEN_URL", "https://attacker.example.com/token")
    with pytest.raises(ValueError, match="issuer"):
        create_from_env()
    monkeypatch.setenv("LOCAL_MCP_OWNER_TOKEN_URL", "https://login.example.com/token")
    monkeypatch.setenv("LOCAL_MCP_PASSKEY_DB", str(private / "permits.sqlite"))
    with pytest.raises(RuntimeError, match="separate files"):
        create_from_env()
    monkeypatch.setenv("LOCAL_MCP_PASSKEY_DB", str(private / "passkeys.sqlite"))
    os.chmod(private / "permits.sqlite", 0o644)
    with pytest.raises(Exception, match="unsafe|unavailable"):
        create_from_env()
