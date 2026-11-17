"""Hosted owner approval is opt-in, issuer-pinned and client-isolated."""

from __future__ import annotations

import os
from pathlib import Path

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server.auth.provider import AccessToken

from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.gateway.issuer_keys import provision_issuer_key
from local_gpt_mcp.gateway.owner_portal import OwnerPortalConfig
from local_gpt_mcp.gateway.server import create_from_env, create_gateway
from local_gpt_mcp.policy.approval_queue import OwnerApprovalQueue
from local_gpt_mcp.policy.owner_presence import OwnerPresence

RESOURCE = "https://gateway.example.com/mcp"
PORTAL = OwnerPortalConfig(
    client_id="owner-public-client",
    authorization_endpoint="https://login.example.com/authorize",
    token_endpoint="https://login.example.com/token",
)


class Tokens:
    async def verify_token(self, token: str) -> AccessToken | None:
        if token not in {"owner-browser", "mcp-client"}:
            return None
        return AccessToken(
            token=token,
            client_id="owner-public-client" if token == "owner-browser" else "chatgpt-mcp",
            scopes=["approvals:manage", "devices:read"],
            subject="alice",
            resource=RESOURCE,
        )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCAL_MCP_RESOURCE_URL", RESOURCE)
    monkeypatch.setenv("LOCAL_MCP_ISSUER_URL", "https://login.example.com")
    monkeypatch.setenv("LOCAL_MCP_JWKS_URL", "https://login.example.com/jwks")
    for name in (
        "LOCAL_MCP_REMOTE_APPROVALS",
        "LOCAL_MCP_REMOTE_SINGLE_PROCESS_ACK",
        "LOCAL_MCP_APPROVAL_SIGNER_FILE",
        "LOCAL_MCP_PASSKEY_DB",
        "LOCAL_MCP_OWNER_CLIENT_ID",
        "LOCAL_MCP_OWNER_AUTHORIZE_URL",
        "LOCAL_MCP_OWNER_TOKEN_URL",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.anyio
async def test_default_hosted_gateway_never_exposes_owner_approval_or_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_env(monkeypatch)
    app = create_from_env()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        assert (await client.get("/owner/approve")).status_code in {404, 405}
        assert (await client.get("/api/owner/approvals")).status_code in {404, 405}
        assert (await client.post("/api/agent/actions/poll", json={})).status_code in {404, 405}


def test_untrusted_or_partial_remote_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_env(monkeypatch)
    monkeypatch.setenv("LOCAL_MCP_REMOTE_APPROVALS", "true")
    with pytest.raises(RuntimeError, match="explicitly"):
        create_from_env()
    monkeypatch.setenv("LOCAL_MCP_REMOTE_APPROVALS", "1")
    with pytest.raises(RuntimeError, match="single-process"):
        create_from_env()
    monkeypatch.setenv("LOCAL_MCP_REMOTE_SINGLE_PROCESS_ACK", "1")
    with pytest.raises(RuntimeError, match="required"):
        create_from_env()


@pytest.mark.anyio
@pytest.mark.skipif(os.name != "posix", reason="Private gateway issuer requires POSIX")
async def test_explicit_one_host_configuration_loads_portal_and_denies_unenrolled_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_env(monkeypatch)
    private = tmp_path / "operator"
    private.mkdir(mode=0o700)
    signer = private / "issuer.pem"
    provision_issuer_key(signer)
    monkeypatch.setenv("LOCAL_MCP_REMOTE_APPROVALS", "1")
    monkeypatch.setenv("LOCAL_MCP_REMOTE_SINGLE_PROCESS_ACK", "1")
    monkeypatch.setenv("LOCAL_MCP_APPROVAL_SIGNER_FILE", str(signer))
    monkeypatch.setenv("LOCAL_MCP_PASSKEY_DB", str(private / "passkeys.sqlite"))
    monkeypatch.setenv("LOCAL_MCP_OWNER_CLIENT_ID", PORTAL.client_id)
    monkeypatch.setenv("LOCAL_MCP_OWNER_AUTHORIZE_URL", PORTAL.authorization_endpoint)
    monkeypatch.setenv("LOCAL_MCP_OWNER_TOKEN_URL", PORTAL.token_endpoint)
    app = create_from_env()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        assert (await client.get("/owner/approve")).status_code == 200
        response = await client.get("/owner/approve-config")
        assert response.json()["client_id"] == PORTAL.client_id
        assert "issuer.pem" not in response.text
        assert (await client.get("/api/owner/approvals")).status_code == 403
        assert (await client.post("/api/agent/actions/poll", json={})).status_code == 403
    assert (private / "passkeys.sqlite").exists()


@pytest.mark.anyio
async def test_owner_approval_requires_pinned_browser_oauth_client() -> None:
    config = GatewayConfig(RESOURCE, "https://login.example.com", "https://login.example.com/jwks")
    presence = OwnerPresence(
        origin="https://gateway.example.com",
        receipt_signer=Ed25519PrivateKey.generate(),
        stopped=lambda: False,
    )
    app = create_gateway(
        config, verifier=Tokens(), approvals=OwnerApprovalQueue(presence), portal=PORTAL
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        model = await client.get(
            "/api/owner/approvals/credentials",
            headers={"Authorization": "Bearer mcp-client"},
        )
        assert model.status_code == 403
        owner = await client.get(
            "/api/owner/approvals/credentials",
            headers={"Authorization": "Bearer owner-browser"},
        )
        assert owner.status_code == 200
        assert owner.json() == {"credential_ids": []}
