"""Optional owner browser portal is explicitly configured, same-origin and token-free."""

from __future__ import annotations

import httpx2 as httpx
import pytest

from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.gateway.owner_portal import OwnerPortalConfig
from local_gpt_mcp.gateway.server import create_gateway

CONFIG = GatewayConfig(
    resource_url="https://gateway.example.com/mcp",
    issuer_url="https://login.example.com",
    jwks_url="https://login.example.com/keys",
)
PORTAL = OwnerPortalConfig(
    client_id="owner-browser-public-client",
    authorization_endpoint="https://login.example.com/oauth/authorize",
    token_endpoint="https://login.example.com/oauth/token",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_opt_in_page_is_same_origin_private_and_no_secret() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from local_gpt_mcp.policy.approval_queue import OwnerApprovalQueue
    from local_gpt_mcp.policy.owner_presence import OwnerPresence

    presence = OwnerPresence(
        origin="https://gateway.example.com",
        receipt_signer=Ed25519PrivateKey.generate(),
        stopped=lambda: False,
    )
    app = create_gateway(CONFIG, approvals=OwnerApprovalQueue(presence), portal=PORTAL)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        page = await client.get("/owner/approve")
        assert page.status_code == 200
        assert "Approve actions on your PC" in page.text
        assert '<script type="module" src="/owner/approve.js"></script>' in page.text
        assert "inline" not in page.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        assert page.headers["cache-control"] == "no-store"
        assert page.headers["x-frame-options"] == "DENY"
        assert "access_token" not in page.text
        settings = await client.get("/owner/approve-config")
        assert settings.status_code == 200
        assert settings.json()["redirect_uri"] == "https://gateway.example.com/owner/approve"
        assert settings.json()["client_id"] == PORTAL.client_id
        assert "client_secret" not in settings.text
        script = await client.get("/owner/approve.js")
        assert script.status_code == 200
        assert "navigator.credentials.get" in script.text
        assert 'code_challenge_method", "S256"' in script.text
        assert "localStorage" not in script.text
        assert "innerHTML" not in script.text
        for headers in ({"Host": "evil.example.com"}, {"Origin": "https://evil.example.com"}):
            assert (await client.get("/owner/approve", headers=headers)).status_code == 403


@pytest.mark.anyio
async def test_portal_not_enabled_in_default_gateway() -> None:
    app = create_gateway(CONFIG)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        assert (await client.get("/owner/approve")).status_code in {404, 405}


def test_portal_configuration_refuses_redirected_or_unpinned_idp() -> None:
    with pytest.raises(ValueError):
        OwnerPortalConfig("browser", "https://evil.example.com/authorize", PORTAL.token_endpoint).validate(CONFIG)
    with pytest.raises(ValueError):
        OwnerPortalConfig("browser", "http://login.example.com/authorize", PORTAL.token_endpoint).validate(CONFIG)
    with pytest.raises(ValueError):
        OwnerPortalConfig("browser", PORTAL.authorization_endpoint, "https://login.example.com/token?x=1").validate(
            CONFIG
        )
