"""The standalone owner portal stays opt-in, same-origin and secret-free."""

from __future__ import annotations

import httpx2 as httpx
import pytest
from starlette.applications import Starlette

from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.gateway.owner_portal import OwnerPortalConfig, install_owner_portal

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
async def test_install_is_explicit_and_same_origin_with_strict_browser_headers() -> None:
    app = Starlette()
    assert not any(getattr(route, "path", "") == "/owner/approve" for route in app.routes)
    install_owner_portal(app, CONFIG, PORTAL)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        for path in (
            "/owner/approve",
            "/owner/approve.js",
            "/owner/approve.css",
            "/owner/approve-config",
        ):
            response = await client.get(path)
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"
            csp = response.headers["content-security-policy"]
            assert "default-src 'none'" in csp
            assert "script-src 'self'" in csp
            assert "frame-ancestors 'none'" in csp
            assert "unsafe-inline" not in csp
            for headers in (
                {"Host": "evil.example.com"},
                {"Origin": "https://evil.example.com"},
            ):
                assert (await client.get(path, headers=headers)).status_code == 403

        page = (await client.get("/owner/approve")).text
        assert '<script type="module" src="/owner/approve.js"></script>' in page
        assert "access_token" not in page
        settings = (await client.get("/owner/approve-config")).json()
        assert settings == {
            "client_id": PORTAL.client_id,
            "authorization_endpoint": PORTAL.authorization_endpoint,
            "token_endpoint": PORTAL.token_endpoint,
            "resource": CONFIG.resource_url,
            "redirect_uri": "https://gateway.example.com/owner/approve",
        }
        script = (await client.get("/owner/approve.js")).text
        assert "navigator.credentials.get" in script
        assert '"code_challenge_method", "S256"' in script
        assert 'userVerification: "required"' in script
        assert "localStorage" not in script
        assert "innerHTML" not in script


@pytest.mark.anyio
async def test_portal_is_absent_without_explicit_installation() -> None:
    app = Starlette()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.example.com"
    ) as client:
        assert (await client.get("/owner/approve")).status_code == 404


def test_owner_portal_rejects_unpinned_issuer_and_missing_public_client() -> None:
    with pytest.raises(ValueError):
        OwnerPortalConfig("", PORTAL.authorization_endpoint, PORTAL.token_endpoint).validate(CONFIG)
    for endpoint in (
        "http://login.example.com/oauth/authorize",
        "https://evil.example.com/oauth/authorize",
        "https://login.example.com/oauth/authorize?redirect=evil",
    ):
        with pytest.raises(ValueError):
            OwnerPortalConfig(PORTAL.client_id, endpoint, PORTAL.token_endpoint).validate(CONFIG)
