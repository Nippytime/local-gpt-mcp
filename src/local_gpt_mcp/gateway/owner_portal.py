"""Optional static owner browser UI with separate OAuth PKCE and WebAuthn.

No bearer, approval receipts, issuer private keys, or native actions are served.
The owner portal must be explicitly enabled with a separately registered IdP
public client and same-issuer HTTPS authorize/token endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from local_gpt_mcp.gateway.auth import GatewayConfig

PORTAL_PATH = "/owner/approve"


def _auth_endpoint(url: str, config: GatewayConfig) -> str:
    parts = urlsplit(url)
    issuer = urlsplit(config.issuer_url)
    if (
        not isinstance(url, str)
        or not 0 < len(url) <= 2048
        or parts.scheme != "https"
        or parts.netloc.casefold() != issuer.netloc.casefold()
        or not parts.path.startswith("/")
        or parts.path == "/"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise ValueError("Owner OAuth endpoints must be fixed HTTPS paths on the pinned issuer")
    return url


@dataclass(frozen=True, slots=True)
class OwnerPortalConfig:
    """Operator-provisioned public SPA OAuth client; never the MCP model client."""

    client_id: str
    authorization_endpoint: str
    token_endpoint: str

    def validate(self, config: GatewayConfig) -> None:
        if not isinstance(self.client_id, str) or not 1 <= len(self.client_id) <= 256:
            raise ValueError("Explicit owner-browser OAuth public client ID is required")
        _auth_endpoint(self.authorization_endpoint, config)
        _auth_endpoint(self.token_endpoint, config)


def install_owner_portal(app: Starlette, config: GatewayConfig, portal: OwnerPortalConfig) -> None:
    """Serve same-origin static UI only when explicitly operator configured."""
    portal.validate(config)
    gateway = urlsplit(config.resource_url)
    origin = f"{gateway.scheme}://{gateway.netloc}"
    idp_origin = f"https://{urlsplit(config.issuer_url).netloc}"
    assets = files("local_gpt_mcp.gateway").joinpath("assets")
    content = {
        "html": assets.joinpath("owner.html").read_text(encoding="utf-8"),
        "js": assets.joinpath("owner.js").read_text(encoding="utf-8"),
        "css": assets.joinpath("owner.css").read_text(encoding="utf-8"),
    }
    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "publickey-credentials-get=(self)",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            f"connect-src 'self' {idp_origin}; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
        ),
    }

    def allowed(request: Request) -> bool:
        return request.headers.get("host", "").casefold() == gateway.netloc.casefold() and request.headers.get(
            "origin"
        ) in (None, origin)

    async def page(request: Request) -> Response:
        if not allowed(request):
            return PlainTextResponse("Unavailable", status_code=403, headers=headers)
        return HTMLResponse(content["html"], headers=headers)

    async def script(request: Request) -> Response:
        if not allowed(request):
            return PlainTextResponse("Unavailable", status_code=403, headers=headers)
        return Response(content["js"], media_type="text/javascript", headers=headers)

    async def style(request: Request) -> Response:
        if not allowed(request):
            return PlainTextResponse("Unavailable", status_code=403, headers=headers)
        return Response(content["css"], media_type="text/css", headers=headers)

    async def settings(request: Request) -> Response:
        if not allowed(request):
            return JSONResponse({"error": "Unavailable"}, status_code=403, headers=headers)
        return JSONResponse(
            {
                "client_id": portal.client_id,
                "authorization_endpoint": portal.authorization_endpoint,
                "token_endpoint": portal.token_endpoint,
                "resource": config.resource_url,
                "redirect_uri": origin + PORTAL_PATH,
            },
            headers=headers,
        )

    app.router.routes[:0] = [
        Route(PORTAL_PATH, page, methods=["GET"]),
        Route("/owner/approve.js", script, methods=["GET"]),
        Route("/owner/approve.css", style, methods=["GET"]),
        Route("/owner/approve-config", settings, methods=["GET"]),
    ]
