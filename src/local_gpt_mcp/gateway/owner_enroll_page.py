"""Opt-in, same-origin OAuth PKCE owner browser first-passkey enrollment page.

This serves only static UI and public OAuth discovery; the independently
authorized WebAuthn API validates the authenticated owner and operator permit.
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
from local_gpt_mcp.gateway.owner_registration import OwnerEnrollmentAPI

PAGE_PATH = "/owner/enroll"


def _issuer_endpoint(value: str, config: GatewayConfig) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("A pinned public OAuth URL is required")
    url, issuer = urlsplit(value), urlsplit(config.issuer_url)
    if (
        url.scheme != "https"
        or url.netloc.casefold() != issuer.netloc.casefold()
        or not url.path.startswith("/")
        or url.path == "/"
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
    ):
        raise ValueError("Owner OAuth endpoints must be fixed paths on the configured issuer")
    return value


@dataclass(frozen=True, slots=True)
class OwnerEnrollmentPageConfig:
    client_id: str
    authorization_endpoint: str
    token_endpoint: str

    def validate(self, config: GatewayConfig, service: OwnerEnrollmentAPI) -> None:
        if not isinstance(self.client_id, str) or not 1 <= len(self.client_id) <= 256:
            raise ValueError("A separate owner OAuth browser client ID is required")
        service.require_browser_client(self.client_id)
        _issuer_endpoint(self.authorization_endpoint, config)
        _issuer_endpoint(self.token_endpoint, config)


def install_owner_enrollment_page(
    app: Starlette,
    config: GatewayConfig,
    page: OwnerEnrollmentPageConfig,
    service: OwnerEnrollmentAPI,
) -> None:
    """Do not install unless the operator supplies the real, matching enrollment service."""
    service.require_gateway_binding(config, service.verifier)
    page.validate(config, service)
    resource = urlsplit(config.resource_url)
    origin = f"{resource.scheme}://{resource.netloc}"
    issuer_origin = f"https://{urlsplit(config.issuer_url).netloc}"
    assets = files("local_gpt_mcp.gateway").joinpath("assets")
    html = assets.joinpath("enroll.html").read_text(encoding="utf-8")
    js = assets.joinpath("enroll.js").read_text(encoding="utf-8")
    css = assets.joinpath("enroll.css").read_text(encoding="utf-8")
    headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Strict-Transport-Security": "max-age=31536000",
        "Permissions-Policy": "publickey-credentials-create=(self)",
        "Content-Security-Policy": (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            f"connect-src 'self' {issuer_origin}; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
        ),
    }

    def allowed(request: Request) -> bool:
        return (
            request.headers.get("host", "").casefold() == resource.netloc.casefold()
            and request.headers.get("origin") in (None, origin)
        )

    async def document(request: Request) -> Response:
        if not allowed(request):
            return PlainTextResponse("Unavailable", status_code=403, headers=headers)
        return HTMLResponse(html, headers=headers)

    async def script(request: Request) -> Response:
        if not allowed(request):
            return PlainTextResponse("Unavailable", status_code=403, headers=headers)
        return Response(js, media_type="text/javascript", headers=headers)

    async def style(request: Request) -> Response:
        if not allowed(request):
            return PlainTextResponse("Unavailable", status_code=403, headers=headers)
        return Response(css, media_type="text/css", headers=headers)

    async def settings(request: Request) -> Response:
        if not allowed(request):
            return JSONResponse({"error": "Unavailable"}, status_code=403, headers=headers)
        return JSONResponse(
            {
                "client_id": page.client_id,
                "authorization_endpoint": page.authorization_endpoint,
                "token_endpoint": page.token_endpoint,
                "resource": config.resource_url,
                "redirect_uri": origin + PAGE_PATH,
            },
            headers=headers,
        )

    app.router.routes[:0] = [
        Route(PAGE_PATH, document, methods=["GET"]),
        Route("/owner/enroll.js", script, methods=["GET"]),
        Route("/owner/enroll.css", style, methods=["GET"]),
        Route("/owner/enroll-config", settings, methods=["GET"]),
    ]
