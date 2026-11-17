"""OAuth 2.1 resource-server verification against a trusted provider's JWKS.

This service does not issue tokens or accept passwords. The configured identity
provider must itself implement authorization-code + PKCE and client registration.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urlsplit

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken


def _https_url(url: str, *, require_mcp_path: bool = False) -> str:
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("A fixed HTTPS URL is required")
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.hostname in {"localhost", "127.0.0.1", "::1"}
        or (require_mcp_path and parts.path != "/mcp")
    ):
        raise ValueError("The gateway and identity provider require HTTPS public URLs")
    return url


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    """Operator-owned configuration, never accepted from an MCP caller."""

    resource_url: str
    issuer_url: str
    jwks_url: str

    def __post_init__(self) -> None:
        _https_url(self.resource_url, require_mcp_path=True)
        _https_url(self.issuer_url)
        _https_url(self.jwks_url)
        issuer = urlsplit(self.issuer_url)
        jwks = urlsplit(self.jwks_url)
        if (issuer.hostname, issuer.port) != (jwks.hostname, jwks.port):
            raise ValueError("JWKS must reside on the configured identity-provider host")
        # Pydantic AnyHttpUrl (used by MCP AuthSettings) canonicalizes a bare
        # issuer origin with a trailing slash; the JWT issuer MUST match it.
        if not issuer.path:
            object.__setattr__(self, "issuer_url", self.issuer_url + "/")


class JWTVerifier:
    """Verify the JWT signature, issuer, audience, times, identity and scopes."""

    def __init__(self, config: GatewayConfig) -> None:
        self._config = config
        self._keys = PyJWKClient(config.jwks_url, cache_jwk_set=True, lifespan=300, timeout=5)

    def _verify(self, raw: str) -> AccessToken | None:
        if not isinstance(raw, str) or not 0 < len(raw) <= 8192:
            return None
        try:
            key = self._keys.get_signing_key_from_jwt(raw)
            claims = jwt.decode(
                raw,
                key.key,
                algorithms=["RS256"],
                audience=self._config.resource_url,
                issuer=self._config.issuer_url,
                options={"require": ["aud", "exp", "iat", "nbf", "iss", "sub"]},
                leeway=15,
            )
        except (jwt.PyJWTError, ValueError, TypeError, OSError):
            return None
        subject = claims.get("sub")
        client = claims.get("client_id") or claims.get("azp")
        scope = claims.get("scope")
        expiry = claims.get("exp")
        if (
            not isinstance(subject, str)
            or not 0 < len(subject) <= 128
            or not isinstance(client, str)
            or not 0 < len(client) <= 2048
            or not isinstance(scope, str)
            or not isinstance(expiry, int)
        ):
            return None
        scopes = scope.split()
        if not scopes or len(scopes) > 32 or any(len(value) > 80 for value in scopes):
            return None
        return AccessToken(
            token=raw,
            client_id=client,
            scopes=scopes,
            expires_at=expiry,
            subject=subject,
            resource=self._config.resource_url,
            claims={"iss": self._config.issuer_url},
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        # JWKS retrieval is blocking; never block the MCP event loop.
        return await asyncio.to_thread(self._verify, token)
