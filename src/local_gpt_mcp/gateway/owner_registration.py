"""Opt-in first-owner WebAuthn registration, separate from MCP tool authority.

Only a preconfigured, dedicated browser OAuth client can invoke these routes.
The operator permit is issued out of band; no HTTP route can create a permit.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from mcp.server.auth.provider import TokenVerifier
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.policy.authority import valid_identifier
from local_gpt_mcp.policy.bootstrap import BootstrapDenied, SQLiteBootstrapPermits, first_owner_registration
from local_gpt_mcp.policy.credential_store import CredentialStoreDenied, SQLiteCredentialStore
from local_gpt_mcp.policy.registration import OperatorAuthorizedRegistration, RegistrationDenied

ENROLL_SCOPE = "owner:enroll"
MAX_BODY_BYTES = 16_384
MAX_PENDING = 128
CEREMONY_TTL = 60
DENIED = {"error": "Owner enrollment unavailable"}
NO_STORE = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'",
}


@dataclass(frozen=True, slots=True)
class _Pending:
    owner: str
    client_id: str
    token_digest: bytes
    expires_at: float
    challenge: str
    registrar: OperatorAuthorizedRegistration


class OwnerEnrollmentAPI:
    """Opt-in server-local owner browser endpoints; never registered as MCP tools."""

    def __init__(
        self,
        *,
        config: GatewayConfig,
        verifier: TokenVerifier,
        permits: SQLiteBootstrapPermits,
        credentials: SQLiteCredentialStore,
        browser_client_id: str,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(browser_client_id, str) or not 1 <= len(browser_client_id) <= 2048:
            raise ValueError("A separate owner-browser OAuth client ID is mandatory")
        self._host = urlsplit(config.resource_url).netloc.casefold()
        self._origin = "https://" + urlsplit(config.resource_url).netloc
        self._resource = config.resource_url
        self._verifier = verifier
        self._permits = permits
        self._credentials = credentials
        self._client_id = browser_client_id
        self._clock = clock
        self._lock = threading.RLock()
        self._pending: dict[str, _Pending] = {}

    async def _identity(self, request: Request) -> tuple[str, str, bytes]:
        if (
            request.headers.get("host", "").casefold() != self._host
            or request.headers.get("origin") != self._origin
            or request.headers.get("sec-fetch-site") != "same-origin"
            or request.headers.get("content-type") != "application/json"
        ):
            raise RegistrationDenied("Untrusted owner browser origin")
        scheme, sep, bearer = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not sep or not 0 < len(bearer) <= 8192 or " " in bearer:
            raise RegistrationDenied("Owner browser authentication required")
        access = await self._verifier.verify_token(bearer)
        if (
            access is None
            or access.resource != self._resource
            or not valid_identifier(access.subject)
            or access.client_id != self._client_id
            or ENROLL_SCOPE not in access.scopes
        ):
            raise RegistrationDenied("Dedicated owner OAuth grant required")
        return access.subject, access.client_id, hashlib.sha256(bearer.encode("utf-8")).digest()

    @staticmethod
    async def _json(request: Request) -> dict[str, object]:
        length = request.headers.get("content-length")
        if length is not None and (not length.isdecimal() or int(length) > MAX_BODY_BYTES):
            raise RegistrationDenied("Untrusted enrollment request")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_BODY_BYTES:
                raise RegistrationDenied("Untrusted enrollment request")

        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            obj: dict[str, object] = {}
            for key, value in pairs:
                if key in obj:
                    raise RegistrationDenied("Duplicate enrollment field")
                obj[key] = value
            return obj

        data = json.loads(body, object_pairs_hook=unique_pairs)
        if not isinstance(data, dict):
            raise RegistrationDenied("Expected enrollment object")
        return data

    async def begin(self, request: Request) -> JSONResponse:
        try:
            owner, client, digest = await self._identity(request)
            data = await self._json(request)
            code = data.get("operator_code")
            if set(data) != {"operator_code"} or not isinstance(code, str):
                raise RegistrationDenied("Operator permit required")
            now = self._clock()
            with self._lock:
                self._pending = {k: v for k, v in self._pending.items() if v.expires_at > now}
                if len(self._pending) >= MAX_PENDING:
                    raise RegistrationDenied("Enrollment capacity exhausted")
            registrar = await asyncio.to_thread(
                first_owner_registration,
                owner=owner,
                code=code,
                origin=self._origin,
                permits=self._permits,
                credentials=self._credentials,
            )
            started = await asyncio.to_thread(registrar.begin, owner)
            ceremony = secrets.token_urlsafe(24)
            with self._lock:
                if len(self._pending) >= MAX_PENDING:
                    raise RegistrationDenied("Enrollment capacity exhausted")
                self._pending[ceremony] = _Pending(
                    owner, client, digest, now + CEREMONY_TTL, started.challenge, registrar
                )
            return JSONResponse(
                {"ceremony_id": ceremony, "options": json.loads(started.options_json)},
                headers=NO_STORE,
            )
        except (BootstrapDenied, CredentialStoreDenied, RegistrationDenied, ValueError, TypeError):
            return JSONResponse(DENIED, status_code=403, headers=NO_STORE)

    async def finish(self, request: Request) -> JSONResponse:
        try:
            owner, client, digest = await self._identity(request)
            data = await self._json(request)
            ceremony, challenge, credential = (
                data.get("ceremony_id"),
                data.get("challenge"),
                data.get("credential"),
            )
            if (
                set(data) != {"ceremony_id", "challenge", "credential"}
                or not isinstance(ceremony, str)
                or not isinstance(challenge, str)
                or not isinstance(credential, dict)
                or len(ceremony) > 64
            ):
                raise RegistrationDenied("Invalid owner enrollment ceremony")
            with self._lock:
                pending = self._pending.pop(ceremony, None)
            if (
                pending is None
                or pending.expires_at <= self._clock()
                or pending.owner != owner
                or pending.client_id != client
                or pending.token_digest != digest
                or pending.challenge != challenge
            ):
                raise RegistrationDenied("Expired or foreign owner ceremony")
            credential_id = await asyncio.to_thread(pending.registrar.finish, owner, challenge, credential)
            return JSONResponse({"registered": True, "credential_id": credential_id}, headers=NO_STORE)
        except (BootstrapDenied, CredentialStoreDenied, RegistrationDenied, ValueError, TypeError):
            return JSONResponse(DENIED, status_code=403, headers=NO_STORE)


def install_owner_enrollment_routes(app: Starlette, service: OwnerEnrollmentAPI) -> None:
    """Routes are absent unless an operator explicitly supplies the service."""
    app.router.routes[:0] = [
        Route("/api/owner/passkey/begin", service.begin, methods=["POST"]),
        Route("/api/owner/passkey/finish", service.finish, methods=["POST"]),
    ]
