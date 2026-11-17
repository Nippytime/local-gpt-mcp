"""Separate OAuth-owner and device-signed outbound endpoints.

These are not MCP tools. Device enrollment is explicitly owner-generated, and
the agent can only poll and answer bounded read requests on its own identity.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

from mcp.server.auth.provider import AccessToken, TokenVerifier
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from local_gpt_mcp.agent.identity import MAX_BODY, DeviceAuthenticationError
from local_gpt_mcp.gateway.action_relay import RemoteActionRelay
from local_gpt_mcp.gateway.agent_relay import AgentRelay
from local_gpt_mcp.gateway.registry import DeviceUnavailable

OWNER_SCOPE = "devices:manage"


async def _owner(request: Request, verify: TokenVerifier, resource: str, *, scope: str = OWNER_SCOPE) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 8192:
        raise DeviceAuthenticationError("Owner authentication required")
    auth: AccessToken | None = await verify.verify_token(token)
    if auth is None or scope not in auth.scopes or not auth.subject or auth.resource != resource:
        raise DeviceAuthenticationError("Owner access denied")
    return auth.subject


async def _bounded_body(request: Request) -> bytes:
    """Read an unauthenticated streamed body without unbounded buffering."""
    length = request.headers.get("content-length")
    if length is not None and (not length.isdecimal() or int(length) > MAX_BODY):
        raise DeviceAuthenticationError("Body too large")
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > MAX_BODY:
            raise DeviceAuthenticationError("Body too large")
    return bytes(data)


async def _json(request: Request, body: bytes | None = None) -> dict[str, Any]:
    raw = await _bounded_body(request) if body is None else body
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise DeviceAuthenticationError("Invalid request body") from error
    if not isinstance(data, dict):
        raise DeviceAuthenticationError("Expected request object")
    return data


def install_agent_routes(
    app: Starlette,
    relay: AgentRelay,
    verifier: TokenVerifier,
    resource: str,
    *,
    actions: RemoteActionRelay | None = None,
) -> None:
    """Add bounded, separately authenticated agent/control APIs to MCP's ASGI app."""
    public = urlsplit(resource)
    host = public.netloc.casefold()
    origin = f"{public.scheme}://{public.netloc}"

    def safe(
        handler: Callable[[Request], Awaitable[JSONResponse]],
    ) -> Callable[[Request], Awaitable[JSONResponse]]:
        async def call(request: Request) -> JSONResponse:
            try:
                # The MCP SDK's transport Host/Origin policy must also apply
                # to these additional non-MCP endpoints.
                if request.headers.get("host", "").casefold() != host or request.headers.get(
                    "origin"
                ) not in (None, origin):
                    raise DeviceAuthenticationError("Untrusted gateway host or browser origin")
                return await handler(request)
            except (DeviceAuthenticationError, DeviceUnavailable, ValueError, TypeError):
                # Do not disclose ownership, enrollment details or signature results.
                return JSONResponse({"error": "Unauthorized or unavailable"}, status_code=403)

        return call

    @safe
    async def owner_enrollment(request: Request) -> JSONResponse:
        owner = await _owner(request, verifier, resource)
        data = await _json(request)
        label = data.get("label")
        if not isinstance(label, str):
            raise DeviceAuthenticationError("Device name required")
        code, device_id = relay.issue_code(owner, label)
        return JSONResponse({"device_id": device_id, "enrollment_code": code, "expires_in": 180})

    @safe
    async def owner_revoke(request: Request) -> JSONResponse:
        owner = await _owner(request, verifier, resource)
        data = await _json(request)
        device_id = data.get("device_id")
        if not isinstance(device_id, str):
            raise DeviceAuthenticationError("Device required")
        relay.revoke(owner, device_id)
        return JSONResponse({"revoked": True})

    @safe
    async def agent_enroll(request: Request) -> JSONResponse:
        data = await _json(request)
        code, device, key = data.get("enrollment_code"), data.get("device_id"), data.get("public_key")
        if not (isinstance(code, str) and isinstance(device, str) and isinstance(key, str)):
            raise DeviceAuthenticationError("Invalid enrollment request")
        relay.enroll(code, device, key)
        return JSONResponse({"enrolled": True})

    async def authenticated_agent(request: Request) -> tuple[str, str, dict[str, Any]]:
        body = await _bounded_body(request)
        device_id = request.headers.get("x-device-id", "")
        owner = relay.authenticate(device_id, request.url.path, body, request.headers)
        data = await _json(request, body)
        return owner, device_id, data

    @safe
    async def agent_poll(request: Request) -> JSONResponse:
        owner, device_id, data = await authenticated_agent(request)
        if data:
            raise DeviceAuthenticationError("Poll payload must be empty")
        return JSONResponse(relay.poll(owner, device_id))

    @safe
    async def agent_result(request: Request) -> JSONResponse:
        owner, device_id, data = await authenticated_agent(request)
        job_id, output = data.get("job_id"), data.get("result")
        if not isinstance(job_id, str) or not isinstance(output, dict):
            raise DeviceAuthenticationError("Invalid bounded response")
        if len(output) > 32 or any(
            not isinstance(key, str) or not 0 < len(key) <= 80 or not isinstance(value, str | int | bool)
            for key, value in output.items()
        ):
            raise DeviceAuthenticationError("Invalid response values")
        relay.reply(owner, device_id, job_id, output)
        return JSONResponse({"accepted": True})

    @safe
    async def action_poll(request: Request) -> JSONResponse:
        if actions is None:
            raise DeviceUnavailable("Remote actions not configured")
        owner, device_id, data = await authenticated_agent(request)
        if data:
            raise DeviceAuthenticationError("Poll payload must be empty")
        return JSONResponse(actions.poll_trusted(owner, device_id))

    @safe
    async def action_result(request: Request) -> JSONResponse:
        if actions is None:
            raise DeviceUnavailable("Remote actions not configured")
        owner, device_id, data = await authenticated_agent(request)
        job_id, result = data.get("job_id"), data.get("result")
        if not isinstance(job_id, str) or not isinstance(result, dict):
            raise DeviceAuthenticationError("Invalid bounded action result")
        actions.reply_trusted(owner, device_id, job_id, result)
        return JSONResponse({"accepted": True})

    # Before generic MCP transport routes: never allow a catch-all mount
    # to shadow authenticated enrollment or signed agent endpoints.
    app.router.routes[:0] = [
        Route("/api/owner/enrollments", owner_enrollment, methods=["POST"]),
        Route("/api/owner/revoke", owner_revoke, methods=["POST"]),
        Route("/api/agent/enroll", agent_enroll, methods=["POST"]),
        Route("/api/agent/poll", agent_poll, methods=["POST"]),
        Route("/api/agent/result", agent_result, methods=["POST"]),
    ]
    if actions is not None:
        app.router.routes[:0] = [
            Route("/api/agent/actions/poll", action_poll, methods=["POST"]),
            Route("/api/agent/actions/result", action_result, methods=["POST"]),
        ]
