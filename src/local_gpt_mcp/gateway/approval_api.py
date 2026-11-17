"""Separate owner-OAuth API: list, deny and passkey-confirm queued actions.

No endpoint here can create a pending action, register a passkey, return an
approval receipt, or execute native commands. Bearer identity alone never signs.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from mcp.server.auth.provider import TokenVerifier
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from local_gpt_mcp.agent.identity import DeviceAuthenticationError
from local_gpt_mcp.gateway.action_relay import RemoteActionRelay
from local_gpt_mcp.gateway.agent_api import _json, _owner
from local_gpt_mcp.policy.approval_queue import OwnerApprovalQueue
from local_gpt_mcp.policy.remote_receipts import RemoteApprovalDenied, _decode

APPROVAL_SCOPE = "approvals:manage"


def install_approval_routes(
    app: Starlette,
    approvals: OwnerApprovalQueue,
    verifier: TokenVerifier,
    resource: str,
    *,
    actions: RemoteActionRelay | None = None,
    owner_client_id: str | None = None,
) -> None:
    """Private non-MCP routes with owner token plus mandatory passkey assertions."""
    public = urlsplit(resource)
    host = public.netloc.casefold()
    origin = f"{public.scheme}://{public.netloc}"

    def safe(
        handler: Callable[[Request], Awaitable[JSONResponse]],
    ) -> Callable[[Request], Awaitable[JSONResponse]]:
        async def call(request: Request) -> JSONResponse:
            try:
                if request.headers.get("host", "").casefold() != host or request.headers.get(
                    "origin"
                ) not in (None, origin):
                    raise DeviceAuthenticationError("Untrusted owner approval origin")
                response = await handler(request)
            except (RemoteApprovalDenied, DeviceAuthenticationError, ValueError, TypeError):
                response = JSONResponse({"error": "Approval unavailable"}, status_code=403)
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response

        return call

    async def authenticate(request: Request) -> str:
        return await _owner(
            request, verifier, resource, scope=APPROVAL_SCOPE, client_id=owner_client_id
        )

    @safe
    async def list_pending(request: Request) -> JSONResponse:
        return JSONResponse({"approvals": approvals.list_owned(await authenticate(request))})

    @safe
    async def credential_ids(request: Request) -> JSONResponse:
        owner = await authenticate(request)
        return JSONResponse({"credential_ids": approvals.credential_ids(owner)})

    @safe
    async def begin(request: Request) -> JSONResponse:
        owner = await authenticate(request)
        data = await _json(request)
        job_id, credential_id = data.get("job_id"), data.get("credential_id")
        if not isinstance(job_id, str) or not isinstance(credential_id, str):
            raise RemoteApprovalDenied("Missing trusted owner approval input")
        challenge = approvals.begin(owner, job_id, credential_id)
        return JSONResponse(
            {
                "challenge": challenge.challenge,
                "expires_at": challenge.expires_at,
                "rp_id": public.hostname,
                "user_verification": "required",
                "credential_id": credential_id,
            }
        )

    @safe
    async def finish(request: Request) -> JSONResponse:
        owner = await authenticate(request)
        data = await _json(request)
        job_id, credential_id, challenge = (
            data.get("job_id"),
            data.get("credential_id"),
            data.get("challenge"),
        )
        if not (isinstance(job_id, str) and isinstance(credential_id, str) and isinstance(challenge, str)):
            raise RemoteApprovalDenied("Malformed owner assertion")
        approvals.finish(
            owner,
            job_id,
            credential_id,
            challenge,
            client_data=_decode(data.get("client_data", "")),
            authenticator_data=_decode(data.get("authenticator_data", "")),
            signature=_decode(data.get("signature", "")),
        )
        return JSONResponse({"approved": True})

    @safe
    async def deny(request: Request) -> JSONResponse:
        owner = await authenticate(request)
        data = await _json(request)
        job_id = data.get("job_id")
        if not isinstance(job_id, str):
            raise RemoteApprovalDenied("Invalid approval job")
        approvals.deny(owner, job_id)
        return JSONResponse({"denied": True})

    @safe
    async def halt(request: Request) -> JSONResponse:
        owner = await authenticate(request)
        if actions is None:
            approvals.halt_owner(owner)
        else:
            actions.halt_owner(owner)
        return JSONResponse({"approval_queue_halted": True})

    # No POST to enqueue/submit jobs; those require a separate trusted relay.
    app.router.routes[:0] = [
        Route("/api/owner/approvals", list_pending, methods=["GET"]),
        Route("/api/owner/approvals/credentials", credential_ids, methods=["GET"]),
        Route("/api/owner/approvals/begin", begin, methods=["POST"]),
        Route("/api/owner/approvals/finish", finish, methods=["POST"]),
        Route("/api/owner/approvals/deny", deny, methods=["POST"]),
        Route("/api/owner/approvals/halt", halt, methods=["POST"]),
    ]
