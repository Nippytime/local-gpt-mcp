"""OAuth-protected, tenant-isolated Streamable HTTP MCP gateway.

This component cannot start the local desktop, grant permissions or approve input.
An agent and trusted remote-approval flow are separate future delivery issues.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette

from local_gpt_mcp.gateway.action_relay import RemoteActionRelay
from local_gpt_mcp.gateway.agent_api import install_agent_routes
from local_gpt_mcp.gateway.agent_relay import AgentRelay
from local_gpt_mcp.gateway.approval_api import install_approval_routes
from local_gpt_mcp.gateway.auth import GatewayConfig, JWTVerifier
from local_gpt_mcp.gateway.owner_enroll_page import OwnerEnrollmentPageConfig, install_owner_enrollment_page
from local_gpt_mcp.gateway.owner_portal import OwnerPortalConfig, install_owner_portal
from local_gpt_mcp.gateway.owner_registration import OwnerEnrollmentAPI, install_owner_enrollment_routes
from local_gpt_mcp.gateway.registry import DeviceDirectory, DeviceUnavailable, ReadRequest
from local_gpt_mcp.policy.approval_queue import OwnerApprovalQueue
from local_gpt_mcp.policy.bootstrap import SQLiteBootstrapPermits
from local_gpt_mcp.policy.credential_store import SQLiteCredentialStore
from local_gpt_mcp.policy.stop_ledger import SQLiteStopLedger

READ_SCOPE = "devices:read"


WRITE_SCOPE = "devices:input"


def _owner(scope: str = READ_SCOPE) -> str:
    verified = get_access_token()
    if (
        verified is None
        or READ_SCOPE not in verified.scopes
        or scope not in verified.scopes
        or not verified.subject
    ):
        raise DeviceUnavailable("An authenticated owner grant is required")
    return verified.subject


def create_gateway_server(
    config: GatewayConfig,
    *,
    directory: DeviceDirectory | None = None,
    verifier: TokenVerifier | None = None,
    actions: RemoteActionRelay | None = None,
) -> MCPServer:
    """Register tools while keeping every principal derived from verified OAuth."""
    store = directory if directory is not None else DeviceDirectory()
    mcp = MCPServer(
        "Local GPT Web Gateway",
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(config.issuer_url),
            resource_server_url=AnyHttpUrl(config.resource_url),
            required_scopes=[READ_SCOPE],
            validate_token_resource=True,
        ),
        token_verifier=verifier if verifier is not None else JWTVerifier(config),
    )

    @mcp.tool()
    def list_my_devices() -> dict[str, list[dict[str, str | bool]]]:
        """List only your authenticated account's enrolled Windows PCs."""
        return {"devices": store.list_owned(_owner())}

    @mcp.tool()
    def device_status(device_id: str) -> dict[str, str | bool]:
        """Read only your own registered PC's online and offline status."""
        return store.status(_owner(), device_id)

    @mcp.tool()
    async def read_from_device(
        device_id: str, kind: str, target: str, selector: str = ""
    ) -> dict[str, str | int | bool]:
        """Request an allowlisted read; deny when the secure local agent is unavailable."""
        owner = _owner()
        request = ReadRequest(kind=kind, target=target, selector=selector)
        return await store.read(owner, device_id, request)

    if actions is not None:

        @mcp.tool()
        async def request_device_click(
            device_id: str, session_id: str, target: str, x: int, y: int
        ) -> dict[str, str | int | bool]:
            """Request one click: requires separate owner passkey and local PC policy.

            Never self-approve. Remote actions are disabled in default hosting.
            """
            owner = _owner(WRITE_SCOPE)
            return await actions.request_trusted(
                owner, device_id, session_id, target, "window.click", {"x": x, "y": y}
            )

    return mcp


def create_gateway(
    config: GatewayConfig,
    *,
    directory: DeviceDirectory | None = None,
    verifier: TokenVerifier | None = None,
    relay: AgentRelay | None = None,
    owner_client_id: str | None = None,
    approvals: OwnerApprovalQueue | None = None,
    actions: RemoteActionRelay | None = None,
    portal: OwnerPortalConfig | None = None,
    owner_enrollment: OwnerEnrollmentAPI | None = None,
    enrollment_page: OwnerEnrollmentPageConfig | None = None,
) -> Starlette:
    """Expose the authenticated MCP server plus optional outbound-only agent APIs."""
    token_verifier = verifier if verifier is not None else JWTVerifier(config)
    if owner_client_id is not None and (
        not isinstance(owner_client_id, str) or not 1 <= len(owner_client_id) <= 256
    ):
        raise ValueError("Explicit independent owner-browser OAuth client ID is required")
    if actions is not None and (relay is None or approvals is None or actions.approvals is not approvals):
        raise ValueError("Remote action endpoints require the matching trusted relay and approval queue")
    if portal is not None and approvals is None:
        raise ValueError("Owner portal requires a separately configured approval queue")
    if relay is not None:
        if directory is None:
            directory = DeviceDirectory(relay)
        relay.bind(directory)
    mcp = create_gateway_server(config, directory=directory, verifier=token_verifier, actions=actions)
    host = urlsplit(config.resource_url).hostname
    assert host is not None
    origin = "https://" + urlsplit(config.resource_url).netloc
    app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[host, host + ":*"],
            allowed_origins=[origin],
        ),
    )
    if relay is not None:
        install_agent_routes(
            app,
            relay,
            token_verifier,
            config.resource_url,
            actions=actions,
            owner_client_id=owner_client_id or (portal.client_id if portal is not None else None),
        )
    if approvals is not None:
        install_approval_routes(
            app,
            approvals,
            token_verifier,
            config.resource_url,
            actions=actions,
            owner_client_id=portal.client_id if portal is not None else None,
            stop_owner=relay.halt_owner if actions is not None and relay is not None else None,
        )
    if portal is not None:
        install_owner_portal(app, config, portal)
    if enrollment_page is not None and owner_enrollment is None:
        raise ValueError("Owner browser UI requires independently authorized enrollment API")
    if owner_enrollment is not None:
        owner_enrollment.require_gateway_binding(config, token_verifier)
        install_owner_enrollment_routes(app, owner_enrollment)
        if enrollment_page is not None:
            install_owner_enrollment_page(app, config, enrollment_page, owner_enrollment)
    return app


def create_from_env() -> Starlette:
    """A hosted process must supply real operator-controlled identity settings."""
    import os

    keys = ["LOCAL_MCP_RESOURCE_URL", "LOCAL_MCP_ISSUER_URL", "LOCAL_MCP_JWKS_URL"]
    if any(not os.environ.get(key) for key in keys):
        raise RuntimeError("Hosted gateway requires an HTTPS resource, issuer and JWKS URL")
    config = GatewayConfig(*(os.environ[key] for key in keys))
    stop_path = os.environ.get("LOCAL_MCP_STOP_DB")
    stops = SQLiteStopLedger(Path(stop_path)) if stop_path is not None else None
    client_id = os.environ.get("LOCAL_MCP_OWNER_CLIENT_ID")
    relay = AgentRelay(stops=stops)
    approvals: OwnerApprovalQueue | None = None
    actions: RemoteActionRelay | None = None
    portal: OwnerPortalConfig | None = None
    remote_mode = os.environ.get("LOCAL_MCP_REMOTE_APPROVALS", "0")
    if remote_mode == "1":
        if os.environ.get("LOCAL_MCP_REMOTE_SINGLE_PROCESS_ACK") != "1":
            raise RuntimeError("Remote approvals require explicit single-process deployment acknowledgment")
        required = [
            "LOCAL_MCP_APPROVAL_SIGNER_FILE",
            "LOCAL_MCP_PASSKEY_DB",
            "LOCAL_MCP_OWNER_CLIENT_ID",
            "LOCAL_MCP_OWNER_AUTHORIZE_URL",
            "LOCAL_MCP_OWNER_TOKEN_URL",
        ]
        if any(not os.environ.get(name) for name in required):
            raise RuntimeError(
                "Remote approval issuer, passkey store and pinned owner OAuth client are required"
            )

        from local_gpt_mcp.gateway.issuer_keys import load_issuer_key
        from local_gpt_mcp.policy.owner_presence import OwnerPresence
        from local_gpt_mcp.policy.passkey_store import SQLitePasskeys

        issuer_path = Path(os.environ["LOCAL_MCP_APPROVAL_SIGNER_FILE"])
        passkey_path = Path(os.environ["LOCAL_MCP_PASSKEY_DB"])
        if passkey_path.parent != issuer_path.parent:
            raise RuntimeError("Passkey database must share the private issuer directory")
        if stops is None:
            raise RuntimeError("Remote approvals require a durable STOP ledger")
        signer = load_issuer_key(issuer_path)
        approval_credentials = SQLitePasskeys(passkey_path)
        origin = config.resource_url.removesuffix("/mcp")
        presence = OwnerPresence(
            origin=origin,
            receipt_signer=signer,
            stopped=lambda: False,
            credential_store=approval_credentials,
        )
        approvals = OwnerApprovalQueue(presence, connected=relay.connected)
        actions = RemoteActionRelay(approvals, connected=relay.connected)
        portal = OwnerPortalConfig(
            client_id=os.environ["LOCAL_MCP_OWNER_CLIENT_ID"],
            authorization_endpoint=os.environ["LOCAL_MCP_OWNER_AUTHORIZE_URL"],
            token_endpoint=os.environ["LOCAL_MCP_OWNER_TOKEN_URL"],
        )
        portal.validate(config)
    elif remote_mode != "0":
        raise RuntimeError("Remote approvals must be explicitly enabled with 1 or disabled with 0")

    mode = os.environ.get("LOCAL_MCP_OWNER_ENROLLMENT", "0")
    if mode == "0":
        return create_gateway(
            config,
            relay=relay,
            owner_client_id=client_id,
            approvals=approvals,
            actions=actions,
            portal=portal,
        )
    if mode != "1":
        raise RuntimeError("Owner enrollment must be explicitly enabled with 1 or disabled with 0")
    if os.environ.get("LOCAL_MCP_OWNER_SINGLE_PROCESS_ACK") != "1":
        raise RuntimeError("Owner enrollment requires explicit single-worker pilot acknowledgment")
    required = [
        "LOCAL_MCP_OWNER_CLIENT_ID",
        "LOCAL_MCP_OWNER_AUTHORIZE_URL",
        "LOCAL_MCP_OWNER_TOKEN_URL",
        "LOCAL_MCP_OWNER_PERMIT_DB",
        "LOCAL_MCP_PASSKEY_DB",
    ]
    if any(not os.environ.get(key) for key in required):
        raise RuntimeError("Owner enrollment requires an independent OAuth client and private stores")
    permit_path = Path(os.environ["LOCAL_MCP_OWNER_PERMIT_DB"])
    credential_path = Path(os.environ["LOCAL_MCP_PASSKEY_DB"])
    if permit_path == credential_path or permit_path.parent != credential_path.parent:
        raise RuntimeError(
            "Operator permit and passkey stores require separate files in one private directory"
        )
    permits = SQLiteBootstrapPermits(permit_path)
    credentials = SQLiteCredentialStore(credential_path)
    verifier = JWTVerifier(config)
    assert client_id is not None
    enrollment = OwnerEnrollmentAPI(
        config=config,
        verifier=verifier,
        permits=permits,
        credentials=credentials,
        browser_client_id=client_id,
    )
    page = OwnerEnrollmentPageConfig(
        client_id=client_id,
        authorization_endpoint=os.environ["LOCAL_MCP_OWNER_AUTHORIZE_URL"],
        token_endpoint=os.environ["LOCAL_MCP_OWNER_TOKEN_URL"],
    )
    return create_gateway(
        config,
        relay=relay,
        verifier=verifier,
        owner_client_id=client_id,
        owner_enrollment=enrollment,
        enrollment_page=page,
        approvals=approvals,
        actions=actions,
        portal=portal,
    )
