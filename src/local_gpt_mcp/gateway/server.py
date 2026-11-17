"""OAuth-protected, tenant-isolated Streamable HTTP MCP gateway.

This component cannot start the local desktop, grant permissions or approve input.
An agent and trusted remote-approval flow are separate future delivery issues.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette

from local_gpt_mcp.gateway.agent_api import install_agent_routes
from local_gpt_mcp.gateway.approval_api import install_approval_routes
from local_gpt_mcp.gateway.agent_relay import AgentRelay
from local_gpt_mcp.gateway.auth import GatewayConfig, JWTVerifier
from local_gpt_mcp.gateway.registry import DeviceDirectory, DeviceUnavailable, ReadRequest
from local_gpt_mcp.policy.approval_queue import OwnerApprovalQueue

READ_SCOPE = "devices:read"


def _owner() -> str:
    verified = get_access_token()
    if verified is None or READ_SCOPE not in verified.scopes or not verified.subject:
        raise DeviceUnavailable("An authenticated owner grant is required")
    return verified.subject


def create_gateway_server(
    config: GatewayConfig,
    *,
    directory: DeviceDirectory | None = None,
    verifier: TokenVerifier | None = None,
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

    return mcp


def create_gateway(
    config: GatewayConfig,
    *,
    directory: DeviceDirectory | None = None,
    verifier: TokenVerifier | None = None,
    relay: AgentRelay | None = None,
    approvals: OwnerApprovalQueue | None = None,
) -> Starlette:
    """Expose the authenticated MCP server plus optional outbound-only agent APIs."""
    token_verifier = verifier if verifier is not None else JWTVerifier(config)
    if relay is not None:
        if directory is None:
            directory = DeviceDirectory(relay)
        relay.bind(directory)
    mcp = create_gateway_server(config, directory=directory, verifier=token_verifier)
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
        install_agent_routes(app, relay, token_verifier, config.resource_url)
    if approvals is not None:
        install_approval_routes(app, approvals, token_verifier, config.resource_url)
    return app


def create_from_env() -> Starlette:
    """A hosted process must supply real operator-controlled identity settings."""
    import os

    keys = ["LOCAL_MCP_RESOURCE_URL", "LOCAL_MCP_ISSUER_URL", "LOCAL_MCP_JWKS_URL"]
    if any(not os.environ.get(key) for key in keys):
        raise RuntimeError("Hosted gateway requires an HTTPS resource, issuer and JWKS URL")
    return create_gateway(GatewayConfig(*(os.environ[key] for key in keys)), relay=AgentRelay())
