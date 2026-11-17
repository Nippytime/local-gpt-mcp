"""Authenticated remote MCP resource server; no device execution or public PC listener."""

from local_gpt_mcp.gateway.registry import DeviceDirectory, DeviceUnavailable, ReadRequest
from local_gpt_mcp.gateway.auth import GatewayConfig
from local_gpt_mcp.gateway.server import create_gateway

__all__ = ["DeviceDirectory", "DeviceUnavailable", "GatewayConfig", "ReadRequest", "create_gateway"]
