"""Device-local, deny-by-default authority for future MCP desktop adapters."""

from local_gpt_mcp.policy.authority import (
    AccessDenied,
    AuditEvent,
    Caller,
    Capability,
    GrantRequest,
    LocalApproval,
    PairingRequest,
    PolicyAuthority,
)

__all__ = [
    "AccessDenied",
    "AuditEvent",
    "Caller",
    "Capability",
    "GrantRequest",
    "LocalApproval",
    "PairingRequest",
    "PolicyAuthority",
]
