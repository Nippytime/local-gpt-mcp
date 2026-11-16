"""Windows-local safety and approval interface.

The user interface never exposes remote endpoints or accepts MCP commands.
"""

from local_gpt_mcp.ui.approvals import ApprovalInbox, LocalApprovalRequest
from local_gpt_mcp.ui.panel import LocalSafetyPanel

__all__ = ["ApprovalInbox", "LocalApprovalRequest", "LocalSafetyPanel"]
