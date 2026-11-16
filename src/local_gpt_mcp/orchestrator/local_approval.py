"""Explicit local human confirmation for EVERY workflow mutation.

Never delegate authorization to a model's classification of action risk.
"""

from __future__ import annotations

from local_gpt_mcp.orchestrator.models import Step
from local_gpt_mcp.pairing.local_approval import ConsoleApproval


class ConsoleActionApproval:
    def __init__(self) -> None:
        self._prompt = ConsoleApproval()

    def approve(self, step: Step) -> bool:
        # No typed text, selector parameters, tokens, or browser URL are copied
        # into the local audit log. The UI still identifies the selected target.
        return self._prompt._confirm(
            f"Approve one workflow action?\n"
            f"Step: {step.step_id}\n"
            f"Action: {step.action.value}\n"
            f"Selected target: {step.target}\n"
            "This action could have consequences. Reject unless intended."
        )
