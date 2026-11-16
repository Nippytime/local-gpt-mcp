"""Out-of-band approval on the user's real local console.

MCP stdin/stdout are never used for approval. A hidden/headless process has no
trusted console and must deny the request.
"""

from __future__ import annotations

import secrets
import sys
from threading import Lock

from local_gpt_mcp.policy import GrantRequest, PairingRequest


class ConsoleApproval:
    """Challenge confirmation that can only be entered at the local console."""

    def __init__(self) -> None:
        self._lock = Lock()

    def _confirm(self, heading: str) -> bool:
        challenge = secrets.token_hex(3).upper()
        expected = f"APPROVE {challenge}"
        input_path = "CONIN$" if sys.platform == "win32" else "/dev/tty"
        output_path = "CONOUT$" if sys.platform == "win32" else "/dev/tty"
        with self._lock:
            try:
                # Deliberately do not fall back to stdin, stderr or environment
                # variables: those may be controlled or captured by the MCP host.
                with open(output_path, "w", encoding="utf-8") as output:
                    output.write(
                        f"\nLocal GPT MCP authorization\n{heading}\n"
                        f"To allow, type exactly: {expected}\n"
                        "To deny, enter anything else or close this console.\n> "
                    )
                    output.flush()
                    with open(input_path, encoding="utf-8") as console:
                        entered = console.readline(64).strip()
                return secrets.compare_digest(entered, expected)
            except (OSError, UnicodeError):
                return False

    def approve_pairing(self, request: PairingRequest) -> bool:
        return self._confirm(
            f"Pair client claiming user '{request.user_id}' with device '{request.device_id}'?"
        )

    def approve_grant(self, request: GrantRequest) -> bool:
        scopes = ", ".join(sorted(capability.value for capability in request.capabilities))
        return self._confirm(
            f"Allow session '{request.caller.session_id}'\n"
            f"Target: {request.target}\n"
            f"Capabilities: {scopes}\n"
            f"Duration: {request.ttl_seconds} seconds?"
        )
