"""Physical Windows-only safety-panel acceptance: no automation of approval.

Run from the checkout: python tests/windows/manual_ui_smoke.py
Confirm local GUI pairing, a scope grant, redacted status and emergency stop.
No network listener or real device input is enabled by this test.
"""

from __future__ import annotations

import sys
import threading

from local_gpt_mcp.policy import (
    Caller,
    Capability,
    GrantRequest,
    PairingRequest,
    PolicyAuthority,
)
from local_gpt_mcp.ui.panel import LocalSafetyPanel


def main() -> int:
    if sys.platform != "win32":
        print("Run on a real interactive Windows desktop.")
        return 2
    panel = LocalSafetyPanel()
    authority = PolicyAuthority(panel)
    panel.bind_authority(authority)
    panel.start()
    done = threading.Event()
    outcome: list[str] = []

    def verify() -> None:
        try:
            authority.pair(PairingRequest("acceptance-user", "acceptance-device"))
            authority.issue(
                GrantRequest(
                    Caller("acceptance-user", "acceptance-device", "acceptance-session"),
                    "window:41",
                    frozenset({Capability.WINDOW_READ}),
                    30,
                )
            )
            outcome.append("Local pairing and a scope grant were accepted")
            # The app intentionally cannot click its own emergency stop.
            # The human must press the visible red STOP button.
            for _ in range(240):
                if authority.stopped or done.wait(0.5):
                    break
            if not authority.stopped:
                outcome.append("FAIL: user did not activate emergency stop")
                return
            if authority.local_status().active_scopes:
                outcome.append("FAIL: grant remained after emergency stop")
                return
            outcome.append("PASS: stop revoked the approved grant")
        except PermissionError:
            outcome.append("Approval denied or timeout; no grant was issued")
        finally:
            done.set()

    task = threading.Thread(target=verify, daemon=True)
    task.start()
    print(
        "Use the visible Windows safety panel to approve both typed challenges, "
        "observe the authorized target, then press the red EMERGENCY STOP button."
    )
    # The physical user controls the stop. This script does not approve itself.
    task.join(timeout=130)
    done.set()
    panel.stop()
    for line in outcome:
        print(line)
    return 0 if any(line.startswith("PASS") for line in outcome) else 1


if __name__ == "__main__":
    raise SystemExit(main())
