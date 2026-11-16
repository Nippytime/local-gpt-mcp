"""Opt-in real Windows desktop acceptance; never collected as a pytest test.

Run locally: python tests/windows/manual_smoke.py
Uses only a disposable test Tkinter window and real local console approvals.
"""

from __future__ import annotations

import os
import secrets
import sys
import time
import tkinter as tk

from local_gpt_mcp.desktop import DesktopController
from local_gpt_mcp.desktop.windows import WindowsBackend
from local_gpt_mcp.pairing import SessionBroker
from local_gpt_mcp.pairing.local_approval import ConsoleApproval
from local_gpt_mcp.policy import Capability, PolicyAuthority


def main() -> int:
    if sys.platform != "win32" or os.name != "nt" or not sys.stdin.isatty():
        print("Interactive smoke requires a local Windows console.")
        return 2

    root = tk.Tk()
    root.title("Local GPT MCP interactive acceptance fixture")
    root.geometry("480x320")
    clicked = [0]
    button = tk.Button(root, text="Smoke test button", command=lambda: clicked.__setitem__(0, 1))
    button.pack(pady=24)
    entry = tk.Entry(root)
    entry.pack(pady=24)
    root.update()
    authority = PolicyAuthority(ConsoleApproval())
    broker = SessionBroker(authority)

    try:
        backend = WindowsBackend(stopped=lambda: authority.stopped)
        handle = int(root.winfo_id())
        native = backend._gui.GetAncestor(handle, 2)
        root.lift()
        root.focus_force()
        root.update()
        time.sleep(0.25)
        allowed = backend.trust_local([native])
        controller = DesktopController(broker, backend, allowed)
        session_result = broker.open("smoke-user", "smoke-device", secrets.token_hex(16))
        session = str(session_result["session_token"])
        grant_result = broker.request_grant(
            session,
            secrets.token_hex(16),
            f"window:{native}",
            frozenset({Capability.WINDOW_READ, Capability.WINDOW_INPUT}),
            60,
        )
        grant = str(grant_result["grant_token"])

        def nonce() -> str:
            return secrets.token_hex(16)

        # The local console approval may have taken foreground focus.
        root.lift()
        root.focus_force()
        root.update()
        time.sleep(0.25)
        info = controller.describe(session, nonce(), grant, native)
        assert info.identity.handle == native
        capture = controller.capture(session, nonce(), grant, native)
        assert capture.startswith(b"\x89PNG")
        assert controller.inspect(session, nonce(), grant, native)

        bx = button.winfo_rootx() + button.winfo_width() // 2
        by = button.winfo_rooty() + button.winfo_height() // 2
        controller.click(session, nonce(), grant, native, bx, by)
        root.update()
        assert clicked[0] == 1, "Click did not reach the test button"

        ex = entry.winfo_rootx() + entry.winfo_width() // 2
        ey = entry.winfo_rooty() + entry.winfo_height() // 2
        controller.click(session, nonce(), grant, native, ex, ey)
        controller.type_text(session, nonce(), grant, native, "smoke")
        root.update()
        assert entry.get() == "smoke", "Text did not reach the test entry"
        controller.scroll(session, nonce(), grant, native, 1)
        controller.press_key(session, nonce(), grant, native, "tab")
        broker.stop(session, nonce())
        try:
            controller.describe(session, nonce(), grant, native)
        except PermissionError:
            print("PASS: window read, UIA, capture, bounded input and stop.")
            return 0
        raise AssertionError("Emergency stop did not deny a later request")
    finally:
        authority.emergency_stop()
        root.destroy()


if __name__ == "__main__":
    raise SystemExit(main())
