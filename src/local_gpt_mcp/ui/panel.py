"""Visible native Tk safety panel with local pairing/grant/action approval.

GUI runs in its own thread. The MCP process only submits approval requests to
the in-process queue; neither MCP stdin nor stdout can approve them.
"""

from __future__ import annotations

import sys
import threading
from typing import TYPE_CHECKING

from local_gpt_mcp.policy import GrantRequest, PairingRequest
from local_gpt_mcp.ui.approvals import ApprovalInbox, LocalApprovalRequest

if TYPE_CHECKING:
    from local_gpt_mcp.orchestrator.models import Step
    from local_gpt_mcp.policy.authority import PolicyAuthority


class LocalSafetyPanel:
    """Fail closed when the real local UI is unavailable or closed."""

    def __init__(self) -> None:
        self._inbox = ApprovalInbox()
        self._authority: PolicyAuthority | None = None
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._failure = False

    def bind_authority(self, authority: PolicyAuthority) -> None:
        if self._authority is not None:
            raise ValueError("Local authority is already bound")
        self._authority = authority

    def start(self) -> None:
        if sys.platform != "win32" or self._authority is None:
            raise RuntimeError("Visible safety panel requires a bound Windows authority")
        self._thread = threading.Thread(target=self._display, daemon=True, name="LocalSafetyPanel")
        self._thread.start()
        if not self._ready.wait(8) or self._failure:
            self._inbox.stop()
            self._authority.emergency_stop()
            raise RuntimeError("Local safety panel could not open")

    def approve_pairing(self, request: PairingRequest) -> bool:
        return self._inbox.request(
            "Pair a local MCP client",
            f"Claimed user: {request.user_id}\nDevice: {request.device_id}\n"
            "Pairing alone does not authorize screen or input access.",
        )

    def approve_grant(self, request: GrantRequest) -> bool:
        scopes = ", ".join(sorted(scope.value for scope in request.capabilities))
        return self._inbox.request(
            "Approve a time-limited grant",
            f"Selected target: {request.target}\nScope: {scopes}\nExpires in: {request.ttl_seconds} seconds.",
        )

    def approve(self, step: Step) -> bool:
        return self._inbox.request(
            "Approve one potentially consequential action",
            f"Step: {step.step_id}\nAction: {step.action.value}\n"
            f"Local target: {step.target}\n"
            "Action arguments, typed data and tokens are not displayed or logged.",
        )

    def stop(self) -> None:
        """Local operator's immediate, irreversible emergency stop."""
        self._inbox.stop()
        if self._authority is not None:
            self._authority.emergency_stop()

    def _display(self) -> None:
        try:
            import tkinter as tk

            root = tk.Tk()
            root.title("Local GPT MCP — Session Safety")
            root.geometry("540x560")
            root.minsize(460, 480)
            root.attributes("-topmost", True)
            root.configure(padx=15, pady=12)
            status = tk.Label(root, text="NO APPROVED SESSIONS", font=("Segoe UI", 14, "bold"))
            status.pack(anchor="w", pady=(0, 12))
            scope_text = tk.StringVar(value="None")
            tk.Label(root, text="Currently authorized targets and scopes:", anchor="w").pack(anchor="w")
            tk.Label(root, textvariable=scope_text, justify="left", wraplength=490, anchor="w").pack(
                anchor="w", pady=(0, 12)
            )

            def stop_and_close() -> None:
                self.stop()
                root.destroy()

            stop_button = tk.Button(
                root,
                text="EMERGENCY STOP — REVOKE ALL ACCESS",
                command=stop_and_close,
                bg="#aa2222",
                fg="white",
                font=("Segoe UI", 11, "bold"),
                height=2,
            )
            stop_button.pack(fill="x", pady=(0, 18))
            prompt_frame = tk.LabelFrame(root, text="Local approvals", padx=10, pady=10)
            prompt_frame.pack(fill="x")
            heading = tk.StringVar(value="No pending approval request")
            details = tk.StringVar(value="")
            challenge = tk.StringVar(value="")
            tk.Label(prompt_frame, textvariable=heading, font=("Segoe UI", 11, "bold")).pack(anchor="w")
            tk.Label(prompt_frame, textvariable=details, wraplength=450, justify="left").pack(
                anchor="w", pady=4
            )
            tk.Label(prompt_frame, textvariable=challenge, font=("Consolas", 10)).pack(anchor="w")
            entry = tk.Entry(prompt_frame)
            entry.pack(fill="x", pady=(5, 8))
            buttons = tk.Frame(prompt_frame)
            buttons.pack(fill="x")
            tk.Label(root, text="Local security events (redacted):").pack(anchor="w", pady=(15, 0))
            audit = tk.Listbox(root, height=7, activestyle="none")
            audit.pack(fill="both", expand=True)
            pending: LocalApprovalRequest | None = None

            def finish(entered: str) -> None:
                nonlocal pending
                if pending is not None:
                    self._inbox.respond(pending, entered)
                pending = None
                entry.delete(0, tk.END)
                heading.set("No pending approval request")
                details.set("")
                challenge.set("")

            tk.Button(
                buttons,
                text="Confirm typed challenge",
                command=lambda: finish(entry.get()),
            ).pack(side="left", padx=(0, 8))
            tk.Button(buttons, text="Deny", command=lambda: finish("DENY")).pack(side="left")
            root.bind("<Escape>", lambda _: finish("DENY"))

            def tick() -> None:
                nonlocal pending
                if self._authority is not None:
                    snapshot = self._authority.local_status()
                    if snapshot.stopped:
                        label, color = "STOPPED — ALL ACCESS REVOKED", "#aa2222"
                    elif snapshot.active_scopes:
                        label = (
                            f"ACTIVE: {snapshot.paired_devices} paired device(s), "
                            f"{len(snapshot.active_scopes)} grant(s)"
                        )
                        color = "#156e31"
                    elif snapshot.paired_devices:
                        label, color = "PAIRED — NO ACTIVE GRANTS", "#666666"
                    else:
                        label, color = "NO APPROVED ACCESS", "#666666"
                    status.configure(text=label, fg=color)
                    scope_text.set("\n".join(snapshot.active_scopes[:8]) or "None")
                    audit.delete(0, tk.END)
                    for event in snapshot.audit[-15:]:
                        audit.insert(tk.END, f"{event.operation}: {event.result} — {event.reason}")
                if pending is None:
                    pending = self._inbox.take()
                    if pending is not None:
                        heading.set(pending.heading)
                        details.set(pending.details)
                        challenge.set(f"Type exactly: APPROVE {pending.challenge}")
                        entry.focus_set()
                elif pending.done.is_set():
                    finish("DENY")
                root.after(150, tick)

            root.protocol("WM_DELETE_WINDOW", stop_and_close)
            self._inbox.start()
            self._ready.set()
            tick()
            root.mainloop()
        except Exception:
            self._failure = True
            self._ready.set()
        finally:
            self.stop()
