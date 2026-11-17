"""Local approval queue, GUI availability, and redacted status contracts."""

from __future__ import annotations

import threading
import time

import pytest

from local_gpt_mcp.policy import (
    Caller,
    Capability,
    GrantRequest,
    PairingRequest,
    PolicyAuthority,
)
from local_gpt_mcp.ui.approvals import ApprovalInbox
from local_gpt_mcp.ui.panel import LocalSafetyPanel


class AlwaysYes:
    def approve_pairing(self, request: PairingRequest) -> bool:
        return True

    def approve_grant(self, request: GrantRequest) -> bool:
        return True


def test_inbox_fails_closed_without_visible_panel() -> None:
    inbox = ApprovalInbox()
    assert not inbox.request("Pair", "unknown device", timeout=0)
    assert inbox.take() is None


def test_challenge_must_match_local_ui_response_exactly() -> None:
    inbox = ApprovalInbox()
    inbox.start()
    values: list[bool] = []

    def ask() -> None:
        values.append(inbox.request("Pair", "device1", timeout=2))

    task = threading.Thread(target=ask)
    task.start()
    pending = None
    for _ in range(200):
        pending = inbox.take()
        if pending is not None:
            break
        time.sleep(0.001)
    assert pending is not None
    assert pending.heading == "Pair"
    assert not inbox.respond(pending, f"APPROVE {pending.challenge}X")
    task.join(2)
    assert values == [False]
    assert not inbox.respond(pending, "APPROVE " + pending.challenge)
    inbox.stop()


def test_exact_local_response_succeeds() -> None:
    inbox = ApprovalInbox()
    inbox.start()
    values: list[bool] = []
    task = threading.Thread(target=lambda: values.append(inbox.request("Grant", "scope", timeout=2)))
    task.start()
    pending = None
    for _ in range(200):
        pending = inbox.take()
        if pending is not None:
            break
        time.sleep(0.001)
    assert pending is not None
    assert inbox.respond(pending, f"APPROVE {pending.challenge}")
    task.join(2)
    assert values == [True]
    inbox.stop()


def test_timeout_is_denial_not_late_approval() -> None:
    inbox = ApprovalInbox()
    inbox.start()
    assert not inbox.request("Pair", "scope", timeout=0.001)
    assert inbox.take() is None
    inbox.stop()


def test_emergency_stop_releases_outstanding_requests() -> None:
    inbox = ApprovalInbox()
    inbox.start()
    values: list[bool] = []
    task = threading.Thread(target=lambda: values.append(inbox.request("Pair", "scope", timeout=2)))
    task.start()
    pending = None
    for _ in range(200):
        pending = inbox.take()
        if pending is not None:
            break
        time.sleep(0.001)
    assert pending is not None
    inbox.stop()
    task.join(2)
    assert values == [False]
    assert not inbox.respond(pending, f"APPROVE {pending.challenge}")
    assert not inbox.request("Future", "scope", timeout=0)


def test_policy_local_status_redacts_secrets_and_observes_revoke() -> None:
    authority = PolicyAuthority(AlwaysYes())
    authority.pair(PairingRequest("local", "pc"))
    caller = Caller("local", "pc", "session1")
    token = authority.issue(GrantRequest(caller, "window:41", frozenset({Capability.WINDOW_READ}), 60))
    snapshot = authority.local_status()
    assert snapshot.paired_devices == 1
    assert snapshot.active_scopes == ("window:41 | window.read",)
    assert "window:41" not in repr(snapshot.audit)
    assert token not in repr(snapshot)
    authority.revoke(token)
    assert authority.local_status().active_scopes == ()
    authority.emergency_stop()
    stopped = authority.local_status()
    assert stopped.stopped and not stopped.active_scopes and stopped.paired_devices == 0


def test_visible_panel_bind_is_one_time_and_stop_revokes_authority() -> None:
    panel = LocalSafetyPanel()
    authority = PolicyAuthority(AlwaysYes())
    panel.bind_authority(authority)
    with pytest.raises(ValueError, match="already bound"):
        panel.bind_authority(authority)
    panel.stop()
    assert authority.stopped


def test_headless_or_non_windows_panel_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    panel = LocalSafetyPanel()
    authority = PolicyAuthority()
    panel.bind_authority(authority)
    monkeypatch.setattr("local_gpt_mcp.ui.panel.sys.platform", "linux")
    with pytest.raises(RuntimeError, match="Windows"):
        panel.start()
    assert not authority.stopped
