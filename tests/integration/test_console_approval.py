"""Local prompt cannot be completed over the MCP protocol stream."""

from __future__ import annotations

import io
from typing import TextIO

import pytest

from local_gpt_mcp.pairing.local_approval import ConsoleApproval
from local_gpt_mcp.policy import Caller, Capability, GrantRequest, PairingRequest


def test_console_denies_when_no_real_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*args: object, **kwargs: object) -> TextIO:
        raise OSError("no console")

    monkeypatch.setattr("builtins.open", unavailable)
    assert not ConsoleApproval().approve_pairing(PairingRequest("person", "computer"))


def test_local_challenge_requires_exact_response(monkeypatch: pytest.MonkeyPatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr("local_gpt_mcp.pairing.local_approval.secrets.token_hex", lambda n: "ab12cd")

    def console(path: str, mode: str = "r", **kwargs: object) -> TextIO:
        if "w" in mode:
            return io.StringIO()
        return io.StringIO("APPROVE AB12CD\n")

    monkeypatch.setattr("builtins.open", console)
    assert ConsoleApproval().approve_pairing(PairingRequest("person", "computer"))
    assert output.getvalue() == ""


def test_wrong_challenge_is_a_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("local_gpt_mcp.pairing.local_approval.secrets.token_hex", lambda n: "ab12cd")
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.StringIO("NO\n"))
    assert not ConsoleApproval().approve_pairing(PairingRequest("person", "computer"))


def test_grant_requires_its_own_local_challenge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("local_gpt_mcp.pairing.local_approval.secrets.token_hex", lambda n: "ab12cd")
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.StringIO("DENY\n"))
    request = GrantRequest(
        Caller("user1", "device1", "session1"),
        "window:1",
        frozenset({Capability.WINDOW_READ}),
        10,
    )
    assert not ConsoleApproval().approve_grant(request)
