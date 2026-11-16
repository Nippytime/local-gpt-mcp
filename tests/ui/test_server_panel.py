"""Windows adapter sessions require a visible native safety panel."""

from __future__ import annotations

from typing import Any

import pytest

from local_gpt_mcp.mcp.server import serve_stdio
from local_gpt_mcp.orchestrator.models import Step
from local_gpt_mcp.policy import GrantRequest, PairingRequest, PolicyAuthority


class FakePanel:
    def __init__(self, fail: bool = False) -> None:
        self.authority: PolicyAuthority | None = None
        self.fail = fail
        self.started = False
        self.stopped = False

    def bind_authority(self, authority: PolicyAuthority) -> None:
        self.authority = authority

    def start(self) -> None:
        if self.fail:
            assert self.authority is not None
            self.authority.emergency_stop()
            raise RuntimeError("No visible local UI")
        self.started = True

    def stop(self) -> None:
        self.stopped = True
        if self.authority is not None:
            self.authority.emergency_stop()

    def approve_pairing(self, request: PairingRequest) -> bool:
        return False

    def approve_grant(self, request: GrantRequest) -> bool:
        return False

    def approve(self, step: Step) -> bool:
        return False


class FakeServer:
    def __init__(self) -> None:
        self.ran = False

    def run(self, *, transport: str) -> None:
        assert transport == "stdio"
        self.ran = True


def test_windows_adapter_binds_visible_local_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakePanel()
    server = FakeServer()
    parameters: list[tuple[Any, ...]] = []

    def factory(*args: Any) -> FakeServer:
        parameters.append(args)
        return server

    monkeypatch.setattr("local_gpt_mcp.mcp.server.sys.platform", "win32")
    monkeypatch.setattr("local_gpt_mcp.mcp.server.LocalSafetyPanel", lambda: fake)
    monkeypatch.setattr("local_gpt_mcp.mcp.server.create_server", factory)
    serve_stdio(browser_origin="https://example.com")
    assert fake.started and fake.stopped and server.ran
    assert fake.authority is not None and fake.authority.stopped
    assert len(parameters) == 1
    assert parameters[0][0] is not None
    assert parameters[0][2] is not None
    assert parameters[0][4] is not None


def test_no_ui_means_no_adapter_server_is_started(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakePanel(fail=True)
    server = FakeServer()
    monkeypatch.setattr("local_gpt_mcp.mcp.server.sys.platform", "win32")
    monkeypatch.setattr("local_gpt_mcp.mcp.server.LocalSafetyPanel", lambda: fake)
    monkeypatch.setattr("local_gpt_mcp.mcp.server.create_server", lambda *a: server)
    with pytest.raises(RuntimeError, match="visible"):
        serve_stdio(browser_origin="https://example.com")
    assert not server.ran
    assert fake.authority is not None and fake.authority.stopped


def test_stdio_without_adapter_does_not_require_window(monkeypatch: pytest.MonkeyPatch) -> None:
    server = FakeServer()
    monkeypatch.setattr("local_gpt_mcp.mcp.server.sys.platform", "win32")
    monkeypatch.setattr(
        "local_gpt_mcp.mcp.server.LocalSafetyPanel",
        lambda: pytest.fail("No adapter must not open the panel"),
    )
    monkeypatch.setattr("local_gpt_mcp.mcp.server.create_server", lambda *a: server)
    serve_stdio()
    assert server.ran
