"""Portable Win32 adapter contract tests; no real input is sent to CI desktops."""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from local_gpt_mcp.desktop import ControlInfo, DesktopDenied, Rect, WindowIdentity, WindowInfo
from local_gpt_mcp.desktop.windows import (
    KEYEVENTF_UNICODE,
    MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP,
    WindowsBackend,
)


class Gui:
    focused = 41
    title = "Test window"
    visible = True
    enabled = True
    iconic = False
    rect = (10, 20, 410, 320)

    def IsWindow(self, hwnd: int) -> bool:
        return hwnd == 41

    def GetWindowText(self, hwnd: int) -> str:
        return self.title

    def GetWindowRect(self, hwnd: int) -> tuple[int, int, int, int]:
        return self.rect

    def IsWindowVisible(self, hwnd: int) -> bool:
        return self.visible

    def IsWindowEnabled(self, hwnd: int) -> bool:
        return self.enabled

    def IsIconic(self, hwnd: int) -> bool:
        return self.iconic

    def GetForegroundWindow(self) -> int:
        return self.focused

    def EnumWindows(self, callback: Callable[[int, object], bool], arg: object) -> None:
        assert callback(41, arg)

    def WindowFromPoint(self, point: tuple[int, int]) -> int:
        return 42

    def GetAncestor(self, hwnd: int, flag: int) -> int:
        return 41


class Process:
    def __init__(self, pid: int) -> None:
        self.pid = pid

    def name(self) -> str:
        return "notepad.exe"

    def create_time(self) -> float:
        return 123456.0

    def username(self) -> str:
        return "EXAMPLE\\user"


class TestImage:
    def thumbnail(self, dimensions: tuple[int, int]) -> None:
        assert dimensions == (1280, 800)

    def save(self, output: Any, format: str) -> None:
        assert format == "PNG"
        output.write(b"\x89PNG\r\n\x1a\nimage")


class UiNode:
    ControlTypeName = "WindowControl"
    Name = "Window"
    IsPassword = False

    def GetChildren(self) -> list[UiNode | SimpleNamespace]:
        return [
            SimpleNamespace(
                ControlTypeName="EditControl",
                Name="SECRET",
                IsPassword=True,
                GetChildren=lambda: [],
            )
        ]


def fake_native(monkeypatch: pytest.MonkeyPatch) -> WindowsBackend:
    backend = WindowsBackend.__new__(WindowsBackend)
    backend._stopped = lambda: False
    backend._trusted = frozenset()
    backend._gui = Gui()
    backend._proc = SimpleNamespace(GetWindowThreadProcessId=lambda hwnd: (1, 1001))
    backend._psutil = SimpleNamespace(Process=Process)
    backend._api = SimpleNamespace(SetCursorPos=lambda position: None)
    backend._grab = SimpleNamespace(grab=lambda **kwargs: TestImage())
    backend._ui = SimpleNamespace(ControlFromHandle=lambda handle: UiNode())
    monkeypatch.setattr(backend, "desktop_ready", lambda: True)
    monkeypatch.setattr(backend, "_session_id", lambda pid: 1)
    monkeypatch.setattr(backend, "_elevated", lambda pid: False)
    return backend


def test_not_available_on_other_platforms() -> None:
    if sys.platform != "win32":
        with pytest.raises(DesktopDenied, match="Windows interactive"):
            WindowsBackend()


def test_window_metadata_and_filtered_enumeration(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    assert backend.window(0) is None
    assert backend.window(42) is None
    info = backend.window(41)
    assert info is not None
    assert info.identity == WindowIdentity(41, 1001, 123456000000)
    assert info.rect == Rect(10, 20, 410, 320)
    assert backend.windows() == (info,)
    selected = backend.trust_local([41])
    assert selected == frozenset({info.identity})


def test_window_guard_rejects_untrusted_and_focus_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    with pytest.raises(DesktopDenied, match="identity"):
        backend._guard(41)
    backend.trust_local([41])
    backend._gui.focused = 99
    with pytest.raises(DesktopDenied, match="foreground"):
        backend._guard(41)
    backend._gui.focused = 41
    assert backend._guard(41).identity.handle == 41


def test_deny_when_target_process_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    monkeypatch.setattr(Process, "name", lambda self: "powershell.exe")
    assert backend.window(41) is None


def test_deny_when_process_security_cannot_be_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    monkeypatch.setattr(backend, "_elevated", lambda pid: (_ for _ in ()).throw(PermissionError()))
    assert backend.window(41) is None


def test_deny_when_desktop_locked(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    monkeypatch.setattr(backend, "desktop_ready", lambda: False)
    with pytest.raises(DesktopDenied):
        backend.trust_local([41])


def test_capture_and_redacted_uia_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    backend.trust_local([41])
    assert backend.capture(41).startswith(b"\x89PNG")
    controls = backend.controls(41, 2, 64)
    assert controls == (
        ControlInfo("WindowControl", "Window", 0),
        ControlInfo("EditControl", "[redacted]", 1),
    )


def test_native_click_and_navigation_events(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    backend.trust_local([41])
    calls: list[tuple[int, int, int]] = []

    def send(kind: int, *, flags: int, value: int = 0) -> None:
        calls.append((kind, flags, value))

    monkeypatch.setattr(backend, "_send", send)
    backend.click(41, 100, 100)
    backend.type_text(41, "A💻")
    backend.scroll(41, -2)
    backend.press_key(41, "tab")
    assert (0, MOUSEEVENTF_LEFTDOWN, 0) in calls
    assert (0, MOUSEEVENTF_LEFTUP, 0) in calls
    assert (0, 0x800, -240) in calls
    assert any(kind == 1 and flags == KEYEVENTF_UNICODE for kind, flags, _ in calls)


def test_click_outside_bounds_and_occluded(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    backend.trust_local([41])
    with pytest.raises(DesktopDenied, match="outside"):
        backend.click(41, 0, 0)
    backend._gui.GetAncestor = lambda hwnd, flag: 12
    with pytest.raises(DesktopDenied, match="obscures"):
        backend.click(41, 100, 100)


def test_win32_sendinput_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    backend._user = SimpleNamespace(SendInput=lambda *args: 0)
    with pytest.raises(DesktopDenied, match="rejected"):
        backend._send(0, flags=MOUSEEVENTF_LEFTDOWN)
    backend._user = SimpleNamespace(SendInput=lambda *args: 1)
    backend._send(1, flags=KEYEVENTF_UNICODE, value=65)


def test_native_session_id_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)

    def failed(pid: int, pointer: Any) -> int:
        return 0

    backend._kernel = SimpleNamespace(ProcessIdToSessionId=failed)
    monkeypatch.undo()
    with pytest.raises(DesktopDenied, match="session"):
        backend._session_id(4)


def test_identity_is_bound_to_same_native_process(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = fake_native(monkeypatch)
    backend._gui.focused = 41
    allowed = backend.trust_local([41])
    assert len(allowed) == 1
    monkeypatch.setattr(Process, "create_time", lambda self: 654321.0)
    with pytest.raises(DesktopDenied, match="identity"):
        backend._guard(41)
