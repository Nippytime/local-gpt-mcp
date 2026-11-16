"""Windows-only API adapter; importing it on other systems is harmless.

It never switches focus, bypasses UAC, uses another user's process, or captures
the whole screen. It accepts only identities selected by the local launcher.
"""

from __future__ import annotations

import ctypes
import io
import os
import sys
from collections.abc import Callable, Iterable
from ctypes import wintypes
from importlib import import_module
from typing import Any

from local_gpt_mcp.desktop.controller import DesktopDenied
from local_gpt_mcp.desktop.types import ControlInfo, Rect, WindowIdentity, WindowInfo

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_ELEVATION = 20
UOI_NAME = 2
DESKTOP_READOBJECTS = 0x0001
GA_ROOT = 2
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_WHEEL = 0x0800
BLOCKED_PROCESSES = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wt.exe",
        "windowsterminal.exe",
        "conhost.exe",
        "regedit.exe",
        "taskmgr.exe",
        "mmc.exe",
        "mshta.exe",
    }
)
KEY_CODES = {
    "tab": 0x09,
    "escape": 0x1B,
    "backspace": 0x08,
    "left": 0x25,
    "up": 0x26,
    "right": 0x27,
    "down": 0x28,
    "home": 0x24,
    "end": 0x23,
}


class _Mouse(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class _Keyboard(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class _InputData(ctypes.Union):
    _fields_ = [("mi", _Mouse), ("ki", _Keyboard)]


class _Input(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("data", _InputData)]


class WindowsBackend:
    """Native Win32 provider. No functionality on non-Windows processes."""

    def __init__(self, stopped: Callable[[], bool] = lambda: False) -> None:
        if sys.platform != "win32" or os.name != "nt":
            raise DesktopDenied("Windows interactive desktop is required")
        self._stopped = stopped
        self._gui: Any = import_module("win32gui")
        self._api: Any = import_module("win32api")
        self._proc: Any = import_module("win32process")
        self._psutil: Any = import_module("psutil")
        self._ui: Any = import_module("uiautomation")
        self._grab: Any = import_module("PIL.ImageGrab")
        self._user: Any = ctypes.WinDLL("user32", use_last_error=True)
        self._kernel: Any = ctypes.WinDLL("kernel32", use_last_error=True)
        self._advapi: Any = ctypes.WinDLL("advapi32", use_last_error=True)
        self._user.OpenInputDesktop.restype = wintypes.HANDLE
        self._user.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self._user.GetUserObjectInformationW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._user.CloseDesktop.argtypes = [wintypes.HANDLE]
        self._user.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(_Input), ctypes.c_int]
        self._user.SendInput.restype = wintypes.UINT
        self._kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self._kernel.OpenProcess.restype = wintypes.HANDLE
        self._kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel.ProcessIdToSessionId.argtypes = [
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._advapi.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self._advapi.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._trusted: frozenset[WindowIdentity] = frozenset()

    def desktop_ready(self) -> bool:
        """Return false for lock screen, UAC secure desktop, logout or stop."""
        if self._stopped():
            return False
        handle = self._user.OpenInputDesktop(0, False, DESKTOP_READOBJECTS)
        if not handle:
            return False
        try:
            name = ctypes.create_unicode_buffer(128)
            used = wintypes.DWORD()
            ok = self._user.GetUserObjectInformationW(
                handle, UOI_NAME, name, ctypes.sizeof(name), ctypes.byref(used)
            )
            return bool(ok) and name.value == "Default"
        finally:
            self._user.CloseDesktop(handle)

    def _session_id(self, pid: int) -> int:
        result = wintypes.DWORD()
        if not self._kernel.ProcessIdToSessionId(pid, ctypes.byref(result)):
            raise DesktopDenied("Cannot verify target session")
        return int(result.value)

    def _elevated(self, pid: int) -> bool:
        process = self._kernel.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not process:
            raise DesktopDenied("Cannot inspect target process security")
        try:
            token = wintypes.HANDLE()
            if not self._advapi.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
                raise DesktopDenied("Cannot query target integrity")
            try:
                enabled = wintypes.DWORD()
                used = wintypes.DWORD()
                if not self._advapi.GetTokenInformation(
                    token, TOKEN_ELEVATION, ctypes.byref(enabled), ctypes.sizeof(enabled), ctypes.byref(used)
                ):
                    raise DesktopDenied("Cannot verify target elevation")
                return bool(enabled.value)
            finally:
                self._kernel.CloseHandle(token)
        finally:
            self._kernel.CloseHandle(process)

    def window(self, handle: int) -> WindowInfo | None:
        if type(handle) is not int or handle <= 0 or not self._gui.IsWindow(handle):
            return None
        try:
            _, pid = self._proc.GetWindowThreadProcessId(handle)
            process = self._psutil.Process(pid)
            if process.name().lower() in BLOCKED_PROCESSES:
                return None
            own = self._psutil.Process(os.getpid())
            bounds = self._gui.GetWindowRect(handle)
            return WindowInfo(
                identity=WindowIdentity(handle, pid, int(process.create_time() * 1_000_000)),
                title=str(self._gui.GetWindowText(handle))[:160],
                rect=Rect(*bounds),
                foreground=handle == self._gui.GetForegroundWindow(),
                visible=bool(self._gui.IsWindowVisible(handle)),
                enabled=bool(self._gui.IsWindowEnabled(handle)),
                minimized=bool(self._gui.IsIconic(handle)),
                same_user=process.username().casefold() == own.username().casefold(),
                same_session=self._session_id(pid) == self._session_id(os.getpid()),
                elevated=self._elevated(pid),
            )
        except (OSError, ValueError, PermissionError, AttributeError):
            return None

    def windows(self) -> tuple[WindowInfo, ...]:
        handles: list[int] = []
        self._gui.EnumWindows(lambda hwnd, _: handles.append(int(hwnd)) or True, None)
        return tuple(info for hwnd in handles if (info := self.window(hwnd)) is not None)

    def trust_local(self, handles: Iterable[int]) -> frozenset[WindowIdentity]:
        """Local startup only. Remote clients cannot add allowed windows."""
        if not self.desktop_ready():
            raise DesktopDenied("Cannot select windows outside the unlocked desktop")
        selected: set[WindowIdentity] = set()
        for hwnd in handles:
            info = self.window(hwnd)
            if not info or not self._safe(info):
                raise DesktopDenied("A locally selected window is unsafe")
            selected.add(info.identity)
        if not selected:
            raise DesktopDenied("No window was selected on the local computer")
        self._trusted = frozenset(selected)
        return self._trusted

    @staticmethod
    def _safe(info: WindowInfo) -> bool:
        return (
            info.foreground
            and info.visible
            and info.enabled
            and not info.minimized
            and info.same_user
            and info.same_session
            and not info.elevated
            and info.rect.width > 0
            and info.rect.height > 0
        )

    def _guard(self, handle: int) -> WindowInfo:
        if not self.desktop_ready():
            raise DesktopDenied("Desktop locked, elevated or stopped")
        info = self.window(handle)
        if info is None or info.identity not in self._trusted or not self._safe(info):
            raise DesktopDenied("Target window changed identity or lost foreground")
        return info

    def capture(self, handle: int) -> bytes:
        self._guard(handle)
        image = self._grab.grab(window=handle)
        image.thumbnail((1280, 800))
        with io.BytesIO() as output:
            image.save(output, format="PNG")
            data = output.getvalue()
        self._guard(handle)
        return data

    def controls(self, handle: int, max_depth: int, max_nodes: int) -> tuple[ControlInfo, ...]:
        self._guard(handle)
        root = self._ui.ControlFromHandle(handle)
        todo = [(root, 0)]
        nodes: list[ControlInfo] = []
        while todo and len(nodes) < max_nodes:
            self._guard(handle)
            node, depth = todo.pop(0)
            role = str(node.ControlTypeName)[:64]
            protected = bool(getattr(node, "IsPassword", False)) or role == "EditControl"
            name = "[redacted]" if protected else str(node.Name)[:120]
            nodes.append(ControlInfo(role, name, depth))
            if depth < max_depth:
                todo.extend((child, depth + 1) for child in node.GetChildren()[:max_nodes])
        return tuple(nodes)

    def _send(self, kind: int, *, flags: int, value: int = 0) -> None:
        event = _Input()
        event.type = kind
        if kind == 0:
            event.data.mi.dwFlags = flags
            event.data.mi.mouseData = value & 0xFFFFFFFF
        else:
            if flags & KEYEVENTF_UNICODE:
                event.data.ki.wScan = value
            else:
                event.data.ki.wVk = value
            event.data.ki.dwFlags = flags
        if self._user.SendInput(1, ctypes.byref(event), ctypes.sizeof(event)) != 1:
            raise DesktopDenied("Windows rejected the input event")

    def click(self, handle: int, x: int, y: int) -> None:
        info = self._guard(handle)
        if not info.rect.contains(x, y):
            raise DesktopDenied("Click outside selected window")
        point_target = self._gui.WindowFromPoint((x, y))
        if self._gui.GetAncestor(point_target, GA_ROOT) != handle:
            raise DesktopDenied("Another window obscures the click location")
        self._api.SetCursorPos((x, y))
        self._guard(handle)
        self._send(0, flags=MOUSEEVENTF_LEFTDOWN)
        self._guard(handle)
        self._send(0, flags=MOUSEEVENTF_LEFTUP)

    def type_text(self, handle: int, text: str) -> None:
        for char in text:
            self._guard(handle)
            units = char.encode("utf-16-le")
            for i in range(0, len(units), 2):
                key = units[i] | units[i + 1] << 8
                self._send(1, flags=KEYEVENTF_UNICODE, value=key)
                self._send(1, flags=KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, value=key)

    def scroll(self, handle: int, steps: int) -> None:
        self._guard(handle)
        self._send(0, flags=MOUSEEVENTF_WHEEL, value=steps * 120)

    def press_key(self, handle: int, key: str) -> None:
        self._guard(handle)
        vk = KEY_CODES[key]
        self._send(1, flags=0, value=vk)
        self._guard(handle)
        self._send(1, flags=KEYEVENTF_KEYUP, value=vk)
