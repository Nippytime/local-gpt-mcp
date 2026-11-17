"""Locally opted-in Win32 click adapter; remote requests cannot choose windows.

Only a trusted local UI may construct this adapter via select_local_windows.
WindowsBackend rechecks the real unlocked desktop, window identity, same
interactive user/session, elevation, foreground and occlusion before each input.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Protocol

from local_gpt_mcp.desktop.controller import DesktopDenied
from local_gpt_mcp.desktop.types import WindowIdentity, WindowInfo
from local_gpt_mcp.desktop.windows import WindowsBackend
from local_gpt_mcp.gateway.registry import DeviceUnavailable
from local_gpt_mcp.policy.authority import PolicyAuthority

TARGET = re.compile(r"^window:([1-9][0-9]{0,15})$")


class SafeWindows(Protocol):
    def desktop_ready(self) -> bool: ...

    def window(self, handle: int) -> WindowInfo | None: ...

    def click(self, handle: int, x: int, y: int) -> None: ...


class WindowsClickAdapter:
    """Bound to immutable, locally selected window/process identities."""

    def __init__(
        self,
        backend: SafeWindows,
        policy: PolicyAuthority,
        selected: frozenset[WindowIdentity],
    ) -> None:
        if not selected:
            raise DeviceUnavailable("No windows selected by the local user")
        self._backend = backend
        self._policy = policy
        self._selected = selected

    async def execute(
        self, target: str, operation: str, parameters: Mapping[str, int]
    ) -> dict[str, str | int | bool]:
        """One bounded click only; no focus switching, typing, shell or UAC bypass."""
        match = TARGET.fullmatch(target) if isinstance(target, str) else None
        if (
            self._policy.stopped
            or match is None
            or operation != "window.click"
            or not isinstance(parameters, Mapping)
            or set(parameters) != {"x", "y"}
        ):
            raise DeviceUnavailable("Remote click denied by local Windows policy")
        x, y = parameters["x"], parameters["y"]
        if type(x) is not int or type(y) is not int:
            raise DeviceUnavailable("Remote click coordinates invalid")
        hwnd = int(match[1])
        info = self._backend.window(hwnd)
        if (
            not self._backend.desktop_ready()
            or info is None
            or info.identity not in self._selected
            or not info.foreground
            or not info.visible
            or not info.enabled
            or info.minimized
            or not info.same_user
            or not info.same_session
            or info.elevated
            or not info.rect.contains(x, y)
        ):
            raise DeviceUnavailable("Locally selected desktop window unavailable")
        if self._policy.stopped:
            raise DeviceUnavailable("Local emergency STOP is active")
        try:
            # WindowsBackend.click also validates window/process identity,
            # desktop lock/UAC, foreground and point occlusion at dispatch.
            self._backend.click(hwnd, x, y)
        except (DesktopDenied, OSError, ValueError, PermissionError) as error:
            raise DeviceUnavailable("Windows refused locally scoped input") from error
        if self._policy.stopped:
            # The input may already have occurred. Never advise an automatic retry.
            raise DeviceUnavailable("Input completion uncertain after emergency STOP")
        return {"ok": True}


def select_local_windows(policy: PolicyAuthority, handles: Iterable[int]) -> WindowsClickAdapter:
    """Use ONLY inside a trusted local Windows UI following explicit selection.

    This function is not registered as an MCP/HTTP tool and is never invoked
    by the default outbound agent CLI.
    """
    if policy.stopped:
        raise DeviceUnavailable("Local emergency STOP is active")
    backend = WindowsBackend(stopped=lambda: policy.stopped)
    try:
        selected = backend.trust_local(handles)
    except DesktopDenied as error:
        raise DeviceUnavailable("Windows cannot trust the local selection") from error
    if policy.stopped:
        raise DeviceUnavailable("Local emergency STOP is active")
    return WindowsClickAdapter(backend, policy, selected)
