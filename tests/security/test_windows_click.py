"""Native adapter denies unselected, changed, locked, elevated or stopped windows."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from local_gpt_mcp.agent.windows_click import WindowsClickAdapter
from local_gpt_mcp.desktop.controller import DesktopDenied
from local_gpt_mcp.desktop.types import Rect, WindowIdentity, WindowInfo
from local_gpt_mcp.desktop.windows import WindowsBackend
from local_gpt_mcp.gateway.registry import DeviceUnavailable
from local_gpt_mcp.policy.authority import PolicyAuthority


class FakeWindows:
    def __init__(self) -> None:
        self.window_info = WindowInfo(
            identity=WindowIdentity(41, 1001, 2_000_000),
            title="Locally selected",
            rect=Rect(10, 10, 120, 120),
            foreground=True,
            visible=True,
            enabled=True,
            minimized=False,
            same_user=True,
            same_session=True,
            elevated=False,
        )
        self.ready = True
        self.clicks: list[tuple[int, int, int]] = []
        self.fail_click = False

    def desktop_ready(self) -> bool:
        return self.ready

    def window(self, handle: int) -> WindowInfo | None:
        return self.window_info if handle == self.window_info.identity.handle else None

    def click(self, handle: int, x: int, y: int) -> None:
        if self.fail_click:
            raise DesktopDenied("Native target changed during input")
        self.clicks.append((handle, x, y))


@pytest.fixture
def setup() -> tuple[WindowsClickAdapter, FakeWindows, PolicyAuthority]:
    backend = FakeWindows()
    policy = PolicyAuthority()
    adapter = WindowsClickAdapter(backend, policy, frozenset({backend.window_info.identity}))
    return adapter, backend, policy


@pytest.mark.anyio
async def test_explicitly_selected_window_can_click_once(
    setup: tuple[WindowsClickAdapter, FakeWindows, PolicyAuthority],
) -> None:
    adapter, backend, _policy = setup
    assert await adapter.execute("window:41", "window.click", {"x": 20, "y": 30}) == {"ok": True}
    assert backend.clicks == [(41, 20, 30)]


@pytest.mark.anyio
async def test_refuses_unselected_reused_and_unsafe_windows(
    setup: tuple[WindowsClickAdapter, FakeWindows, PolicyAuthority],
) -> None:
    adapter, backend, _policy = setup
    original = backend.window_info
    for replacement in (
        replace(original, identity=WindowIdentity(41, 1002, 2_000_001)),
        replace(original, foreground=False),
        replace(original, visible=False),
        replace(original, enabled=False),
        replace(original, minimized=True),
        replace(original, same_user=False),
        replace(original, same_session=False),
        replace(original, elevated=True),
    ):
        backend.window_info = replacement
        with pytest.raises(DeviceUnavailable):
            await adapter.execute("window:41", "window.click", {"x": 20, "y": 30})
    backend.window_info = original
    backend.ready = False
    with pytest.raises(DeviceUnavailable):
        await adapter.execute("window:41", "window.click", {"x": 20, "y": 30})
    assert backend.clicks == []


@pytest.mark.anyio
async def test_refuses_malformed_coordinate_target_and_dispatch_failure(
    setup: tuple[WindowsClickAdapter, FakeWindows, PolicyAuthority],
) -> None:
    adapter, backend, _policy = setup
    for target, operation, xy in (
        ("window:0", "window.click", {"x": 20, "y": 30}),
        ("window:99", "window.click", {"x": 20, "y": 30}),
        ("window:41", "window.type", {"x": 20, "y": 30}),
        ("window:41", "window.click", {"x": True, "y": 30}),
        ("window:41", "window.click", {"x": 20, "y": 200}),
        ("window:41", "window.click", {"x": 20}),
    ):
        with pytest.raises(DeviceUnavailable):
            await adapter.execute(target, operation, xy)
    backend.fail_click = True
    with pytest.raises(DeviceUnavailable):
        await adapter.execute("window:41", "window.click", {"x": 20, "y": 30})
    assert backend.clicks == []


@pytest.mark.anyio
async def test_emergency_stop_blocks_input(
    setup: tuple[WindowsClickAdapter, FakeWindows, PolicyAuthority],
) -> None:
    adapter, backend, policy = setup
    policy.emergency_stop()
    with pytest.raises(DeviceUnavailable):
        await adapter.execute("window:41", "window.click", {"x": 20, "y": 30})
    assert backend.clicks == []


def test_never_implicitly_trusts_unselected_windows() -> None:
    backend = FakeWindows()
    with pytest.raises(DeviceUnavailable):
        WindowsClickAdapter(backend, PolicyAuthority(), frozenset())


def test_native_click_refuses_new_occlusion_after_cursor_move(monkeypatch: pytest.MonkeyPatch) -> None:
    native = object.__new__(WindowsBackend)
    sent: list[int] = []
    points = iter((41, 99))
    monkeypatch.setattr(native, "_guard", lambda handle: FakeWindows().window_info)
    native._gui = SimpleNamespace(
        WindowFromPoint=lambda point: next(points),
        GetAncestor=lambda target, root: target,
    )
    native._api = SimpleNamespace(SetCursorPos=lambda point: None)
    monkeypatch.setattr(native, "_send", lambda kind, **kwargs: sent.append(kind))
    with pytest.raises(DesktopDenied, match="obscures"):
        native.click(41, 20, 30)
    assert sent == []
