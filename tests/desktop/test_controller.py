"""Deterministic adapter tests use real session grants and fake native windows."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from local_gpt_mcp.desktop import (
    ControlInfo,
    DesktopController,
    DesktopDenied,
    Rect,
    WindowIdentity,
    WindowInfo,
)
from local_gpt_mcp.pairing import SessionBroker, SessionDenied
from local_gpt_mcp.policy import AccessDenied, Capability, GrantRequest, PairingRequest, PolicyAuthority


class Approval:
    def approve_pairing(self, request: PairingRequest) -> bool:
        return True

    def approve_grant(self, request: GrantRequest) -> bool:
        return True


class FakeBackend:
    def __init__(self) -> None:
        self.ready = True
        self.info = WindowInfo(
            WindowIdentity(41, 1001, 123456),
            "Approved test window",
            Rect(100, 200, 500, 600),
            True,
            True,
            True,
            False,
            True,
            True,
            False,
        )
        self.actions: list[tuple[object, ...]] = []
        self.image = b"\x89PNG\r\n\x1a\nvalid"
        self.nodes: tuple[ControlInfo, ...] = (ControlInfo("ButtonControl", "OK", 1),)

    def desktop_ready(self) -> bool:
        return self.ready

    def windows(self) -> tuple[WindowInfo, ...]:
        return (self.info,)

    def window(self, handle: int) -> WindowInfo | None:
        return self.info if handle == self.info.identity.handle else None

    def capture(self, handle: int) -> bytes:
        self.actions.append(("capture", handle))
        return self.image

    def controls(self, handle: int, max_depth: int, max_nodes: int) -> tuple[ControlInfo, ...]:
        self.actions.append(("controls", handle, max_depth, max_nodes))
        return self.nodes

    def click(self, handle: int, x: int, y: int) -> None:
        self.actions.append(("click", handle, x, y))

    def type_text(self, handle: int, text: str) -> None:
        self.actions.append(("type", handle, text))

    def scroll(self, handle: int, steps: int) -> None:
        self.actions.append(("scroll", handle, steps))

    def press_key(self, handle: int, key: str) -> None:
        self.actions.append(("key", handle, key))


class Fixture:
    def __init__(self, trusted: bool = True) -> None:
        self.backend = FakeBackend()
        self.policy = PolicyAuthority(Approval())
        self.broker = SessionBroker(self.policy)
        self.n = 0
        allowed = (self.backend.info.identity,) if trusted else ()
        self.controller = DesktopController(self.broker, self.backend, allowed)
        session = self.broker.open("user1", "device1", self.nonce())["session_token"]
        assert isinstance(session, str)
        self.session: str = session
        self.read = self.grant(Capability.WINDOW_READ)
        self.input = self.grant(Capability.WINDOW_INPUT)

    def nonce(self) -> str:
        self.n += 1
        return f"{self.n:032x}"

    def grant(self, capability: Capability) -> str:
        result = self.broker.request_grant(
            self.session, self.nonce(), "window:41", frozenset({capability}), 60
        )
        token = result["grant_token"]
        assert isinstance(token, str)
        return token

    def info(self) -> WindowInfo:
        return self.controller.describe(self.session, self.nonce(), self.read, 41)


def test_approved_window_read_and_actions() -> None:
    f = Fixture()
    assert f.info().title == "Approved test window"
    assert f.controller.local_windows() == (f.backend.info,)
    assert f.controller.capture(f.session, f.nonce(), f.read, 41).startswith(b"\x89PNG")
    assert f.controller.inspect(f.session, f.nonce(), f.read, 41) == f.backend.nodes
    f.controller.click(f.session, f.nonce(), f.input, 41, 200, 300)
    f.controller.type_text(f.session, f.nonce(), f.input, 41, "hello")
    f.controller.scroll(f.session, f.nonce(), f.input, 41, -2)
    f.controller.press_key(f.session, f.nonce(), f.input, 41, "TAB")
    assert ("click", 41, 200, 300) in f.backend.actions
    assert ("type", 41, "hello") in f.backend.actions
    assert ("key", 41, "tab") in f.backend.actions


def test_remote_cannot_add_unauthorized_window() -> None:
    f = Fixture(trusted=False)
    with pytest.raises(DesktopDenied, match="safely available"):
        f.info()
    assert not f.backend.actions


@pytest.mark.parametrize(
    "changed",
    [
        {"foreground": False},
        {"visible": False},
        {"enabled": False},
        {"minimized": True},
        {"same_user": False},
        {"same_session": False},
        {"elevated": True},
        {"rect": Rect(200, 200, 200, 300)},
    ],
)
def test_unsafe_windows_fail_closed(changed: dict[str, object]) -> None:
    f = Fixture()
    f.backend.info = replace(f.backend.info, **cast(dict[str, Any], changed))
    with pytest.raises(DesktopDenied):
        f.info()
    assert not f.backend.actions


def test_identity_reuse_blocks_authorized_window() -> None:
    f = Fixture()
    f.backend.info = replace(
        f.backend.info,
        identity=WindowIdentity(41, 1001, 999999),
    )
    with pytest.raises(DesktopDenied):
        f.info()


def test_locked_desktop_suppresses_even_local_enumeration() -> None:
    f = Fixture()
    f.backend.ready = False
    assert f.controller.local_windows() == ()
    with pytest.raises(DesktopDenied, match="unsafe"):
        f.info()


def test_no_session_grant_or_wrong_capability() -> None:
    f = Fixture()
    with pytest.raises(AccessDenied):
        f.controller.describe(f.session, f.nonce(), f.input, 41)
    with pytest.raises(AccessDenied):
        f.controller.click(f.session, f.nonce(), f.read, 41, 300, 400)


def test_invalid_session_and_nonce_replay_do_not_call_backend() -> None:
    f = Fixture()
    with pytest.raises(SessionDenied):
        f.controller.describe("invalid", f.nonce(), f.read, 41)
    nonce = f.nonce()
    f.controller.describe(f.session, nonce, f.read, 41)
    with pytest.raises(SessionDenied, match="replayed"):
        f.controller.describe(f.session, nonce, f.read, 41)
    assert not f.backend.actions


def test_wrong_window_and_scoped_target_denied() -> None:
    f = Fixture()
    with pytest.raises(AccessDenied):
        f.controller.describe(f.session, f.nonce(), f.read, 42)
    assert not f.backend.actions


def test_no_click_beyond_bounds() -> None:
    f = Fixture()
    for x, y in ((99, 200), (500, 400), (200, 600)):
        with pytest.raises(DesktopDenied, match="outside"):
            f.controller.click(f.session, f.nonce(), f.input, 41, x, y)
    with pytest.raises(DesktopDenied, match="integer"):
        f.controller.click(f.session, f.nonce(), f.input, 41, True, 400)


@pytest.mark.parametrize("text", ["", "a" * 257, "line\nbreak", "field\tvalue", "\x00"])
def test_invalid_typing_is_blocked(text: str) -> None:
    f = Fixture()
    with pytest.raises(DesktopDenied):
        f.controller.type_text(f.session, f.nonce(), f.input, 41, text)
    assert not f.backend.actions


@pytest.mark.parametrize("key", ["enter", "ctrl", "alt", "win", "f4", "a", ""])
def test_unbounded_hotkeys_are_denied(key: str) -> None:
    f = Fixture()
    with pytest.raises(DesktopDenied):
        f.controller.press_key(f.session, f.nonce(), f.input, 41, key)
    assert not f.backend.actions


@pytest.mark.parametrize("steps", [-99, 0, 4, True])
def test_unbounded_scroll_is_denied(steps: int) -> None:
    f = Fixture()
    with pytest.raises(DesktopDenied):
        f.controller.scroll(f.session, f.nonce(), f.input, 41, steps)


def test_screen_capture_is_size_limited() -> None:
    f = Fixture()
    f.backend.image = b"x" * 4_000_001
    with pytest.raises(DesktopDenied, match="size limit"):
        f.controller.capture(f.session, f.nonce(), f.read, 41)


def test_ui_automation_nodes_are_bounded() -> None:
    f = Fixture()
    f.backend.nodes = tuple(ControlInfo("Button", "ok", 1) for _ in range(65))
    with pytest.raises(DesktopDenied, match="limits"):
        f.controller.inspect(f.session, f.nonce(), f.read, 41)
    f.backend.nodes = (ControlInfo("Button", "ok", 4),)
    with pytest.raises(DesktopDenied, match="limits"):
        f.controller.inspect(f.session, f.nonce(), f.read, 41)


def test_grant_revocation_and_emergency_stop_apply_immediately() -> None:
    f = Fixture()
    f.broker.revoke_grant(f.session, f.nonce(), f.input)
    with pytest.raises(SessionDenied):
        f.controller.click(f.session, f.nonce(), f.input, 41, 200, 300)
    f.broker.stop(f.session, f.nonce())
    with pytest.raises(SessionDenied):
        f.controller.describe(f.session, f.nonce(), f.read, 41)
    assert not f.backend.actions
