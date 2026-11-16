"""Executor-side authorization. Never expose the local allowlist as an MCP tool."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Protocol

from local_gpt_mcp.desktop.types import ControlInfo, WindowIdentity, WindowInfo
from local_gpt_mcp.pairing import SessionBroker
from local_gpt_mcp.policy import Capability

MAX_TEXT = 256
MAX_IMAGE_BYTES = 4_000_000
MAX_CONTROLS = 64
MAX_DEPTH = 3
SAFE_KEYS = frozenset(
    {"tab", "escape", "backspace", "left", "right", "up", "down", "home", "end"}
)


class DesktopDenied(PermissionError):
    """Window safety precondition, scope, or action limit was rejected."""


class WindowBackend(Protocol):
    """Native Windows implementation, injectable for deterministic tests."""

    def desktop_ready(self) -> bool: ...

    def windows(self) -> tuple[WindowInfo, ...]: ...

    def window(self, handle: int) -> WindowInfo | None: ...

    def capture(self, handle: int) -> bytes: ...

    def controls(self, handle: int, max_depth: int, max_nodes: int) -> tuple[ControlInfo, ...]: ...

    def click(self, handle: int, x: int, y: int) -> None: ...

    def type_text(self, handle: int, text: str) -> None: ...

    def scroll(self, handle: int, steps: int) -> None: ...

    def press_key(self, handle: int, key: str) -> None: ...


class DesktopController:
    """Only accepts window identities selected by a trusted, local human.

    The allowlist is immutable for this controller lifetime. A remote MCP
    caller cannot add or swap a handle. Backend methods re-check native state
    just before dispatch to defend against window replacement/focus changes.
    """

    def __init__(
        self,
        broker: SessionBroker,
        backend: WindowBackend,
        allowed: Iterable[WindowIdentity],
    ) -> None:
        self._broker = broker
        self._backend = backend
        self._allowed = frozenset(allowed)
        self._lock = threading.RLock()

    def local_windows(self) -> tuple[WindowInfo, ...]:
        """For trusted local selection UI only, NOT registered as an MCP tool."""
        with self._lock:
            if not self._backend.desktop_ready():
                return ()
            return tuple(
                item
                for item in self._backend.windows()
                if item.identity in self._allowed
                and item.visible
                and item.same_user
                and item.same_session
                and not item.elevated
            )

    def _window(self, handle: int) -> WindowInfo:
        if type(handle) is not int or handle <= 0 or not self._backend.desktop_ready():
            raise DesktopDenied("Desktop is unavailable or unsafe")
        window = self._backend.window(handle)
        if (
            window is None
            or window.identity not in self._allowed
            or not window.visible
            or not window.foreground
            or not window.enabled
            or window.minimized
            or not window.same_user
            or not window.same_session
            or window.elevated
            or window.rect.width < 1
            or window.rect.height < 1
        ):
            raise DesktopDenied("Selected window is not safely available")
        return window

    def _authorized(
        self, session: str, nonce: str, grant: str, handle: int, capability: Capability
    ) -> WindowInfo:
        # Consume the nonce and enforce pairing, expiry, caller, exact target,
        # capability and cancellation, even when the native window is unsafe.
        self._broker.authorize_grant(session, nonce, grant, f"window:{handle}", capability)
        return self._window(handle)

    def describe(self, session: str, nonce: str, grant: str, handle: int) -> WindowInfo:
        with self._lock:
            return self._authorized(session, nonce, grant, handle, Capability.WINDOW_READ)

    def capture(self, session: str, nonce: str, grant: str, handle: int) -> bytes:
        with self._lock:
            self._authorized(session, nonce, grant, handle, Capability.WINDOW_READ)
            data = self._backend.capture(handle)
            if not isinstance(data, bytes) or not 0 < len(data) <= MAX_IMAGE_BYTES:
                raise DesktopDenied("Window capture failed or exceeded its size limit")
            return data

    def inspect(self, session: str, nonce: str, grant: str, handle: int) -> tuple[ControlInfo, ...]:
        with self._lock:
            self._authorized(session, nonce, grant, handle, Capability.WINDOW_READ)
            nodes = self._backend.controls(handle, MAX_DEPTH, MAX_CONTROLS)
            if len(nodes) > MAX_CONTROLS or any(
                node.depth > MAX_DEPTH or node.depth < 0 for node in nodes
            ):
                raise DesktopDenied("UI Automation output exceeded safety limits")
            return nodes

    def click(
        self, session: str, nonce: str, grant: str, handle: int, x: int, y: int
    ) -> None:
        if type(x) is not int or type(y) is not int:
            raise DesktopDenied("Click coordinates must be integer screen pixels")
        with self._lock:
            window = self._authorized(session, nonce, grant, handle, Capability.WINDOW_INPUT)
            if not window.rect.contains(x, y):
                raise DesktopDenied("Click is outside the selected window")
            self._backend.click(handle, x, y)

    def type_text(self, session: str, nonce: str, grant: str, handle: int, text: str) -> None:
        if (
            not isinstance(text, str)
            or not 0 < len(text) <= MAX_TEXT
            or not text.isprintable()
        ):
            raise DesktopDenied("Text must be printable and contain 1–256 characters")
        with self._lock:
            self._authorized(session, nonce, grant, handle, Capability.WINDOW_INPUT)
            self._backend.type_text(handle, text)

    def scroll(self, session: str, nonce: str, grant: str, handle: int, steps: int) -> None:
        if type(steps) is not int or steps == 0 or abs(steps) > 3:
            raise DesktopDenied("Scroll must be between -3 and 3 wheel steps")
        with self._lock:
            self._authorized(session, nonce, grant, handle, Capability.WINDOW_INPUT)
            self._backend.scroll(handle, steps)

    def press_key(self, session: str, nonce: str, grant: str, handle: int, key: str) -> None:
        if not isinstance(key, str) or key.lower() not in SAFE_KEYS:
            raise DesktopDenied("Only bounded navigation keys are supported")
        with self._lock:
            self._authorized(session, nonce, grant, handle, Capability.WINDOW_INPUT)
            self._backend.press_key(handle, key.lower())
