"""Immutable window identity and observation data contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WindowIdentity:
    handle: int
    process_id: int
    process_created: int

    def __post_init__(self) -> None:
        if min(self.handle, self.process_id, self.process_created) <= 0:
            raise ValueError("A window identity must contain positive native identifiers")


@dataclass(frozen=True, slots=True)
class Rect:
    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        return self.right - self.left

    @property
    def height(self) -> int:
        return self.bottom - self.top

    def contains(self, x: int, y: int) -> bool:
        return self.left <= x < self.right and self.top <= y < self.bottom


@dataclass(frozen=True, slots=True)
class WindowInfo:
    identity: WindowIdentity
    title: str
    rect: Rect
    foreground: bool
    visible: bool
    enabled: bool
    minimized: bool
    same_user: bool
    same_session: bool
    elevated: bool


@dataclass(frozen=True, slots=True)
class ControlInfo:
    role: str
    name: str
    depth: int
