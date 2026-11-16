"""Bounded, consent-gated Windows desktop adapter."""

from local_gpt_mcp.desktop.controller import DesktopController, DesktopDenied, WindowBackend
from local_gpt_mcp.desktop.types import ControlInfo, Rect, WindowIdentity, WindowInfo

__all__ = [
    "ControlInfo",
    "DesktopController",
    "DesktopDenied",
    "Rect",
    "WindowBackend",
    "WindowIdentity",
    "WindowInfo",
]
