"""Tenant-scoped device directory and fail-closed transport boundary.

The gateway never owns local grants, executes OS actions, or receives cookies.
The outbound agent (Issue #22) must implement the read transport separately.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from local_gpt_mcp.browser.controller import BrowserDenied, approved_origin

IDENTITY = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
READ_KINDS = frozenset({"desktop_window_info", "desktop_controls", "browser_read"})


class DeviceUnavailable(PermissionError):
    """The device is offline, outside the caller's account, or not authorized."""


@dataclass(frozen=True, slots=True)
class ReadRequest:
    kind: str
    target: str
    selector: str = ""

    def __post_init__(self) -> None:
        if (
            self.kind not in READ_KINDS
            or not isinstance(self.target, str)
            or not 0 < len(self.target) <= 128
            or not isinstance(self.selector, str)
            or len(self.selector) > 256
            or (self.kind == "browser_read" and not self.selector)
            or (self.kind != "browser_read" and self.selector)
        ):
            raise DeviceUnavailable("Unsupported scoped observation")
        if self.kind.startswith("desktop_"):
            if re.fullmatch(r"window:[1-9][0-9]{0,15}", self.target) is None:
                raise DeviceUnavailable("A selected HWND is required")
        else:
            try:
                approved_origin(self.target)
            except BrowserDenied:
                raise DeviceUnavailable("A public HTTPS origin is required") from None


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    owner: str
    device_id: str
    label: str
    online: bool = False


class ReadTransport(Protocol):
    async def read(
        self, owner: str, device_id: str, request: ReadRequest
    ) -> Mapping[str, str | int | bool]: ...


class DenyAllTransport:
    async def read(
        self, owner: str, device_id: str, request: ReadRequest
    ) -> Mapping[str, str | int | bool]:
        raise DeviceUnavailable("A verified outbound agent is not connected")


class DeviceDirectory:
    """Only trusted server/agent code can enroll or mark a device online.

    No MCP tools expose enrollment or connection-state mutation.
    """

    def __init__(self, transport: ReadTransport | None = None) -> None:
        self._transport = transport if transport is not None else DenyAllTransport()
        self._devices: dict[str, DeviceRecord] = {}
        self._lock = threading.RLock()

    def enroll_trusted(self, owner: str, device_id: str, label: str) -> None:
        """Internal trusted enrollment seam. Owner proof arrives in Issue #22."""
        if (
            not isinstance(owner, str)
            or not IDENTITY.fullmatch(owner)
            or not isinstance(device_id, str)
            or not IDENTITY.fullmatch(device_id)
            or not isinstance(label, str)
            or not 0 < len(label) <= 80
        ):
            raise ValueError("Invalid registered identity")
        with self._lock:
            if device_id in self._devices:
                raise DeviceUnavailable("Device is already registered")
            self._devices[device_id] = DeviceRecord(owner, device_id, label)

    def set_online_trusted(self, owner: str, device_id: str, online: bool) -> None:
        """Internal seam; never expose this as an MCP tool or public API."""
        with self._lock:
            current = self._owned(owner, device_id)
            self._devices[device_id] = DeviceRecord(owner, device_id, current.label, online)

    def _owned(self, owner: str, device_id: str) -> DeviceRecord:
        current = self._devices.get(device_id)
        if current is None or current.owner != owner:
            # Do not disclose whether a different user's machine exists.
            raise DeviceUnavailable("Device unavailable")
        return current

    def list_owned(self, owner: str) -> list[dict[str, str | bool]]:
        with self._lock:
            return [
                {"device_id": device.device_id, "label": device.label, "online": device.online}
                for device in sorted(self._devices.values(), key=lambda item: item.device_id)
                if device.owner == owner
            ]

    def status(self, owner: str, device_id: str) -> dict[str, str | bool]:
        with self._lock:
            device = self._owned(owner, device_id)
            return {"device_id": device.device_id, "label": device.label, "online": device.online}

    async def read(
        self, owner: str, device_id: str, request: ReadRequest
    ) -> dict[str, str | int | bool]:
        with self._lock:
            if not self._owned(owner, device_id).online:
                raise DeviceUnavailable("Device unavailable")
        # Never share a bearer credential or a local grant with the cloud.
        # The agent must independently authorize a scoped observation.
        result = await self._transport.read(owner, device_id, request)
        with self._lock:
            if not self._owned(owner, device_id).online:
                raise DeviceUnavailable("Device disconnected")
        if not isinstance(result, Mapping) or len(result) > 32:
            raise DeviceUnavailable("Untrusted device response")
        if any(
            not isinstance(key, str)
            or not 0 < len(key) <= 80
            or not isinstance(value, str | int | bool)
            for key, value in result.items()
        ):
            raise DeviceUnavailable("Untrusted device response")
        output = dict(result)
        if len(json.dumps(output)) > 8192:
            raise DeviceUnavailable("Untrusted device response")
        return output
