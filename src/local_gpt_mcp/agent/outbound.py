"""Opt-in outbound HTTPS agent. It never listens on a Windows network port.

The agent receives only scoped read requests. A trusted local adapter must
independently authenticate its window/browser grants before responding.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Protocol
from urllib.parse import urlsplit

import httpx2 as httpx

from local_gpt_mcp.agent.identity import DeviceAuthenticationError, DeviceIdentity, sign_request
from local_gpt_mcp.gateway.registry import DeviceUnavailable, ReadRequest

ReadResult = Mapping[str, str | int | bool]


class LocalReadExecutor(Protocol):
    async def read(self, request: ReadRequest) -> ReadResult: ...


class DenyAllExecutor:
    async def read(self, request: ReadRequest) -> ReadResult:
        raise DeviceUnavailable("Locally authorized read adapter is not configured")


class OutboundAgent:
    """Only this process initiates HTTPS. No shell, input or remote grant API."""

    def __init__(
        self,
        identity: DeviceIdentity,
        base_url: str,
        *,
        executor: LocalReadExecutor | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parts = urlsplit(base_url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
            or parts.path not in {"", "/"}
        ):
            raise ValueError("Outbound device agent requires a fixed HTTPS gateway")
        self.identity = identity
        self.base_url = base_url.rstrip("/")
        self.executor = executor if executor is not None else DenyAllExecutor()
        self._client = client

    async def _post(self, path: str, body: dict[str, object], *, signed: bool) -> dict[str, object]:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if signed:
            headers.update(sign_request(self.identity.private_key, self.identity.device_id, path, raw))
        if self._client is None:
            raise DeviceUnavailable("No trusted outbound transport")
        response = await self._client.post(
            self.base_url + path, content=raw, headers=headers, follow_redirects=False, timeout=8
        )
        if response.status_code != 200 or len(response.content) > 8192:
            raise DeviceUnavailable("Gateway rejected device operation")
        result = response.json()
        if not isinstance(result, dict):
            raise DeviceUnavailable("Invalid gateway response")
        return result

    async def enroll(self, code: str) -> None:
        if not isinstance(code, str) or not 20 <= len(code) <= 128:
            raise DeviceAuthenticationError("Invalid owner enrollment code")
        reply = await self._post(
            "/api/agent/enroll",
            {
                "enrollment_code": code,
                "device_id": self.identity.device_id,
                "public_key": self.identity.public_key,
            },
            signed=False,
        )
        if reply.get("enrolled") is not True:
            raise DeviceAuthenticationError("Device enrollment was refused")

    async def tick(self) -> bool:
        """Poll once and deliver a read only after an independent local grant."""
        response = await self._post("/api/agent/poll", {}, signed=True)
        job_id = response.get("job_id")
        if job_id is None:
            return False
        if not isinstance(job_id, str) or len(job_id) != 32:
            raise DeviceUnavailable("Invalid work identifier")
        request = ReadRequest(
            kind=response.get("kind", ""),
            target=response.get("target", ""),
            selector=response.get("selector", ""),
        )
        try:
            output = await asyncio.wait_for(self.executor.read(request), timeout=6)
        except (DeviceUnavailable, PermissionError, TimeoutError, ValueError):
            # Never convert denied local authorization into successful work.
            output = {"error": "Local read was not approved or the PC is unavailable"}
        result = dict(output)
        if len(json.dumps(result)) > 8192 or len(result) > 32:
            raise DeviceUnavailable("Local read response exceeds limit")
        acknowledgment = await self._post(
            "/api/agent/result", {"job_id": job_id, "result": result}, signed=True
        )
        if acknowledgment.get("accepted") is not True:
            raise DeviceUnavailable("Gateway did not accept the read result")
        return True

    async def run(self, stop: asyncio.Event) -> None:
        """Reconnect with bounded backoff. No background service is installed."""
        pause = 1.0
        while not stop.is_set():
            try:
                await self.tick()
                pause = 1.0
                # A remote command cannot determine or disable this local stop.
                try:
                    await asyncio.wait_for(stop.wait(), timeout=1)
                except TimeoutError:
                    pass
            except (DeviceUnavailable, httpx.HTTPError, ValueError, TypeError, OSError):
                try:
                    await asyncio.wait_for(stop.wait(), timeout=pause)
                except TimeoutError:
                    pass
                pause = min(pause * 2, 16.0)
