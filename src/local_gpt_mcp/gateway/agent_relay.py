"""Single-process outbound agent relay with trusted enrollment and bounded reads.

No remotely mutating actions. All polls/results require device-key signatures.
A production deployment needs durable, shared enrollment/replay/queue state.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from local_gpt_mcp.agent.identity import (
    DeviceAuthenticationError,
    DeviceReplayGuard,
    decode_public_key,
)
from local_gpt_mcp.gateway.registry import DeviceDirectory, DeviceUnavailable, ReadRequest

ENROLL_SECONDS = 180
READ_SECONDS = 8
MAX_QUEUED = 4


@dataclass(frozen=True, slots=True)
class _Enrollment:
    owner: str
    device_id: str
    label: str
    expiry: float


@dataclass(slots=True)
class _Job:
    owner: str
    device_id: str
    request: ReadRequest
    future: asyncio.Future[Mapping[str, str | int | bool]]
    expiry: float
    delivered: bool = False


@dataclass(slots=True)
class _Member:
    owner: str
    key: Ed25519PublicKey
    last_seen: float = 0


class AgentRelay:
    """Own the device read boundary; OAuth users can never call these methods via MCP."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._directory: DeviceDirectory | None = None
        self._enrollments: dict[str, _Enrollment] = {}
        self._members: dict[str, _Member] = {}
        self._jobs: dict[str, _Job] = {}
        self._guard = DeviceReplayGuard(clock=self._clock)
        self._lock = threading.RLock()

    def bind(self, directory: DeviceDirectory) -> None:
        if self._directory is not None:
            raise RuntimeError("Agent relay is already bound")
        self._directory = directory

    def issue_code(self, owner: str, label: str) -> tuple[str, str]:
        """Call ONLY after OAuth owner authentication; code is not an MCP tool."""
        if not isinstance(owner, str) or not 0 < len(owner) <= 128:
            raise DeviceAuthenticationError("Invalid owner")
        if not isinstance(label, str) or not 0 < len(label) <= 80:
            raise DeviceAuthenticationError("Invalid device label")
        code = secrets.token_urlsafe(32)
        device_id = "pc-" + secrets.token_hex(12)
        with self._lock:
            self._enrollments[hashlib.sha256(code.encode()).hexdigest()] = _Enrollment(
                owner, device_id, label, self._clock() + ENROLL_SECONDS
            )
        return code, device_id

    def enroll(self, code: str, device_id: str, public_key: str) -> None:
        """One-time high-entropy code authorizes binding this new public key."""
        if not isinstance(code, str) or len(code) > 128:
            raise DeviceAuthenticationError("Invalid enrollment")
        key = decode_public_key(public_key)
        digest = hashlib.sha256(code.encode()).hexdigest()
        with self._lock:
            entry = self._enrollments.pop(digest, None)
            if entry is None or entry.device_id != device_id or self._clock() >= entry.expiry:
                raise DeviceAuthenticationError("Enrollment unavailable")
            if self._directory is None:
                raise DeviceAuthenticationError("No trusted directory")
            self._directory.enroll_trusted(entry.owner, device_id, entry.label)
            self._members[device_id] = _Member(entry.owner, key)

    def authenticate(
        self, device_id: str, path: str, body: bytes, headers: Mapping[str, str]
    ) -> str:
        with self._lock:
            member = self._members.get(device_id)
            if member is None or not isinstance(device_id, str):
                raise DeviceAuthenticationError("Unknown device identity")
            self._guard.verify(member.key, device_id, path, body, headers)
            member.last_seen = self._clock()
            if self._directory is not None:
                self._directory.set_online_trusted(member.owner, device_id, True)
            return member.owner

    def revoke(self, owner: str, device_id: str) -> None:
        """Owner-only, authenticated API; revoke any queued work immediately."""
        with self._lock:
            member = self._members.get(device_id)
            if member is None or member.owner != owner:
                raise DeviceUnavailable("Device unavailable")
            del self._members[device_id]
            if self._directory is not None:
                self._directory.set_online_trusted(owner, device_id, False)
            for job_id, job in list(self._jobs.items()):
                if job.device_id == device_id:
                    if not job.future.done():
                        job.future.set_exception(DeviceUnavailable("Device revoked"))
                    del self._jobs[job_id]

    async def read(
        self, owner: str, device_id: str, request: ReadRequest
    ) -> Mapping[str, str | int | bool]:
        loop = asyncio.get_running_loop()
        job_id = secrets.token_hex(16)
        with self._lock:
            member = self._members.get(device_id)
            if (
                member is None
                or member.owner != owner
                or self._clock() - member.last_seen > 20
                or sum(1 for job in self._jobs.values() if job.device_id == device_id) >= MAX_QUEUED
            ):
                raise DeviceUnavailable("Device not actively connected")
            future: asyncio.Future[Mapping[str, str | int | bool]] = loop.create_future()
            self._jobs[job_id] = _Job(owner, device_id, request, future, self._clock() + READ_SECONDS)
        try:
            result = await asyncio.wait_for(future, timeout=READ_SECONDS)
            if "error" in result:
                raise DeviceUnavailable("The local PC denied the observation")
            return result
        except TimeoutError:
            raise DeviceUnavailable("Device read expired") from None
        finally:
            with self._lock:
                self._jobs.pop(job_id, None)

    def poll(self, owner: str, device_id: str) -> dict[str, object]:
        """At most one read job, delivered once and never replayed."""
        with self._lock:
            for job_id, job in self._jobs.items():
                if job.owner == owner and job.device_id == device_id and not job.delivered:
                    if self._clock() >= job.expiry:
                        continue
                    job.delivered = True
                    return {
                        "job_id": job_id,
                        "kind": job.request.kind,
                        "target": job.request.target,
                        "selector": job.request.selector,
                    }
        return {"job_id": None}

    def reply(
        self, owner: str, device_id: str, job_id: str, values: Mapping[str, str | int | bool]
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if (
                job is None
                or job.owner != owner
                or job.device_id != device_id
                or not job.delivered
                or self._clock() >= job.expiry
                or job.future.done()
            ):
                raise DeviceUnavailable("Unknown, expired or completed device job")
            job.future.set_result(values)
