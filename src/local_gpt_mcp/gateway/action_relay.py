"""Outbound action transport; only separately verified owner presence releases receipts."""

from __future__ import annotations

import asyncio
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from local_gpt_mcp.gateway.registry import DeviceUnavailable
from local_gpt_mcp.policy.approval_queue import OwnerApprovalQueue
from local_gpt_mcp.policy.authority import Caller, Capability
from local_gpt_mcp.policy.remote_receipts import (
    RemoteApprovalDenied,
    ScopedAction,
    action_fingerprint,
)

ACTION_SECONDS = 60
MAX_PENDING_PER_DEVICE = 4
ACTION_OPERATIONS = frozenset({"window.click"})


@dataclass(slots=True)
class _ActionJob:
    action: ScopedAction
    operation: str
    parameters: dict[str, str | int | bool]
    result: asyncio.Future[dict[str, str | int | bool]]
    expires_at: float
    delivered: bool = False


class RemoteActionRelay:

    def __init__(
        self,
        approvals: OwnerApprovalQueue,
        *,
        connected: Callable[[str, str], bool],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.approvals = approvals
        self._connected = connected
        self._clock = clock
        self._jobs: dict[str, _ActionJob] = {}
        self._lock = threading.RLock()
        self._halted: set[str] = set()

    async def request_trusted(
        self,
        owner: str,
        device_id: str,
        session_id: str,
        target: str,
        operation: str,
        parameters: Mapping[str, str | int | bool],
    ) -> dict[str, str | int | bool]:
        """ONLY an authenticated, authorized server request may call this."""
        if operation not in ACTION_OPERATIONS or set(parameters) != {"x", "y"}:
            raise DeviceUnavailable("Unsupported remote action")
        x, y = parameters["x"], parameters["y"]
        if (
            not isinstance(x, int)
            or isinstance(x, bool)
            or not 0 <= x <= 100_000
            or not isinstance(y, int)
            or isinstance(y, bool)
            or not 0 <= y <= 100_000
        ):
            raise DeviceUnavailable("Invalid window click coordinates")
        with self._lock:
            if (
                owner in self._halted
                or not self._connected(owner, device_id)
                or sum(job.action.caller.device_id == device_id for job in self._jobs.values())
                >= MAX_PENDING_PER_DEVICE
            ):
                raise DeviceUnavailable("Device unavailable for remote input")
            job_id = secrets.token_hex(16)
            try:
                action = ScopedAction(
                    Caller(owner, device_id, session_id),
                    target,
                    Capability.WINDOW_INPUT,
                    action_fingerprint(operation, parameters),
                    job_id,
                )
            except RemoteApprovalDenied as error:
                raise DeviceUnavailable("Invalid remote input scope") from error
            loop = asyncio.get_running_loop()
            future: asyncio.Future[dict[str, str | int | bool]] = loop.create_future()
            job = _ActionJob(action, operation, dict(parameters), future, self._clock() + ACTION_SECONDS)
            self.approvals.offer_trusted(action, operation=operation, parameters=parameters)
            self._jobs[job_id] = job
        try:
            result = await asyncio.wait_for(future, timeout=ACTION_SECONDS)
            if "error" in result:
                raise DeviceUnavailable("The local PC denied or could not confirm remote input")
            return result
        except TimeoutError:
            raise DeviceUnavailable("Owner approval or device response expired") from None
        finally:
            with self._lock:
                self._jobs.pop(job_id, None)
            try:
                self.approvals.deny(owner, job_id)
            except RemoteApprovalDenied:
                pass

    def poll_trusted(self, owner: str, device_id: str) -> dict[str, object]:
        """Call only after validating the device signature on the poll endpoint."""
        with self._lock:
            if owner in self._halted or not self._connected(owner, device_id):
                raise DeviceUnavailable("Device offline or remote actions stopped")
            for job_id, job in self._jobs.items():
                if (
                    job.action.caller.user_id != owner
                    or job.action.caller.device_id != device_id
                    or job.delivered
                    or self._clock() >= job.expires_at
                    or job.result.done()
                ):
                    continue
                try:
                    receipt = self.approvals.take_trusted(owner, device_id, job.action)
                except RemoteApprovalDenied:
                    continue  # no passkey proof: never dispatch
                job.delivered = True
                return {
                    "job_id": job_id,
                    "user_id": owner,
                    "device_id": device_id,
                    "session_id": job.action.caller.session_id,
                    "target": job.action.target,
                    "capability": job.action.capability.value,
                    "action_sha256": job.action.action_sha256,
                    "operation": job.operation,
                    "parameters": dict(job.parameters),
                    "receipt": receipt,
                }
        return {"job_id": None}

    def reply_trusted(
        self, owner: str, device_id: str, job_id: str, result: Mapping[str, str | int | bool]
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if (
                job is None
                or owner in self._halted
                or job.action.caller.user_id != owner
                or job.action.caller.device_id != device_id
                or not job.delivered
                or self._clock() >= job.expires_at
                or job.result.done()
                or not self._connected(owner, device_id)
                or not isinstance(result, Mapping)
                or len(result) > 8
                or any(
                    not isinstance(key, str)
                    or not 0 < len(key) <= 60
                    or not isinstance(value, str | int | bool)
                    for key, value in result.items()
                )
            ):
                raise DeviceUnavailable("Untrusted or expired action acknowledgment")
            job.result.set_result(dict(result))

    def revoke_device(self, owner: str, device_id: str) -> None:
        """Cancel without replaying any previously delivered ambiguous effect."""
        with self._lock:
            for job in self._jobs.values():
                if (
                    job.action.caller.user_id == owner
                    and job.action.caller.device_id == device_id
                    and not job.result.done()
                ):
                    job.result.set_exception(DeviceUnavailable("Device revoked"))

    def halt_owner(self, owner: str) -> None:
        with self._lock:
            self._halted.add(owner)
            self.approvals.halt_owner(owner)
            for job in self._jobs.values():
                if job.action.caller.user_id == owner and not job.result.done():
                    job.result.set_exception(DeviceUnavailable("Owner stopped remote requests"))
