"""Owner-visible, deny-first pending approval queue; never callable as an MCP tool.

A trusted server component alone can enqueue validated, exact device actions.
The owner APIs cannot enqueue work or retrieve a signed approval receipt.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from local_gpt_mcp.policy.owner_presence import OwnerPresence, PresenceChallenge
from local_gpt_mcp.policy.remote_receipts import (
    RemoteApprovalDenied,
    ScopedAction,
    action_fingerprint,
)

PENDING_SECONDS = 60
MAX_PENDING = 128


@dataclass(slots=True)
class _PendingAction:
    action: ScopedAction
    operation: str
    parameters: dict[str, str | int | bool]
    expires_at: int
    challenge: str | None = None
    credential_id: str | None = None
    receipt: str | None = None


class OwnerApprovalQueue:
    """Hold the exact action awaiting independent, UV-verified owner consent."""

    def __init__(
        self,
        presence: OwnerPresence,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._presence = presence
        self._clock = clock
        self._lock = threading.RLock()
        self._pending: dict[str, _PendingAction] = {}
        self._halted: set[str] = set()

    def _prune(self, now: int) -> None:
        self._pending = {key: entry for key, entry in self._pending.items() if entry.expires_at > now}

    def _find(self, owner: str, job_id: str) -> _PendingAction:
        if not isinstance(owner, str) or not isinstance(job_id, str) or owner in self._halted:
            raise RemoteApprovalDenied("Approval is unavailable")
        self._prune(int(self._clock()))
        entry = self._pending.get(job_id)
        if entry is None or entry.action.caller.user_id != owner:
            raise RemoteApprovalDenied("Approval is unavailable")
        return entry

    def offer_trusted(
        self,
        action: ScopedAction,
        *,
        operation: str,
        parameters: Mapping[str, str | int | bool],
    ) -> None:
        """Trusted relay ONLY: validate the displayed operation equals the action hash."""
        if not isinstance(action, ScopedAction):
            raise RemoteApprovalDenied("Invalid action")
        digest = action_fingerprint(operation, parameters)
        if digest != action.action_sha256:
            raise RemoteApprovalDenied("Pending action differs from its consent scope")
        with self._lock:
            now = int(self._clock())
            self._prune(now)
            if action.caller.user_id in self._halted or action.job_id in self._pending:
                raise RemoteApprovalDenied("Approval is stopped or already pending")
            if len(self._pending) >= MAX_PENDING:
                raise RemoteApprovalDenied("Too many pending approvals")
            self._pending[action.job_id] = _PendingAction(
                action, operation, dict(parameters), now + PENDING_SECONDS
            )

    def list_owned(self, owner: str) -> list[dict[str, object]]:
        """Only owner-bound pending action details, never passkey or receipt secrets."""
        with self._lock:
            if owner in self._halted:
                return []
            self._prune(int(self._clock()))
            return [
                {
                    "job_id": entry.action.job_id,
                    "device_id": entry.action.caller.device_id,
                    "session_id": entry.action.caller.session_id,
                    "target": entry.action.target,
                    "capability": entry.action.capability.value,
                    "operation": entry.operation,
                    "parameters": dict(entry.parameters),
                    "expires_at": entry.expires_at,
                    "approved": entry.receipt is not None,
                }
                for entry in self._pending.values()
                if entry.action.caller.user_id == owner
            ]

    def begin(self, owner: str, job_id: str, credential_id: str) -> PresenceChallenge:
        """An authenticated owner chooses an EXISTING pending action, not its arguments."""
        with self._lock:
            entry = self._find(owner, job_id)
            if entry.challenge is not None or entry.receipt is not None:
                raise RemoteApprovalDenied("Approval already started")
            challenge = self._presence.begin(owner, credential_id, entry.action)
            entry.challenge = challenge.challenge
            entry.credential_id = credential_id
            return challenge

    def finish(
        self,
        owner: str,
        job_id: str,
        credential_id: str,
        challenge: str,
        *,
        client_data: bytes,
        authenticator_data: bytes,
        signature: bytes,
    ) -> None:
        """Never return the signed receipt to the owner HTTP caller or the model."""
        with self._lock:
            entry = self._find(owner, job_id)
            if (
                entry.challenge is None
                or entry.challenge != challenge
                or entry.credential_id != credential_id
                or entry.receipt is not None
            ):
                raise RemoteApprovalDenied("Challenge is not tied to this job")
            entry.receipt = self._presence.finish(
                owner,
                credential_id,
                challenge,
                client_data=client_data,
                authenticator_data=authenticator_data,
                signature=signature,
            )

    def take_trusted(self, owner: str, device_id: str, expected: ScopedAction) -> str:
        """ONLY signed device polling may use this seam; not an owner/API endpoint."""
        with self._lock:
            entry = self._find(owner, expected.job_id)
            if (
                entry.action != expected
                or entry.action.caller.device_id != device_id
                or entry.receipt is None
            ):
                raise RemoteApprovalDenied("Device job has no matching owner approval")
            receipt = entry.receipt
            del self._pending[expected.job_id]
            return receipt

    def deny(self, owner: str, job_id: str) -> None:
        with self._lock:
            self._find(owner, job_id)
            del self._pending[job_id]

    def halt_owner(self, owner: str) -> None:
        """Cancel queued approvals permanently for this service instance.

        This does not yet replace independent native Windows emergency STOP.
        """
        with self._lock:
            self._halted.add(owner)
            self._pending = {
                job_id: entry
                for job_id, entry in self._pending.items()
                if entry.action.caller.user_id != owner
            }
