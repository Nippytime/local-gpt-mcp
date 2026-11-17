"""Device-local, fail-closed execution gate for independent owner receipts.

All remote input requires a pinned receipt verifier, a trusted local pairing,
and an explicitly installed native adapter with its own lock/UAC/target checks.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from local_gpt_mcp.gateway.registry import DeviceUnavailable
from local_gpt_mcp.policy.authority import Caller, Capability, PolicyAuthority
from local_gpt_mcp.policy.remote_receipts import (
    RemoteApprovalDenied,
    RemoteApprovalVerifier,
    ScopedAction,
    action_fingerprint,
)

RESULT = dict[str, str | int | bool]


class NativeActionAdapter(Protocol):
    """Must check live foreground, lock/UAC, target and STOP at effect dispatch."""

    async def execute(self, target: str, operation: str, parameters: Mapping[str, int]) -> RESULT: ...


class DenyAllNativeAdapter:
    async def execute(self, target: str, operation: str, parameters: Mapping[str, int]) -> RESULT:
        raise DeviceUnavailable("Native remote input adapter is not locally enabled")


class AuthorizedActionRunner:
    """An authenticated agent cannot self-sign owner consent or bypass pairing."""

    def __init__(
        self,
        device_id: str,
        verifier: RemoteApprovalVerifier,
        policy: PolicyAuthority,
        *,
        executor: NativeActionAdapter | None = None,
    ) -> None:
        self.device_id = device_id
        self.verifier = verifier
        self.policy = policy
        self.executor = executor if executor is not None else DenyAllNativeAdapter()

    async def execute(self, delivery: Mapping[str, object]) -> RESULT:
        if not isinstance(delivery, Mapping):
            raise DeviceUnavailable("Invalid remote action")
        job_id = delivery.get("job_id")
        owner = delivery.get("user_id")
        device = delivery.get("device_id")
        session = delivery.get("session_id")
        target = delivery.get("target")
        capability = delivery.get("capability")
        fingerprint = delivery.get("action_sha256")
        operation = delivery.get("operation")
        parameters = delivery.get("parameters")
        receipt = delivery.get("receipt")
        if (
            not all(isinstance(value, str) for value in (
                job_id, owner, device, session, target, capability, fingerprint, operation, receipt
            ))
            or device != self.device_id
            or capability != Capability.WINDOW_INPUT.value
            or operation != "window.click"
            or not isinstance(parameters, dict)
            or set(parameters) != {"x", "y"}
            or any(type(parameters[axis]) is not int or not 0 <= parameters[axis] <= 100_000 for axis in ("x", "y"))
        ):
            raise DeviceUnavailable("Unsupported remote input payload")
        try:
            assert isinstance(owner, str)
            assert isinstance(device, str)
            assert isinstance(session, str)
            assert isinstance(job_id, str)
            assert isinstance(target, str)
            assert isinstance(fingerprint, str)
            assert isinstance(operation, str)
            assert isinstance(receipt, str)
            action = ScopedAction(
                Caller(owner, device, session), target, Capability.WINDOW_INPUT, fingerprint, job_id
            )
            if action.action_sha256 != action_fingerprint(operation, parameters):
                raise RemoteApprovalDenied("Remote action parameters differ from approved request")
            # One-use, issuer-pinned proof, consumed before any possible side effect.
            self.verifier.verify(receipt, action)
            self.policy.require_remote_pairing(action.caller, action.target, action.capability)
            # Native implementation must recheck Windows foreground, lock/UAC and
            # the authority STOP immediately at the actual input dispatch.
            result = await self.executor.execute(action.target, operation, parameters)
        except (RemoteApprovalDenied, ValueError, TypeError) as error:
            raise DeviceUnavailable("Remote input was not locally authorized") from error
        if (
            not isinstance(result, dict)
            or len(result) > 8
            or any(
                not isinstance(key, str)
                or not 0 < len(key) <= 60
                or not isinstance(value, str | int | bool)
                for key, value in result.items()
            )
        ):
            raise DeviceUnavailable("Untrusted native input result")
        return result
