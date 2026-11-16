"""Sequential workflow execution with local action approval and crash-safe stop points."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from local_gpt_mcp.orchestrator.models import READ_ONLY, Checkpoint, SessionGrants, Step, WorkflowPlan
from local_gpt_mcp.orchestrator.store import CheckpointStore
from local_gpt_mcp.pairing import SessionBroker

STEP_TIMEOUT_SECONDS = 12
MAX_READ_ATTEMPTS = 2


class WorkflowFailure(RuntimeError):
    """Sanitized workflow failure; contains no user text, tokens, or target URL."""


class ActionApproval(Protocol):
    """Trusted local UI callback, never wired to an MCP tool or remote flag."""

    def approve(self, step: Step) -> bool: ...


class DenyAllActions:
    def approve(self, step: Step) -> bool:
        return False


class WorkflowDriver(Protocol):
    async def perform(self, step: Step, credentials: SessionGrants, nonce: str) -> str: ...

    async def condition(
        self, step: Step, condition: object, credentials: SessionGrants, nonce: str
    ) -> bool: ...


class Cancellation:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()


@dataclass(frozen=True, slots=True)
class StepOutput:
    step_id: str
    result: str


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    plan_id: str
    completed: int
    finished: bool
    outputs: tuple[StepOutput, ...]


class WorkflowEngine:
    """Each operation is scoped by an existing session and independently approved grants."""

    def __init__(
        self,
        broker: SessionBroker,
        driver: WorkflowDriver,
        store: CheckpointStore,
        approval: ActionApproval | None = None,
    ) -> None:
        self._broker = broker
        self._driver = driver
        self._store = store
        self._approval = approval if approval is not None else DenyAllActions()
        self._lock = asyncio.Lock()

    async def _interruptible[T](
        self, operation: Coroutine[Any, Any, T], cancellation: Cancellation, timeout: float
    ) -> T:
        if cancellation.cancelled:
            operation.close()
            raise WorkflowFailure("Workflow cancelled")
        task = asyncio.create_task(operation)
        stop = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait({task, stop}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
            if stop in done:
                raise WorkflowFailure("Workflow cancelled")
            if task not in done:
                raise TimeoutError("Workflow step timed out")
            return await task
        finally:
            stop.cancel()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, stop, return_exceptions=True)

    async def _condition(
        self, step: Step, condition: object, credentials: SessionGrants, cancellation: Cancellation
    ) -> None:
        valid = await self._interruptible(
            self._driver.condition(step, condition, credentials, secrets.token_hex(16)),
            cancellation,
            STEP_TIMEOUT_SECONDS,
        )
        if not valid:
            raise WorkflowFailure("Workflow condition did not match")

    async def run(
        self,
        plan: WorkflowPlan,
        credentials: SessionGrants,
        *,
        resume: bool = False,
        cancellation: Cancellation | None = None,
    ) -> WorkflowResult:
        cancellation = cancellation or Cancellation()
        if self._lock.locked():
            raise WorkflowFailure("Another workflow is already active")
        async with self._lock:
            if cancellation.cancelled:
                raise WorkflowFailure("Workflow cancelled")
            # The session must still be live, even when resuming a completed plan.
            self._broker.status(credentials.session_token, secrets.token_hex(16))
            digest = plan.digest()
            existing = self._store.read(plan.plan_id)
            if existing is not None:
                if existing.plan_digest != digest:
                    raise WorkflowFailure("Checkpoint belongs to a different plan")
                if not resume:
                    raise WorkflowFailure("Existing checkpoint requires explicit resume")
                if existing.state in {"started", "uncertain"}:
                    raise WorkflowFailure("Uncertain side effect requires manual reconciliation")
                if existing.index > len(plan.steps):
                    raise WorkflowFailure("Checkpoint exceeds plan length")
                index = existing.index
                if existing.state == "complete":
                    return WorkflowResult(plan.plan_id, index, True, ())
            else:
                if resume:
                    raise WorkflowFailure("No existing checkpoint to resume")
                index = 0
                self._store.save(plan.plan_id, Checkpoint(digest, 0, "ready"))
            outputs: list[StepOutput] = []
            for position in range(index, len(plan.steps)):
                step = plan.steps[position]
                if cancellation.cancelled:
                    raise WorkflowFailure("Workflow cancelled")
                try:
                    if step.before is not None:
                        await self._condition(step, step.before, credentials, cancellation)
                    # Mutating actions are ALWAYS local-consent-gated, even if
                    # a remote caller claims the action is harmless.
                    if step.action not in READ_ONLY:
                        approved = await self._interruptible(
                            asyncio.to_thread(self._approval.approve, step),
                            cancellation,
                            STEP_TIMEOUT_SECONDS,
                        )
                        if not approved:
                            raise WorkflowFailure("Local approval denied")
                        if cancellation.cancelled:
                            raise WorkflowFailure("Workflow cancelled")
                        # Persist uncertainty BEFORE any possible side effect.
                        self._store.save(plan.plan_id, Checkpoint(digest, position, "started"))
                    attempts = MAX_READ_ATTEMPTS if step.action in READ_ONLY else 1
                    for attempt in range(attempts):
                        try:
                            result = await self._interruptible(
                                self._driver.perform(step, credentials, secrets.token_hex(16)),
                                cancellation,
                                STEP_TIMEOUT_SECONDS,
                            )
                            break
                        except (TimeoutError, ConnectionError):
                            if attempt + 1 >= attempts or cancellation.cancelled:
                                raise
                            await self._interruptible(
                                asyncio.sleep(0.2 * (attempt + 1)), cancellation, STEP_TIMEOUT_SECONDS
                            )
                    if step.after is not None:
                        await self._condition(step, step.after, credentials, cancellation)
                except WorkflowFailure:
                    # Started side effects never become implicitly retryable.
                    if step.action not in READ_ONLY and self._store.read(plan.plan_id) == Checkpoint(
                        digest, position, "started"
                    ):
                        self._store.save(plan.plan_id, Checkpoint(digest, position, "uncertain"))
                    raise
                except Exception:
                    if step.action not in READ_ONLY:
                        self._store.save(plan.plan_id, Checkpoint(digest, position, "uncertain"))
                    # Suppress untrusted page text, underlying URLs and tokens.
                    raise WorkflowFailure("Workflow action failed or timed out") from None
                outputs.append(StepOutput(step.step_id, result))
                state: Literal["ready", "complete"] = "complete" if position + 1 == len(plan.steps) else "ready"
                self._store.save(plan.plan_id, Checkpoint(digest, position + 1, state))
            return WorkflowResult(plan.plan_id, len(plan.steps), True, tuple(outputs))
