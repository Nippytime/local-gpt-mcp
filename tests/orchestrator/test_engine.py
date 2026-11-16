"""Flow tests with real session/grant policy and an in-memory trusted adapter."""

from __future__ import annotations

import asyncio

import pytest

from local_gpt_mcp.orchestrator import (
    Action,
    Cancellation,
    Condition,
    MemoryCheckpointStore,
    SessionGrants,
    Step,
    WorkflowEngine,
    WorkflowFailure,
    WorkflowPlan,
)
from local_gpt_mcp.pairing import SessionBroker
from local_gpt_mcp.policy import Capability, GrantRequest, PairingRequest, PolicyAuthority


class LocalPairing:
    def approve_pairing(self, request: PairingRequest) -> bool:
        return True

    def approve_grant(self, request: GrantRequest) -> bool:
        return True


class ActionPrompt:
    def __init__(self, allow: bool = True) -> None:
        self.allow = allow
        self.calls = 0

    def approve(self, step: Step) -> bool:
        self.calls += 1
        return self.allow


class FakeDriver:
    def __init__(self, broker: SessionBroker) -> None:
        self.broker = broker
        self.calls: list[str] = []
        self.read_failures = 0
        self.fail_mutation = False
        self.slow = False
        self.value = "READY"
        self.started = asyncio.Event()

    async def condition(self, step: Step, condition: object, credentials: SessionGrants, nonce: str) -> bool:
        assert isinstance(condition, Condition)
        self.broker.authorize_grant(
            credentials.session_token,
            nonce,
            credentials.read_grant,
            "https://example.com",
            Capability.BROWSER_READ,
        )
        self.calls.append("check")
        return condition.contains in self.value

    async def perform(self, step: Step, credentials: SessionGrants, nonce: str) -> str:
        read = step.action == Action.BROWSER_READ
        self.broker.authorize_grant(
            credentials.session_token,
            nonce,
            credentials.read_grant if read else credentials.input_grant,
            "https://example.com",
            Capability.BROWSER_READ if read else Capability.BROWSER_INPUT,
        )
        self.calls.append(step.step_id)
        self.started.set()
        if self.slow:
            await asyncio.Event().wait()
        if read and self.read_failures:
            self.read_failures -= 1
            raise ConnectionError("transient")
        if not read and self.fail_mutation:
            raise TimeoutError("side effect uncertain")
        return self.value if read else ""


class Fixture:
    def __init__(self, approval: ActionPrompt | None = None) -> None:
        self.policy = PolicyAuthority(LocalPairing())
        self.broker = SessionBroker(self.policy)
        self.count = 0
        token = self.broker.open("person", "computer", self.nonce())["session_token"]
        assert isinstance(token, str)
        read = self.broker.request_grant(
            token, self.nonce(), "https://example.com", frozenset({Capability.BROWSER_READ}), 180
        )["grant_token"]
        write = self.broker.request_grant(
            token, self.nonce(), "https://example.com", frozenset({Capability.BROWSER_INPUT}), 180
        )["grant_token"]
        assert isinstance(read, str) and isinstance(write, str)
        self.grants = SessionGrants(token, read, write)
        self.prompt = approval or ActionPrompt()
        self.driver = FakeDriver(self.broker)
        self.store = MemoryCheckpointStore()
        self.engine = WorkflowEngine(self.broker, self.driver, self.store, self.prompt)

    def nonce(self) -> str:
        self.count += 1
        return f"{self.count:032x}"


def read_step(step_id: str = "read", **kwargs: object) -> Step:
    return Step(step_id, Action.BROWSER_READ, "local-tab", selector="#status", **kwargs)  # type: ignore[arg-type]


def change_step(step_id: str = "change", **kwargs: object) -> Step:
    return Step(step_id, Action.BROWSER_CLICK, "local-tab", selector="#button", **kwargs)  # type: ignore[arg-type]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_observation_uses_grants_without_mutation_prompt() -> None:
    f = Fixture()
    plan = WorkflowPlan("plan-1", (read_step(),))
    result = await f.engine.run(plan, f.grants)
    assert result.finished and result.completed == 1
    assert result.outputs[0].result == "READY"
    assert f.prompt.calls == 0
    assert f.store.read("plan-1").state == "complete"  # type: ignore[union-attr]


@pytest.mark.anyio
async def test_mutation_requires_fresh_local_approval() -> None:
    prompt = ActionPrompt(False)
    f = Fixture(prompt)
    plan = WorkflowPlan("plan-1", (change_step(),))
    with pytest.raises(WorkflowFailure, match="Local approval denied"):
        await f.engine.run(plan, f.grants)
    assert f.driver.calls == []
    assert f.store.read("plan-1").state == "ready"  # type: ignore[union-attr]
    prompt.allow = True
    result = await f.engine.run(plan, f.grants, resume=True)
    assert result.finished and f.prompt.calls == 2
    assert f.driver.calls == ["change"]


@pytest.mark.anyio
async def test_no_mutation_is_automatically_retried_on_timeout() -> None:
    f = Fixture()
    f.driver.fail_mutation = True
    plan = WorkflowPlan("plan-1", (change_step(),))
    with pytest.raises(WorkflowFailure, match="failed or timed out"):
        await f.engine.run(plan, f.grants)
    assert f.driver.calls == ["change"]
    assert f.store.read("plan-1").state == "uncertain"  # type: ignore[union-attr]
    with pytest.raises(WorkflowFailure, match="manual reconciliation"):
        await f.engine.run(plan, f.grants, resume=True)
    assert f.driver.calls == ["change"]


@pytest.mark.anyio
async def test_retry_applies_only_to_idempotent_observation() -> None:
    f = Fixture()
    f.driver.read_failures = 1
    plan = WorkflowPlan("plan-1", (read_step(),))
    result = await f.engine.run(plan, f.grants)
    assert result.finished
    assert f.driver.calls == ["read", "read"]


@pytest.mark.anyio
async def test_preconditions_gate_effect_and_postconditions_check_it() -> None:
    f = Fixture()
    plan = WorkflowPlan(
        "plan-1",
        (change_step(before=Condition("#status", "READY"), after=Condition("#status", "READY")),),
    )
    result = await f.engine.run(plan, f.grants)
    assert result.finished
    assert f.driver.calls == ["check", "change", "check"]


@pytest.mark.anyio
async def test_failed_precondition_does_not_start_mutation() -> None:
    f = Fixture()
    plan = WorkflowPlan("plan-1", (change_step(before=Condition("#status", "NOT READY")),))
    with pytest.raises(WorkflowFailure, match="condition"):
        await f.engine.run(plan, f.grants)
    assert f.prompt.calls == 0
    assert f.driver.calls == ["check"]
    assert f.store.read("plan-1").state == "ready"  # type: ignore[union-attr]


@pytest.mark.anyio
async def test_completed_prefix_can_resume_only_with_matching_plan() -> None:
    f = Fixture(ActionPrompt(False))
    plan = WorkflowPlan("plan-1", (read_step(), change_step()))
    with pytest.raises(WorkflowFailure, match="approval"):
        await f.engine.run(plan, f.grants)
    assert f.store.read("plan-1").index == 1  # type: ignore[union-attr]
    f.prompt.allow = True
    result = await f.engine.run(plan, f.grants, resume=True)
    assert result.completed == 2
    assert f.driver.calls == ["read", "change"]
    assert (await f.engine.run(plan, f.grants, resume=True)).outputs == ()
    with pytest.raises(WorkflowFailure, match="different plan"):
        await f.engine.run(WorkflowPlan("plan-1", (change_step(),)), f.grants, resume=True)


@pytest.mark.anyio
async def test_expired_or_revoked_grants_block_resume() -> None:
    f = Fixture(ActionPrompt(False))
    plan = WorkflowPlan("plan-1", (read_step(), change_step()))
    with pytest.raises(WorkflowFailure):
        await f.engine.run(plan, f.grants)
    f.broker.revoke_grant(f.grants.session_token, f.nonce(), f.grants.input_grant)
    f.prompt.allow = True
    with pytest.raises(WorkflowFailure):
        await f.engine.run(plan, f.grants, resume=True)
    assert f.driver.calls == ["read"]


@pytest.mark.anyio
async def test_cancel_before_start_never_performs_actions() -> None:
    f = Fixture()
    cancelled = Cancellation()
    cancelled.cancel()
    with pytest.raises(WorkflowFailure, match="cancelled"):
        await f.engine.run(WorkflowPlan("plan-1", (change_step(),)), f.grants, cancellation=cancelled)
    assert not f.driver.calls


@pytest.mark.anyio
async def test_cancel_running_mutation_leaves_uncertain_checkpoint() -> None:
    f = Fixture()
    f.driver.slow = True
    cancelled = Cancellation()
    plan = WorkflowPlan("plan-1", (change_step(),))
    task = asyncio.create_task(f.engine.run(plan, f.grants, cancellation=cancelled))
    await asyncio.wait_for(f.driver.started.wait(), 2)
    cancelled.cancel()
    with pytest.raises(WorkflowFailure, match="cancelled"):
        await asyncio.wait_for(task, 2)
    assert f.store.read("plan-1").state == "uncertain"  # type: ignore[union-attr]


@pytest.mark.anyio
async def test_session_emergency_stop_prohibits_future_steps() -> None:
    f = Fixture(ActionPrompt(False))
    plan = WorkflowPlan("plan-1", (read_step(), change_step()))
    with pytest.raises(WorkflowFailure):
        await f.engine.run(plan, f.grants)
    f.broker.stop(f.grants.session_token, f.nonce())
    f.prompt.allow = True
    with pytest.raises(PermissionError):
        await f.engine.run(plan, f.grants, resume=True)


@pytest.mark.anyio
async def test_replaying_plan_needs_explicit_resume() -> None:
    f = Fixture()
    plan = WorkflowPlan("plan-1", (read_step(),))
    await f.engine.run(plan, f.grants)
    with pytest.raises(WorkflowFailure, match="explicit resume"):
        await f.engine.run(plan, f.grants)


@pytest.mark.anyio
async def test_missing_resume_checkpoint_fails_closed() -> None:
    f = Fixture()
    with pytest.raises(WorkflowFailure, match="No existing checkpoint"):
        await f.engine.run(WorkflowPlan("plan-1", (read_step(),)), f.grants, resume=True)
