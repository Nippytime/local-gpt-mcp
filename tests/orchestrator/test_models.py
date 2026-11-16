"""Plan schema is strict, deterministic and secret-free in checkpoints."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from local_gpt_mcp.orchestrator import (
    Action,
    Checkpoint,
    Condition,
    FileCheckpointStore,
    Step,
    WorkflowPlan,
)


def browser_step(**kwargs: object) -> Step:
    defaults: dict[str, object] = {
        "step_id": "one",
        "action": Action.BROWSER_READ,
        "target": "local-tab",
        "selector": "#title",
    }
    defaults.update(kwargs)
    return Step(**defaults)  # type: ignore[arg-type]


def test_plan_fingerprint_is_deterministic_and_sensitive_to_changes() -> None:
    plan = WorkflowPlan("plan-one", (browser_step(),))
    assert len(plan.digest()) == 64
    assert plan.digest() == WorkflowPlan("plan-one", (browser_step(),)).digest()
    assert plan.digest() != WorkflowPlan("plan-two", (browser_step(),)).digest()
    assert plan.digest() != WorkflowPlan("plan-one", (browser_step(selector="#status"),)).digest()


@pytest.mark.parametrize(
    "changes",
    [
        {"step_id": ""},
        {"step_id": "../escape"},
        {"target": "window:41"},
        {"target": "https://example.com"},
        {"selector": ""},
        {"selector": "a\nb"},
        {"text": "unnecessary"},
        {"x": 1},
        {"amount": 1},
        {"after": Condition("#title", "finished")},
    ],
)
def test_invalid_step_contract(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        browser_step(**changes)


def test_mutations_validate_arguments() -> None:
    Step("nav", Action.BROWSER_NAVIGATE, "local-tab", text="https://example.com")
    Step("click", Action.DESKTOP_CLICK, "window:41", x=10, y=10)
    Step("type", Action.DESKTOP_TYPE, "window:41", text="hello")
    Step("key", Action.DESKTOP_KEY, "window:41", text="tab")
    invalid: list[dict[str, object]] = [
        {"action": Action.DESKTOP_CLICK, "target": "window:41", "x": 2},
        {"action": Action.BROWSER_FILL, "text": ""},
        {"action": Action.BROWSER_SCROLL, "amount": 5, "selector": ""},
        {"action": Action.DESKTOP_TYPE, "target": "window:0", "text": "hello", "selector": ""},
    ]
    for kwargs in invalid:
        with pytest.raises(ValueError):
            browser_step(**kwargs)


def test_plan_limits_and_unique_step_ids() -> None:
    with pytest.raises(ValueError):
        WorkflowPlan("plan", ())
    with pytest.raises(ValueError):
        WorkflowPlan("plan", (browser_step(),) * 9)
    with pytest.raises(ValueError):
        WorkflowPlan("plan", (browser_step(), browser_step()))


def test_conditions_reject_bad_text() -> None:
    for selector, expected in [("", "ok"), ("#status", ""), ("#status", "x\nbad")]:
        with pytest.raises(ValueError):
            Condition(selector, expected)


def test_file_checkpoint_is_atomic_private_and_contains_no_secrets(tmp_path: Path) -> None:
    store = FileCheckpointStore(tmp_path)
    plan = WorkflowPlan("plan-1", (browser_step(text=""),))
    checkpoint = Checkpoint(plan.digest(), 1, "complete")
    store.save(plan.plan_id, checkpoint)
    file = tmp_path / "plan-1.json"
    contents = file.read_text()
    assert json.loads(contents) == {"plan_digest": plan.digest(), "index": 1, "state": "complete"}
    assert "https://" not in contents and "window:" not in contents and "token" not in contents
    assert store.read(plan.plan_id) == checkpoint
    if os.name == "posix":
        assert stat.S_IMODE(file.stat().st_mode) == 0o600


def test_checkpoint_fail_closed_on_tampering(tmp_path: Path) -> None:
    store = FileCheckpointStore(tmp_path)
    file = tmp_path / "plan-1.json"
    file.write_text('{"plan_digest":"bad","index":0,"state":"ready"}')
    with pytest.raises(ValueError):
        store.read("plan-1")
    file.write_text('{"plan_digest":"bad","index":0,"state":"ready","token":"secret"}')
    with pytest.raises(ValueError):
        store.read("plan-1")
    with pytest.raises(ValueError):
        store.save("../escape", Checkpoint("0" * 64, 0, "ready"))


def test_checkpoint_rejects_symlink(tmp_path: Path) -> None:
    real = tmp_path / "actual.json"
    real.write_text("{}")
    path = tmp_path / "plan-1.json"
    try:
        path.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("No symlink support on this host")
    store = FileCheckpointStore(tmp_path)
    with pytest.raises(ValueError, match="Symlink"):
        store.read("plan-1")
    with pytest.raises(ValueError, match="Symlink"):
        store.save("plan-1", Checkpoint("0" * 64, 0, "ready"))
