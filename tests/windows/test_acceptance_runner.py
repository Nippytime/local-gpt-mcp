"""Portable regression tests for the opt-in physical Windows evidence collector."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ci.windows_acceptance import (
    OPEN_BLOCKERS,
    SMOKES,
    checked_revision,
    new_report,
    require_standard_user,
    run_smokes,
    save_report,
    verify_report_checkout,
)

SHA = "a" * 40


def test_report_never_claims_release_or_closes_blockers(tmp_path: Path) -> None:
    report = new_report(SHA)
    assert report["source_commit"] == SHA
    assert report["release_ready"] is False
    assert report["physical_acceptance"] == "unverified"
    assert report["not_an_attestation"] is True
    assert report["high_blockers"] == dict.fromkeys(OPEN_BLOCKERS, "open")
    assert len(report["remaining_external_acceptance"]) >= 5
    file = save_report(report, tmp_path)
    recorded = json.loads(file.read_text(encoding="utf-8"))
    assert recorded == report
    assert "password" not in file.read_text(encoding="utf-8").lower()
    assert "bearer" not in file.read_text(encoding="utf-8").lower()


@pytest.mark.parametrize("revision", ["", "a" * 39, "G" * 40, "a" * 40 + "\n"])
def test_unverified_commit_is_rejected(revision: str) -> None:
    with pytest.raises(ValueError, match="exact checked Git SHA"):
        new_report(revision)


@pytest.mark.parametrize(
    "platform,os_name,stdin_tty,stdout_tty,administrator",
    [
        ("linux", "posix", True, True, False),
        ("win32", "nt", False, True, False),
        ("win32", "nt", True, False, False),
        ("win32", "nt", True, True, True),
    ],
)
def test_physical_operator_denies_noninteractive_or_admin(
    platform: str, os_name: str, stdin_tty: bool, stdout_tty: bool, administrator: bool
) -> None:
    with pytest.raises(PermissionError):
        require_standard_user(
            platform=platform,
            os_name=os_name,
            stdin_tty=stdin_tty,
            stdout_tty=stdout_tty,
            administrator=administrator,
        )


def test_standard_user_tty_is_only_eligible_environment() -> None:
    require_standard_user(
        platform="win32",
        os_name="nt",
        stdin_tty=True,
        stdout_tty=True,
        administrator=False,
    )


def test_manual_smokes_record_exit_codes_but_never_self_approve_release() -> None:
    report = new_report(SHA)
    seen: list[list[str]] = []

    def fake_invoke(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append(args)
        assert kwargs["check"] is False
        assert kwargs["timeout"] == 180
        assert "capture_output" not in kwargs
        return subprocess.CompletedProcess(args, 0)

    assert run_smokes(report, ask=lambda _prompt: "RUN", invoke=fake_invoke) == 0
    assert len(seen) == len(SMOKES) == 2
    for name, _ in SMOKES:
        assert report["smokes"][name] == {"status": "passed", "exit_code": 0}
    assert report["high_blockers"] == dict.fromkeys(OPEN_BLOCKERS, "open")
    assert report["physical_acceptance"] == "unverified"
    assert report["release_ready"] is False


def test_declined_manual_approval_executes_no_scripts() -> None:
    report = new_report(SHA)

    def forbidden(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise AssertionError("No script may run without operator authorization")

    assert run_smokes(report, ask=lambda _prompt: "no", invoke=forbidden) == 1
    assert report["smokes"]["local_desktop"]["status"] == "declined"
    assert report["smokes"]["safety_panel_stop"]["status"] == "not_run"


def test_failure_does_not_retry_or_start_following_smoke() -> None:
    report = new_report(SHA)
    calls = [0]

    def fake_invoke(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls[0] += 1
        return subprocess.CompletedProcess(args, 1)

    assert run_smokes(report, ask=lambda _prompt: "RUN", invoke=fake_invoke) == 1
    assert calls == [1]
    assert report["smokes"]["local_desktop"] == {"status": "failed", "exit_code": 1}
    assert report["smokes"]["safety_panel_stop"]["status"] == "not_run"


def test_timeout_is_fail_closed_and_never_retried() -> None:
    report = new_report(SHA)
    calls = [0]

    def fake_invoke(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls[0] += 1
        raise subprocess.TimeoutExpired(args, timeout=180)

    assert run_smokes(report, ask=lambda _prompt: "RUN", invoke=fake_invoke) == 1
    assert calls == [1]
    assert report["smokes"]["local_desktop"]["status"] == "timeout"
    assert report["smokes"]["safety_panel_stop"]["status"] == "not_run"


def test_checkout_revision_requires_clean_worktree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def git(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        assert kwargs["cwd"] == tmp_path
        assert kwargs["capture_output"] is True
        assert kwargs["check"] is True
        assert kwargs["timeout"] == 10
        stdout = SHA + "\n" if args[1] == "rev-parse" else ""
        return subprocess.CompletedProcess(args, 0, stdout=stdout)

    monkeypatch.setattr("ci.windows_acceptance.subprocess.run", git)
    assert checked_revision(tmp_path) == SHA
    assert calls == [
        ["git", "rev-parse", "HEAD"],
        ["git", "status", "--porcelain=v1", "--untracked-files=normal"],
    ]


@pytest.mark.parametrize(
    "dirty",
    [
        " M ci/windows_acceptance.py\n",
        "M  tests/windows/manual_smoke.py\n",
        "?? tests/windows/untracked.py\n",
        " D docs/WINDOWS_ACCEPTANCE.md\n",
    ],
)
def test_checkout_refuses_dirty_staged_unstaged_and_untracked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, dirty: str
) -> None:
    def git(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, stdout=SHA + "\n" if args[1] == "rev-parse" else dirty)

    monkeypatch.setattr("ci.windows_acceptance.subprocess.run", git)
    with pytest.raises(ValueError, match="not clean"):
        checked_revision(tmp_path)


def test_checkout_refuses_failed_git_status(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def git(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[1] == "status":
            raise subprocess.CalledProcessError(128, args)
        return subprocess.CompletedProcess(args, 0, stdout=SHA + "\n")

    monkeypatch.setattr("ci.windows_acceptance.subprocess.run", git)
    with pytest.raises(subprocess.CalledProcessError):
        checked_revision(tmp_path)


def test_report_rechecks_revision_after_manual_smokes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = new_report(SHA)
    monkeypatch.setattr("ci.windows_acceptance.checked_revision", lambda root: SHA)
    assert verify_report_checkout(report)
    assert report["checkout_integrity"] == "verified_before_and_after"
    assert report["release_ready"] is False


@pytest.mark.parametrize("changed", ["b" * 40, None])
def test_checkout_change_or_unverified_git_denies_report(
    monkeypatch: pytest.MonkeyPatch, changed: str | None
) -> None:
    report = new_report(SHA)

    def revision(root: Path) -> str:
        if changed is None:
            raise ValueError("Cannot verify status")
        return changed

    monkeypatch.setattr("ci.windows_acceptance.checked_revision", revision)
    assert not verify_report_checkout(report)
    assert report["checkout_integrity"] == "changed_or_unverified"
    assert report["high_blockers"] == dict.fromkeys(OPEN_BLOCKERS, "open")


def test_runner_does_not_report_success_after_midrun_checkout_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ci import windows_acceptance as runner

    revisions = iter([SHA, "b" * 40])
    recorded: list[dict[str, Any]] = []

    monkeypatch.setattr(runner, "checked_revision", lambda root=runner.ROOT: next(revisions))
    monkeypatch.setattr(runner, "require_local_operator", lambda: None)
    monkeypatch.setattr(runner, "run_smokes", lambda report, **kwargs: 0)
    monkeypatch.setattr(
        runner, "save_report", lambda report: recorded.append(report.copy()) or Path("record.json")
    )
    monkeypatch.setattr("sys.argv", ["windows_acceptance"])
    assert runner.main() == 2
    assert recorded[0]["checkout_integrity"] == "changed_or_unverified"
    assert recorded[0]["release_ready"] is False
