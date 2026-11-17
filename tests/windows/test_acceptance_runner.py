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
    new_report,
    require_standard_user,
    run_smokes,
    save_report,
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
