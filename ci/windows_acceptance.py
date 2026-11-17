"""Opt-in real Windows smoke evidence; never self-certifies a release blocker.

Run physically on a standard-user Windows desktop:
    python -m ci.windows_acceptance

Both existing smoke tests demand a human at the PC. This tool never collects
their terminal input/output or turns manual acceptance into production approval.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SMOKES = (
    ("local_desktop", Path("tests/windows/manual_smoke.py")),
    ("safety_panel_stop", Path("tests/windows/manual_ui_smoke.py")),
)
OPEN_BLOCKERS = ("DNS_REBINDING_TOCTOU", "PHYSICAL_WINDOWS_ACCEPTANCE", "WEB_REMOTE_E2E")
REMAINING = (
    "Real Windows lock, UAC secure desktop, elevated/occluded target and local STOP",
    "Fresh non-administrator install/uninstall and emergency disconnect trials",
    "Independent owner OAuth and physical second-device WebAuthn UP+UV",
    "Supported ChatGPT web-to-PC action from a different physical network",
    "Real DNS rebinding and complete Chromium/OS network egress verification",
)


def checked_revision(root: Path = ROOT) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    revision = result.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("Unverified checkout revision")
    return revision


def require_standard_user(
    *, platform: str, os_name: str, stdin_tty: bool, stdout_tty: bool, administrator: bool
) -> None:
    if platform != "win32" or os_name != "nt" or not stdin_tty or not stdout_tty:
        raise PermissionError("A real interactive Windows console is required")
    if administrator:
        raise PermissionError("Run as a standard user, never as administrator")


def require_local_operator() -> None:
    if sys.platform != "win32" or os.name != "nt" or not sys.stdin.isatty() or not sys.stdout.isatty():
        raise PermissionError("A real interactive Windows console is required")
    try:
        administrator = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError) as error:
        raise PermissionError("Cannot verify non-administrator Windows context") from error
    require_standard_user(
        platform=sys.platform,
        os_name=os.name,
        stdin_tty=sys.stdin.isatty(),
        stdout_tty=sys.stdout.isatty(),
        administrator=administrator,
    )


def new_report(revision: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("Acceptance evidence requires an exact checked Git SHA")
    return {
        "schema_version": 1,
        "source_commit": revision,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "smokes": {name: {"status": "not_run", "exit_code": None} for name, _ in SMOKES},
        "remaining_external_acceptance": list(REMAINING),
        "high_blockers": {blocker: "open" for blocker in OPEN_BLOCKERS},
        "physical_acceptance": "unverified",
        "release_ready": False,
        "not_an_attestation": True,
    }


def run_smokes(
    report: dict[str, Any],
    *,
    ask: Callable[[str], str],
    invoke: Callable[..., subprocess.CompletedProcess[Any]],
) -> int:
    """No automatic consent, retries, terminal capture or implicit script execution."""
    for name, path in SMOKES:
        answer = ask(f"Physically review {path}. Type RUN to start this manual test: ")
        if answer != "RUN":
            report["smokes"][name]["status"] = "declined"
            return 1
        try:
            result = invoke([sys.executable, str(ROOT / path)], cwd=ROOT, check=False, timeout=180)
        except subprocess.TimeoutExpired:
            report["smokes"][name]["status"] = "timeout"
            return 1
        except OSError:
            report["smokes"][name]["status"] = "execution_error"
            return 1
        report["smokes"][name] = {
            "status": "passed" if result.returncode == 0 else "failed",
            "exit_code": result.returncode,
        }
        if result.returncode != 0:
            return 1
    return 0


def save_report(report: dict[str, Any], root: Path = ROOT) -> Path:
    directory = root / "artifacts" / "acceptance"
    directory.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    path = directory / f"windows-{stamp}.json"
    with path.open("x", encoding="utf-8") as target:
        json.dump(report, target, indent=2)
        target.write("\n")
    return path


def main() -> int:
    argparse.ArgumentParser(
        description="Collect real local Windows smoke outcomes; never approve a production release"
    ).parse_args()
    try:
        report = new_report(checked_revision())
    except (ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"Cannot verify the source checkout: {error}", file=sys.stderr)
        return 2

    status = 2
    try:
        require_local_operator()
        status = run_smokes(report, ask=input, invoke=subprocess.run)
    except (PermissionError, EOFError, KeyboardInterrupt) as error:
        print(f"Physical acceptance was not completed: {error}", file=sys.stderr)
    finally:
        try:
            path = save_report(report)
            print(f"Redacted local smoke record: {path}")
        except OSError as error:
            print(f"Could not save local smoke record: {error}", file=sys.stderr)
            return 2

    print("All three HIGH release blockers remain OPEN. This is NOT release approval.")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
