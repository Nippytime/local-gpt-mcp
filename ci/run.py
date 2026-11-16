"""Fail-closed, explicit CI command runner with machine-readable evidence.

Ported from the neutral stage/reporting design of mlookhere/CI-Pipline.
Commands are argument vectors, never shell code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".chatfreept" / "ci.json"
REPORT_DIR = ROOT / "artifacts" / "ci"


def read_commands(config: dict[str, Any], stage: str) -> list[list[str]]:
    groups: Any = config.get("stages", {}).get(stage)
    if not isinstance(groups, list) or not groups:
        raise ValueError(f"Undefined or empty CI stage: {stage}")
    commands: list[list[str]] = []
    for group in groups:
        entries: Any = config.get("commands", {}).get(group)
        if not isinstance(entries, list) or not entries:
            raise ValueError(f"Missing CI command group: {group}")
        for command in entries:
            if not isinstance(command, list) or not command or not all(
                isinstance(arg, str) and arg for arg in command
            ):
                raise ValueError(f"Invalid CI command in {group}")
            commands.append([sys.executable if arg == "@python" else arg for arg in command])
    return commands


def checked_revision(root: Path = ROOT) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
    )
    sha = result.stdout.strip()
    if len(sha) != 40 or any(char not in "0123456789abcdef" for char in sha):
        raise ValueError("Checkout SHA could not be validated")
    return sha


def execute(stage: str) -> int:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    commands = read_commands(config, stage)
    revision = checked_revision()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for command in commands:
        started = dt.datetime.now(dt.UTC)
        print(f"$ {' '.join(command)}", flush=True)
        result = subprocess.run(command, cwd=ROOT, check=False)
        records.append(
            {
                "argv": command,
                "exit_code": result.returncode,
                "started_at": started.isoformat(),
                "ended_at": dt.datetime.now(dt.UTC).isoformat(),
            }
        )
        if result.returncode:
            break
    success = bool(records) and all(entry["exit_code"] == 0 for entry in records)
    report = {"stage": stage, "commit": revision, "success": success, "commands": records}
    path = REPORT_DIR / f"{stage}.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"CI report: {path}", flush=True)
    return 0 if success else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CI gates deterministically")
    parser.add_argument("stage", help="fast, pr, audit, or release")
    args = parser.parse_args()
    try:
        return execute(args.stage)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"CI configuration/checkout failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
