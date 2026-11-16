"""Validate CI metadata against actual workflows and supported project commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_CHECKS = {
    "integration": [
        "PR metadata",
        "Fast deterministic gates",
        "PR test/build gates",
        "Dependency audit",
        "Workflow policy",
    ],
    "production": ["Release metadata", "Full regression and production build", "Workflow policy"],
}
EXPECTED_STAGES = {"fast", "pr", "audit", "release"}


def load(path: Path) -> dict[str, Any]:
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return result


def validate(root: Path = ROOT) -> list[str]:
    project = load(root / ".chatfreept" / "project.json")
    ci = load(root / ".chatfreept" / "ci.json")
    policy = load(root / ".chatfreept" / "github.json")
    failures: list[str] = []
    if project.get("repository") != "Nippytime/local-gpt-mcp":
        failures.append("Repository identity mismatch")
    if project.get("agent", {}).get("provider") != "chatgpt":
        failures.append("Only ChatGPT may orchestrate this project")
    if project.get("branches") != {"integration": "dev", "production": "main", "default": "main"}:
        failures.append("Branches must preserve dev integration and main production/default")
    if policy.get("branches") != {"integration": "dev", "production": "main"}:
        failures.append("GitHub branch policy differs from project")
    for scope, checks in EXPECTED_CHECKS.items():
        if project.get("required_checks", {}).get(scope) != checks:
            failures.append(f"Required checks mismatch for {scope}")
        if policy.get("github", {}).get("branch_protection", {}).get(scope, {}).get("required_checks") != checks:
            failures.append(f"Branch policy checks mismatch for {scope}")
    for scope, checks in EXPECTED_CHECKS.items():
        paths = {
            "integration": ["ci-pr.yml", "security.yml"],
            "production": ["ci-release.yml", "security.yml"],
        }[scope]
        body = "\n".join(
            (root / ".github" / "workflows" / path).read_text(encoding="utf-8") for path in paths
        )
        for check in checks:
            if f"name: {check}" not in body:
                failures.append(f"Missing required workflow check: {check}")
    stages = ci.get("stages", {})
    commands = ci.get("commands", {})
    for stage in EXPECTED_STAGES:
        groups: Any = stages.get(stage)
        if not isinstance(groups, list) or not groups:
            failures.append(f"Missing stage: {stage}")
            continue
        for group in groups:
            entries = commands.get(group)
            if not isinstance(entries, list) or not entries:
                failures.append(f"Empty command group: {group}")
                continue
            for command in entries:
                if not isinstance(command, list) or not command or not all(
                    isinstance(arg, str) and arg for arg in command
                ):
                    failures.append(f"Invalid executable command: {group}")
    if project.get("required_checks", {}).get("zero_is_success") is not False:
        failures.append("Zero CI checks must fail closed")
    if project.get("required_checks", {}).get("require_completed") is not True:
        failures.append("Incomplete checks must fail closed")
    if [item.get("number") for item in project.get("slices", [])] != list(range(1, 10)):
        failures.append("Nine tracked slices are required")
    return failures


def main() -> int:
    try:
        failures = validate()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Control-plane validation failed: {error}", file=sys.stderr)
        return 1
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print("Project and CI control-plane contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
