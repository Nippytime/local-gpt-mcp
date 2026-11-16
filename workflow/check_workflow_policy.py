"""Reject workflow privilege escalation, unpinned actions and unsafe code execution."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED_ACTION = re.compile(r"(?m)^\s*-\s*uses:\s*[^\s@]+@([0-9a-f]{40})(?:\s|$)")
USE_LINE = re.compile(r"(?m)^\s*-\s*uses:\s*(\S+)")
UNTRUSTED = re.compile(r"\$\{\{\s*github\.event\.(?:pull_request|issue|comment)\.(?:title|body)")
FORBIDDEN = (
    "pull_request_target:",
    "permissions: write-all",
    "permissions: read-all",
    "anthropic_api_key",
    "anthropics/claude",
    "claude-code",
    "curl | bash",
    "wget | bash",
)


def inspect_workflow(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    executable = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    findings: list[str] = []
    for word in FORBIDDEN:
        if word in executable.lower():
            findings.append(f"{path.name}: forbidden workflow feature {word}")
    if UNTRUSTED.search(executable):
        findings.append(f"{path.name}: untrusted event text interpolated into workflow")
    for match in USE_LINE.finditer(executable):
        if not PINNED_ACTION.fullmatch(match.group()):
            findings.append(f"{path.name}: action not pinned to a full commit: {match.group().strip()}")
    if "permissions:" not in executable:
        findings.append(f"{path.name}: missing explicit least-privilege permissions")
    return findings


def validate(root: Path = ROOT) -> list[str]:
    folder = root / ".github" / "workflows"
    expected = {"ci-pr.yml", "ci-release.yml", "security.yml"}
    present = {p.name for p in folder.glob("*.yml")}
    failures = [f"Missing workflow: {name}" for name in sorted(expected - present)]
    for file in sorted(folder.glob("*.yml")):
        failures.extend(inspect_workflow(file))
    return failures


def main() -> int:
    failures = validate()
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print("Workflow security policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
