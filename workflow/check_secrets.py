"""Fail closed on common credential formats in tracked text files."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"(?:ghp_|github_pat_)[A-Za-z0-9_]{25,}"),
    "OpenAI token": re.compile(r"sk-" + r"(?:proj-)?[A-Za-z0-9_-]{30,}"),
}
SECRET_FILES = re.compile(r"(^|/)(\.env(?:\..+)?|id_rsa|id_ed25519)$")


def findings(path: str, content: str) -> list[str]:
    problems: list[str] = []
    if SECRET_FILES.search(path) and path != ".env.example":
        problems.append(f"{path}: secret-file path must not be tracked")
    for name, pattern in PATTERNS.items():
        if pattern.search(content):
            problems.append(f"{path}: detected {name}")
    return problems


def tracked_files(root: Path = ROOT) -> list[str]:
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    return [p.decode("utf-8") for p in output.split(b"\0") if p]


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    for path in tracked_files(root):
        target = root / path
        if not target.is_file():
            continue
        data = target.read_bytes()
        if b"\0" in data[:8192]:
            continue
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        errors.extend(findings(path, content))
    return errors


def main() -> int:
    errors = validate()
    for message in errors:
        print(message, file=sys.stderr)
    if errors:
        return 1
    print("Tracked-file secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
