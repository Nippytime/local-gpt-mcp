"""Block production CI whenever a high-risk security or acceptance issue is open."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "security" / "release_blockers.json"


def validate(data: dict[str, Any]) -> list[str]:
    if data.get("version") != 1:
        raise ValueError("Unsupported release blocker manifest")
    records = data.get("blockers")
    if not isinstance(records, list) or not records:
        raise ValueError("Release blockers must be an explicit nonempty list")
    seen: set[str] = set()
    open_high: list[str] = []
    for entry in records:
        if not isinstance(entry, dict) or set(entry) != {
            "id", "severity", "status", "issue", "evidence"
        }:
            raise ValueError("Invalid release blocker schema")
        identifier = entry["id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", identifier):
            raise ValueError("Invalid blocker identifier")
        if identifier in seen:
            raise ValueError("Duplicated release blocker")
        seen.add(identifier)
        if entry["severity"] not in {"high", "medium", "low"}:
            raise ValueError("Invalid blocker severity")
        if entry["status"] not in {"open", "closed"}:
            raise ValueError("Invalid blocker state")
        issue = entry["issue"]
        if not isinstance(issue, str) or not issue.startswith(
            "https://github.com/Nippytime/local-gpt-mcp/issues/"
        ):
            raise ValueError("Every blocker needs a real project Issue")
        evidence = entry["evidence"]
        if not isinstance(evidence, str):
            raise ValueError("Invalid blocker evidence")
        if entry["status"] == "closed" and not evidence.startswith(
            "https://github.com/Nippytime/local-gpt-mcp/"
        ):
            raise ValueError("Closed blockers require verifiable repository evidence")
        if entry["severity"] == "high" and entry["status"] == "open":
            open_high.append(identifier)
    return open_high


def main() -> int:
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Invalid blocker manifest object")
        blockers = validate(data)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Release security blockers cannot be verified: {error}", file=sys.stderr)
        return 1
    if blockers:
        print("PRODUCTION RELEASE BLOCKED: " + ", ".join(blockers), file=sys.stderr)
        return 1
    print("Production release blockers closed with repository evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
