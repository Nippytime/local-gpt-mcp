"""PR-to-Issue relationship, source branch, risk declarations and size gates.

Uses read-only GitHub API requests with the workflow-scoped GitHub token.
Because the connected GitHub tool currently cannot create missing labels, exact
risk and state declarations in the Issue and PR sections are an explicit fallback.
When real GitHub labels exist, those are accepted instead.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO = "Nippytime/local-gpt-mcp"
API = f"https://api.github.com/repos/{REPO}"
ISSUE_PATTERN = re.compile(r"(?im)^\s*Refs\s+#(\d+)\s*$")
WORK_BRANCH = re.compile(r"^work/(\d+)-[a-z0-9][a-z0-9-]*$")
SECTIONS = ("Result", "Implementation", "Verification", "Risk", "Remaining work")
REQUIRED_RISKS: dict[str, tuple[str, ...]] = {
    "risk:ci": (".github/workflows/", "ci/", "workflow/", ".chatfreept/"),
    "risk:dependencies": ("pyproject.toml", "ci/requirements-ci.txt"),
    "risk:deployment": ("packaging/", "scripts/"),
    "risk:security": ("src/local_gpt_mcp/policy/", "src/local_gpt_mcp/mcp/"),
}


def documented_labels(body: str, heading: str) -> set[str]:
    """Recognize labels only in the intended metadata section, not random prose."""
    match = re.search(rf"(?im)^##\s+{re.escape(heading)}\s*$", body)
    if not match:
        return set()
    remaining = body[match.end() :]
    next_heading = re.search(r"(?m)^##\s+", remaining)
    section = remaining[: next_heading.start()] if next_heading else remaining
    return set(re.findall(r"\x60((?:type|state|risk):[a-z][a-z-]*)\x60", section))


def labels_for(issue: dict[str, Any], section: str) -> set[str]:
    labels = {str(item.get("name")) for item in issue.get("labels", [])}
    return labels | documented_labels(str(issue.get("body") or ""), section)


def required_risks(paths: list[str]) -> set[str]:
    return {
        risk
        for risk, prefixes in REQUIRED_RISKS.items()
        if any(path.startswith(prefix) or path == prefix for path in paths for prefix in prefixes)
    }


def check_metadata(
    pr: dict[str, Any], issue: dict[str, Any], paths: list[str], changed_lines: int
) -> list[str]:
    body = str(pr.get("body") or "")
    head = str(pr.get("head", {}).get("ref") or "")
    base = str(pr.get("base", {}).get("ref") or "")
    match = ISSUE_PATTERN.search(body)
    errors = []
    if not match:
        return ["PR body must have a standalone Refs #<issue> line"]
    issue_number = int(match.group(1))
    if int(issue.get("number", -1)) != issue_number or issue.get("state") != "open":
        errors.append("Referenced Issue must exist and be open")
    for section in SECTIONS:
        if not re.search(rf"(?m)^##\s+{re.escape(section)}\s*$", body):
            errors.append(f"Missing PR section: {section}")
    if base == "dev":
        branch = WORK_BRANCH.fullmatch(head)
        if not branch or int(branch.group(1)) != issue_number:
            errors.append("Integration PR must originate from work/<issue>-<slug>")
        declared_types = labels_for(issue, "Intended labels")
        if not {"type:feature", "type:security", "type:release"} & declared_types:
            errors.append("Controlling Issue requires a type:* label/declaration")
    elif base == "main":
        if head != "dev":
            errors.append("Production PR must originate from dev")
        if "type:release" not in labels_for(issue, "Intended labels"):
            errors.append("Production PR requires a release Issue")
    else:
        errors.append(f"Unexpected PR base: {base}")
    if not ({"state:active", "state:review", "state:release-ready"} & labels_for(issue, "Intended labels")):
        errors.append("Issue must declare an active/review state")
    issue_labels = labels_for(issue, "Intended labels")
    pr_labels = labels_for(pr, "Risk")
    for risk in sorted(required_risks(paths)):
        if risk not in issue_labels:
            errors.append(f"Issue missing risk label/declaration: {risk}")
        if risk not in pr_labels:
            errors.append(f"PR missing risk label/declaration: {risk}")
    if len(paths) > 80 or changed_lines > 4000:
        errors.append("PR exceeds 80 files or 4000 changed lines; split the change")
    return errors


def api_get(path: str, token: str) -> Any:
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Invalid API resource")
    request = urllib.request.Request(
        API + path,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "local-gpt-mcp-ci",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def changed_paths(number: int, token: str) -> tuple[list[str], int]:
    paths: list[str] = []
    total = 0
    for page in range(1, 11):
        files = api_get(f"/pulls/{number}/files?per_page=100&page={page}", token)
        if not isinstance(files, list):
            raise ValueError("Unexpected GitHub PR file result")
        for file in files:
            paths.append(str(file["filename"]))
            total += int(file.get("additions", 0)) + int(file.get("deletions", 0))
        if len(files) < 100:
            return paths, total
    raise ValueError("PR exceeds file pagination limit")


def main() -> int:
    try:
        event_path = os.environ["GITHUB_EVENT_PATH"]
        token = os.environ["GH_TOKEN"]
        if os.environ["GITHUB_REPOSITORY"] != REPO:
            raise ValueError("Wrong GitHub repository")
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        pr = event["pull_request"]
        pr_number = int(pr["number"])
        body = str(pr.get("body") or "")
        match = ISSUE_PATTERN.search(body)
        if not match:
            raise ValueError("PR requires a standalone Refs #<issue> line")
        issue_number = int(match.group(1))
        issue = api_get(f"/issues/{issue_number}", token)
        paths, lines = changed_paths(pr_number, token)
        errors = check_metadata(pr, issue, paths, lines)
    except (KeyError, ValueError, OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        print(f"PR metadata validation failed: {error}", file=sys.stderr)
        return 1
    for failure in errors:
        print(failure, file=sys.stderr)
    if errors:
        return 1
    print(f"PR metadata accepted for Issue #{issue_number} with {len(paths)} changed files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
