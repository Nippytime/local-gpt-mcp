from typing import Any

from workflow.validate_pr import check_metadata, documented_labels, required_risks


def proposal() -> tuple[dict[str, Any], dict[str, Any]]:
    pr = {
        "body": "Refs #2\n\n## Result\nOK\n## Implementation\nDone\n"
        "## Verification\nTested\n## Risk\n\x60risk:ci\x60, \x60risk:dependencies\x60\n"
        "## Remaining work\nNone\n",
        "head": {"ref": "work/2-scaffold-ci"},
        "base": {"ref": "dev"},
        "labels": [],
    }
    issue = {
        "number": 2,
        "state": "open",
        "labels": [],
        "body": "## Intended labels\n\x60type:feature\x60, \x60state:active\x60, "
        "\x60risk:ci\x60, \x60risk:dependencies\x60",
    }
    return pr, issue


def test_pr_contract_accepts_explicit_documented_labels() -> None:
    pr, issue = proposal()
    assert check_metadata(pr, issue, ["ci/run.py", "pyproject.toml"], 200) == []


def test_wrong_issue_or_head_fails() -> None:
    pr, issue = proposal()
    pr["head"]["ref"] = "work/3-wrong"
    assert any("work/<issue>" in message for message in check_metadata(pr, issue, [], 0))
    issue["state"] = "closed"
    assert any("open" in message for message in check_metadata(pr, issue, [], 0))


def test_pr_and_issue_missing_risks_fail_closed() -> None:
    pr, issue = proposal()
    pr["body"] = pr["body"].replace("\x60risk:dependencies\x60", "")
    issue["body"] = issue["body"].replace("\x60risk:dependencies\x60", "")
    errors = check_metadata(pr, issue, ["pyproject.toml"], 1)
    assert len(errors) == 2


def test_file_limits_enforced() -> None:
    pr, issue = proposal()
    assert any("4000" in value for value in check_metadata(pr, issue, [], 4001))


def test_risk_path_and_section_boundaries() -> None:
    assert required_risks([".github/workflows/ci-pr.yml"]) == {"risk:ci"}
    assert documented_labels("random \x60risk:ci\x60", "Risk") == set()
