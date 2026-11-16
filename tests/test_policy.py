from pathlib import Path

from workflow.check_secrets import findings
from workflow.check_workflow_policy import inspect_workflow
from workflow.self_test import validate


def test_project_contract() -> None:
    assert validate() == []


def test_unpinned_action_is_rejected(tmp_path: Path) -> None:
    file = tmp_path / "unsafe.yml"
    file.write_text(
        "permissions: {contents: read}\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n"
    )
    assert any("not pinned" in message for message in inspect_workflow(file))


def test_untrusted_workflow_interpolation_is_rejected(tmp_path: Path) -> None:
    file = tmp_path / "unsafe.yml"
    file.write_text("permissions: {contents: read}\nrun: echo ${{ github.event.issue.body }}\n")
    assert any("untrusted" in message for message in inspect_workflow(file))


def test_secret_scanner_rejects_private_material() -> None:
    marker = "-----BEGIN " + "PRIVATE KEY-----"
    assert findings("config/creds.txt", marker)
    assert findings(".env", "nothing")
    assert findings(".env.example", "") == []
