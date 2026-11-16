"""Production release gate must reject unresolved high-risk findings."""

from __future__ import annotations

import json

import pytest

from workflow.check_release_blockers import MANIFEST, validate


def test_current_manifest_prevents_premature_production_release() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert validate(data) == ["DNS_REBINDING_TOCTOU", "PHYSICAL_WINDOWS_ACCEPTANCE"]


def test_release_gate_allows_only_evidence_backed_closure() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for record in data["blockers"]:
        record["status"] = "closed"
        record["evidence"] = "https://github.com/Nippytime/local-gpt-mcp/issues/10"
    assert validate(data) == []


def test_closed_without_evidence_is_rejected() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    data["blockers"][0]["status"] = "closed"
    with pytest.raises(ValueError, match="evidence"):
        validate(data)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.update({"blockers": []}),
        lambda data: data["blockers"].append(data["blockers"][0].copy()),
        lambda data: data["blockers"][0].update({"severity": "undocumented"}),
        lambda data: data["blockers"][0].update({"status": "ignored"}),
        lambda data: data["blockers"][0].update({"id": "../escape"}),
    ],
)
def test_missing_duplicate_or_tampered_entries_fail_closed(mutate: object) -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert callable(mutate)
    mutate(data)
    with pytest.raises(ValueError):
        validate(data)
