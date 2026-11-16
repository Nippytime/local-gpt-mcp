"""CycloneDX inventory is deterministic and contains no sensitive environment values."""

from __future__ import annotations

import json
from importlib.metadata import Distribution
from types import SimpleNamespace
from typing import cast

import pytest

from ci.generate_sbom import build_sbom


def fake_package(name: str, version: str) -> Distribution:
    return cast(Distribution, SimpleNamespace(metadata={"Name": name}, version=version))


def test_inventory_is_deterministic_and_de_duplicates_packages() -> None:
    data = build_sbom(
        [
            fake_package("Playwright", "1.65.2"),
            fake_package("mcp", "2.3.0"),
            fake_package("Playwright", "1.65.2"),
        ]
    )
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    components = data["components"]
    assert isinstance(components, list) and len(components) == 2
    assert [x["name"] for x in components] == ["mcp", "playwright"]
    assert json.dumps(data) == json.dumps(
        build_sbom([fake_package("mcp", "2.3.0"), fake_package("Playwright", "1.65.2")])
    )
    assert "secret" not in json.dumps(data).lower()


@pytest.mark.parametrize("name,version", [("bad name", "1.0"), ("valid", "bad version")])
def test_invalid_metadata_is_rejected(name: str, version: str) -> None:
    with pytest.raises(ValueError):
        build_sbom([fake_package(name, version)])


def test_empty_inventory_fails_closed() -> None:
    with pytest.raises(ValueError, match="No installed"):
        build_sbom([])
