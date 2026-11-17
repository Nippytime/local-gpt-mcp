"""Release artifact evidence binds exact bytes to the checked Git revision."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ci.build_manifest import inventory

REVISION = "a" * 40


def test_build_inventory_records_exact_checksums_and_sorted_artifacts(tmp_path: Path) -> None:
    wheel = tmp_path / "local_gpt_mcp-0.1.0-py3-none-any.whl"
    source = tmp_path / "local_gpt_mcp-0.1.0.tar.gz"
    wheel.write_bytes(b"real wheel bytes")
    source.write_bytes(b"real source bytes")
    report = inventory([wheel, source], revision=REVISION, version="0.1.0")
    assert report["source_commit"] == REVISION
    assert report["signed"] is False
    files = report["artifacts"]
    assert isinstance(files, list) and len(files) == 2
    assert files[0]["file"] == wheel.name
    assert files[1]["file"] == source.name
    assert files[0]["sha256"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
    wheel.write_bytes(b"modified wheel bytes")
    changed = inventory([wheel, source], revision=REVISION, version="0.1.0")
    assert files[0]["sha256"] != changed["artifacts"][0]["sha256"]


@pytest.mark.parametrize("revision", ["abc", "g" * 40, "A" * 40])
def test_unverified_revision_is_rejected(revision: str, tmp_path: Path) -> None:
    wheel = tmp_path / "local_gpt_mcp-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"valid")
    with pytest.raises(ValueError, match="revision"):
        inventory([wheel], revision=revision, version="0.1.0")


def test_missing_empty_or_wrong_artifacts_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Nonempty"):
        inventory([], revision=REVISION, version="0.1.0")
    good = tmp_path / "local_gpt_mcp-0.1.0.tar.gz"
    good.touch()
    with pytest.raises(ValueError, match="Nonempty"):
        inventory([good], revision=REVISION, version="0.1.0")
    wrong = tmp_path / "local_gpt_mcp-0.2.0.tar.gz"
    wrong.write_bytes(b"wrong version")
    with pytest.raises(ValueError, match="Unexpected"):
        inventory([wrong], revision=REVISION, version="0.1.0")


def test_symlinked_distributions_are_rejected(tmp_path: Path) -> None:
    target = tmp_path / "local_gpt_mcp-0.1.0.tar.gz"
    target.write_bytes(b"valid")
    link = tmp_path / "local_gpt_mcp-0.1.0-py3-none-any.whl"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not permitted on this OS/runner")
    with pytest.raises(ValueError, match="linked"):
        inventory([link], revision=REVISION, version="0.1.0")
