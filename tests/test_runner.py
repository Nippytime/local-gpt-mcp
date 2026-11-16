from pathlib import Path
from typing import Any

import pytest

from ci.run import read_commands


def test_ci_stage_never_succeeds_with_missing_steps() -> None:
    with pytest.raises(ValueError, match="Undefined or empty"):
        read_commands({"stages": {"fast": []}}, "fast")
    with pytest.raises(ValueError, match="Missing CI command"):
        read_commands({"stages": {"fast": ["unit"]}}, "fast")


def test_ci_commands_are_argv_not_shell() -> None:
    config: dict[str, Any] = {
        "stages": {"fast": ["unit"]},
        "commands": {"unit": [["@python", "-m", "pytest", "-q"]]},
    }
    result = read_commands(config, "fast")
    assert len(result) == 1
    assert result[0][1:] == ["-m", "pytest", "-q"]
    with pytest.raises(ValueError, match="Invalid CI command"):
        read_commands({"stages": {"fast": ["unit"]}, "commands": {"unit": [""]}}, "fast")


def test_ci_runtime_source_exists() -> None:
    root = Path(__file__).resolve().parents[1]
    assert (root / "scripts/bootstrap").is_file()
    assert (root / "ci/run").is_file()
