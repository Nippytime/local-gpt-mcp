from pytest import CaptureFixture

from local_gpt_mcp import package_version
from local_gpt_mcp.cli import main


def test_safe_default(capsys: CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "unpaired" in capsys.readouterr().out


def test_version(capsys: CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == package_version()
