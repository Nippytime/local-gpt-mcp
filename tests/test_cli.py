import pytest
from pytest import CaptureFixture

from local_gpt_mcp import package_version
from local_gpt_mcp.cli import main


def test_safe_default(capsys: CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "unpaired" in capsys.readouterr().out


def test_version(capsys: CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == package_version()


def test_missing_distribution(monkeypatch: pytest.MonkeyPatch) -> None:
    from importlib.metadata import PackageNotFoundError

    def absent(_: str) -> str:
        raise PackageNotFoundError

    monkeypatch.setattr("local_gpt_mcp.version", absent)
    assert package_version() == "0+uninstalled"


def test_module_entrypoint(monkeypatch: pytest.MonkeyPatch, capsys: CaptureFixture[str]) -> None:
    import runpy
    import sys

    monkeypatch.setattr(sys, "argv", ["local_gpt_mcp"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("local_gpt_mcp.__main__", run_name="__main__")
    assert exit_info.value.code == 0
    assert "unpaired" in capsys.readouterr().out


def test_stdio_uses_explicit_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[str] = []
    monkeypatch.setattr("local_gpt_mcp.mcp.server.serve_stdio", lambda: executed.append("stdio"))
    assert main(["--stdio"]) == 0
    assert executed == ["stdio"]
