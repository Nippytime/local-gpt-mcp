"""Consent-first desktop companion; no device control is enabled by default."""

from importlib.metadata import PackageNotFoundError, version


def package_version() -> str:
    """Report installed distribution version without hardcoding another copy."""
    try:
        return version("local-gpt-mcp")
    except PackageNotFoundError:
        return "0+uninstalled"
