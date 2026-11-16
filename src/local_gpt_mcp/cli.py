"""Consent-first entry point. Local stdio is opt-in and never opens network ports."""

from __future__ import annotations

import argparse

from local_gpt_mcp import package_version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local GPT MCP consent-first companion")
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--version", action="store_true", help="Print installed package version")
    choice.add_argument("--stdio", action="store_true", help="Serve the local MCP protocol via stdio")
    args = parser.parse_args(argv)
    if args.version:
        print(package_version())
    elif args.stdio:
        from local_gpt_mcp.mcp.server import serve_stdio

        serve_stdio()
    else:
        print("Local GPT MCP: unpaired; no desktop or browser access is enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
