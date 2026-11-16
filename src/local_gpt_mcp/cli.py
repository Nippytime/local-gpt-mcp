"""Consent-first entry point. Local stdio is opt-in and never opens network ports."""

from __future__ import annotations

import argparse
from pathlib import Path

from local_gpt_mcp import package_version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local GPT MCP consent-first companion")
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--version", action="store_true", help="Print installed package version")
    choice.add_argument("--stdio", action="store_true", help="Serve the local MCP protocol via stdio")
    parser.add_argument(
        "--allow-window",
        action="append",
        type=int,
        default=[],
        metavar="HWND",
        help="Locally select a currently foreground Windows window for this session",
    )
    parser.add_argument(
        "--browser-origin",
        metavar="HTTPS_ORIGIN",
        help="Locally opt into one isolated Chromium tab on an exact public HTTPS origin",
    )
    parser.add_argument(
        "--workflow-state-dir",
        type=Path,
        help="Trusted local checkpoint directory; checkpoints contain hashes only",
    )
    args = parser.parse_args(argv)
    if args.allow_window and not args.stdio:
        parser.error("--allow-window requires --stdio")
    if args.browser_origin and not args.stdio:
        parser.error("--browser-origin requires --stdio")
    if args.browser_origin:
        from local_gpt_mcp.browser.controller import approved_origin

        approved_origin(args.browser_origin)
    if args.workflow_state_dir and (not args.stdio or not (args.browser_origin or args.allow_window)):
        parser.error("--workflow-state-dir needs --stdio and a locally selected adapter")
    if args.version:
        print(package_version())
    elif args.stdio:
        from local_gpt_mcp.mcp.server import serve_stdio

        if args.allow_window or args.browser_origin:
            if args.workflow_state_dir:
                serve_stdio(
                    tuple(args.allow_window),
                    browser_origin=args.browser_origin,
                    workflow_state_dir=args.workflow_state_dir,
                )
            else:
                serve_stdio(tuple(args.allow_window), browser_origin=args.browser_origin)
        else:
            serve_stdio()
    else:
        print("Local GPT MCP: unpaired; no desktop or browser access is enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
