"""Safe, headless scaffold entry point."""

import argparse

from local_gpt_mcp import package_version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local GPT MCP companion (not paired)")
    parser.add_argument("--version", action="store_true", help="Print the installed version")
    args = parser.parse_args(argv)
    if args.version:
        print(package_version())
    else:
        print("Local GPT MCP: unpaired; no desktop or browser access is enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
