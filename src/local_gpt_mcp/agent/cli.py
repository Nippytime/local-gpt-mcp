"""Explicit user-launched outbound agent. Never installs a listener or background task."""

from __future__ import annotations

import argparse
import asyncio
import getpass

import httpx2 as httpx

from local_gpt_mcp.agent.credentials import credential_file, load_identity, save_identity
from local_gpt_mcp.agent.identity import DeviceIdentity
from local_gpt_mcp.agent.outbound import OutboundAgent


async def operate(gateway: str, *, pair: bool) -> None:
    async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
        if pair:
            if credential_file().exists():
                raise RuntimeError("Already enrolled; revoke the previous device before replacing it")
            device_id = input("Device ID shown in the authenticated owner portal: ").strip()
            code = getpass.getpass("One-time owner enrollment code: ").strip()
            identity = DeviceIdentity.generate(device_id)
            await OutboundAgent(identity, gateway, client=client).enroll(code)
            save_identity(identity)
            print("Device enrolled for this Windows user. No remote input was enabled.")
            return

        identity = load_identity()
        agent = OutboundAgent(identity, gateway, client=client)
        stop = asyncio.Event()
        print("Agent running outbound-only; Ctrl+C stops it. Reads deny until locally authorized.")
        try:
            await agent.run(stop)
        except KeyboardInterrupt:
            stop.set()


def main() -> None:
    parser = argparse.ArgumentParser(description="Opt-in Windows outbound MCP agent")
    parser.add_argument("--gateway", required=True, help="Public HTTPS gateway origin")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pair", action="store_true", help="Pair this PC with a one-time owner code")
    group.add_argument("--run", action="store_true", help="Connect outbound, deny remote reads by default")
    options = parser.parse_args()
    try:
        asyncio.run(operate(options.gateway, pair=options.pair))
    except (RuntimeError, ValueError, httpx.HTTPError) as error:
        parser.exit(1, f"Outbound agent unavailable: {type(error).__name__}\n")


if __name__ == "__main__":
    main()
