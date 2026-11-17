"""Explicit user-launched outbound agent. Never installs a listener or background task."""

from __future__ import annotations

import argparse
import asyncio
import getpass

import httpx2 as httpx

from local_gpt_mcp.agent.credentials import credential_file, load_identity, save_identity
from local_gpt_mcp.agent.identity import DeviceIdentity
from local_gpt_mcp.agent.local_setup import run_locally_approved
from local_gpt_mcp.agent.outbound import OutboundAgent


async def operate(
    gateway: str,
    *,
    pair: bool,
    approved_input: bool = False,
    owner_id: str | None = None,
    window_handle: int | None = None,
) -> None:
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
        if approved_input:
            if owner_id is None or window_handle is None:
                raise ValueError("Approved input requires a local owner ID and selected window")
            await run_locally_approved(
                gateway, identity, client, owner_id=owner_id, window_handle=window_handle
            )
            return
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
    group.add_argument(
        "--run-approved-input",
        action="store_true",
        help="Start visible local safety UI and explicitly authorize a selected window",
    )
    parser.add_argument("--owner-id", help="Exact owner identity verified by the gateway issuer")
    parser.add_argument("--window-handle", type=int, help="Native Win32 window selected at this PC")
    options = parser.parse_args()
    if options.run_approved_input and (options.owner_id is None or options.window_handle is None):
        parser.error("--run-approved-input requires --owner-id and --window-handle")
    if not options.run_approved_input and (options.owner_id is not None or options.window_handle is not None):
        parser.error("--owner-id and --window-handle are only valid with --run-approved-input")
    try:
        asyncio.run(
            operate(
                options.gateway,
                pair=options.pair,
                approved_input=options.run_approved_input,
                owner_id=options.owner_id,
                window_handle=options.window_handle,
            )
        )
    except (RuntimeError, ValueError, PermissionError, httpx.HTTPError) as error:
        parser.exit(1, f"Outbound agent unavailable: {type(error).__name__}\n")


if __name__ == "__main__":
    main()
