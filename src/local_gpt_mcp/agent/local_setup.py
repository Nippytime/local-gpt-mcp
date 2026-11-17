"""Opt-in local Windows bootstrap for approved remote clicks.

Requires a physically present operator on first launch. A remote MCP tool cannot
call this code, select windows, install keys, or approve device pairing.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

import httpx2 as httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from local_gpt_mcp.agent.credentials import credential_file
from local_gpt_mcp.agent.identity import DeviceAuthenticationError, DeviceIdentity, decode_public_key
from local_gpt_mcp.agent.outbound import OutboundAgent
from local_gpt_mcp.agent.remote_actions import AuthorizedActionRunner
from local_gpt_mcp.agent.windows_click import WindowsClickAdapter
from local_gpt_mcp.desktop.controller import DesktopDenied
from local_gpt_mcp.desktop.windows import WindowsBackend
from local_gpt_mcp.policy.authority import PairingRequest, PolicyAuthority, valid_identifier
from local_gpt_mcp.policy.remote_receipts import RemoteApprovalVerifier, SQLiteConsumptionStore
from local_gpt_mcp.ui.panel import LocalSafetyPanel

SELECTION_SECONDS = 15.0
USER_KEY_NAME = "owner-issuer.pub"
REPLAY_NAME = "remote-consumed.sqlite"


def load_local_issuer() -> Ed25519PublicKey:
    """Load only the manually pinned key in the Windows user's private profile."""
    folder = credential_file().parent
    path = folder / USER_KEY_NAME
    if (
        sys.platform != "win32"
        or not folder.is_dir()
        or folder.is_symlink()
        or path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 128
    ):
        raise RuntimeError("A locally pinned owner issuer key is required")
    try:
        return decode_public_key(path.read_text(encoding="ascii").strip())
    except (UnicodeError, OSError, DeviceAuthenticationError) as error:
        raise RuntimeError("The locally pinned owner issuer key is invalid") from error


def select_foreground_window(policy: PolicyAuthority, handle: int) -> WindowsClickAdapter:
    """Local operator selects an exact handle; never switch focus automatically."""
    if sys.platform != "win32" or os.name != "nt" or type(handle) is not int or handle <= 0:
        raise RuntimeError("A real interactive Windows window handle is required")
    backend = WindowsBackend(stopped=lambda: policy.stopped)
    matching = [window for window in backend.windows() if window.identity.handle == handle]
    if len(matching) != 1:
        raise RuntimeError("The locally selected window is not eligible for remote input")
    print("Switch to the selected window now. No window focus will be changed automatically.")
    deadline = time.monotonic() + SELECTION_SECONDS
    while time.monotonic() < deadline and not policy.stopped:
        try:
            selected = backend.trust_local([handle])
            return WindowsClickAdapter(backend, policy, selected)
        except DesktopDenied:
            time.sleep(0.2)
    raise RuntimeError("Window was not safely selected before the local setup expired")


async def run_locally_approved(
    gateway: str,
    identity: DeviceIdentity,
    client: httpx.AsyncClient,
    *,
    owner_id: str,
    window_handle: int,
) -> None:
    """Run only after a local owner has pinned issuer and approved pairing in Tk."""
    if sys.platform != "win32" or os.name != "nt" or not valid_identifier(owner_id):
        raise RuntimeError("Interactive Windows and a valid verified owner ID are required")
    issuer = load_local_issuer()
    policy_panel = LocalSafetyPanel(always_on_top=False)
    policy = PolicyAuthority(policy_panel)
    adapter = select_foreground_window(policy, window_handle)
    policy_panel.bind_authority(policy)
    try:
        policy_panel.start()
        # This is a LOCAL Tk typed-challenge approval, not a cloud or MCP consent.
        policy.pair(PairingRequest(owner_id, identity.device_id))
        replay_file: Path = credential_file().parent / REPLAY_NAME
        verifier = RemoteApprovalVerifier(
            issuer,
            SQLiteConsumptionStore(replay_file),
            stopped=lambda: policy.stopped,
        )
        runner = AuthorizedActionRunner(identity.device_id, verifier, policy, executor=adapter)
        agent = OutboundAgent(identity, gateway, client=client, action_runner=runner)
        stop = asyncio.Event()

        async def observe_local_stop() -> None:
            while not stop.is_set():
                if policy.stopped:
                    stop.set()
                    break
                await asyncio.sleep(0.1)

        print(
            "Local click approval enabled for ONE selected window and account. "
            "Restore that window to foreground; locking Windows denies input. "
            "Close the local safety panel or press STOP to revoke this process."
        )
        try:
            await asyncio.gather(agent.run(stop), observe_local_stop())
        finally:
            stop.set()
    finally:
        policy_panel.stop()
        policy.emergency_stop()
