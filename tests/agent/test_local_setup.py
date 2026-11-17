"""Manual Windows authorization startup is opt-in and rejects unsafe issuer setup."""

from __future__ import annotations

import asyncio
import base64
import sys
from pathlib import Path

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from local_gpt_mcp.agent import cli, local_setup
from local_gpt_mcp.agent.identity import DeviceIdentity


def test_local_key_missing_linked_invalid_or_valid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_path = tmp_path / local_setup.USER_KEY_NAME
    monkeypatch.setattr(local_setup, "credential_file", lambda: tmp_path / "device-identity.json")
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(RuntimeError, match="pinned"):
        local_setup.load_local_issuer()
    key_path.write_text("not-a-real-key", encoding="ascii")
    with pytest.raises(RuntimeError, match="invalid"):
        local_setup.load_local_issuer()
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_path.write_text(base64.urlsafe_b64encode(raw).decode("ascii"), encoding="ascii")
    assert local_setup.load_local_issuer().public_bytes(Encoding.Raw, PublicFormat.Raw) == raw
    original = tmp_path / "trusted.pub"
    key_path.rename(original)
    try:
        key_path.symlink_to(original)
    except (OSError, NotImplementedError):
        pytest.skip("Platform cannot create symlinks")
    with pytest.raises(RuntimeError, match="pinned"):
        local_setup.load_local_issuer()


@pytest.mark.anyio
async def test_explicit_opt_in_routes_to_local_setup_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = DeviceIdentity.generate("pc-alice")
    calls: list[tuple[str, str, str, int]] = []

    async def fake_setup(
        gateway: str,
        device: DeviceIdentity,
        client: httpx.AsyncClient,
        *,
        owner_id: str,
        window_handle: int,
    ) -> None:
        assert device is identity
        assert isinstance(client, httpx.AsyncClient)
        calls.append((gateway, device.device_id, owner_id, window_handle))

    monkeypatch.setattr(cli, "load_identity", lambda: identity)
    monkeypatch.setattr(cli, "run_locally_approved", fake_setup)
    await cli.operate(
        "https://gateway.example.com",
        pair=False,
        approved_input=True,
        owner_id="alice",
        window_handle=41,
    )
    assert calls == [("https://gateway.example.com", "pc-alice", "alice", 41)]
    with pytest.raises(ValueError, match="selected window"):
        await cli.operate(
            "https://gateway.example.com",
            pair=False,
            approved_input=True,
            owner_id="alice",
        )
    assert len(calls) == 1


def test_local_setup_never_enables_on_non_windows() -> None:
    if sys.platform == "win32":
        pytest.skip("Covered on native Windows integration gate")
    with pytest.raises(RuntimeError, match="Interactive Windows"):
        asyncio.run(
            local_setup.run_locally_approved(
                "https://gateway.example.com",
                DeviceIdentity.generate("pc-alice"),
                httpx.AsyncClient(),
                owner_id="alice",
                window_handle=41,
            )
        )


def test_no_issuer_secret_or_remote_input_in_default_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sys.argv",
        ["local-gpt-agent", "--gateway", "https://gateway.example.com", "--owner-id", "alice", "--run"],
    )
    with pytest.raises(SystemExit, match="2"):
        cli.main()
