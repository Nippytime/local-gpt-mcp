"""User-scoped device identity storage must preserve ownership and refuse replacement."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from local_gpt_mcp.agent import credentials
from local_gpt_mcp.agent.identity import DeviceIdentity


class FakeDPAPI:
    """Deterministic test double: never used to encrypt production credentials."""

    @staticmethod
    def CryptProtectData(raw: bytes, *args: object) -> bytes:
        return b"test-protected:" + bytes(value ^ 0xA5 for value in raw)

    @staticmethod
    def CryptUnprotectData(blob: bytes, *args: object) -> tuple[str, bytes]:
        if not blob.startswith(b"test-protected:"):
            raise ValueError("Credential tampered")
        return "", bytes(value ^ 0xA5 for value in blob[len(b"test-protected:") :])


def test_identity_roundtrip_uses_protected_bytes_and_rejects_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(credentials, "_windows_dpapi", FakeDPAPI)
    identity = DeviceIdentity.generate("pc-owner")
    file = tmp_path / "user" / "identity.json"
    credentials.save_identity(identity, file)
    assert file.is_file()
    assert "protected_key" in file.read_text(encoding="utf-8")
    assert base64.b64encode(identity.private_key.private_bytes_raw()).decode("ascii") not in file.read_text(
        encoding="utf-8"
    )
    restored = credentials.load_identity(file)
    assert restored.device_id == identity.device_id
    assert restored.public_key == identity.public_key
    with pytest.raises(FileExistsError):
        credentials.save_identity(DeviceIdentity.generate("pc-other"), file)


def test_identity_read_refuses_missing_and_linked_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(credentials, "_windows_dpapi", FakeDPAPI)
    missing = tmp_path / "missing.json"
    with pytest.raises(RuntimeError):
        credentials.load_identity(missing)

    real = tmp_path / "real.json"
    credentials.save_identity(DeviceIdentity.generate("pc-owner"), real)
    link = tmp_path / "alias.json"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("This runner does not support symlink creation")
    with pytest.raises(RuntimeError, match="unsafe"):
        credentials.load_identity(link)
    with pytest.raises(RuntimeError, match="linked"):
        credentials.save_identity(DeviceIdentity.generate("pc-other"), link)
