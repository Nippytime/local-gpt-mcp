"""Windows user-scoped DPAPI storage for the outbound device private key.

No plaintext keys on disk, no machine-wide secret, and no Linux fallback.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from local_gpt_mcp.agent.identity import DeviceIdentity


def _windows_dpapi() -> object:
    if sys.platform != "win32":
        raise RuntimeError("Device credentials require a signed-in Windows user and DPAPI")
    import win32crypt

    return win32crypt


def credential_file() -> Path:
    folder = os.environ.get("LOCALAPPDATA")
    if not folder:
        raise RuntimeError("Windows user LocalAppData is not available")
    return Path(folder) / "LocalGPTMCP" / "device-identity.json"


def save_identity(identity: DeviceIdentity, path: Path | None = None) -> None:
    crypt = _windows_dpapi()
    file = credential_file() if path is None else path
    if file.is_symlink() or file.parent.is_symlink():
        raise RuntimeError("Refusing linked credential path")
    if file.exists():
        raise FileExistsError("Existing device identity cannot be silently overwritten")
    file.parent.mkdir(parents=True, exist_ok=True)
    key = identity.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    encrypted: bytes = crypt.CryptProtectData(key, "Local GPT MCP device", None, None, None, 0)
    payload = json.dumps(
        {
            "version": 1,
            "device_id": identity.device_id,
            "protected_key": base64.b64encode(encrypted).decode("ascii"),
        }
    )
    temporary = file.with_suffix(".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError("Refusing existing temporary credential file")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(payload)
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        if file.exists() or file.is_symlink():
            raise FileExistsError("Credential path was created during enrollment")
        os.replace(temporary, file)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_identity(path: Path | None = None) -> DeviceIdentity:
    crypt = _windows_dpapi()
    file = credential_file() if path is None else path
    if file.is_symlink() or file.parent.is_symlink() or not file.is_file():
        raise RuntimeError("Credential file unavailable or unsafe")
    payload = json.loads(file.read_text(encoding="utf-8"))
    if payload.get("version") != 1:
        raise RuntimeError("Unknown encrypted credential format")
    encrypted = base64.b64decode(payload["protected_key"], validate=True)
    _, key = crypt.CryptUnprotectData(encrypted, None, None, None, 0)
    return DeviceIdentity(payload["device_id"], Ed25519PrivateKey.from_private_bytes(key))
