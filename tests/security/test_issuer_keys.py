"""Operator-only issuer private-key provisioning remains private and restart-safe."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from local_gpt_mcp.agent.identity import public_key_text
from local_gpt_mcp.gateway.issuer_keys import load_issuer_key, provision_issuer_key


@pytest.mark.skipif(os.name != "posix", reason="Private key setup requires POSIX owner/mode checks")
def test_issuer_provision_once_and_load_same_public_pin(tmp_path: Path) -> None:
    path = tmp_path / "issuer.pem"
    public = provision_issuer_key(path)
    assert len(public) == 44
    assert public_key_text(load_issuer_key(path)) == public
    assert path.stat().st_mode & 0o077 == 0
    assert "BEGIN PRIVATE KEY" in path.read_text(encoding="ascii")
    with pytest.raises(FileExistsError):
        provision_issuer_key(path)
    assert public_key_text(load_issuer_key(path)) == public


@pytest.mark.skipif(os.name != "posix", reason="Private key setup requires POSIX owner/mode checks")
def test_refuse_linked_world_readable_and_unsafe_directory(tmp_path: Path) -> None:
    path = tmp_path / "issuer.pem"
    provision_issuer_key(path)
    path.chmod(0o644)
    with pytest.raises(RuntimeError, match="permissions"):
        load_issuer_key(path)
    path.chmod(0o600)
    alias = tmp_path / "linked.pem"
    alias.symlink_to(path)
    with pytest.raises(RuntimeError, match="Linked"):
        load_issuer_key(alias)
    with pytest.raises(RuntimeError, match="Linked"):
        provision_issuer_key(alias)
    unsafe = tmp_path / "shared"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(RuntimeError, match="private"):
        provision_issuer_key(unsafe / "issuer.pem")
    assert not (unsafe / "issuer.pem").exists()


@pytest.mark.skipif(os.name != "posix", reason="Private key setup requires POSIX owner/mode checks")
def test_bad_format_and_missing_key_deny(tmp_path: Path) -> None:
    missing = tmp_path / "absent.pem"
    with pytest.raises(OSError):
        load_issuer_key(missing)
    bad = tmp_path / "issuer.pem"
    bad.write_bytes(b"not a PEM")
    bad.chmod(stat.S_IRUSR | stat.S_IWUSR)
    with pytest.raises(RuntimeError, match="Malformed"):
        load_issuer_key(bad)
    wrong = Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    bad.write_bytes(wrong + b"x" * 3000)
    with pytest.raises(RuntimeError, match="size"):
        load_issuer_key(bad)


def test_non_absolute_path_never_provisions_a_key() -> None:
    with pytest.raises(RuntimeError):
        provision_issuer_key(Path("issuer.pem"))
