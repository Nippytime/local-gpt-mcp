"""Operator-managed Ed25519 approval issuer keys; private bytes never leave this host.

Only trusted local operators may provision/load the key. No HTTP/MCP route
exposes private key bytes, rekeys a running gateway, or issues owner consent.
"""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from local_gpt_mcp.agent.identity import public_key_text

MAX_KEY_BYTES = 2048


def _trusted_path(path: Path) -> None:
    """Require a private operator-owned POSIX directory, not a shared mount."""
    if os.name != "posix":
        raise RuntimeError("Private gateway issuer files currently require a POSIX host")
    if not path.is_absolute() or ".." in path.parts or not path.parent.is_dir():
        raise RuntimeError("A private absolute issuer key path is required")
    if any(parent.is_symlink() for parent in path.parents) or path.is_symlink():
        raise RuntimeError("Linked issuer key paths are not trusted")
    parent = path.parent.stat()
    if parent.st_uid != getattr(os, "geteuid")() or parent.st_mode & 0o077:
        raise RuntimeError("Issuer key directory must be owned by this user and private (0700)")


def provision_issuer_key(path: Path) -> str:
    """Generate once with O_EXCL + 0600; never replace an enrolled issuer."""
    _trusted_path(path)
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW")
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(pem)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return public_key_text(private)


def load_issuer_key(path: Path) -> Ed25519PrivateKey:
    """Fail closed on altered ACL/mode, symlink, oversized or non-Ed25519 PEM."""
    _trusted_path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW"))
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != getattr(os, "geteuid")()
            or info.st_mode & 0o077
            or not 0 < info.st_size <= MAX_KEY_BYTES
        ):
            raise RuntimeError("Issuer key file owner, permissions, or size are unsafe")
        data = os.read(fd, MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    try:
        private = load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as error:
        raise RuntimeError("Malformed issuer private key") from error
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("Approval issuer must be an Ed25519 private key")
    return private


def main() -> None:
    """Offline operator command. Only the public pin is printed to stdout."""
    parser = argparse.ArgumentParser(description="Provision a private remote-approval issuer")
    parser.add_argument(
        "--key-file", required=True, type=Path, help="Private absolute PEM path (0700 parent)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--create", action="store_true", help="Create once, never overwrite")
    group.add_argument("--show-public", action="store_true", help="Print the public PC pin only")
    args = parser.parse_args()
    try:
        public = (
            provision_issuer_key(args.key_file)
            if args.create
            else public_key_text(load_issuer_key(args.key_file))
        )
    except (RuntimeError, OSError, ValueError) as error:
        parser.exit(1, f"Issuer setup refused: {type(error).__name__}\n")
    print(public)


if __name__ == "__main__":
    main()
