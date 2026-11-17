"""Device signatures cannot be forged, replayed, redirected or expired."""

from __future__ import annotations

import time

import pytest

from local_gpt_mcp.agent.identity import (
    DeviceAuthenticationError,
    DeviceIdentity,
    DeviceReplayGuard,
    decode_public_key,
    sign_request,
)


def lower(headers: dict[str, str]) -> dict[str, str]:
    return {name.lower(): value for name, value in headers.items()}


def test_signed_request_is_bound_to_device_path_body_time_and_nonce() -> None:
    identity = DeviceIdentity.generate("pc-one")
    guard = DeviceReplayGuard()
    headers = lower(sign_request(identity.private_key, "pc-one", "/api/agent/poll", b"{}"))
    public = decode_public_key(identity.public_key)
    guard.verify(public, "pc-one", "/api/agent/poll", b"{}", headers)
    with pytest.raises(DeviceAuthenticationError, match="Replayed"):
        guard.verify(public, "pc-one", "/api/agent/poll", b"{}", headers)
    for path, content in [
        ("/api/agent/result", b"{}"),
        ("/api/agent/poll", b'{"modified":true}'),
    ]:
        with pytest.raises(DeviceAuthenticationError):
            DeviceReplayGuard().verify(public, "pc-one", path, content, headers)
    with pytest.raises(DeviceAuthenticationError):
        DeviceReplayGuard().verify(public, "pc-two", "/api/agent/poll", b"{}", headers)
    foreign = DeviceIdentity.generate("pc-one")
    with pytest.raises(DeviceAuthenticationError):
        DeviceReplayGuard().verify(
            decode_public_key(foreign.public_key), "pc-one", "/api/agent/poll", b"{}", headers
        )


def test_timestamp_expiry_and_malformed_keys_are_denied() -> None:
    identity = DeviceIdentity.generate("pc-safe")
    old = int(time.time()) - 100
    headers = lower(
        sign_request(identity.private_key, identity.device_id, "/api/agent/poll", b"{}", timestamp=old)
    )
    with pytest.raises(DeviceAuthenticationError, match="Expired"):
        DeviceReplayGuard().verify(
            decode_public_key(identity.public_key), identity.device_id, "/api/agent/poll", b"{}", headers
        )
    for value in ["bad", "!", "A" * 44]:
        with pytest.raises(DeviceAuthenticationError):
            decode_public_key(value)
    with pytest.raises(ValueError):
        DeviceIdentity.generate("../unsafe")
