"""Device health must expire after a lost poll without a false online claim."""

from __future__ import annotations

import time

import pytest

from local_gpt_mcp.agent.identity import DeviceIdentity, sign_request
from local_gpt_mcp.gateway.agent_relay import HEARTBEAT_SECONDS, AgentRelay
from local_gpt_mcp.gateway.registry import DeviceDirectory, DeviceUnavailable, ReadRequest


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_lost_heartbeat_marks_device_offline_and_denies_reads() -> None:
    now = [time.time()]
    relay = AgentRelay(clock=lambda: now[0])
    directory = DeviceDirectory(relay)
    relay.bind(directory)
    code, device_id = relay.issue_code("alice", "Owner PC")
    identity = DeviceIdentity.generate(device_id)
    relay.enroll(code, device_id, identity.public_key)

    assert directory.status("alice", device_id)["online"] is False
    headers = sign_request(identity.private_key, device_id, "/api/agent/poll", b"{}", timestamp=int(now[0]))
    relay.authenticate(
        device_id,
        "/api/agent/poll",
        b"{}",
        {name.lower(): value for name, value in headers.items()},
    )
    assert directory.status("alice", device_id)["online"] is True
    assert directory.list_owned("alice")[0]["online"] is True

    now[0] += HEARTBEAT_SECONDS + 1
    assert relay.connected("alice", device_id) is False
    assert directory.status("alice", device_id)["online"] is False
    assert directory.list_owned("alice")[0]["online"] is False
    with pytest.raises(DeviceUnavailable):
        await directory.read("alice", device_id, ReadRequest("desktop_window_info", "window:41"))
    assert relay.connected("bob", device_id) is False
