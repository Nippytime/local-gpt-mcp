"""Account ownership must not be inferred from a model-supplied device ID."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from local_gpt_mcp.gateway.registry import DeviceDirectory, DeviceUnavailable, ReadRequest


class FakeAgent:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, ReadRequest]] = []

    async def read(
        self, owner: str, device_id: str, request: ReadRequest
    ) -> Mapping[str, str | int | bool]:
        self.requests.append((owner, device_id, request))
        return {"title": "Approved window"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_registered_devices_are_isolated_by_owner_and_offline_by_default() -> None:
    directory = DeviceDirectory()
    directory.enroll_trusted("alice", "pc-a", "Alice's PC")
    directory.enroll_trusted("bob", "pc-b", "Bob's PC")
    assert directory.list_owned("alice") == [{"device_id": "pc-a", "label": "Alice's PC", "online": False}]
    assert directory.list_owned("bob") == [{"device_id": "pc-b", "label": "Bob's PC", "online": False}]
    with pytest.raises(DeviceUnavailable):
        directory.status("bob", "pc-a")
    with pytest.raises(DeviceUnavailable):
        directory.set_online_trusted("bob", "pc-a", True)
    with pytest.raises(DeviceUnavailable):
        directory.enroll_trusted("bob", "pc-a", "Stolen PC")


@pytest.mark.anyio
async def test_observation_denied_when_offline_or_no_verified_agent_connected() -> None:
    directory = DeviceDirectory()
    directory.enroll_trusted("alice", "pc-a", "Alice's PC")
    request = ReadRequest("desktop_window_info", "window:41")
    with pytest.raises(DeviceUnavailable):
        await directory.read("alice", "pc-a", request)
    directory.set_online_trusted("alice", "pc-a", True)
    with pytest.raises(DeviceUnavailable):
        await directory.read("alice", "pc-a", request)


@pytest.mark.anyio
async def test_agent_dispatch_is_owner_bound_and_read_only() -> None:
    agent = FakeAgent()
    directory = DeviceDirectory(agent)
    directory.enroll_trusted("alice", "pc-a", "Alice's PC")
    directory.enroll_trusted("bob", "pc-b", "Bob's PC")
    directory.set_online_trusted("alice", "pc-a", True)
    with pytest.raises(DeviceUnavailable):
        await directory.read("bob", "pc-a", ReadRequest("desktop_window_info", "window:41"))
    assert await directory.read(
        "alice", "pc-a", ReadRequest("desktop_window_info", "window:41")
    ) == {"title": "Approved window"}
    assert agent.requests == [("alice", "pc-a", ReadRequest("desktop_window_info", "window:41"))]


@pytest.mark.parametrize(
    "kind,target,selector",
    [
        ("desktop_click", "window:41", ""),
        ("shell", "pc-a", ""),
        ("desktop_window_info", "", ""),
        ("desktop_window_info", "window:41", "#password"),
        ("browser_read", "https://example.com", ""),
        ("browser_read", "https://example.com", "x" * 300),
    ],
)
def test_unsafe_requests_do_not_reach_agent(kind: str, target: str, selector: str) -> None:
    with pytest.raises(DeviceUnavailable):
        ReadRequest(kind, target, selector)


def test_untrusted_identifiers_and_duplicate_claiming_denied() -> None:
    directory = DeviceDirectory()
    with pytest.raises(ValueError):
        directory.enroll_trusted("alice", "../../pc", "unsafe")
    with pytest.raises(ValueError):
        directory.enroll_trusted("alice", "pc-a", "")
    directory.enroll_trusted("alice", "pc-a", "Initial")
    with pytest.raises(DeviceUnavailable):
        directory.enroll_trusted("alice", "pc-a", "Reclaimed")
