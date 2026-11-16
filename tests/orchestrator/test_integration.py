"""Real scoped browser controller and MCP client integration for workflow steps."""

from __future__ import annotations

import pytest
from mcp import Client

from local_gpt_mcp.browser import BrowserController
from local_gpt_mcp.mcp.server import create_server
from local_gpt_mcp.orchestrator import (
    Action,
    Condition,
    MemoryCheckpointStore,
    SessionGrants,
    Step,
    WorkflowEngine,
    WorkflowPlan,
)
from local_gpt_mcp.orchestrator.driver import ScopedDriver
from local_gpt_mcp.pairing import SessionBroker
from local_gpt_mcp.policy import Capability, GrantRequest, PairingRequest, PolicyAuthority


class LocalPairing:
    def approve_pairing(self, request: PairingRequest) -> bool:
        return True

    def approve_grant(self, request: GrantRequest) -> bool:
        return True


class LocalAction:
    def __init__(self, allows: bool = True) -> None:
        self.allows = allows
        self.count = 0

    def approve(self, step: Step) -> bool:
        self.count += 1
        return self.allows


class Page:
    url = "https://example.com/"

    def __init__(self) -> None:
        self.title = "Ready"
        self.effects: list[str] = []

    async def navigate(self, url: str) -> None:
        self.effects.append("navigate")
        self.url = url

    async def read_text(self, selector: str) -> str:
        assert selector == "#title"
        return self.title

    async def click(self, selector: str) -> None:
        assert selector == "#open"
        self.effects.append("click")
        self.title = "Opened"

    async def fill(self, selector: str, text: str) -> None:
        self.effects.append("fill")

    async def scroll(self, steps: int) -> None:
        self.effects.append("scroll")

    async def screenshot(self) -> bytes:
        return b"\x89PNG"


class Setup:
    def __init__(self, approval: LocalAction | None = None) -> None:
        self.broker = SessionBroker(PolicyAuthority(LocalPairing()))
        self.browser = BrowserController(self.broker)
        self.page = Page()
        self.tab = self.browser.attach_local("https://example.com", self.page)
        self.approval = approval or LocalAction()
        self.engine = WorkflowEngine(
            self.broker,
            ScopedDriver(browser=self.browser),
            MemoryCheckpointStore(),
            self.approval,
        )
        self.serial = 0
        token = self.broker.open("person", "desktop", self.nonce())["session_token"]
        assert isinstance(token, str)
        read = self.broker.request_grant(
            token, self.nonce(), "https://example.com", frozenset({Capability.BROWSER_READ}), 120
        )["grant_token"]
        write = self.broker.request_grant(
            token, self.nonce(), "https://example.com", frozenset({Capability.BROWSER_INPUT}), 120
        )["grant_token"]
        assert isinstance(read, str) and isinstance(write, str)
        self.auth = SessionGrants(token, read, write)

    def nonce(self) -> str:
        self.serial += 1
        return f"{self.serial:032x}"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_scoped_browser_adapter_runs_conditions_and_effects() -> None:
    f = Setup()
    plan = WorkflowPlan(
        "plan-1",
        (
            Step("observe", Action.BROWSER_READ, f.tab.tab_id, selector="#title"),
            Step(
                "click",
                Action.BROWSER_CLICK,
                f.tab.tab_id,
                selector="#open",
                before=Condition("#title", "Ready"),
                after=Condition("#title", "Opened"),
            ),
        ),
    )
    completed = await f.engine.run(plan, f.auth)
    assert completed.finished and completed.completed == 2
    assert completed.outputs[0].result == "Ready"
    assert f.page.effects == ["click"]
    assert f.approval.count == 1


@pytest.mark.anyio
async def test_real_mcp_protocol_exposes_workflow_only_with_local_adapter() -> None:
    f = Setup()
    async with Client(create_server(f.broker)) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert "workflow_execute" not in names
    async with Client(create_server(f.broker, browser=f.browser, workflows=f.engine)) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert "workflow_execute" in names
        payload = {
            "session_token": f.auth.session_token,
            "client_nonce": f.nonce(),
            "read_grant_token": f.auth.read_grant,
            "input_grant_token": f.auth.input_grant,
            "plan_id": "mcp-plan",
            "steps": [
                {
                    "step_id": "read-one",
                    "action": "browser.read",
                    "target": f.tab.tab_id,
                    "selector": "#title",
                }
            ],
        }
        result = await client.call_tool("workflow_execute", payload)
        assert not result.is_error
        assert result.structured_content is not None
        assert result.structured_content["finished"] is True
        assert result.structured_content["completed"] == 1
        # Replay the original client nonce: the broker must reject it.
        replay = await client.call_tool("workflow_execute", payload)
        assert replay.is_error


@pytest.mark.anyio
async def test_mcp_mutation_always_needs_separate_on_device_approval() -> None:
    prompt = LocalAction(False)
    f = Setup(prompt)
    async with Client(create_server(f.broker, browser=f.browser, workflows=f.engine)) as client:
        result = await client.call_tool(
            "workflow_execute",
            {
                "session_token": f.auth.session_token,
                "client_nonce": f.nonce(),
                "read_grant_token": f.auth.read_grant,
                "input_grant_token": f.auth.input_grant,
                "plan_id": "click-plan",
                "steps": [
                    {
                        "step_id": "click-one",
                        "action": "browser.click",
                        "target": f.tab.tab_id,
                        "selector": "#open",
                    }
                ],
            },
        )
        assert result.is_error
        assert f.page.effects == []
        assert prompt.count == 1
