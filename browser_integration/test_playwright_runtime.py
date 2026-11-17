"""Real Chromium and MCP SDK integration with all network responses served locally."""

from __future__ import annotations

import asyncio
import base64
from types import SimpleNamespace
from typing import Any

import pytest
from mcp import Client
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Route

from local_gpt_mcp.browser import BrowserController
from local_gpt_mcp.browser.controller import BrowserDenied, origin_of
from local_gpt_mcp.browser.playwright_driver import IsolatedBrowserSession
from local_gpt_mcp.browser.safe_fetch import PinnedResponse
from local_gpt_mcp.mcp.server import create_server
from local_gpt_mcp.orchestrator.models import Step
from local_gpt_mcp.pairing import SessionBroker
from local_gpt_mcp.policy import GrantRequest, PairingRequest, PolicyAuthority

HTML = """<!doctype html><html><body>
<h1 id="title">Welcome</h1>
<button id="open" onclick="document.querySelector('#title').textContent='Opened'">Open</button>
<input id="query" type="text" autocomplete="off" />
<input id="password" type="password" value="never-read-me" />
<input id="secretToken" type="text" value="never-fill-me" />
<form><button id="submit">Send money</button></form>
<input id="upload" type="file" />
</body></html>"""


class Approval:
    def approve_pairing(self, request: PairingRequest) -> bool:
        return True

    def approve_grant(self, request: GrantRequest) -> bool:
        return True

    def approve(self, step: Step) -> bool:
        return True


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_real_chromium_isolated_mcp_read_fill_click_and_redaction() -> None:
    broker = SessionBroker(PolicyAuthority(Approval()))
    controller = BrowserController(broker)
    async with IsolatedBrowserSession("https://example.com", controller, headless=True) as runtime:
        assert runtime.context is not None
        page = runtime.context.pages[0]

        async def serve_html(route: Route) -> None:
            await route.fulfill(status=200, content_type="text/html", body=HTML)

        # Override the network response with local synthetic content so CI
        # never depends on external site availability or credentials.
        await page.route("https://example.com/**", serve_html)
        async with Client(
            create_server(broker, browser=controller, direct_action_approval=Approval())
        ) as client:
            seq = 0

            def nonce() -> str:
                nonlocal seq
                seq += 1
                return f"{seq:032x}"

            discovered = await client.list_tools()
            names = {tool.name for tool in discovered.tools}
            assert {"browser_selected_tabs", "browser_navigate", "browser_capture"} <= names
            assert "shell_execute" not in names

            unauth = await client.call_tool(
                "browser_selected_tabs", {"session_token": "invalid", "client_nonce": nonce()}
            )
            assert unauth.is_error

            pair = await client.call_tool(
                "session_open",
                {"user_id": "person", "device_id": "desktop", "client_nonce": nonce()},
            )
            assert not pair.is_error and pair.structured_content is not None
            session = str(pair.structured_content["session_token"])
            tabs_result = await client.call_tool(
                "browser_selected_tabs", {"session_token": session, "client_nonce": nonce()}
            )
            assert not tabs_result.is_error
            assert tabs_result.structured_content is not None
            tabs = tabs_result.structured_content["tabs"]
            assert isinstance(tabs, list) and len(tabs) == 1
            tab_id = tabs[0]["tab_id"]

            approval = await client.call_tool(
                "session_request_grant",
                {
                    "session_token": session,
                    "client_nonce": nonce(),
                    "target": "https://example.com",
                    "capabilities": ["browser.read", "browser.input"],
                    "ttl_seconds": 60,
                },
            )
            assert not approval.is_error and approval.structured_content is not None
            grant = str(approval.structured_content["grant_token"])
            auth: dict[str, Any] = {"session_token": session, "grant_token": grant, "tab_id": tab_id}

            navigated = await client.call_tool(
                "browser_navigate", {**auth, "client_nonce": nonce(), "url": "https://example.com/"}
            )
            assert not navigated.is_error

            title = await client.call_tool(
                "browser_read", {**auth, "client_nonce": nonce(), "selector": "#title"}
            )
            assert not title.is_error
            assert title.structured_content is not None
            assert title.structured_content["text"] == "Welcome"

            filled = await client.call_tool(
                "browser_fill",
                {**auth, "client_nonce": nonce(), "selector": "#query", "text": "safe search"},
            )
            assert not filled.is_error
            assert await page.locator("#query").input_value() == "safe search"

            clicked = await client.call_tool(
                "browser_click", {**auth, "client_nonce": nonce(), "selector": "#open"}
            )
            assert not clicked.is_error
            assert await page.locator("#title").inner_text() == "Opened"

            for selector in ("#password", "#secretToken", "#upload"):
                denied = await client.call_tool(
                    "browser_fill",
                    {**auth, "client_nonce": nonce(), "selector": selector, "text": "do not send"},
                )
                assert denied.is_error

            no_form_submit = await client.call_tool(
                "browser_click", {**auth, "client_nonce": nonce(), "selector": "#submit"}
            )
            assert no_form_submit.is_error

            screenshot = await client.call_tool("browser_capture", {**auth, "client_nonce": nonce()})
            assert not screenshot.is_error and screenshot.structured_content is not None
            assert base64.b64decode(screenshot.structured_content["base64"]).startswith(b"\x89PNG")

            prohibited = await client.call_tool(
                "browser_navigate",
                {**auth, "client_nonce": nonce(), "url": "https://other.example.com"},
            )
            assert prohibited.is_error
            assert len(runtime.context.pages) == 1

            stop = await client.call_tool(
                "session_emergency_stop",
                {"session_token": session, "client_nonce": nonce()},
            )
            assert not stop.is_error
            denied = await client.call_tool(
                "browser_read", {**auth, "client_nonce": nonce(), "selector": "#title"}
            )
            assert denied.is_error


@pytest.mark.anyio
async def test_network_route_denies_private_and_cross_origin_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = SessionBroker(PolicyAuthority(Approval()))
    controller = BrowserController(broker)
    runtime = IsolatedBrowserSession("https://example.com", controller, headless=True)

    def fetch(url: str, origin: str, method: str, headers: dict[str, str]) -> PinnedResponse:
        if origin_of(url) != origin or method != "GET" or "/redirect" in url:
            raise BrowserDenied("Unsafe or redirected network request")
        return PinnedResponse(200, {"content-type": "text/plain"}, b"safe")

    monkeypatch.setattr("local_gpt_mcp.browser.playwright_driver.fetch_public_https", fetch)

    class RouteFake:
        def __init__(self, url: str) -> None:
            self.request = SimpleNamespace(url=url, method="GET", headers={})
            self.result = ""

        async def fulfill(self, *, status: int, headers: dict[str, str], body: bytes) -> None:
            assert status == 200 and body == b"safe"
            self.result = "allowed"

        async def abort(self, reason: str) -> None:
            self.result = reason

    for url, expected in (
        ("https://example.com/assets.js", "allowed"),
        ("https://example.com/redirect", "blockedbyclient"),
        ("https://sub.example.com/", "blockedbyclient"),
        ("http://example.com/", "blockedbyclient"),
        ("http://127.0.0.1/private", "blockedbyclient"),
        ("https://169.254.169.254/latest/meta-data", "blockedbyclient"),
    ):
        route = RouteFake(url)
        await runtime._network(route)  # type: ignore[arg-type]
        assert route.result == expected


@pytest.mark.anyio
async def test_real_chromium_private_navigation_never_reaches_loopback_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Observe an actual TCP listener, not just an intercepted Playwright route fake."""
    accepted = 0

    async def observe(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal accepted
        accepted += 1
        writer.close()
        await writer.wait_closed()

    listener = await asyncio.start_server(observe, "127.0.0.1", 0)
    try:
        assert listener.sockets is not None
        port = listener.sockets[0].getsockname()[1]
        routed: list[str] = []

        def safe_fetch(url: str, origin: str, method: str, _headers: dict[str, str]) -> PinnedResponse:
            routed.append(url)
            if origin_of(url) != origin or method != "GET":
                raise BrowserDenied("Unapproved browser egress")
            return PinnedResponse(200, {"content-type": "text/html"}, b"<html><body>safe page</body></html>")

        monkeypatch.setattr("local_gpt_mcp.browser.playwright_driver.fetch_public_https", safe_fetch)
        broker = SessionBroker(PolicyAuthority(Approval()))
        controller = BrowserController(broker)
        async with IsolatedBrowserSession("https://example.com", controller, headless=True) as runtime:
            assert runtime.context is not None
            page = runtime.context.pages[0]
            await page.goto("https://example.com/approved", wait_until="domcontentloaded", timeout=10_000)
            assert "safe page" in await page.locator("body").inner_text()
            assert "https://example.com/approved" in routed

            image_url = f"https://127.0.0.1:{port}/image.png"
            image_denied = await page.evaluate(
                """url => new Promise(resolve => {
                    const image = new Image();
                    image.onload = () => resolve(false);
                    image.onerror = () => resolve(true);
                    image.src = url;
                })""",
                image_url,
            )
            assert image_denied is True
            assert image_url in routed

            fetch_url = f"https://127.0.0.1:{port}/resource"
            fetch_denied = await page.evaluate(
                """async url => {
                    try {
                        await fetch(url, {mode: "no-cors"});
                        return false;
                    } catch {
                        return true;
                    }
                }""",
                fetch_url,
            )
            assert fetch_denied is True

            websocket_url = f"wss://127.0.0.1:{port}/socket"
            websocket_denied = await page.evaluate(
                """url => Promise.race([
                    new Promise(resolve => {
                        const ws = new WebSocket(url);
                        ws.onopen = () => { ws.close(); resolve(false); };
                        ws.onerror = () => resolve(true);
                        ws.onclose = () => resolve(true);
                    }),
                    new Promise(resolve => setTimeout(() => resolve(false), 2000))
                ])""",
                websocket_url,
            )
            assert websocket_denied is True

            local_url = f"http://127.0.0.1:{port}/private"
            with pytest.raises(PlaywrightError):
                await page.goto(local_url, wait_until="domcontentloaded", timeout=5_000)
            assert local_url in routed

        await asyncio.sleep(0.05)
        assert accepted == 0, "Chromium must not connect directly to the private listener"
    finally:
        listener.close()
        await listener.wait_closed()
