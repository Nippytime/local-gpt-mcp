"""Unit-test the Playwright boundary with fake handles in the normal coverage gate."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from playwright.async_api import Page

from local_gpt_mcp.browser import BrowserController, BrowserDenied
from local_gpt_mcp.browser.playwright_driver import IsolatedBrowserSession, PlaywrightTab
from local_gpt_mcp.pairing import SessionBroker
from local_gpt_mcp.policy import PolicyAuthority


class FakeLocator:
    def __init__(
        self,
        tag: str = "div",
        attrs: dict[str, str] | None = None,
        *,
        count: int = 1,
        visible: bool = True,
        enabled: bool = True,
        form: bool = False,
    ) -> None:
        self.tag = tag
        self.attrs = attrs or {}
        self.matched = count
        self.visible = visible
        self.enabled = enabled
        self.form = form
        self.value = ""
        self.clicked = False

    async def count(self) -> int:
        return self.matched

    async def is_visible(self) -> bool:
        return self.visible

    async def is_enabled(self) -> bool:
        return self.enabled

    async def get_attribute(self, attribute: str) -> str | None:
        return self.attrs.get(attribute)

    async def evaluate(self, expression: str) -> str | bool:
        return self.form if "closest(" in expression else self.tag

    async def inner_text(self, **kwargs: Any) -> str:
        return "Safe heading"

    async def click(self, **kwargs: Any) -> None:
        self.clicked = True

    async def fill(self, text: str, **kwargs: Any) -> None:
        self.value = text


class FakeMouse:
    def __init__(self) -> None:
        self.wheel_events: list[tuple[int, int]] = []

    async def wheel(self, x: int, y: int) -> None:
        self.wheel_events.append((x, y))


class FakePage:
    def __init__(self) -> None:
        self.url = "about:blank"
        self.mouse = FakeMouse()
        self.elements: dict[str, FakeLocator] = {
            "#heading": FakeLocator(),
            "#button": FakeLocator("button"),
            "#input": FakeLocator("input", {"type": "text", "autocomplete": "off"}),
        }
        self.masked = False

    async def goto(self, url: str, **kwargs: Any) -> None:
        self.url = url

    def locator(self, selector: str) -> FakeLocator:
        return self.elements.get(selector, FakeLocator())

    async def screenshot(self, **kwargs: Any) -> bytes:
        self.masked = bool(kwargs.get("mask"))
        return b"\x89PNG\r\n\x1a\n"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_safe_playwright_navigation_read_edit_click_and_redacted_capture() -> None:
    page = FakePage()
    adapter = PlaywrightTab(cast(Page, page))
    await adapter.navigate("https://example.com/")
    assert adapter.url == "https://example.com/"
    assert await adapter.read_text("#heading") == "Safe heading"
    await adapter.click("#button")
    await adapter.fill("#input", "search query")
    await adapter.scroll(2)
    image = await adapter.screenshot()
    assert image.startswith(b"\x89PNG")
    assert page.masked
    assert page.elements["#button"].clicked
    assert page.elements["#input"].value == "search query"
    assert page.mouse.wheel_events == [(0, 480)]


@pytest.mark.anyio
async def test_sensitive_inputs_and_form_submit_rejected() -> None:
    page = FakePage()
    page.elements["#password"] = FakeLocator("input", {"type": "password"})
    page.elements["#payment"] = FakeLocator("input", {"name": "credit_card"})
    page.elements["#file"] = FakeLocator("input", {"type": "file"})
    page.elements["#send"] = FakeLocator("button", form=True)
    adapter = PlaywrightTab(cast(Page, page))
    for selector in ("#password", "#payment", "#file"):
        with pytest.raises(BrowserDenied):
            await adapter.fill(selector, "secret")
    with pytest.raises(BrowserDenied):
        await adapter.click("#send")
    with pytest.raises(BrowserDenied):
        await adapter.read_text("#input")
    assert not page.elements["#send"].clicked


@pytest.mark.anyio
async def test_ambiguous_hidden_disabled_and_wrong_type_rejected() -> None:
    page = FakePage()
    page.elements["#many"] = FakeLocator(count=2)
    page.elements["#hidden"] = FakeLocator(visible=False)
    page.elements["#disabled"] = FakeLocator(enabled=False)
    adapter = PlaywrightTab(cast(Page, page))
    for selector in ("#many", "#hidden", "#disabled"):
        with pytest.raises(BrowserDenied):
            await adapter.click(selector)
    with pytest.raises(BrowserDenied, match="editable"):
        await adapter.fill("#heading", "hello")


@pytest.mark.anyio
async def test_contenteditable_supported_only_for_filling() -> None:
    page = FakePage()
    page.elements["#editor"] = FakeLocator("div", {"contenteditable": "true"})
    adapter = PlaywrightTab(cast(Page, page))
    await adapter.fill("#editor", "editable")
    assert page.elements["#editor"].value == "editable"
    with pytest.raises(BrowserDenied):
        await adapter.read_text("#editor")


class FakeContext:
    def __init__(self) -> None:
        self.page = FakePage()
        self.closed = False
        self.config: dict[str, Any] = {}
        self.hooks: list[str] = []

    async def route(self, pattern: str, callback: Any) -> None:
        self.hooks.append("route")

    async def route_web_socket(self, pattern: str, callback: Any) -> None:
        self.hooks.append("websocket")

    async def new_page(self) -> Page:
        self.hooks.append("page")
        return cast(Page, self.page)

    def on(self, name: str, callback: Any) -> None:
        self.hooks.append(name)

    async def close(self) -> None:
        self.closed = True


class FakeBrowser:
    def __init__(self, context: FakeContext) -> None:
        self.context = context
        self.closed = False

    async def new_context(self, **kwargs: Any) -> FakeContext:
        self.context.config = kwargs
        return self.context

    async def close(self) -> None:
        self.closed = True


class FakePlaywright:
    def __init__(self, browser: FakeBrowser) -> None:
        self.browser = browser
        self.chromium = SimpleNamespace(launch=self.launch)
        self.stopped = False

    async def launch(self, *, headless: bool) -> FakeBrowser:
        assert headless
        return self.browser

    async def stop(self) -> None:
        self.stopped = True


class FakeStarter:
    def __init__(self, implementation: FakePlaywright) -> None:
        self.implementation = implementation

    async def start(self) -> FakePlaywright:
        return self.implementation


@pytest.mark.anyio
async def test_isolated_context_lifecycle_disables_downloads_and_service_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = FakeContext()
    browser = FakeBrowser(context)
    fake = FakePlaywright(browser)
    monkeypatch.setattr("local_gpt_mcp.browser.playwright_driver.async_playwright", lambda: FakeStarter(fake))
    controller = BrowserController(SessionBroker(PolicyAuthority()))
    runtime = IsolatedBrowserSession("https://example.com", controller, headless=True)
    async with runtime:
        assert len(controller.selected_tabs()) == 1
        assert context.config["accept_downloads"] is False
        assert context.config["service_workers"] == "block"
        assert context.config["permissions"] == []
        assert context.hooks == ["route", "websocket", "page", "page"]
    assert browser.closed and context.closed and fake.stopped
