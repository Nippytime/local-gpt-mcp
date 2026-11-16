"""Ephemeral Playwright Chromium context with strict network and content limits."""

from __future__ import annotations

import asyncio
import re
from typing import Self

from playwright.async_api import (
    Browser,
    BrowserContext,
    Locator,
    Page,
    Playwright,
    Route,
    WebSocketRoute,
    async_playwright,
)
from playwright.async_api import Error as PlaywrightError

from local_gpt_mcp.browser.controller import (
    BrowserController,
    BrowserDenied,
    approved_origin,
    origin_of,
)

SENSITIVE = re.compile(r"password|passcode|otp|one.time|credit|card|cvv|cvc|ssn|secret|token|api.key", re.I)


class PlaywrightTab:
    """Only public, visible text and non-sensitive controls are exposed."""

    def __init__(self, page: Page) -> None:
        self._page = page

    @property
    def url(self) -> str:
        return self._page.url

    async def navigate(self, url: str) -> None:
        await self._page.goto(url, wait_until="domcontentloaded", timeout=10_000)

    async def _element(self, selector: str, *, edit: bool = False) -> Locator:
        locator = self._page.locator(selector)
        if await locator.count() != 1 or not await locator.is_visible():
            raise BrowserDenied("A single visible element is required")
        if not await locator.is_enabled():
            raise BrowserDenied("The selected element is disabled")
        tag = str(await locator.evaluate("(element) => element.tagName.toLowerCase()"))
        kind = (await locator.get_attribute("type") or "").lower()
        name = await locator.get_attribute("name") or ""
        identifier = await locator.get_attribute("id") or ""
        auto = await locator.get_attribute("autocomplete") or ""
        editable = (await locator.get_attribute("contenteditable") or "").lower() == "true"
        if kind in {"password", "hidden", "file", "submit", "reset"}:
            raise BrowserDenied("Protected or consequential form control")
        if SENSITIVE.search(" ".join((name, identifier, auto))):
            raise BrowserDenied("Sensitive form control")
        if edit:
            if tag not in {"input", "textarea"} and not editable:
                raise BrowserDenied("A visible editable control is required")
        elif tag in {"input", "textarea", "select"} or editable:
            raise BrowserDenied("Reading editable field values is prohibited")
        # Clicking inside forms can submit consequential actions; deny by default.
        if not edit and (tag == "button" or kind == "button"):
            if bool(await locator.evaluate("(element) => Boolean(element.closest('form'))")):
                raise BrowserDenied("Form submission requires a separate approval workflow")
        return locator

    async def read_text(self, selector: str) -> str:
        element = await self._element(selector)
        return (await element.inner_text(timeout=5000)).strip()

    async def click(self, selector: str) -> None:
        element = await self._element(selector)
        await element.click(timeout=5000, no_wait_after=True)

    async def fill(self, selector: str, text: str) -> None:
        element = await self._element(selector, edit=True)
        await element.fill(text, timeout=5000, no_wait_after=True)

    async def scroll(self, steps: int) -> None:
        await self._page.mouse.wheel(0, steps * 240)

    async def screenshot(self) -> bytes:
        return await self._page.screenshot(
            type="png",
            full_page=False,
            animations="disabled",
            mask=[self._page.locator("input, textarea, select, [contenteditable]")],
        )


class IsolatedBrowserSession:
    """One new temporary browser context, without existing user cookies or files."""

    def __init__(self, origin: str, controller: BrowserController, *, headless: bool = False) -> None:
        self._origin = approved_origin(origin)
        self._controller = controller
        self._headless = headless
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self.context: BrowserContext | None = None

    async def _network(self, route: Route) -> None:
        try:
            allowed = origin_of(route.request.url) == self._origin
        except BrowserDenied:
            allowed = False
        if not allowed:
            await route.abort("blockedbyclient")
            return
        # Route.continue_ follows redirect chains without re-interception.
        # Fetch without following redirects; reject all 3xx responses before
        # Chromium can contact any second URL.
        try:
            response = await route.fetch(max_redirects=0, timeout=10_000)
            if 300 <= response.status < 400:
                await route.abort("blockedbyclient")
            else:
                await route.fulfill(response=response)
        except PlaywrightError:
            await route.abort("failed")

    @staticmethod
    async def _websocket(ws: WebSocketRoute) -> None:
        # No WebSocket connections in this initial browser automation slice.
        await ws.close(code=1008, reason="WebSockets disabled")

    @staticmethod
    def _close_popup(page: Page) -> None:
        # Popups may otherwise obtain an unmanaged tab outside the selected scope.
        asyncio.create_task(page.close())

    async def __aenter__(self) -> Self:
        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.launch(headless=self._headless)
            self.context = await self._browser.new_context(
                accept_downloads=False,
                service_workers="block",
                permissions=[],
                ignore_https_errors=False,
                java_script_enabled=True,
            )
            await self.context.route("**/*", self._network)
            await self.context.route_web_socket("**/*", self._websocket)
            page = await self.context.new_page()
            self.context.on("page", self._close_popup)
            self._controller.attach_local(self._origin, PlaywrightTab(page))
            return self
        except BaseException:
            await self.__aexit__(None, None, None)
            raise

    async def __aexit__(self, *_: object) -> None:
        if self.context is not None:
            await self.context.close()
            self.context = None
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None
