"""Async MCP browser authority and strict origin-scoped tab contracts."""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from local_gpt_mcp.pairing import SessionBroker
from local_gpt_mcp.policy import Capability
from local_gpt_mcp.policy.authority import valid_target

MAX_SCREENSHOT_BYTES = 4_000_000
MAX_TEXT_LENGTH = 2048
MAX_FILL_LENGTH = 256
MAX_SELECTOR_LENGTH = 160


class BrowserDenied(PermissionError):
    """Browser origin, scope, sensitive field or operation was rejected."""


def origin_of(url: str) -> str:
    """Return an exact public HTTPS origin; reject local/private network targets."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise BrowserDenied("Invalid browser origin") from error
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or host.endswith((".", ".local", ".internal"))
        or host == "localhost"
        or "." not in host
        or port not in (None, 443)
    ):
        raise BrowserDenied("Only public HTTPS origins are allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise BrowserDenied("Private network origins are prohibited")
    return f"https://{host}" + (f":{port}" if port else "")


def approved_origin(value: str) -> str:
    origin = origin_of(value)
    if value != origin or not valid_target(origin, frozenset({Capability.BROWSER_READ})):
        raise BrowserDenied("A local allowlist entry must be an exact HTTPS origin")
    return origin


class BrowserPage(Protocol):
    @property
    def url(self) -> str: ...

    async def navigate(self, url: str) -> None: ...

    async def read_text(self, selector: str) -> str: ...

    async def click(self, selector: str) -> None: ...

    async def fill(self, selector: str, text: str) -> None: ...

    async def scroll(self, steps: int) -> None: ...

    async def screenshot(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class TabInfo:
    tab_id: str
    origin: str


class BrowserController:
    """Binds application-issued grants to fixed locally selected isolated tabs."""

    def __init__(self, broker: SessionBroker) -> None:
        self._broker = broker
        self._tabs: dict[str, tuple[str, BrowserPage]] = {}
        self._lock = asyncio.Lock()

    def attach_local(self, origin: str, page: BrowserPage) -> TabInfo:
        """Called by trusted local browser setup, never an MCP tool."""
        origin = approved_origin(origin)
        if self._tabs:
            raise BrowserDenied("Only one locally selected tab is supported")
        tab_id = secrets.token_hex(16)
        self._tabs[tab_id] = (origin, page)
        return TabInfo(tab_id, origin)

    def selected_tabs(self) -> tuple[TabInfo, ...]:
        """Local UI only; requires no remote metadata discovery endpoint."""
        return tuple(TabInfo(tab_id, origin) for tab_id, (origin, _) in self._tabs.items())

    def _authorized(
        self,
        session: str,
        nonce: str,
        grant: str,
        tab_id: str,
        capability: Capability,
        *,
        allow_blank: bool = False,
    ) -> tuple[str, BrowserPage]:
        if not isinstance(tab_id, str) or tab_id not in self._tabs:
            raise BrowserDenied("Tab was not locally selected")
        origin, page = self._tabs[tab_id]
        self._broker.authorize_grant(session, nonce, grant, origin, capability)
        if not allow_blank or page.url != "about:blank":
            if origin_of(page.url) != origin:
                raise BrowserDenied("Tab navigated outside its approved origin")
        return origin, page

    @staticmethod
    def _selector(selector: str) -> str:
        if (
            not isinstance(selector, str)
            or not 0 < len(selector) <= MAX_SELECTOR_LENGTH
            or any(char in selector for char in "\n\r\x00")
        ):
            raise BrowserDenied("Invalid bounded CSS selector")
        return selector

    async def navigate(self, session: str, nonce: str, grant: str, tab_id: str, url: str) -> str:
        if not isinstance(url, str) or len(url) > 2048:
            raise BrowserDenied("Invalid navigation URL")
        async with self._lock:
            origin, page = self._authorized(
                session, nonce, grant, tab_id, Capability.BROWSER_INPUT, allow_blank=True
            )
            if origin_of(url) != origin:
                raise BrowserDenied("Navigation outside approved origin")
            await page.navigate(url)
            if origin_of(page.url) != origin:
                raise BrowserDenied("Navigation redirected outside approved origin")
            return page.url[:2048]

    async def read(self, session: str, nonce: str, grant: str, tab_id: str, selector: str) -> str:
        selector = self._selector(selector)
        async with self._lock:
            origin, page = self._authorized(session, nonce, grant, tab_id, Capability.BROWSER_READ)
            value = await page.read_text(selector)
            if origin_of(page.url) != origin:
                raise BrowserDenied("Tab changed origin during reading")
            return value[:MAX_TEXT_LENGTH]

    async def click(self, session: str, nonce: str, grant: str, tab_id: str, selector: str) -> None:
        selector = self._selector(selector)
        async with self._lock:
            origin, page = self._authorized(session, nonce, grant, tab_id, Capability.BROWSER_INPUT)
            await page.click(selector)
            if origin_of(page.url) != origin:
                raise BrowserDenied("Click changed the approved origin")

    async def fill(self, session: str, nonce: str, grant: str, tab_id: str, selector: str, text: str) -> None:
        selector = self._selector(selector)
        if not isinstance(text, str) or not 0 < len(text) <= MAX_FILL_LENGTH or not text.isprintable():
            raise BrowserDenied("Text must be 1–256 printable characters")
        async with self._lock:
            origin, page = self._authorized(session, nonce, grant, tab_id, Capability.BROWSER_INPUT)
            await page.fill(selector, text)
            if origin_of(page.url) != origin:
                raise BrowserDenied("Tab changed origin during editing")

    async def scroll(self, session: str, nonce: str, grant: str, tab_id: str, steps: int) -> None:
        if type(steps) is not int or steps == 0 or abs(steps) > 3:
            raise BrowserDenied("Scroll must be between -3 and 3 steps")
        async with self._lock:
            origin, page = self._authorized(session, nonce, grant, tab_id, Capability.BROWSER_INPUT)
            await page.scroll(steps)
            if origin_of(page.url) != origin:
                raise BrowserDenied("Tab changed origin during scrolling")

    async def capture(self, session: str, nonce: str, grant: str, tab_id: str) -> bytes:
        async with self._lock:
            origin, page = self._authorized(session, nonce, grant, tab_id, Capability.BROWSER_READ)
            image = await page.screenshot()
            if origin_of(page.url) != origin or not 0 < len(image) <= MAX_SCREENSHOT_BYTES:
                raise BrowserDenied("Capture unavailable or exceeded limit")
            return image
