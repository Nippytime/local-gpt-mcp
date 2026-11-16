"""Approved workflow adapter to existing native and browser controllers.

Controllers enforce session nonce, grant, target identity and scope themselves.
No generic shell, unrestricted UI automation, or file access is exposed.
"""

from __future__ import annotations

import asyncio

from local_gpt_mcp.browser import BrowserController
from local_gpt_mcp.desktop import DesktopController
from local_gpt_mcp.orchestrator.models import Action, Condition, SessionGrants, Step


class ScopedDriver:
    def __init__(
        self,
        *,
        browser: BrowserController | None = None,
        desktop: DesktopController | None = None,
    ) -> None:
        self._browser = browser
        self._desktop = desktop

    def _require_browser(self) -> BrowserController:
        if self._browser is None:
            raise PermissionError("Browser adapter not locally enabled")
        return self._browser

    def _require_desktop(self) -> DesktopController:
        if self._desktop is None:
            raise PermissionError("Desktop adapter not locally enabled")
        return self._desktop

    @staticmethod
    def _handle(step: Step) -> int:
        return int(step.target.removeprefix("window:"))

    async def condition(self, step: Step, condition: object, credentials: SessionGrants, nonce: str) -> bool:
        if not isinstance(condition, Condition):
            raise PermissionError("Unexpected workflow condition")
        if step.action.value.startswith("browser."):
            value = await self._require_browser().read(
                credentials.session_token,
                nonce,
                credentials.read_grant,
                step.target,
                condition.selector,
            )
        else:
            if condition.selector != "title":
                raise PermissionError("Windows workflow conditions only inspect window title")
            window = await asyncio.to_thread(
                self._require_desktop().describe,
                credentials.session_token,
                nonce,
                credentials.read_grant,
                self._handle(step),
            )
            value = window.title
        return condition.contains in value

    async def perform(self, step: Step, credentials: SessionGrants, nonce: str) -> str:
        session = credentials.session_token
        if step.action.value.startswith("browser."):
            browser = self._require_browser()
            if step.action == Action.BROWSER_READ:
                return await browser.read(session, nonce, credentials.read_grant, step.target, step.selector)
            if step.action == Action.BROWSER_NAVIGATE:
                return await browser.navigate(session, nonce, credentials.input_grant, step.target, step.text)
            if step.action == Action.BROWSER_CLICK:
                await browser.click(session, nonce, credentials.input_grant, step.target, step.selector)
            elif step.action == Action.BROWSER_FILL:
                await browser.fill(
                    session, nonce, credentials.input_grant, step.target, step.selector, step.text
                )
            elif step.action == Action.BROWSER_SCROLL:
                await browser.scroll(session, nonce, credentials.input_grant, step.target, step.amount)
            else:
                raise PermissionError("Unsupported browser workflow action")
            return ""
        desktop = self._require_desktop()
        handle = self._handle(step)
        if step.action == Action.DESKTOP_INFO:
            window = await asyncio.to_thread(desktop.describe, session, nonce, credentials.read_grant, handle)
            return window.title
        if step.action == Action.DESKTOP_CLICK:
            if step.x is None or step.y is None:
                raise PermissionError("Coordinates were not validated")
            await asyncio.to_thread(
                desktop.click, session, nonce, credentials.input_grant, handle, step.x, step.y
            )
        elif step.action == Action.DESKTOP_TYPE:
            await asyncio.to_thread(
                desktop.type_text, session, nonce, credentials.input_grant, handle, step.text
            )
        elif step.action == Action.DESKTOP_SCROLL:
            await asyncio.to_thread(
                desktop.scroll, session, nonce, credentials.input_grant, handle, step.amount
            )
        elif step.action == Action.DESKTOP_KEY:
            await asyncio.to_thread(
                desktop.press_key, session, nonce, credentials.input_grant, handle, step.text
            )
        else:
            raise PermissionError("Unsupported desktop workflow action")
        return ""
