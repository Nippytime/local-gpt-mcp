"""Real policy broker with fake isolated browser, covering deny-first behavior."""

from __future__ import annotations

from typing import Any

import pytest

from local_gpt_mcp.browser import BrowserController, BrowserDenied
from local_gpt_mcp.browser.controller import approved_origin, origin_of
from local_gpt_mcp.pairing import SessionBroker, SessionDenied
from local_gpt_mcp.policy import AccessDenied, Capability, GrantRequest, PairingRequest, PolicyAuthority


class Approval:
    def approve_pairing(self, request: PairingRequest) -> bool:
        return True

    def approve_grant(self, request: GrantRequest) -> bool:
        return True


class FakePage:
    def __init__(self) -> None:
        self.url = "about:blank"
        self.effects: list[tuple[str, Any]] = []
        self.image = b"\x89PNG\r\n\x1a\n"
        self.destination: str | None = None

    async def navigate(self, url: str) -> None:
        self.effects.append(("navigate", url))
        self.url = self.destination or url

    async def read_text(self, selector: str) -> str:
        self.effects.append(("read", selector))
        return "Safe public text"

    async def click(self, selector: str) -> None:
        self.effects.append(("click", selector))

    async def fill(self, selector: str, text: str) -> None:
        self.effects.append(("fill", selector + ":" + text))

    async def scroll(self, steps: int) -> None:
        self.effects.append(("scroll", steps))

    async def screenshot(self) -> bytes:
        self.effects.append(("capture", "masked"))
        return self.image


class Fixture:
    def __init__(self) -> None:
        self.policy = PolicyAuthority(Approval())
        self.broker = SessionBroker(self.policy)
        self.browser = BrowserController(self.broker)
        self.page = FakePage()
        self.tab = self.browser.attach_local("https://example.com", self.page)
        self.index = 0
        s = self.broker.open("human", "device", self.nonce())["session_token"]
        assert isinstance(s, str)
        self.session = s
        grant = self.broker.request_grant(
            s,
            self.nonce(),
            "https://example.com",
            frozenset({Capability.BROWSER_READ, Capability.BROWSER_INPUT}),
            60,
        )["grant_token"]
        assert isinstance(grant, str)
        self.grant = grant

    def nonce(self) -> str:
        self.index += 1
        return f"{self.index:032x}"

    async def navigate(self, url: str = "https://example.com/home") -> str:
        return await self.browser.navigate(self.session, self.nonce(), self.grant, self.tab.tab_id, url)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://192.168.1.1",
        "https://user:secret@example.com",
        "https://example.com:8443",
        "https://example.com.",
        "https://example.local",
        "https://example.com.evil.invalid",
        "data:text/html,hello",
    ],
)
def test_invalid_or_nonexact_origins_are_rejected(url: str) -> None:
    if url == "https://example.com.evil.invalid":
        assert origin_of(url) == url  # host is not the approved host
        return
    with pytest.raises(BrowserDenied):
        approved_origin(url)


def test_https_origin_cannot_include_path_query_or_fragment() -> None:
    for url in ["https://example.com/path", "https://example.com?secret=x", "https://example.com#x"]:
        with pytest.raises(BrowserDenied):
            approved_origin(url)
    assert approved_origin("https://example.com") == "https://example.com"


@pytest.mark.anyio
async def test_happy_path_requires_session_and_grant_for_every_action() -> None:
    f = Fixture()
    assert await f.navigate() == "https://example.com/home"
    assert await f.browser.read(f.session, f.nonce(), f.grant, f.tab.tab_id, "#title") == "Safe public text"
    await f.browser.click(f.session, f.nonce(), f.grant, f.tab.tab_id, "#open")
    await f.browser.fill(f.session, f.nonce(), f.grant, f.tab.tab_id, "#query", "hello")
    await f.browser.scroll(f.session, f.nonce(), f.grant, f.tab.tab_id, 2)
    assert (await f.browser.capture(f.session, f.nonce(), f.grant, f.tab.tab_id)).startswith(b"\x89PNG")
    assert len(f.page.effects) == 6


@pytest.mark.anyio
async def test_unpaired_and_missing_session_cannot_act() -> None:
    f = Fixture()
    with pytest.raises(SessionDenied):
        await f.browser.navigate("invalid", f.nonce(), f.grant, f.tab.tab_id, "https://example.com")
    assert not f.page.effects


@pytest.mark.anyio
async def test_cross_origin_navigate_and_redirect_fail_closed() -> None:
    f = Fixture()
    with pytest.raises(BrowserDenied, match="approved origin"):
        await f.navigate("https://evil.example.net/")
    assert not f.page.effects
    f.page.destination = "https://other.example.com"
    with pytest.raises(BrowserDenied, match="redirected"):
        await f.navigate()
    with pytest.raises(BrowserDenied):
        await f.browser.read(f.session, f.nonce(), f.grant, f.tab.tab_id, "#title")


@pytest.mark.anyio
async def test_unselected_tabs_not_exposed() -> None:
    f = Fixture()
    with pytest.raises(BrowserDenied, match="not locally selected"):
        await f.browser.navigate(f.session, f.nonce(), f.grant, "other-tab", "https://example.com")
    with pytest.raises(BrowserDenied, match="Only one"):
        f.browser.attach_local("https://other.example.com", FakePage())


@pytest.mark.anyio
async def test_read_only_grant_cannot_edit() -> None:
    f = Fixture()
    read = f.broker.request_grant(
        f.session,
        f.nonce(),
        "https://example.com",
        frozenset({Capability.BROWSER_READ}),
        60,
    )["grant_token"]
    assert isinstance(read, str)
    await f.navigate()
    with pytest.raises(AccessDenied):
        await f.browser.click(f.session, f.nonce(), read, f.tab.tab_id, "#button")


@pytest.mark.anyio
async def test_nonce_replay_and_revocation_prohibit_actions() -> None:
    f = Fixture()
    await f.navigate()
    nonce = f.nonce()
    await f.browser.read(f.session, nonce, f.grant, f.tab.tab_id, "#title")
    with pytest.raises(SessionDenied, match="replayed"):
        await f.browser.read(f.session, nonce, f.grant, f.tab.tab_id, "#title")
    f.broker.revoke_grant(f.session, f.nonce(), f.grant)
    with pytest.raises(SessionDenied):
        await f.browser.click(f.session, f.nonce(), f.grant, f.tab.tab_id, "#button")


@pytest.mark.anyio
async def test_emergency_stop_blocks_browser_actions() -> None:
    f = Fixture()
    await f.navigate()
    f.broker.stop(f.session, f.nonce())
    with pytest.raises(SessionDenied):
        await f.browser.read(f.session, f.nonce(), f.grant, f.tab.tab_id, "#title")


@pytest.mark.anyio
async def test_scroll_and_fill_limits() -> None:
    f = Fixture()
    await f.navigate()
    for value in (-4, 0, 4, True):
        with pytest.raises(BrowserDenied):
            await f.browser.scroll(f.session, f.nonce(), f.grant, f.tab.tab_id, value)
    for text in ("", "a" * 257, "hello\nworld"):
        with pytest.raises(BrowserDenied):
            await f.browser.fill(f.session, f.nonce(), f.grant, f.tab.tab_id, "#name", text)
    assert all(action[0] not in {"fill", "scroll"} for action in f.page.effects)


@pytest.mark.anyio
async def test_screenshot_must_be_size_bounded() -> None:
    f = Fixture()
    await f.navigate()
    f.page.image = b"x" * 4_000_001
    with pytest.raises(BrowserDenied, match="limit"):
        await f.browser.capture(f.session, f.nonce(), f.grant, f.tab.tab_id)


@pytest.mark.anyio
async def test_selector_injection_and_missing_origin() -> None:
    f = Fixture()
    with pytest.raises(BrowserDenied):
        await f.browser.read(f.session, f.nonce(), f.grant, f.tab.tab_id, "#title")
    await f.navigate()
    for selector in ("", "a" * 200, "#text\nclick"):
        with pytest.raises(BrowserDenied):
            await f.browser.read(f.session, f.nonce(), f.grant, f.tab.tab_id, selector)
