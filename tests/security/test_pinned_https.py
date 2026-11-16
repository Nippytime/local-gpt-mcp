"""Routed HTTPS must connect to a validated IP, not re-resolve after approval."""

from __future__ import annotations

import socket
import ssl
from typing import Any, cast

import pytest

from local_gpt_mcp.browser.controller import BrowserDenied
from local_gpt_mcp.browser.safe_fetch import PinnedHTTPSConnection, fetch_public_https


class FakeSocket:
    def __init__(self) -> None:
        self.destination: tuple[str, int] | None = None
        self.timeout: object = None
        self.closed = False

    def settimeout(self, value: object) -> None:
        self.timeout = value

    def connect(self, destination: tuple[str, int]) -> None:
        self.destination = destination

    def close(self) -> None:
        self.closed = True


class FakeTLS:
    post_handshake_auth = False

    def __init__(self) -> None:
        self.server_hostname = ""

    def wrap_socket(self, connection: Any, *, server_hostname: str) -> Any:
        self.server_hostname = server_hostname
        return connection


def test_actual_tcp_socket_uses_approved_ip_and_tls_original_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = [0]
    channel = FakeSocket()
    tls = FakeTLS()

    def resolve(*args: object, **kwargs: object) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        calls[0] += 1
        ip = "93.184.215.14" if calls[0] == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", lambda *args: channel)
    conn = PinnedHTTPSConnection(
        "approved.example.com", port=443, timeout=8, context=cast(ssl.SSLContext, tls)
    )
    conn.connect()
    assert calls == [1], "Do not resolve hostname again between validation and connection"
    assert channel.destination == ("93.184.215.14", 443)
    assert tls.server_hostname == "approved.example.com"
    conn.close()


def test_private_address_never_opens_network_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    opened = [False]

    def resolve(*args: object, **kwargs: object) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]

    def socket_factory(*args: object) -> FakeSocket:
        opened[0] = True
        return FakeSocket()

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", socket_factory)
    connection = PinnedHTTPSConnection("approved.example.com", port=443, timeout=8)
    with pytest.raises(BrowserDenied):
        connection.connect()
    assert not opened[0]


class FakeHTTPResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.length = len(body)
        self.body = body

    def read(self, maximum: int) -> bytes:
        return self.body[:maximum]

    def getheaders(self) -> list[tuple[str, str]]:
        return [
            ("Content-Type", "text/plain"),
            ("Location", "https://127.0.0.1/unsafe"),
            ("Connection", "keep-alive"),
        ]


class FakeConnection:
    def __init__(self, status: int, body: bytes) -> None:
        self.requested: tuple[str, str, dict[str, str]] | None = None
        self.status = status
        self.body = body
        self.closed = False

    def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
        self.requested = method, path, headers

    def getresponse(self) -> FakeHTTPResponse:
        return FakeHTTPResponse(self.status, self.body)

    def close(self) -> None:
        self.closed = True


def test_https_forwarding_strips_untrusted_headers_and_caps_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = FakeConnection(200, b"OK")
    monkeypatch.setattr(
        "local_gpt_mcp.browser.safe_fetch.PinnedHTTPSConnection", lambda *a, **k: channel
    )
    result = fetch_public_https(
        "https://example.com/path?name=one",
        "https://example.com",
        "GET",
        {"Host": "127.0.0.1", "Connection": "keep-alive", "Accept": "text/plain"},
    )
    assert result.status == 200 and result.body == b"OK"
    assert result.headers == {"content-type": "text/plain"}
    assert channel.requested == ("GET", "/path?name=one", {"Accept": "text/plain"})
    assert channel.closed


@pytest.mark.parametrize(
    "url,method",
    [
        ("https://other.example.com/path", "GET"),
        ("http://example.com/", "GET"),
        ("https://example.com/path", "POST"),
        ("https://example.com/path", "PUT"),
        ("https://user:password@example.com/", "GET"),
        ("https://127.0.0.1/internal", "GET"),
        ("https://example.com/\r\nHeader: injected", "GET"),
    ],
)
def test_outbound_request_scope_fails_before_socket(url: str, method: str) -> None:
    with pytest.raises(BrowserDenied):
        fetch_public_https(url, "https://example.com", method, {})


@pytest.mark.parametrize("status,size", [(302, 0), (307, 0), (200, 4_000_001)])
def test_redirect_and_oversized_response_are_blocked(
    monkeypatch: pytest.MonkeyPatch, status: int, size: int
) -> None:
    channel = FakeConnection(status, b"x" * size)
    monkeypatch.setattr(
        "local_gpt_mcp.browser.safe_fetch.PinnedHTTPSConnection", lambda *a, **k: channel
    )
    with pytest.raises(BrowserDenied):
        fetch_public_https("https://example.com/", "https://example.com", "GET", {})
    assert channel.closed
