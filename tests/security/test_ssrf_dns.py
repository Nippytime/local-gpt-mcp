"""DNS resolution must not point an approved public host into private services."""

from __future__ import annotations

import socket

import pytest

from local_gpt_mcp.browser.playwright_driver import _public_dns


@pytest.mark.parametrize(
    "addresses,expected",
    [
        (["93.184.215.14"], True),
        (["2001:4860:4860::8888"], True),
        (["93.184.215.14", "127.0.0.1"], False),
        (["10.0.0.8"], False),
        (["192.168.1.20"], False),
        (["169.254.169.254"], False),
        (["::1"], False),
        (["fe80::1"], False),
        ([], False),
    ],
)
def test_public_dns_rejects_all_non_global_addresses(
    monkeypatch: pytest.MonkeyPatch, addresses: list[str], expected: bool
) -> None:
    def resolve(*args: object, **kwargs: object) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [(0, 0, 0, "", (address, 443)) for address in addresses]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    assert _public_dns("approved.example.com") is expected


def test_unavailable_dns_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> list[object]:
        raise socket.gaierror("resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert not _public_dns("approved.example.com")
