"""Exact connection-time DNS selection rejects unsafe or mixed responses."""

from __future__ import annotations

import socket

import pytest

from local_gpt_mcp.browser.controller import BrowserDenied
from local_gpt_mcp.browser.safe_fetch import public_addresses


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
    def resolve(
        *args: object, **kwargs: object
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [
            (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
            for address in addresses
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    if expected:
        assert len(public_addresses("approved.example.com", 443)) == len(addresses)
    else:
        with pytest.raises(BrowserDenied):
            public_addresses("approved.example.com", 443)


def test_unavailable_dns_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> list[object]:
        raise socket.gaierror("resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(BrowserDenied):
        public_addresses("approved.example.com", 443)
