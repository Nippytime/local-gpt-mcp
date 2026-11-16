"""Bounded HTTPS transport: validate DNS addresses and connect to the approved IP.

Unlike a DNS preflight followed by a fresh hostname resolution, this transport
uses the exact validated sockaddr for TCP and the original hostname for TLS
certificate verification and SNI. No implicit proxies or redirect following.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from local_gpt_mcp.browser.controller import BrowserDenied, origin_of

MAX_RESPONSE_BYTES = 4_000_000
MAX_URL_BYTES = 4096
SAFE_REQUEST_HEADERS = frozenset(
    {"accept", "accept-language", "user-agent", "cookie", "if-none-match", "if-modified-since"}
)
SAFE_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "content-encoding",
        "content-language",
        "cache-control",
        "etag",
        "last-modified",
        "set-cookie",
        "content-security-policy",
    }
)


def public_addresses(host: str, port: int) -> list[tuple[int, int, int, str, tuple[str, int]]]:
    """Reject the entire DNS answer if ANY address is not publicly routable."""
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not addresses or any(
            address[0] not in {socket.AF_INET, socket.AF_INET6}
            or not ipaddress.ip_address(address[4][0]).is_global
            for address in addresses
        ):
            raise BrowserDenied("DNS returned an unsafe destination")
        return addresses
    except (OSError, ValueError, IndexError) as error:
        raise BrowserDenied("Cannot verify a public destination") from error


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TCP uses validated IP, TLS verifies the requested original hostname."""

    def connect(self) -> None:
        addresses = public_addresses(self.host, self.port)
        family, socktype, proto, _, sockaddr = addresses[0]
        channel = socket.socket(family, socktype, proto)
        try:
            channel.settimeout(self.timeout)
            channel.connect(sockaddr)
            self.sock = self._context.wrap_socket(channel, server_hostname=self.host)
        except BaseException:
            channel.close()
            raise


@dataclass(frozen=True, slots=True)
class PinnedResponse:
    status: int
    headers: dict[str, str]
    body: bytes


def fetch_public_https(
    url: str, allowed_origin: str, method: str, request_headers: dict[str, str]
) -> PinnedResponse:
    """Resolve/validate/connect once for a bounded GET/HEAD to one approved origin."""
    if (
        not isinstance(url, str)
        or len(url) > MAX_URL_BYTES
        or any(ord(char) < 32 or ord(char) == 127 for char in url)
        or method not in {"GET", "HEAD"}
        or origin_of(url) != allowed_origin
    ):
        raise BrowserDenied("Network request exceeds its approved scope")
    parsed = urlsplit(url)
    host = parsed.hostname
    if host is None:
        raise BrowserDenied("Missing HTTPS destination")
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = {
        key: value
        for key, value in request_headers.items()
        if key.lower() in SAFE_REQUEST_HEADERS
        and isinstance(value, str)
        and not any(ord(char) < 32 and char != "\t" for char in value)
    }
    connection = PinnedHTTPSConnection(host, port=port, timeout=8, context=ssl.create_default_context())
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise BrowserDenied("Unapproved network redirect")
        if response.length is not None and response.length > MAX_RESPONSE_BYTES:
            raise BrowserDenied("Network response exceeds size limit")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise BrowserDenied("Network response exceeds size limit")
        accepted: dict[str, str] = {}
        for name, value in response.getheaders():
            if name.lower() in SAFE_RESPONSE_HEADERS:
                accepted[name.lower()] = value
        return PinnedResponse(response.status, accepted, body)
    except (OSError, http.client.HTTPException, ssl.SSLError) as error:
        raise BrowserDenied("Verified HTTPS request failed") from error
    finally:
        connection.close()
