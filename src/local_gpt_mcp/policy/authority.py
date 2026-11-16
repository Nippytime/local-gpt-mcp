"""In-process policy authority. Callers cannot self-authorize.

The approval provider must be implemented by a trusted *local* UI in a later slice.
No device or browser operations are implemented in this module.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Protocol
from urllib.parse import urlsplit

MAX_TTL_SECONDS = 600
IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
WINDOW_TARGET = re.compile(r"^window:([1-9][0-9]*)$")


class Capability(StrEnum):
    WINDOW_READ = "window.read"
    WINDOW_INPUT = "window.input"
    BROWSER_READ = "browser.read"
    BROWSER_INPUT = "browser.input"


class AccessDenied(PermissionError):
    """An approval or scoped action was rejected without disclosing secrets."""


@dataclass(frozen=True, slots=True)
class PairingRequest:
    user_id: str
    device_id: str


@dataclass(frozen=True, slots=True)
class Caller:
    user_id: str
    device_id: str
    session_id: str


@dataclass(frozen=True, slots=True)
class GrantRequest:
    caller: Caller
    target: str
    capabilities: frozenset[Capability]
    ttl_seconds: int


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Does not include bearer tokens, target URLs, typed text or credentials."""

    operation: str
    result: str
    reason: str


class LocalApproval(Protocol):
    """Implemented ONLY by a trusted local interactive UI, never an MCP tool."""

    def approve_pairing(self, request: PairingRequest) -> bool: ...

    def approve_grant(self, request: GrantRequest) -> bool: ...


class DenyAllApproval:
    def approve_pairing(self, request: PairingRequest) -> bool:
        return False

    def approve_grant(self, request: GrantRequest) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class _Grant:
    caller: Caller
    target: str
    capabilities: frozenset[Capability]
    expires_at: float


def valid_identifier(value: str) -> bool:
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def valid_target(target: str, capabilities: frozenset[Capability]) -> bool:
    if not isinstance(target, str) or not isinstance(capabilities, frozenset) or not capabilities:
        return False
    if not all(isinstance(capability, Capability) for capability in capabilities):
        return False
    if WINDOW_TARGET.fullmatch(target):
        return all(value in {Capability.WINDOW_READ, Capability.WINDOW_INPUT} for value in capabilities)
    try:
        parts = urlsplit(target)
        port = parts.port
    except ValueError:
        return False
    # Browser grants are exact HTTPS origins, never credential-bearing URLs.
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        return False
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        return False
    if parts.netloc != parts.hostname and parts.netloc != f"{parts.hostname}:{port}":
        return False
    return all(value in {Capability.BROWSER_READ, Capability.BROWSER_INPUT} for value in capabilities)


class PolicyAuthority:
    """Locally-owned consent and grant store with atomic revocation checks."""

    def __init__(
        self,
        approval: LocalApproval | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._approval = approval if approval is not None else DenyAllApproval()
        self._clock = clock
        self._pairings: set[PairingRequest] = set()
        self._grants: dict[str, _Grant] = {}
        self._events: deque[AuditEvent] = deque(maxlen=500)
        self._lock = threading.RLock()
        self._stopped = threading.Event()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

    @property
    def stopped(self) -> bool:
        return self._stopped.is_set()

    def _record(self, operation: str, result: str, reason: str) -> None:
        self._events.append(AuditEvent(operation, result, reason))

    def _deny(self, operation: str, reason: str) -> None:
        self._record(operation, "denied", reason)
        raise AccessDenied(f"{operation} denied: {reason}")

    def pair(self, request: PairingRequest) -> None:
        if not valid_identifier(request.user_id) or not valid_identifier(request.device_id):
            with self._lock:
                self._deny("pair", "invalid identity")
        with self._lock:
            if self._stopped.is_set():
                self._deny("pair", "stopped")
        approved = self._approval.approve_pairing(request)
        with self._lock:
            if self._stopped.is_set():
                self._deny("pair", "stopped")
            if not approved:
                self._deny("pair", "local approval required")
            self._pairings.add(request)
            self._record("pair", "allowed", "local approval")

    def issue(self, request: GrantRequest) -> str:
        caller = request.caller
        if not all(valid_identifier(value) for value in (caller.user_id, caller.device_id, caller.session_id)):
            with self._lock:
                self._deny("grant", "invalid identity")
        if type(request.ttl_seconds) is not int or not 0 < request.ttl_seconds <= MAX_TTL_SECONDS:
            with self._lock:
                self._deny("grant", "invalid duration")
        if not valid_target(request.target, request.capabilities):
            with self._lock:
                self._deny("grant", "invalid scope")
        pairing = PairingRequest(caller.user_id, caller.device_id)
        with self._lock:
            if self._stopped.is_set():
                self._deny("grant", "stopped")
            if pairing not in self._pairings:
                self._deny("grant", "unpaired")
        approved = self._approval.approve_grant(request)
        with self._lock:
            if self._stopped.is_set() or pairing not in self._pairings:
                self._deny("grant", "revoked")
            if not approved:
                self._deny("grant", "local approval required")
            token = secrets.token_urlsafe(32)
            self._grants[token] = _Grant(caller, request.target, request.capabilities, self._clock() + request.ttl_seconds)
            self._record("grant", "allowed", "local approval")
            return token

    def authorize(self, token: str, caller: Caller, target: str, capability: Capability) -> None:
        """Check immediately before EACH device action; never cache a permit."""
        with self._lock:
            if not isinstance(token, str):
                self._deny("authorize", "invalid token")
            if self._stopped.is_set():
                self._deny("authorize", "stopped")
            grant = self._grants.get(token)
            if grant is None:
                self._deny("authorize", "unknown or revoked grant")
            if self._clock() >= grant.expires_at:
                del self._grants[token]
                self._deny("authorize", "expired")
            if grant.caller != caller:
                self._deny("authorize", "caller mismatch")
            if grant.target != target or capability not in grant.capabilities:
                self._deny("authorize", "scope mismatch")
            if PairingRequest(caller.user_id, caller.device_id) not in self._pairings:
                self._deny("authorize", "unpaired")
            self._record("authorize", "allowed", "scope approved")

    def revoke(self, token: str) -> None:
        with self._lock:
            self._grants.pop(token, None)
            self._record("revoke", "allowed", "session grant invalidated")

    def revoke_pairing(self, request: PairingRequest) -> None:
        with self._lock:
            self._pairings.discard(request)
            for token, grant in list(self._grants.items()):
                if (grant.caller.user_id, grant.caller.device_id) == (request.user_id, request.device_id):
                    del self._grants[token]
            self._record("revoke", "allowed", "pairing invalidated")

    def emergency_stop(self) -> None:
        """Set cancellation first; then invalidate all authority permanently."""
        self._stopped.set()
        with self._lock:
            self._pairings.clear()
            self._grants.clear()
            self._record("stop", "allowed", "all authority revoked")
