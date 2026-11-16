"""MCP caller sessions and replay protection; no implicit device authority."""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from local_gpt_mcp.policy import (
    Caller,
    Capability,
    GrantRequest,
    PairingRequest,
    PolicyAuthority,
)

NONCE = re.compile(r"^[a-fA-F0-9]{32,64}$")
SESSION_SECONDS = 300
MAX_ACTIVE = 8
MAX_REQUESTS_PER_MINUTE = 30


class SessionDenied(PermissionError):
    """An unauthenticated, expired or replayed session operation was rejected."""


@dataclass(slots=True)
class _Session:
    caller: Caller
    expires: float
    nonces: set[str] = field(default_factory=set)
    request_times: deque[float] = field(default_factory=deque)
    grants: set[str] = field(default_factory=set)


class SessionBroker:
    """Authenticates scoped MCP requests before delegating to local policy."""

    def __init__(
        self,
        policy: PolicyAuthority,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy = policy
        self._clock = clock
        self._sessions: dict[str, _Session] = {}
        self._attempts: deque[float] = deque()
        self._pair_nonces: set[str] = set()
        self._lock = threading.RLock()

    def _clean(self, now: float) -> None:
        for token, session in list(self._sessions.items()):
            if now >= session.expires:
                for grant in session.grants:
                    self._policy.revoke(grant)
                del self._sessions[token]

    def open(self, user_id: str, device_id: str, nonce: str) -> dict[str, str | int]:
        """Pair through the local prompt; never from a model-generated approval."""
        with self._lock:
            now = self._clock()
            self._clean(now)
            while self._attempts and self._attempts[0] <= now - 60:
                self._attempts.popleft()
            if len(self._attempts) >= 3 or len(self._sessions) >= MAX_ACTIVE:
                raise SessionDenied("pairing attempts limited")
            self._attempts.append(now)
            if not isinstance(nonce, str) or not NONCE.fullmatch(nonce) or nonce in self._pair_nonces:
                raise SessionDenied("invalid or repeated pairing nonce")
            self._pair_nonces.add(nonce)
            # A new grant must never be authorized while a stop is active.
            if self._policy.stopped:
                raise SessionDenied("local authority stopped")
            # Hold the local broker lock across the approval: another pairing
            # attempt cannot race this one and exceed the session count.
            self._policy.pair(PairingRequest(user_id, device_id))
            session_id = secrets.token_hex(24)
            bearer = secrets.token_urlsafe(32)
            self._sessions[bearer] = _Session(
                Caller(user_id, device_id, session_id), self._clock() + SESSION_SECONDS
            )
            return {"session_id": session_id, "session_token": bearer, "expires_in": SESSION_SECONDS}

    def _require(self, token: str, nonce: str) -> _Session:
        now = self._clock()
        self._clean(now)
        if self._policy.stopped:
            raise SessionDenied("local authority stopped")
        if not isinstance(token, str) or token not in self._sessions:
            raise SessionDenied("unknown session")
        session = self._sessions[token]
        if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
            raise SessionDenied("invalid request nonce")
        if nonce in session.nonces:
            raise SessionDenied("replayed request")
        session.nonces.add(nonce)
        if len(session.nonces) > 128:
            raise SessionDenied("session nonce budget exhausted; pair again")
        while session.request_times and session.request_times[0] <= now - 60:
            session.request_times.popleft()
        if len(session.request_times) >= MAX_REQUESTS_PER_MINUTE:
            raise SessionDenied("session rate limit")
        session.request_times.append(now)
        return session

    def status(self, token: str, nonce: str) -> dict[str, bool | int]:
        with self._lock:
            session = self._require(token, nonce)
            return {
                "paired": True,
                "stopped": False,
                "expires_in": max(0, int(session.expires - self._clock())),
            }

    def request_grant(
        self, token: str, nonce: str, target: str, capabilities: frozenset[Capability], ttl: int
    ) -> dict[str, str | int]:
        with self._lock:
            session = self._require(token, nonce)
            remaining = int(session.expires - self._clock())
            if remaining <= 0:
                raise SessionDenied("session expired")
            grant = self._policy.issue(
                GrantRequest(session.caller, target, capabilities, min(ttl, remaining))
            )
            session.grants.add(grant)
            return {"grant_token": grant, "expires_in": min(ttl, remaining)}

    def revoke_grant(self, token: str, nonce: str, grant: str) -> None:
        with self._lock:
            session = self._require(token, nonce)
            if grant not in session.grants:
                raise SessionDenied("grant does not belong to this session")
            session.grants.remove(grant)
            self._policy.revoke(grant)

    def close(self, token: str, nonce: str) -> None:
        with self._lock:
            session = self._require(token, nonce)
            for grant in session.grants:
                self._policy.revoke(grant)
            del self._sessions[token]

    def stop(self, token: str, nonce: str) -> None:
        with self._lock:
            self._require(token, nonce)
            self._policy.emergency_stop()
            self._sessions.clear()

    def authorize_grant(
        self, session_token: str, nonce: str, grant_token: str, target: str, capability: Capability
    ) -> None:
        """Future adapters must call this before each *actual* device action."""
        with self._lock:
            session = self._require(session_token, nonce)
            if grant_token not in session.grants:
                raise SessionDenied("grant does not belong to this session")
            self._policy.authorize(grant_token, session.caller, target, capability)
