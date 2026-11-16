"""Bounded cross-thread local-approval queue. No remote approval path."""

from __future__ import annotations

import queue
import secrets
import threading
from dataclasses import dataclass, field


@dataclass(slots=True)
class LocalApprovalRequest:
    heading: str
    details: str
    challenge: str = field(default_factory=lambda: secrets.token_hex(3).upper())
    done: threading.Event = field(default_factory=threading.Event)
    approved: bool = False


class ApprovalInbox:
    """Only the local UI may respond; request threads cannot self-approve."""

    def __init__(self) -> None:
        self._queue: queue.Queue[LocalApprovalRequest] = queue.Queue(maxsize=8)
        self._waiting: list[LocalApprovalRequest] = []
        self._lock = threading.Lock()
        self._running = False

    def start(self) -> None:
        with self._lock:
            self._running = True

    def request(self, heading: str, details: str, *, timeout: float = 45.0) -> bool:
        pending = LocalApprovalRequest(heading[:100], details[:400])
        with self._lock:
            if not self._running:
                return False
            try:
                self._queue.put_nowait(pending)
            except queue.Full:
                return False
            self._waiting.append(pending)
        pending.done.wait(timeout)
        with self._lock:
            if pending in self._waiting:
                self._waiting.remove(pending)
            if not pending.done.is_set():
                pending.approved = False
                pending.done.set()
            return pending.approved

    def take(self) -> LocalApprovalRequest | None:
        while True:
            try:
                pending = self._queue.get_nowait()
            except queue.Empty:
                return None
            with self._lock:
                if self._running and pending in self._waiting and not pending.done.is_set():
                    return pending

    def respond(self, pending: LocalApprovalRequest, entered: str) -> bool:
        with self._lock:
            if not self._running or pending not in self._waiting or pending.done.is_set():
                return False
            pending.approved = secrets.compare_digest(
                entered.strip(), f"APPROVE {pending.challenge}"
            )
            pending.done.set()
            return pending.approved

    def stop(self) -> None:
        with self._lock:
            self._running = False
            for pending in self._waiting:
                pending.approved = False
                pending.done.set()
            self._waiting.clear()
