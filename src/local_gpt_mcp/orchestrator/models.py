"""Small immutable action plan schema; no arbitrary code or shell execution."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Literal

IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
MAX_STEPS = 8
SAFE_ATTEMPTS = 2


class Action(StrEnum):
    BROWSER_READ = "browser.read"
    BROWSER_NAVIGATE = "browser.navigate"
    BROWSER_CLICK = "browser.click"
    BROWSER_FILL = "browser.fill"
    BROWSER_SCROLL = "browser.scroll"
    DESKTOP_INFO = "desktop.info"
    DESKTOP_CLICK = "desktop.click"
    DESKTOP_TYPE = "desktop.type"
    DESKTOP_SCROLL = "desktop.scroll"
    DESKTOP_KEY = "desktop.key"


READ_ONLY = frozenset({Action.BROWSER_READ, Action.DESKTOP_INFO})
BROWSER_ACTIONS = frozenset(a for a in Action if a.value.startswith("browser."))
DESKTOP_ACTIONS = frozenset(a for a in Action if a.value.startswith("desktop."))


@dataclass(frozen=True, slots=True)
class Condition:
    """Browser text or Windows title must contain this exact substring."""

    selector: str
    contains: str

    def __post_init__(self) -> None:
        if not self.selector or len(self.selector) > 160 or any(c in self.selector for c in "\n\r\x00"):
            raise ValueError("Condition selector must be bounded and printable")
        if not self.contains or len(self.contains) > 160 or not self.contains.isprintable():
            raise ValueError("Condition expected text must be bounded and printable")


@dataclass(frozen=True, slots=True)
class Step:
    step_id: str
    action: Action
    target: str
    selector: str = ""
    text: str = ""
    x: int | None = None
    y: int | None = None
    amount: int = 0
    before: Condition | None = None
    after: Condition | None = None

    def __post_init__(self) -> None:
        if not IDENTIFIER.fullmatch(self.step_id):
            raise ValueError("Invalid workflow step ID")
        if not isinstance(self.action, Action):
            raise ValueError("Unknown workflow action")
        if not isinstance(self.target, str) or not 0 < len(self.target) <= 128:
            raise ValueError("Invalid window or browser tab target")
        if any(c in self.target for c in "\r\n\x00"):
            raise ValueError("Invalid target")
        if self.action in BROWSER_ACTIONS:
            if not self.target.isascii() or not IDENTIFIER.fullmatch(self.target):
                raise ValueError("Browser tab ID must be locally issued")
        else:
            if not re.fullmatch(r"window:[1-9][0-9]*", self.target):
                raise ValueError("Desktop target must be an exact positive HWND")
        if self.action in {Action.BROWSER_READ, Action.BROWSER_CLICK, Action.BROWSER_FILL}:
            if not 0 < len(self.selector) <= 160 or any(c in self.selector for c in "\r\n\x00"):
                raise ValueError("Browser selector required")
        elif self.selector:
            raise ValueError("Unexpected selector")
        if self.action in {
            Action.BROWSER_FILL,
            Action.BROWSER_NAVIGATE,
            Action.DESKTOP_TYPE,
            Action.DESKTOP_KEY,
        }:
            max_len = 2048 if self.action == Action.BROWSER_NAVIGATE else 256
            if not 0 < len(self.text) <= max_len or not self.text.isprintable():
                raise ValueError("Invalid input text")
        elif self.text:
            raise ValueError("Unexpected action text")
        if self.action == Action.DESKTOP_CLICK:
            if type(self.x) is not int or type(self.y) is not int:
                raise ValueError("Desktop click needs integer coordinates")
        elif self.x is not None or self.y is not None:
            raise ValueError("Unexpected coordinates")
        if self.action in {Action.BROWSER_SCROLL, Action.DESKTOP_SCROLL}:
            if type(self.amount) is not int or self.amount == 0 or abs(self.amount) > 3:
                raise ValueError("Scroll is limited to 1–3 steps")
        elif self.amount != 0:
            raise ValueError("Unexpected scroll amount")
        if self.before is not None and not isinstance(self.before, Condition):
            raise ValueError("Invalid precondition")
        if self.after is not None and not isinstance(self.after, Condition):
            raise ValueError("Invalid postcondition")
        if self.action in READ_ONLY and self.after is not None:
            raise ValueError("Read-only steps do not need postconditions")


@dataclass(frozen=True, slots=True)
class WorkflowPlan:
    plan_id: str
    steps: tuple[Step, ...]

    def __post_init__(self) -> None:
        if not IDENTIFIER.fullmatch(self.plan_id):
            raise ValueError("Invalid plan identifier")
        if not 0 < len(self.steps) <= MAX_STEPS:
            raise ValueError("Plans must contain 1–8 steps")
        if any(not isinstance(step, Step) for step in self.steps):
            raise ValueError("Every plan entry must be a validated Step")
        if len({step.step_id for step in self.steps}) != len(self.steps):
            raise ValueError("Workflow step IDs must be unique")

    def digest(self) -> str:
        """Checkpoint only this digest, never operation payloads or credentials."""
        payload = {
            "plan_id": self.plan_id,
            "steps": [asdict(step) for step in self.steps],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SessionGrants:
    """Ephemeral, never written to checkpoints or audit logs."""

    session_token: str
    read_grant: str
    input_grant: str


@dataclass(frozen=True, slots=True)
class Checkpoint:
    plan_digest: str
    index: int
    state: Literal["ready", "started", "uncertain", "complete"]

    def __post_init__(self) -> None:
        if len(self.plan_digest) != 64 or not re.fullmatch(r"[0-9a-f]{64}", self.plan_digest):
            raise ValueError("Invalid checkpoint plan hash")
        if type(self.index) is not int or self.index < 0:
            raise ValueError("Invalid checkpoint index")
        if self.state not in {"ready", "started", "uncertain", "complete"}:
            raise ValueError("Invalid checkpoint state")
