"""Core data models shared across the engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel

PathTuple = tuple  # tuple[str | int, ...] — concrete path of a JSON leaf


class Action(str, Enum):
    ALLOW = "allow"
    PARTIAL_MASK = "partial_mask"
    MASK = "mask"
    REDACT = "redact"
    BLOCK = "block"


# When overlapping spans resolve to different actions, the highest severity wins.
SEVERITY: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.PARTIAL_MASK: 1,
    Action.MASK: 2,
    Action.REDACT: 3,
    Action.BLOCK: 4,
}


@dataclass(frozen=True)
class Span:
    """A detected entity within a single leaf string.

    Offsets are codepoint indices into the leaf's text (str(value) for
    non-string leaves), never into a serialized document.
    """

    start: int
    end: int
    entity_type: str
    confidence: float
    tier: int
    detector: str


@dataclass(frozen=True)
class Finding:
    """A span bound to its leaf path with the policy decision applied."""

    span: Span
    path: PathTuple
    resolved_action: Action
    rule_id: str | None  # None ⇒ resolved via defaults.unknown_entity_action


class AuditEvent(BaseModel):
    """What gets recorded about a detection. Never holds the raw value —
    only a salted HMAC, so the log is safe to show to anyone who can see
    the redacted output."""

    ts: datetime
    policy: str
    tool: str
    direction: Literal["request", "result"]
    entity_type: str
    tier: int
    confidence: float
    rule_id: str | None
    action: Action
    json_path: str
    start: int
    end: int
    value_hmac: str


@dataclass
class GuardrailResult:
    payload: Any
    blocked: bool = False
    block_reason: str | None = None
    events: list[AuditEvent] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return self.blocked or any(e.action != Action.ALLOW for e in self.events)
