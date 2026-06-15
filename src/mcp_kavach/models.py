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
    TOKENIZE = "tokenize"
    REDACT = "redact"
    BLOCK = "block"


# When overlapping spans resolve to different actions, the highest severity wins.
# tokenize sits above mask: both hide every plaintext character, but a token
# additionally preserves the value in the vault, so on a conflict nothing is
# lost by choosing it. redact and block stay above tokenize — they exist to
# hide even the entity type or the whole payload, and a *reversible* token
# must never override an explicitly irreversible action.
SEVERITY: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.PARTIAL_MASK: 1,
    Action.MASK: 2,
    Action.TOKENIZE: 3,
    Action.REDACT: 4,
    Action.BLOCK: 5,
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

    event_kind: Literal["detection"] = "detection"
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


class FlowEvent(BaseModel):
    """One event per payload crossing toward the model — emitted (opt-in)
    whether or not anything was detected, so the log answers "what has the
    model been seeing?" and not just "what did we catch?".

    `payload_masked` is only set when masked-payload capture is enabled and
    only ever holds the POST-transform payload — exactly what the model saw,
    never the original. A blocked payload stores only the block marker."""

    event_kind: Literal["flow"] = "flow"
    ts: datetime
    policy: str
    tool: str
    direction: Literal["prompt", "tool_input", "tool_output"]
    payload_chars: int
    leaf_count: int
    findings_count: int
    actions: tuple[str, ...] = ()  # unique actions applied; empty = clean
    payload_masked: str | None = None

    @property
    def clean(self) -> bool:
        return self.findings_count == 0


@dataclass
class GuardrailResult:
    payload: Any
    blocked: bool = False
    block_reason: str | None = None
    events: list[AuditEvent] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return self.blocked or any(e.action != Action.ALLOW for e in self.events)
