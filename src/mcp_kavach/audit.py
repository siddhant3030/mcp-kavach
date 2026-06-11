"""Audit sinks. Events never contain raw values — only hmac_value() ever
touches plaintext, and it returns a salted HMAC."""

from __future__ import annotations

import hashlib
import hmac
from typing import Protocol, runtime_checkable

from mcp_kavach.models import AuditEvent


@runtime_checkable
class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class InMemorySink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def hmac_value(salt: bytes, value: str) -> str:
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
