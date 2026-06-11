"""Audit sinks. Events never contain raw values — only hmac_value() ever
touches plaintext, and it returns a salted HMAC."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
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


class JsonlSink:
    """Append-only JSON-lines sink. O_APPEND keeps short concurrent writes
    from interleaving, so multiple hook processes can share one file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: AuditEvent) -> None:
        line = event.model_dump_json() + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)


def hmac_value(salt: bytes, value: str) -> str:
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
