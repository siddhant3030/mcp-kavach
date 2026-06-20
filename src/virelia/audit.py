"""Audit sinks. Events never contain raw values — only hmac_value() ever
touches plaintext, and it returns a salted HMAC."""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from pathlib import Path
from typing import Protocol, runtime_checkable

from virelia.models import AuditEvent

# Column order shared by the SQL sinks and the CLI readers.
COLUMNS = (
    "ts",
    "policy",
    "tool",
    "direction",
    "entity_type",
    "tier",
    "confidence",
    "rule_id",
    "action",
    "json_path",
    "span_start",
    "span_end",
    "value_hmac",
)

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS audit_events (
    id {pk},
    ts TEXT NOT NULL,
    policy TEXT NOT NULL,
    tool TEXT NOT NULL,
    direction TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    tier INTEGER NOT NULL,
    confidence REAL NOT NULL,
    rule_id TEXT,
    action TEXT NOT NULL,
    json_path TEXT NOT NULL,
    span_start INTEGER NOT NULL,
    span_end INTEGER NOT NULL,
    value_hmac TEXT NOT NULL
)"""

_CREATE_INDEXES = tuple(
    f"CREATE INDEX IF NOT EXISTS idx_audit_{name} ON audit_events ({column})"
    for name, column in (
        ("ts", "ts"),
        ("entity", "entity_type"),
        ("action", "action"),
        ("tool", "tool"),
    )
)


def event_row(event: AuditEvent) -> tuple:
    """Event as a tuple in COLUMNS order (timestamps as ISO-8601 text)."""
    return (
        event.ts.isoformat(),
        event.policy,
        event.tool,
        event.direction,
        event.entity_type,
        event.tier,
        event.confidence,
        event.rule_id,
        event.action.value,
        event.json_path,
        event.start,
        event.end,
        event.value_hmac,
    )


def event_from_row(row: tuple) -> AuditEvent:
    """Inverse of event_row(); pydantic coerces the ISO timestamp and action."""
    data = dict(zip(COLUMNS, row, strict=True))
    data["start"] = data.pop("span_start")
    data["end"] = data.pop("span_end")
    return AuditEvent(**data)


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


class SqliteSink:
    """SQLite sink (stdlib sqlite3). WAL mode plus a busy timeout lets several
    short-lived hook processes append to the same file safely."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, timeout=5)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(_CREATE_TABLE.format(pk="INTEGER PRIMARY KEY AUTOINCREMENT"))
        for stmt in _CREATE_INDEXES:
            self._conn.execute(stmt)
        self._conn.commit()

    def emit(self, event: AuditEvent) -> None:
        placeholders = ", ".join("?" * len(COLUMNS))
        self._conn.execute(
            f"INSERT INTO audit_events ({', '.join(COLUMNS)}) VALUES ({placeholders})",
            event_row(event),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


class PostgresSink:
    """Postgres sink behind the [postgres] extra. Deliberately thin: one table
    created with IF NOT EXISTS, no migrations framework."""

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
        except ImportError as err:
            raise ImportError(
                "PostgresSink requires psycopg — install with: pip install 'virelia[postgres]'"
            ) from err
        self._conn = psycopg.connect(dsn, autocommit=True)
        with self._conn.cursor() as cur:
            cur.execute(_CREATE_TABLE.format(pk="BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY"))
            for stmt in _CREATE_INDEXES:
                cur.execute(stmt)

    def emit(self, event: AuditEvent) -> None:
        placeholders = ", ".join(["%s"] * len(COLUMNS))
        with self._conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO audit_events ({', '.join(COLUMNS)}) VALUES ({placeholders})",
                event_row(event),
            )

    def close(self) -> None:
        self._conn.close()


def detect_backend(destination: str | Path) -> str:
    """'postgres', 'sqlite', or 'jsonl' from the shape of the destination."""
    dest = str(destination)
    if dest.startswith(("postgres://", "postgresql://")):
        return "postgres"
    if dest.endswith((".db", ".sqlite", ".sqlite3")):
        return "sqlite"
    return "jsonl"


def open_sink(destination: str | Path) -> AuditSink:
    """Pick a sink from a destination: a postgres:// URL, a .db/.sqlite path,
    or (the default) a JSONL file path."""
    backend = detect_backend(destination)
    if backend == "postgres":
        return PostgresSink(str(destination))
    if backend == "sqlite":
        return SqliteSink(destination)
    return JsonlSink(destination)


def hmac_value(salt: bytes, value: str) -> str:
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
