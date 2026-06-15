"""`kavach audit` subcommands: report (aggregate the hash-only log) and tail
(stream events live). Reads the same destinations the sinks write — JSONL,
SQLite, or Postgres — picked by the same auto-detection as open_sink()."""

from __future__ import annotations

import sqlite3
import sys
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from mcp_kavach.audit import (
    COLUMNS,
    LEGACY_COLUMNS,
    detect_backend,
    event_from_json,
    event_from_row,
)
from mcp_kavach.models import Action, AuditEvent, FlowEvent

_POLL_SECONDS = 0.5
_SELECT = f"SELECT id, {', '.join(COLUMNS)} FROM audit_events"
# Databases written before flow events existed lack the flow columns.
_SELECT_LEGACY = f"SELECT id, {', '.join(LEGACY_COLUMNS)} FROM audit_events"

Event = AuditEvent | FlowEvent


def default_source() -> str:
    """Where the hooks write by default — honours KAVACH_AUDIT / config.yaml."""
    from mcp_kavach.hooks.config import load_config
    from mcp_kavach.hooks.runner import data_dir

    return load_config().audit or str(data_dir() / "audit.jsonl")


def parse_when(value: str) -> datetime:
    """ISO date or datetime; naive values are taken as UTC."""
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- readers


def _iter_jsonl(path: Path) -> Iterator[Event]:
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield event_from_json(line)
            except ValueError:
                continue  # tolerate a torn/foreign line rather than die mid-report


def _iter_sqlite(path: Path) -> Iterator[Event]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        try:
            rows = conn.execute(_SELECT + " ORDER BY id")
        except sqlite3.OperationalError:  # pre-flow schema: detection columns only
            rows = conn.execute(_SELECT_LEGACY + " ORDER BY id")
        for row in rows:
            yield event_from_row(row[1:])
    finally:
        conn.close()


def _iter_postgres(dsn: str) -> Iterator[Event]:
    import psycopg  # [postgres] extra

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        try:
            cur.execute(_SELECT + " ORDER BY id")
        except psycopg.errors.UndefinedColumn:  # pre-flow schema
            conn.rollback()
            cur.execute(_SELECT_LEGACY + " ORDER BY id")
        for row in cur:
            yield event_from_row(tuple(row[1:]))


def iter_events(
    source: str,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    policy: str | None = None,
) -> Iterator[Event]:
    backend = detect_backend(source)
    if backend == "postgres":
        events = _iter_postgres(source)
    elif backend == "sqlite":
        events = _iter_sqlite(Path(source))
    else:
        events = _iter_jsonl(Path(source))
    for event in events:
        ts = _aware(event.ts)
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        if policy and event.policy != policy:
            continue
        yield event


# ---------------------------------------------------------------- report


@dataclass
class Report:
    total: int = 0  # detection events only, as before flow events existed
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    by_entity: dict[str, Counter] = field(default_factory=dict)
    by_action: Counter = field(default_factory=Counter)
    by_tool: Counter = field(default_factory=Counter)
    flows_total: int = 0
    flows_clean: int = 0
    flows_by_tool: Counter = field(default_factory=Counter)

    def add(self, event: Event) -> None:
        ts = _aware(event.ts)
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts
        if isinstance(event, FlowEvent):
            self.flows_total += 1
            self.flows_clean += event.clean
            self.flows_by_tool[event.tool] += 1
            return
        self.total += 1
        self.by_entity.setdefault(event.entity_type, Counter())[event.action.value] += 1
        self.by_action[event.action.value] += 1
        self.by_tool[event.tool] += 1


def aggregate(events: Iterator[Event]) -> Report:
    report = Report()
    for event in events:
        report.add(event)
    return report


def _table(header: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(str(r[i])) for r in [header, *rows]) for i in range(len(header))]
    lines = []
    for row in [header, *rows]:
        cells = [
            str(c).ljust(w) if i == 0 else str(c).rjust(w)
            for i, (c, w) in enumerate(zip(row, widths, strict=True))
        ]
        lines.append("  ".join(cells).rstrip())
    return "\n".join(lines)


def render_report(report: Report, source: str) -> str:
    if report.total == 0 and report.flows_total == 0:
        return f"no audit events found in {source}"
    span = ""
    if report.first_ts and report.last_ts:
        fmt = "%Y-%m-%d %H:%M"
        span = (
            f" · {report.first_ts.strftime(fmt)} → "
            f"{report.last_ts.strftime(fmt)} UTC"
        )
    out = [f"audit report — {source}", f"{report.total} events{span}"]
    if report.flows_total:  # only present when traffic monitoring was on
        flagged = report.flows_total - report.flows_clean
        pct = 100 * flagged / report.flows_total
        out.append(
            f"traffic: {report.flows_total} payloads seen · "
            f"{report.flows_clean} clean · {flagged} flagged ({pct:.0f}%)"
        )
    out.append("")

    actions = [a.value for a in Action if report.by_action.get(a.value)]
    entity_rows = [
        [entity, str(sum(counts.values()))] + [str(counts.get(a, 0)) for a in actions]
        for entity, counts in sorted(
            report.by_entity.items(), key=lambda kv: -sum(kv[1].values())
        )
    ]
    out.append(_table(["ENTITY", "EVENTS", *(a.upper() for a in actions)], entity_rows))
    out.append("")
    out.append(
        _table(
            ["ACTION", "EVENTS"],
            [[a, str(n)] for a, n in report.by_action.most_common()],
        )
    )
    out.append("")
    out.append(
        _table(
            ["TOOL", "EVENTS"],
            [[t, str(n)] for t, n in report.by_tool.most_common()],
        )
    )
    return "\n".join(out)


def run_report(
    source: str | None,
    since: str | None,
    until: str | None,
    policy: str | None,
) -> int:
    src = source or default_source()
    backend = detect_backend(src)
    if backend != "postgres" and not Path(src).exists():
        print(f"no audit events found in {src}")
        return 0
    report = aggregate(
        iter_events(
            src,
            since=parse_when(since) if since else None,
            until=parse_when(until) if until else None,
            policy=policy,
        )
    )
    print(render_report(report, src))
    return 0


# ---------------------------------------------------------------- tail


def format_flow(event: FlowEvent) -> str:
    ts = _aware(event.ts).strftime("%Y-%m-%dT%H:%M:%SZ")
    status = "clean"
    if event.findings_count:
        s = "s" if event.findings_count > 1 else ""
        status = f"{event.findings_count} finding{s}: {','.join(event.actions)}"
    return (
        f"{ts}  {event.direction:<12} {event.tool:<24} "
        f"{event.payload_chars:>7} ch  {status}"
    )


def format_event(event: Event) -> str:
    if isinstance(event, FlowEvent):
        return format_flow(event)
    ts = _aware(event.ts).strftime("%Y-%m-%dT%H:%M:%SZ")
    rule = event.rule_id or "(default)"
    return (
        f"{ts}  {event.action.value:<12} {event.entity_type:<16} "
        f"{event.tool:<24} {event.direction:<8} {rule}"
    )


def _tail_jsonl(path: Path) -> Iterator[Event]:
    existed = path.exists()
    while not path.exists():
        time.sleep(_POLL_SECONDS)
    with path.open(encoding="utf-8") as f:
        if existed:
            f.seek(0, 2)  # only events that land after we start
        buf = ""
        while True:
            chunk = f.readline()
            if not chunk:
                time.sleep(_POLL_SECONDS)
                continue
            buf += chunk
            if not buf.endswith("\n"):
                continue  # torn write: wait for the rest of the line
            line, buf = buf.strip(), ""
            if not line:
                continue
            try:
                yield event_from_json(line)
            except ValueError:
                continue


def _tail_sqlite(path: Path) -> Iterator[Event]:
    existed = path.exists()
    while not path.exists():
        time.sleep(_POLL_SECONDS)
    conn = sqlite3.connect(path, timeout=5)
    try:
        last = 0
        if existed:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM audit_events").fetchone()
            last = row[0]
        while True:
            try:
                rows = conn.execute(_SELECT + " WHERE id > ? ORDER BY id", (last,)).fetchall()
            except sqlite3.OperationalError as err:
                if "no such column" in str(err):  # pre-flow schema: legacy columns only
                    rows = conn.execute(
                        _SELECT_LEGACY + " WHERE id > ? ORDER BY id", (last,)
                    ).fetchall()
                else:  # file just created, table not there yet
                    time.sleep(_POLL_SECONDS)
                    continue
            for row in rows:
                last = row[0]
                yield event_from_row(row[1:])
            if not rows:
                time.sleep(_POLL_SECONDS)
    finally:
        conn.close()


def _tail_postgres(dsn: str) -> Iterator[Event]:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(id), 0) FROM audit_events")
        last = cur.fetchone()[0]
        select = _SELECT
        while True:
            try:
                cur.execute(select + " WHERE id > %s ORDER BY id", (last,))
            except psycopg.errors.UndefinedColumn:  # pre-flow schema
                select = _SELECT_LEGACY
                cur.execute(select + " WHERE id > %s ORDER BY id", (last,))
            rows = cur.fetchall()
            for row in rows:
                last = row[0]
                yield event_from_row(tuple(row[1:]))
            if not rows:
                time.sleep(_POLL_SECONDS)


def _tail_source(src: str) -> Iterator[Event]:
    backend = detect_backend(src)
    tails = {"postgres": _tail_postgres, "sqlite": _tail_sqlite, "jsonl": _tail_jsonl}
    return tails[backend](src if backend == "postgres" else Path(src))


def run_tail(source: str | None) -> int:
    src = source or default_source()
    print(f"tailing {src} — Ctrl-C to stop", file=sys.stderr)
    try:
        for event in _tail_source(src):
            print(format_event(event), flush=True)
    except KeyboardInterrupt:
        pass
    return 0


# ---------------------------------------------------------------- monitor


@dataclass
class MonitorStats:
    seen: int = 0
    clean: int = 0
    by_tool: Counter = field(default_factory=Counter)

    def add(self, event: FlowEvent) -> None:
        self.seen += 1
        self.clean += event.clean
        self.by_tool[event.tool] += 1

    def summary(self) -> str:
        if self.seen == 0:
            return "no traffic seen — is monitoring on? (monitor: true / --monitor)"
        flagged = self.seen - self.clean
        pct = 100 * flagged / self.seen
        lines = [
            f"{self.seen} payloads · {self.clean} clean · {flagged} flagged ({pct:.0f}%)",
            "",
            _table(
                ["TOOL", "PAYLOADS"],
                [[t, str(n)] for t, n in self.by_tool.most_common()],
            ),
        ]
        return "\n".join(lines)


def run_monitor(source: str | None, summary_every: int = 25) -> int:
    """Live traffic view: one line per flow event, summary every N events
    and a final one on Ctrl-C. Detection events are skipped — `kavach audit
    tail` already shows those."""
    src = source or default_source()
    stats = MonitorStats()
    print(f"monitoring {src} — Ctrl-C to stop", file=sys.stderr)
    try:
        for event in _tail_source(src):
            if not isinstance(event, FlowEvent):
                continue
            stats.add(event)
            print(format_flow(event), flush=True)
            if summary_every and stats.seen % summary_every == 0:
                print(f"-- {stats.summary().splitlines()[0]}", flush=True)
    except KeyboardInterrupt:
        print(f"\n{stats.summary()}")
    return 0
