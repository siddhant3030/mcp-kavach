"""Audit sinks (JSONL/SQLite/Postgres), source auto-detection, and the
`virelia audit report` aggregation/CLI."""

import sqlite3
from datetime import datetime, timezone

import pytest

from virelia.audit import (
    JsonlSink,
    PostgresSink,
    SqliteSink,
    detect_backend,
    event_from_row,
    event_row,
    open_sink,
)
from virelia.cli.audit import aggregate, format_event, iter_events, parse_when, render_report
from virelia.cli.main import main
from virelia.models import Action, AuditEvent


def make_event(**overrides) -> AuditEvent:
    base = dict(
        ts=datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc),
        policy="personal",
        tool="mcp__gmail__search",
        direction="result",
        entity_type="email",
        tier=1,
        confidence=0.95,
        rule_id="email-default",
        action=Action.MASK,
        json_path="$.messages[0].from",
        start=3,
        end=22,
        value_hmac="ab" * 32,
    )
    base.update(overrides)
    return AuditEvent(**base)


FIXTURE = [
    make_event(),
    make_event(entity_type="email", tool="UserPromptSubmit", direction="request"),
    make_event(
        entity_type="aadhaar",
        action=Action.BLOCK,
        rule_id=None,
        ts=datetime(2026, 1, 15, 8, 30, tzinfo=timezone.utc),
    ),
    make_event(
        entity_type="phone_in",
        action=Action.REDACT,
        policy="strict",
        ts=datetime(2026, 4, 2, 9, 0, tzinfo=timezone.utc),
    ),
]


class TestDetectBackend:
    def test_postgres_urls(self):
        assert detect_backend("postgres://u:p@host/db") == "postgres"
        assert detect_backend("postgresql://host/db") == "postgres"

    def test_sqlite_paths(self):
        for suffix in (".db", ".sqlite", ".sqlite3"):
            assert detect_backend(f"/tmp/audit{suffix}") == "sqlite"

    def test_everything_else_is_jsonl(self):
        assert detect_backend("/tmp/audit.jsonl") == "jsonl"
        assert detect_backend("/tmp/audit.log") == "jsonl"

    def test_open_sink_picks_matching_class(self, tmp_path):
        assert isinstance(open_sink(tmp_path / "a.jsonl"), JsonlSink)
        assert isinstance(open_sink(tmp_path / "a.db"), SqliteSink)


class TestRoundTrips:
    def test_jsonl(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        sink = JsonlSink(path)
        for event in FIXTURE:
            sink.emit(event)
        assert list(iter_events(str(path))) == FIXTURE

    def test_sqlite(self, tmp_path):
        path = tmp_path / "audit.db"
        sink = SqliteSink(path)
        for event in FIXTURE:
            sink.emit(event)
        sink.close()
        assert list(iter_events(str(path))) == FIXTURE

    def test_sqlite_has_indexes_and_wal(self, tmp_path):
        path = tmp_path / "audit.db"
        sink = SqliteSink(path)
        sink.emit(FIXTURE[0])
        conn = sqlite3.connect(path)
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"idx_audit_ts", "idx_audit_entity", "idx_audit_action", "idx_audit_tool"} <= names
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        conn.close()
        sink.close()

    def test_event_row_round_trip(self):
        for event in FIXTURE:
            assert event_from_row(event_row(event)) == event

    def test_no_plaintext_in_sqlite_file(self, tmp_path):
        """The audit DB must only ever hold metadata and HMACs."""
        path = tmp_path / "audit.db"
        sink = SqliteSink(path)
        sink.emit(make_event(value_hmac="cd" * 32))
        sink.close()
        blob = path.read_bytes()
        assert b"lakshmi@example.org" not in blob  # nothing ever passed plaintext in
        assert b"cd" * 32 in blob


class TestReport:
    def test_aggregation_counts(self):
        report = aggregate(iter(FIXTURE))
        assert report.total == 4
        assert report.by_entity["email"][Action.MASK.value] == 2
        assert report.by_entity["aadhaar"][Action.BLOCK.value] == 1
        assert report.by_action == {"mask": 2, "block": 1, "redact": 1}
        assert report.by_tool["mcp__gmail__search"] == 3
        assert report.by_tool["UserPromptSubmit"] == 1
        assert report.first_ts == datetime(2026, 1, 15, 8, 30, tzinfo=timezone.utc)
        assert report.last_ts == datetime(2026, 4, 2, 9, 0, tzinfo=timezone.utc)

    def test_since_until_policy_filters(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        sink = JsonlSink(path)
        for event in FIXTURE:
            sink.emit(event)
        since = list(iter_events(str(path), since=parse_when("2026-02-01")))
        assert {e.entity_type for e in since} == {"email", "phone_in"}
        until = list(iter_events(str(path), until=parse_when("2026-02-01")))
        assert [e.entity_type for e in until] == ["aadhaar"]
        strict = list(iter_events(str(path), policy="strict"))
        assert [e.entity_type for e in strict] == ["phone_in"]

    def test_render_lists_entities_and_actions(self):
        text = render_report(aggregate(iter(FIXTURE)), "audit.jsonl")
        assert "4 events" in text
        for token in ("email", "aadhaar", "phone_in", "mask", "block", "ENTITY", "TOOL"):
            assert token in text

    def test_render_empty(self):
        assert "no audit events" in render_report(aggregate(iter([])), "x.jsonl")

    @pytest.mark.parametrize("name", ["audit.jsonl", "audit.db"])
    def test_cli_report_from_each_source(self, tmp_path, capsys, name):
        path = tmp_path / name
        sink = open_sink(path)
        for event in FIXTURE:
            sink.emit(event)
        assert main(["audit", "report", "--source", str(path)]) == 0
        out = capsys.readouterr().out
        assert "4 events" in out
        assert "aadhaar" in out

    def test_cli_report_missing_source(self, tmp_path, capsys):
        assert main(["audit", "report", "--source", str(tmp_path / "nope.jsonl")]) == 0
        assert "no audit events" in capsys.readouterr().out

    def test_cli_report_defaults_to_hook_log(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("VIRELIA_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("VIRELIA_CONFIG", str(tmp_path / "no-config.yaml"))
        monkeypatch.delenv("VIRELIA_AUDIT", raising=False)
        JsonlSink(tmp_path / "audit.jsonl").emit(FIXTURE[0])
        assert main(["audit", "report"]) == 0
        assert "1 events" in capsys.readouterr().out

    def test_virelia_audit_env_overrides_default_source(self, tmp_path, monkeypatch, capsys):
        db = tmp_path / "audit.db"
        sink = SqliteSink(db)
        sink.emit(FIXTURE[0])
        sink.close()
        monkeypatch.setenv("VIRELIA_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("VIRELIA_CONFIG", str(tmp_path / "no-config.yaml"))
        monkeypatch.setenv("VIRELIA_AUDIT", str(db))
        assert main(["audit", "report"]) == 0
        assert "1 events" in capsys.readouterr().out


class TestTailHelpers:
    def test_format_event_is_single_line_without_plaintext(self):
        line = format_event(FIXTURE[0])
        assert "\n" not in line
        assert "email" in line and "mask" in line and "mcp__gmail__search" in line


class TestHookSinkSelection:
    def test_hooks_write_sqlite_when_configured(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VIRELIA_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("VIRELIA_CONFIG", str(tmp_path / "no-config.yaml"))
        monkeypatch.setenv("VIRELIA_AUDIT", str(tmp_path / "audit.db"))
        from virelia.hooks import prompt_guard

        out = prompt_guard.handle({"prompt": "mail me at lakshmi@example.org"})
        assert out["decision"] == "block"
        events = list(iter_events(str(tmp_path / "audit.db")))
        assert events and events[0].entity_type == "EMAIL"
        assert all("lakshmi" not in e.value_hmac for e in events)

    def test_hooks_default_to_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VIRELIA_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("VIRELIA_CONFIG", str(tmp_path / "no-config.yaml"))
        monkeypatch.delenv("VIRELIA_AUDIT", raising=False)
        from virelia.hooks import prompt_guard

        prompt_guard.handle({"prompt": "mail me at lakshmi@example.org"})
        assert (tmp_path / "audit.jsonl").exists()


class TestPostgres:
    """SQL-shape tests run whenever psycopg is importable; the live round-trip
    additionally needs VIRELIA_TEST_POSTGRES_DSN pointing at a scratch database."""

    def test_emit_sql(self, monkeypatch):
        psycopg = pytest.importorskip("psycopg")

        executed = []

        class FakeCursor:
            def execute(self, sql, params=None):
                executed.append((sql, params))

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class FakeConn:
            def cursor(self):
                return FakeCursor()

        monkeypatch.setattr(psycopg, "connect", lambda dsn, autocommit=True: FakeConn())
        sink = PostgresSink("postgresql://example/db")
        sink.emit(FIXTURE[0])
        creates = [sql for sql, _ in executed if sql.startswith("CREATE")]
        assert any("audit_events" in sql for sql in creates)
        assert sum("CREATE INDEX" in sql for sql in creates) == 4
        insert_sql, params = executed[-1]
        assert insert_sql.startswith("INSERT INTO audit_events")
        assert params == event_row(FIXTURE[0])

    def test_live_round_trip(self):
        import os

        pytest.importorskip("psycopg")
        dsn = os.environ.get("VIRELIA_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("VIRELIA_TEST_POSTGRES_DSN not set")
        import psycopg

        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS audit_events")
        sink = PostgresSink(dsn)
        for event in FIXTURE:
            sink.emit(event)
        sink.close()
        assert list(iter_events(dsn)) == FIXTURE
