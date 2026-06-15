"""Traffic monitoring: flow events (one per payload, clean ones included),
opt-in masked-payload capture, schema back-compat, and `kavach monitor`."""

import sqlite3
from datetime import datetime, timezone

import pytest

from mcp_kavach import Engine, InMemorySink, load_preset
from mcp_kavach.audit import (
    LEGACY_COLUMNS,
    JsonlSink,
    SqliteSink,
    event_from_json,
    event_from_row,
    event_row,
)
from mcp_kavach.cli.audit import (
    MonitorStats,
    aggregate,
    format_event,
    format_flow,
    iter_events,
    render_report,
)
from mcp_kavach.hooks.config import load_config
from mcp_kavach.models import AuditEvent, FlowEvent

EMAIL = "lakshmi@example.org"


def make_flow(**overrides) -> FlowEvent:
    base = dict(
        ts=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
        policy="personal",
        tool="mcp__gmail__search",
        direction="tool_output",
        payload_chars=240,
        leaf_count=6,
        findings_count=2,
        actions=("mask", "redact"),
        payload_masked=None,
    )
    base.update(overrides)
    return FlowEvent(**base)


def make_detection(**overrides) -> AuditEvent:
    base = dict(
        ts=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
        policy="personal",
        tool="mcp__gmail__search",
        direction="result",
        entity_type="EMAIL",
        tier=1,
        confidence=0.95,
        rule_id="email-default",
        action="mask",
        json_path="$.from",
        start=0,
        end=10,
        value_hmac="ab" * 32,
    )
    base.update(overrides)
    return AuditEvent(**base)


FLOWS = [
    make_flow(),
    make_flow(direction="prompt", tool="UserPromptSubmit", findings_count=0, actions=()),
    make_flow(direction="tool_input", payload_masked='{"q": "[MASKED:EMAIL]"}'),
]


class TestRoundTrips:
    def test_jsonl(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        sink = JsonlSink(path)
        for event in FLOWS:
            sink.emit(event)
        assert list(iter_events(str(path))) == FLOWS

    def test_sqlite(self, tmp_path):
        path = tmp_path / "audit.db"
        sink = SqliteSink(path)
        for event in FLOWS:
            sink.emit(event)
        sink.close()
        assert list(iter_events(str(path))) == FLOWS

    def test_mixed_kinds_in_one_log(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        sink = JsonlSink(path)
        sink.emit(make_detection())
        sink.emit(FLOWS[0])
        events = list(iter_events(str(path)))
        assert [type(e) for e in events] == [AuditEvent, FlowEvent]

    def test_event_row_round_trip(self):
        for event in [*FLOWS, make_detection()]:
            assert event_from_row(event_row(event)) == event

    def test_legacy_row_reads_as_detection(self):
        row = event_row(make_detection())[: len(LEGACY_COLUMNS)]
        assert event_from_row(row) == make_detection()

    def test_legacy_jsonl_line_reads_as_detection(self):
        line = make_detection().model_dump_json(exclude={"event_kind"})
        assert event_from_json(line) == make_detection()


class TestSchemaMigration:
    def _legacy_db(self, path):
        conn = sqlite3.connect(path)
        cols = ", ".join(f"{c} TEXT" for c in LEGACY_COLUMNS)
        conn.execute(f"CREATE TABLE audit_events (id INTEGER PRIMARY KEY, {cols})")
        placeholders = ", ".join("?" * len(LEGACY_COLUMNS))
        conn.execute(
            f"INSERT INTO audit_events ({', '.join(LEGACY_COLUMNS)}) VALUES ({placeholders})",
            event_row(make_detection())[: len(LEGACY_COLUMNS)],
        )
        conn.commit()
        conn.close()

    def test_old_db_gains_flow_columns_and_keeps_rows(self, tmp_path):
        path = tmp_path / "audit.db"
        self._legacy_db(path)
        sink = SqliteSink(path)  # opening migrates in place
        sink.emit(FLOWS[0])
        sink.close()
        events = list(iter_events(str(path)))
        assert events == [make_detection(), FLOWS[0]]

    def test_old_db_still_readable_without_migration(self, tmp_path):
        path = tmp_path / "audit.db"
        self._legacy_db(path)
        assert list(iter_events(str(path))) == [make_detection()]


@pytest.fixture
def policy():
    return load_preset("ngo-default")


class TestEngineEmission:
    def test_clean_payload_emits_flow_event_with_zero_findings(self, policy):
        sink = InMemorySink()
        engine = Engine(policy, sink=sink, hmac_salt=b"s", monitor=True)
        engine.scan_result("health_check", {"status": "ok", "count": 42})
        flows = [e for e in sink.events if isinstance(e, FlowEvent)]
        assert len(flows) == 1
        assert flows[0].findings_count == 0
        assert flows[0].actions == ()
        assert flows[0].clean
        assert flows[0].direction == "tool_output"
        assert flows[0].leaf_count == 2
        assert flows[0].payload_masked is None

    def test_findings_counted_and_actions_summarized(self, policy):
        sink = InMemorySink()
        engine = Engine(policy, sink=sink, hmac_salt=b"s", monitor=True)
        engine.scan_result("get_users", {"email": EMAIL})
        flow = [e for e in sink.events if isinstance(e, FlowEvent)][-1]
        detections = [e for e in sink.events if isinstance(e, AuditEvent)]
        assert flow.findings_count == len(detections) >= 1
        assert flow.actions == tuple(sorted({e.action.value for e in detections}))
        assert not flow.clean

    def test_direction_mapping(self, policy):
        sink = InMemorySink()
        engine = Engine(policy, sink=sink, hmac_salt=b"s", monitor=True)
        engine.scan_request("some_tool", {"q": "hi"})
        engine.scan_result("some_tool", {"q": "hi"})
        engine.scan_request("UserPromptSubmit", "hello")
        flows = [e for e in sink.events if isinstance(e, FlowEvent)]
        assert [f.direction for f in flows] == ["tool_input", "tool_output", "prompt"]

    def test_monitoring_disabled_emits_zero_flow_events(self, policy):
        sink = InMemorySink()
        engine = Engine(policy, sink=sink, hmac_salt=b"s")
        engine.scan_result("get_users", {"email": EMAIL, "note": "clean"})
        assert not any(isinstance(e, FlowEvent) for e in sink.events)

    def test_invalid_monitor_payloads_rejected(self, policy):
        with pytest.raises(ValueError):
            Engine(policy, hmac_salt=b"s", monitor_payloads="plaintext")


class TestMaskedPayloadCapture:
    def test_capture_stores_masked_content_only(self, policy, tmp_path):
        path = tmp_path / "audit.jsonl"
        engine = Engine(
            policy,
            sink=JsonlSink(path),
            hmac_salt=b"s",
            monitor=True,
            monitor_payloads="masked",
        )
        engine.scan_result("get_users", {"email": EMAIL})
        blob = path.read_bytes()
        assert EMAIL.encode() not in blob  # the original never lands on disk
        flow = [e for e in iter_events(str(path)) if isinstance(e, FlowEvent)][0]
        assert EMAIL not in flow.payload_masked
        assert "***" in flow.payload_masked  # the post-masking payload, as the model saw it

    def test_capture_off_by_default(self, policy):
        sink = InMemorySink()
        engine = Engine(policy, sink=sink, hmac_salt=b"s", monitor=True)
        engine.scan_result("get_users", {"email": EMAIL})
        flow = [e for e in sink.events if isinstance(e, FlowEvent)][0]
        assert flow.payload_masked is None

    def test_blocked_payload_stores_only_the_block_marker(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        engine = Engine(
            load_preset("strict"),
            sink=JsonlSink(path),
            hmac_salt=b"s",
            monitor=True,
            monitor_payloads="masked",
        )
        token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        result = engine.scan_result("get_config", {"note": f"use {token}"})
        assert result.blocked
        blob = path.read_bytes()
        assert token.encode() not in blob
        flow = [e for e in iter_events(str(path)) if isinstance(e, FlowEvent)][0]
        assert "blocked by mcp-kavach" in flow.payload_masked
        assert "block" in flow.actions


class TestMonitorCli:
    def test_format_flow_clean(self):
        line = format_flow(FLOWS[1])
        assert "\n" not in line
        assert "prompt" in line and "UserPromptSubmit" in line and "clean" in line

    def test_format_flow_flagged(self):
        line = format_flow(FLOWS[0])
        assert "2 findings: mask,redact" in line
        assert "240 ch" in line

    def test_format_event_dispatches_to_flow(self):
        assert format_event(FLOWS[0]) == format_flow(FLOWS[0])

    def test_stats_summary(self):
        stats = MonitorStats()
        for event in FLOWS:
            stats.add(event)
        text = stats.summary()
        assert "3 payloads · 1 clean · 2 flagged (67%)" in text
        assert "mcp__gmail__search" in text

    def test_stats_summary_empty(self):
        assert "no traffic seen" in MonitorStats().summary()


class TestFlowAwareReport:
    def test_traffic_line_when_flow_events_exist(self):
        report = aggregate(iter([make_detection(), *FLOWS]))
        text = render_report(report, "audit.jsonl")
        assert "1 events" in text
        assert "traffic: 3 payloads seen · 1 clean · 2 flagged (67%)" in text

    def test_detection_only_logs_unchanged(self):
        text = render_report(aggregate(iter([make_detection()])), "audit.jsonl")
        assert "traffic:" not in text

    def test_flow_only_log_still_renders(self):
        text = render_report(aggregate(iter(FLOWS)), "audit.jsonl")
        assert "traffic: 3 payloads seen" in text
        assert "no audit events" not in text


class TestHookWiring:
    def test_config_knobs_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KAVACH_CONFIG", str(tmp_path / "no-config.yaml"))
        monkeypatch.setenv("KAVACH_MONITOR", "true")
        monkeypatch.setenv("KAVACH_MONITOR_PAYLOADS", "masked")
        cfg = load_config()
        assert cfg.monitor is True
        assert cfg.monitor_payloads == "masked"

    def test_plaintext_capture_is_not_a_thing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KAVACH_CONFIG", str(tmp_path / "no-config.yaml"))
        monkeypatch.setenv("KAVACH_MONITOR_PAYLOADS", "plaintext")
        assert load_config().monitor_payloads == ""

    def test_config_knobs_from_yaml(self, tmp_path, monkeypatch):
        config = tmp_path / "config.yaml"
        config.write_text("monitor: true\nmonitor_payloads: masked\n")
        monkeypatch.setenv("KAVACH_CONFIG", str(config))
        monkeypatch.delenv("KAVACH_MONITOR", raising=False)
        monkeypatch.delenv("KAVACH_MONITOR_PAYLOADS", raising=False)
        cfg = load_config()
        assert cfg.monitor is True
        assert cfg.monitor_payloads == "masked"

    def test_hooks_emit_flow_events_when_enabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KAVACH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("KAVACH_CONFIG", str(tmp_path / "no-config.yaml"))
        monkeypatch.delenv("KAVACH_AUDIT", raising=False)
        monkeypatch.setenv("KAVACH_MONITOR", "true")
        from mcp_kavach.hooks import prompt_guard

        prompt_guard.handle({"prompt": "totally clean message"})
        flows = [
            e for e in iter_events(str(tmp_path / "audit.jsonl")) if isinstance(e, FlowEvent)
        ]
        assert len(flows) == 1
        assert flows[0].direction == "prompt"
        assert flows[0].clean

    def test_hooks_default_emits_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KAVACH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("KAVACH_CONFIG", str(tmp_path / "no-config.yaml"))
        monkeypatch.delenv("KAVACH_AUDIT", raising=False)
        monkeypatch.delenv("KAVACH_MONITOR", raising=False)
        from mcp_kavach.hooks import prompt_guard

        prompt_guard.handle({"prompt": f"mail me at {EMAIL}"})
        events = list(iter_events(str(tmp_path / "audit.jsonl")))
        assert events and not any(isinstance(e, FlowEvent) for e in events)
