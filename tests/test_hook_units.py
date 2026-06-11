"""Fast in-process tests for hook internals (state store, config, summary)."""

import time

import pytest

from mcp_kavach.hooks import state
from mcp_kavach.hooks.config import load_config
from mcp_kavach.hooks.summary import summarize_events
from mcp_kavach.models import Action, AuditEvent


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("KAVACH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KAVACH_CONFIG", str(tmp_path / "no-config.yaml"))


class TestState:
    def test_store_then_consume(self):
        state.store("s", "abc", 300)
        assert state.consume("s", "abc", 300)
        assert not state.consume("s", "abc", 300)  # consumed

    def test_expired_entry_not_consumed(self, monkeypatch):
        state.store("s", "abc", 300)
        real_time = time.time
        monkeypatch.setattr(time, "time", lambda: real_time() + 301)
        assert not state.consume("s", "abc", 300)

    def test_cap_keeps_newest(self):
        for i in range(25):
            state.store("s", f"h{i}", 3600)
        assert not state.consume("s", "h0", 3600)
        assert state.consume("s", "h24", 3600)


class TestConfig:
    def test_defaults(self):
        cfg = load_config()
        assert cfg.policy == "personal"
        assert cfg.prompt_guard == "confirm"
        assert cfg.tool_input_guard == "ask"
        assert "Read" in cfg.tool_allowlist

    def test_yaml_config_and_env_precedence(self, tmp_path, monkeypatch):
        config = tmp_path / "config.yaml"
        config.write_text("policy: strict\nprompt_guard: warn\ntool_allowlist: [Foo]\n")
        monkeypatch.setenv("KAVACH_CONFIG", str(config))
        cfg = load_config()
        assert cfg.policy == "strict"
        assert cfg.prompt_guard == "warn"
        assert cfg.tool_allowlist == ("Foo",)
        monkeypatch.setenv("KAVACH_PROMPT_MODE", "off")
        assert load_config().prompt_guard == "off"


class TestSummary:
    def test_previews_are_masked(self):
        from datetime import datetime, timezone

        event = AuditEvent(
            ts=datetime.now(timezone.utc),
            policy="p",
            tool="t",
            direction="request",
            entity_type="EMAIL",
            tier=1,
            confidence=0.95,
            rule_id="r",
            action=Action.PARTIAL_MASK,
            json_path="$",
            start=8,
            end=27,
            value_hmac="x",
        )
        text = "mail me lakshmi@example.org"
        summary = summarize_events([event], text)
        assert "EMAIL" in summary
        assert "l***@example.org" in summary
        assert "lakshmi@example.org" not in summary
