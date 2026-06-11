import json
import os
import subprocess
import sys

import pytest
from conftest import VALID_AADHAAR


@pytest.fixture
def hook_env(tmp_path, monkeypatch):
    """Isolate hook state and config from the developer's machine."""
    env = {
        "KAVACH_DATA_DIR": str(tmp_path / "data"),
        "KAVACH_CONFIG": str(tmp_path / "no-config.yaml"),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return {**os.environ, **env}


def run_cli(args, stdin_text, env):
    return subprocess.run(
        [sys.executable, "-m", "mcp_kavach.cli.main", *args],
        input=stdin_text.encode(),
        capture_output=True,
        env=env,
        timeout=60,
    )


def hook_out(proc):
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout.decode()) if proc.stdout.strip() else None


class TestPromptGuard:
    def test_clean_prompt_is_silent(self, hook_env):
        out = hook_out(run_cli(["hook", "prompt-guard"], '{"prompt": "hello world"}', hook_env))
        assert out is None

    def test_pii_prompt_blocks_with_masked_version(self, hook_env):
        payload = json.dumps({"prompt": "mail me at lakshmi@example.org", "session_id": "s1"})
        out = hook_out(run_cli(["hook", "prompt-guard"], payload, hook_env))
        assert out["decision"] == "block"
        assert out["continue"] is False
        assert out["reason"] == out["stopReason"]
        assert "EMAIL" in out["reason"]
        assert "l***@example.org" in out["reason"]  # masked copy to paste
        assert "lakshmi@example.org" not in out["reason"].replace("l***@example.org", "")

    def test_identical_resend_confirms(self, hook_env):
        payload = json.dumps({"prompt": "mail me at lakshmi@example.org", "session_id": "s1"})
        first = hook_out(run_cli(["hook", "prompt-guard"], payload, hook_env))
        assert first["decision"] == "block"
        second = hook_out(run_cli(["hook", "prompt-guard"], payload, hook_env))
        assert "decision" not in second
        assert "confirmed" in second["systemMessage"]
        # Confirmation is consumed: a third send blocks again.
        third = hook_out(run_cli(["hook", "prompt-guard"], payload, hook_env))
        assert third["decision"] == "block"

    def test_different_session_does_not_share_confirmation(self, hook_env):
        p1 = json.dumps({"prompt": "mail lakshmi@example.org", "session_id": "a"})
        p2 = json.dumps({"prompt": "mail lakshmi@example.org", "session_id": "b"})
        hook_out(run_cli(["hook", "prompt-guard"], p1, hook_env))
        out = hook_out(run_cli(["hook", "prompt-guard"], p2, hook_env))
        assert out["decision"] == "block"

    def test_warn_mode_lets_prompt_through(self, hook_env):
        env = {**hook_env, "KAVACH_PROMPT_MODE": "warn"}
        payload = json.dumps({"prompt": "mail lakshmi@example.org"})
        out = hook_out(run_cli(["hook", "prompt-guard"], payload, hook_env | env))
        assert "decision" not in out
        assert "sent as-is" in out["systemMessage"]

    def test_off_mode(self, hook_env):
        env = {**hook_env, "KAVACH_PROMPT_MODE": "off"}
        out = hook_out(run_cli(["hook", "prompt-guard"], '{"prompt": "a@b.co"}', env))
        assert out is None

    def test_garbage_stdin_fails_open(self, hook_env, tmp_path):
        proc = run_cli(["hook", "prompt-guard"], "not json {{{", hook_env)
        assert proc.returncode == 0
        assert proc.stdout.strip() == b""


class TestToolInputGuard:
    def test_ask_on_pii(self, hook_env):
        payload = json.dumps(
            {"tool_name": "mcp__crm__update", "tool_input": {"email": "a@b.co"}}
        )
        out = hook_out(run_cli(["hook", "tool-input-guard"], payload, hook_env))
        decision = out["hookSpecificOutput"]
        assert decision["permissionDecision"] == "ask"
        assert "EMAIL" in decision["permissionDecisionReason"]

    def test_allowlisted_tool_skipped(self, hook_env):
        payload = json.dumps({"tool_name": "Read", "tool_input": {"email": "a@b.co"}})
        out = hook_out(run_cli(["hook", "tool-input-guard"], payload, hook_env))
        assert out is None

    def test_mask_mode_rewrites_input(self, hook_env):
        env = {**hook_env, "KAVACH_TOOL_INPUT_MODE": "mask"}
        payload = json.dumps(
            {"tool_name": "mcp__crm__update", "tool_input": {"email": "a@b.co", "note": "x"}}
        )
        out = hook_out(run_cli(["hook", "tool-input-guard"], payload, env))
        decision = out["hookSpecificOutput"]
        assert decision["permissionDecision"] == "allow"
        assert decision["updatedInput"]["email"] == "a***@b.co"
        assert decision["updatedInput"]["note"] == "x"

    def test_clean_input_silent(self, hook_env):
        payload = json.dumps({"tool_name": "mcp__crm__list", "tool_input": {"page": 1}})
        out = hook_out(run_cli(["hook", "tool-input-guard"], payload, hook_env))
        assert out is None


class TestToolOutputGuard:
    def test_warns_on_pii_in_dict_response(self, hook_env):
        payload = json.dumps(
            {
                "tool_name": "mcp__warehouse__rows",
                "tool_response": {"rows": [{"aadhaar": VALID_AADHAAR}]},
            }
        )
        out = hook_out(run_cli(["hook", "tool-output-guard"], payload, hook_env))
        assert "AADHAAR" in out["systemMessage"]
        assert "kavach proxy" in out["systemMessage"]

    def test_string_and_content_block_responses(self, hook_env):
        for response in (
            "contact lakshmi@example.org",
            [{"type": "text", "text": "contact lakshmi@example.org"}],
        ):
            payload = json.dumps({"tool_name": "mcp__x__y", "tool_response": response})
            out = hook_out(run_cli(["hook", "tool-output-guard"], payload, hook_env))
            assert "EMAIL" in out["systemMessage"], response

    def test_audit_log_is_hash_only(self, hook_env, tmp_path):
        payload = json.dumps(
            {"tool_name": "mcp__x__y", "tool_response": "contact lakshmi@example.org"}
        )
        hook_out(run_cli(["hook", "tool-output-guard"], payload, hook_env))
        audit = (tmp_path / "data" / "audit.jsonl").read_text()
        assert "EMAIL" in audit
        assert "lakshmi@example.org" not in audit

    def test_clean_response_silent(self, hook_env):
        payload = json.dumps({"tool_name": "mcp__x__y", "tool_response": {"ok": True}})
        out = hook_out(run_cli(["hook", "tool-output-guard"], payload, hook_env))
        assert out is None


class TestScanCommand:
    def test_scan_prints_masked_text_and_table(self, hook_env):
        proc = run_cli(["scan", "call me at 9876543210", "--policy", "personal"], "", hook_env)
        assert proc.returncode == 0
        out = proc.stdout.decode()
        assert "******3210" in out
        assert "PHONE" in out
        assert "9876543210" not in out
