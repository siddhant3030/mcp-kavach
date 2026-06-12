"""Hook configuration. Precedence: env vars > ~/.kavach/config.yaml > defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mcp_kavach.audit import AuditSink, open_sink
from mcp_kavach.engine import Engine
from mcp_kavach.hooks.runner import data_dir, hmac_salt
from mcp_kavach.policy import Policy, load_policy, load_preset

# Local-only built-ins: their inputs never leave the machine, so scanning
# them only adds friction.
_DEFAULT_ALLOWLIST = ("Read", "Write", "Edit", "Glob", "Grep", "Task", "TodoWrite")


@dataclass
class HookConfig:
    policy: str = "personal"
    prompt_guard: str = "confirm"  # confirm | warn | off
    tool_input_guard: str = "ask"  # ask | mask | warn | off
    tool_output_guard: str = "warn"  # warn | off
    tool_allowlist: tuple[str, ...] = field(default_factory=lambda: _DEFAULT_ALLOWLIST)
    confirm_window_seconds: int = 300
    # Audit destination: a .jsonl path (default), a .db/.sqlite path, or a
    # postgres:// URL. Empty means $KAVACH_DATA_DIR/audit.jsonl.
    audit: str = ""


def load_config() -> HookConfig:
    cfg = HookConfig()
    path = Path(os.environ.get("KAVACH_CONFIG") or Path.home() / ".kavach" / "config.yaml")
    if path.is_file():
        data = yaml.safe_load(path.read_text()) or {}
        if isinstance(data, dict):
            for key in (
                "policy",
                "prompt_guard",
                "tool_input_guard",
                "tool_output_guard",
                "confirm_window_seconds",
                "audit",
            ):
                if key in data:
                    setattr(cfg, key, data[key])
            if isinstance(data.get("tool_allowlist"), list):
                cfg.tool_allowlist = tuple(str(t) for t in data["tool_allowlist"])

    env = os.environ
    cfg.policy = env.get("KAVACH_POLICY", cfg.policy)
    cfg.prompt_guard = env.get("KAVACH_PROMPT_MODE", cfg.prompt_guard)
    cfg.tool_input_guard = env.get("KAVACH_TOOL_INPUT_MODE", cfg.tool_input_guard)
    cfg.tool_output_guard = env.get("KAVACH_TOOL_OUTPUT_MODE", cfg.tool_output_guard)
    if env.get("KAVACH_TOOL_ALLOWLIST"):
        cfg.tool_allowlist = tuple(
            t.strip() for t in env["KAVACH_TOOL_ALLOWLIST"].split(",") if t.strip()
        )
    if env.get("KAVACH_CONFIRM_WINDOW"):
        cfg.confirm_window_seconds = int(env["KAVACH_CONFIRM_WINDOW"])
    cfg.audit = env.get("KAVACH_AUDIT", cfg.audit)
    return cfg


def resolve_policy(ref: str) -> Policy:
    """Preset name, or a path to a YAML policy file."""
    if os.sep in ref or ref.endswith((".yaml", ".yml")) or Path(ref).is_file():
        return load_policy(ref)
    return load_preset(ref)


def audit_sink(cfg: HookConfig) -> AuditSink:
    """The configured audit sink (JSONL by default; SQLite/Postgres via the
    `audit` config key or KAVACH_AUDIT)."""
    return open_sink(cfg.audit or data_dir() / "audit.jsonl")


def load_engine(cfg: HookConfig, *, sink: AuditSink | None = None) -> Engine:
    return Engine(resolve_policy(cfg.policy), sink=sink, hmac_salt=hmac_salt())
