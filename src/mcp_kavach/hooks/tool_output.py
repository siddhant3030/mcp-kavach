"""PostToolUse detector: hooks cannot rewrite a tool result, so this guard
detects, audits, and tells the user how to actually mask (kavach proxy)."""

from __future__ import annotations

from mcp_kavach.audit import JsonlSink
from mcp_kavach.hooks.config import load_config, load_engine
from mcp_kavach.hooks.runner import data_dir
from mcp_kavach.hooks.summary import summarize_events


def handle(data: dict) -> dict | None:
    cfg = load_config()
    if cfg.tool_output_guard == "off":
        return None
    tool = str(data.get("tool_name") or "unknown")
    response = data.get("tool_response", data.get("tool_output"))
    if response is None:
        return None
    payload = response if isinstance(response, (dict, list, str)) else str(response)

    engine = load_engine(cfg, sink=JsonlSink(data_dir() / "audit.jsonl"))
    result = engine.scan_result(tool, payload)
    if not result.modified:
        return None

    entities = summarize_events(result.events, payload if isinstance(payload, str) else None)
    return {
        "systemMessage": (
            f"⚠️ kavach: '{tool}' returned {entities} — this has already reached the model "
            f"(hooks can't rewrite tool output). Wrap this server with `kavach proxy` to "
            f"mask results before the model sees them."
        )
    }
