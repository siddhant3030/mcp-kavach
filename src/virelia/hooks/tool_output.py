"""PostToolUse detector: hooks cannot rewrite a tool result, so this guard
detects, audits, and tells the user how to actually mask (virelia proxy)."""

from __future__ import annotations

from virelia.hooks.config import audit_sink, load_config, load_engine
from virelia.hooks.summary import summarize_events


def handle(data: dict) -> dict | None:
    cfg = load_config()
    if cfg.tool_output_guard == "off":
        return None
    tool = str(data.get("tool_name") or "unknown")
    response = data.get("tool_response", data.get("tool_output"))
    if response is None:
        return None
    payload = response if isinstance(response, (dict, list, str)) else str(response)

    engine = load_engine(cfg, sink=audit_sink(cfg))
    result = engine.scan_result(tool, payload)
    if not result.modified:
        return None

    entities = summarize_events(result.events, payload if isinstance(payload, str) else None)
    return {
        "systemMessage": (
            f"⚠️ virelia: '{tool}' returned {entities} — this has already reached the model "
            f"(hooks can't rewrite tool output). Wrap this server with `virelia proxy` to "
            f"mask results before the model sees them."
        )
    }
