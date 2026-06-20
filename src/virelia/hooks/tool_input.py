"""PreToolUse guard: PII in tool arguments triggers an "are you sure?" dialog
(default), automatic masking, or a warning — before the data leaves."""

from __future__ import annotations

import fnmatch

from virelia.hooks.config import audit_sink, load_config, load_engine
from virelia.hooks.summary import summarize_events


def _decision(decision: str, reason: str, updated_input: dict | None = None) -> dict:
    output: dict = {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }
    if updated_input is not None:
        output["updatedInput"] = updated_input
    return {"hookSpecificOutput": output}


def handle(data: dict) -> dict | None:
    cfg = load_config()
    if cfg.tool_input_guard == "off":
        return None
    tool = str(data.get("tool_name") or "")
    if any(fnmatch.fnmatch(tool, pattern) for pattern in cfg.tool_allowlist):
        return None
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, (dict, list, str)) or not tool_input:
        return None

    engine = load_engine(cfg, sink=audit_sink(cfg))
    result = engine.scan_request(tool or "unknown", tool_input)
    if not result.modified:
        return None

    entities = summarize_events(result.events, tool_input if isinstance(tool_input, str) else None)
    if result.blocked:
        return _decision("deny", f"virelia: {result.block_reason}")
    # updatedInput must mirror the original shape; non-dict inputs fall back to ask.
    if (
        cfg.tool_input_guard == "mask"
        and isinstance(tool_input, dict)
        and isinstance(result.payload, dict)
    ):
        return _decision("allow", f"virelia: masked {entities} in the tool input", result.payload)
    if cfg.tool_input_guard in ("ask", "mask"):
        return _decision(
            "ask",
            f"virelia: this call to '{tool}' contains {entities} — share it with the tool anyway?",
        )
    return {
        "systemMessage": f"virelia: tool '{tool}' was called with {entities} in its input."
    }
