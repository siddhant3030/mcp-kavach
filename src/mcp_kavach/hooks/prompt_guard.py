"""UserPromptSubmit guard: block PII prompts with a confirm-by-resend flow.

Claude Code cannot rewrite a submitted prompt, so the guard blocks it and
hands the user (a) a masked version to copy and (b) the option to resend
the identical message to confirm sending it unmasked.
"""

from __future__ import annotations

import hashlib
import json

from mcp_kavach.audit import JsonlSink
from mcp_kavach.hooks import state
from mcp_kavach.hooks.config import load_config, load_engine
from mcp_kavach.hooks.runner import data_dir
from mcp_kavach.hooks.summary import summarize_events


def handle(data: dict) -> dict | None:
    cfg = load_config()
    if cfg.prompt_guard == "off":
        return None
    prompt = data.get("prompt") or data.get("userPrompt") or data.get("user_prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return None

    engine = load_engine(cfg, sink=JsonlSink(data_dir() / "audit.jsonl"))
    result = engine.scan_request("UserPromptSubmit", prompt)
    if not result.modified:
        return None

    entities = summarize_events(result.events, prompt)
    if cfg.prompt_guard == "warn":
        return {
            "systemMessage": f"kavach: your prompt contained {entities} and was sent as-is "
            "(warn mode — set prompt_guard: confirm to block instead)."
        }

    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    session = str(data.get("session_id") or "global")
    if state.consume(session, digest, cfg.confirm_window_seconds):
        return {"systemMessage": "kavach: PII confirmed by resend — prompt sent unmasked."}

    state.store(session, digest, cfg.confirm_window_seconds)
    masked = result.payload if isinstance(result.payload, str) else json.dumps(result.payload)
    minutes = max(1, cfg.confirm_window_seconds // 60)
    message = (
        f"kavach blocked this prompt — it contains {entities}.\n\n"
        f"Masked version you can copy:\n\n```\n{masked}\n```\n\n"
        f"To send the original anyway, resend the exact same message "
        f"within {minutes} minutes."
    )
    # Both output dialects, merged for compatibility across Claude Code versions.
    return {"decision": "block", "reason": message, "continue": False, "stopReason": message}
