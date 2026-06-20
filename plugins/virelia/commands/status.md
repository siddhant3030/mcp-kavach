---
description: Show virelia PII-guard status — recent detections, config, and how to tune it
---

Show the user their virelia PII-guard status. Follow these steps:

1. Run `virelia version`. If the command is missing, tell the user the guards are
   inactive and to install with `pip install virelia`, then stop.
2. Run `virelia audit report` and show its output (it aggregates the hash-only
   audit log by entity type, action, and tool — the log contains only entity
   types and salted hashes, never raw values, so it is safe to display). If it
   prints "no audit events", say no PII has been detected yet. If the `audit`
   subcommand is missing (older install), fall back to reading the last ~100
   lines of `${VIRELIA_DATA_DIR:-$HOME/.local/share/virelia}/audit.jsonl` and
   summarize counts by entity type, tool, and action yourself.
3. If `~/.virelia/config.yaml` exists, show the effective settings; otherwise state
   the defaults: policy `personal`, prompt_guard `confirm`, tool_input_guard `ask`,
   tool_output_guard `warn`.
4. Remind the user: tool OUTPUTS can only be detected (not masked) by hooks — to
   actually mask MCP tool results they should wrap servers with `virelia proxy`
   (see docs/claude-plugin.md in the repo).
