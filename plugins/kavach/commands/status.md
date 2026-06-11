---
description: Show kavach PII-guard status — recent detections, config, and how to tune it
---

Show the user their kavach PII-guard status. Follow these steps:

1. Run `kavach version`. If the command is missing, tell the user the guards are
   inactive and to install with `pip install mcp-kavach`, then stop.
2. Read the audit log at `${KAVACH_DATA_DIR:-$HOME/.local/share/kavach}/audit.jsonl`
   (last ~100 lines; it contains only entity types and salted hashes — never raw
   values, so it is safe to display). Summarize: counts by entity type, by tool,
   by action taken, and the most recent few events with timestamps. If the file
   doesn't exist, say no PII has been detected yet.
3. If `~/.kavach/config.yaml` exists, show the effective settings; otherwise state
   the defaults: policy `personal`, prompt_guard `confirm`, tool_input_guard `ask`,
   tool_output_guard `warn`.
4. Remind the user: tool OUTPUTS can only be detected (not masked) by hooks — to
   actually mask MCP tool results they should wrap servers with `kavach proxy`
   (see docs/claude-plugin.md in the repo).
