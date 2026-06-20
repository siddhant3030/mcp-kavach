# virelia — Claude Code plugin

PII guardrail for Claude Code. Three guards, one engine:

| Guard | Hook | What happens |
|---|---|---|
| **Prompt guard** | UserPromptSubmit | Your prompt contains an email/phone/Aadhaar/card/secret → it's **blocked** with a masked version to copy. Resend the identical message within 5 minutes to send it as-is (confirm-by-resend). |
| **Tool-input guard** | PreToolUse | A tool call (MCP, Bash, WebFetch) is about to carry PII out → Claude Code shows an **"allow this?"** dialog naming the entities. |
| **Tool-output detector** | PostToolUse | An MCP tool returned PII → you get a **warning** + a hash-only audit entry. Hooks can't rewrite tool output — wrap the server with `virelia proxy` to truly mask it. |

## Install

```bash
uv tool install virelia      # the engine (or: pip install virelia)
```

Then in Claude Code:

```
/plugin marketplace add siddhant3030/virelia
/plugin install virelia@virelia
```

Without the engine installed, the plugin stays silent (fails open) and tells you
once per session how to enable it.

## Configure

`~/.virelia/config.yaml` (all optional):

```yaml
policy: personal          # preset name or path to your own policy YAML
prompt_guard: confirm     # confirm | warn | off
tool_input_guard: ask     # ask | mask | warn | off
tool_output_guard: warn   # warn | off
tool_allowlist: [Read, Write, Edit, Glob, Grep, Task, TodoWrite]
```

Env overrides: `VIRELIA_POLICY`, `VIRELIA_PROMPT_MODE`, `VIRELIA_TOOL_INPUT_MODE`,
`VIRELIA_TOOL_OUTPUT_MODE`, `VIRELIA_TOOL_ALLOWLIST`, `VIRELIA_DATA_DIR`.

`/virelia:status` shows recent detections and effective config.

Full docs: [docs/claude-plugin.md](../../docs/claude-plugin.md) in the repo.
