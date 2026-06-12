# kavach — Claude Code plugin

PII guardrail for Claude Code. Three guards, one engine:

| Guard | Hook | What happens |
|---|---|---|
| **Prompt guard** | UserPromptSubmit | Your prompt contains an email/phone/Aadhaar/card/secret → it's **blocked** with a masked version to copy. Resend the identical message within 5 minutes to send it as-is (confirm-by-resend). |
| **Tool-input guard** | PreToolUse | A tool call (MCP, Bash, WebFetch) is about to carry PII out → Claude Code shows an **"allow this?"** dialog naming the entities. |
| **Tool-output detector** | PostToolUse | An MCP tool returned PII → you get a **warning** + a hash-only audit entry. Hooks can't rewrite tool output — wrap the server with `kavach proxy` to truly mask it. |

## Install

```bash
uv tool install mcp-kavach      # the engine (or: pip install mcp-kavach)
```

Then in Claude Code:

```
/plugin marketplace add siddhant3030/mcp-kavach
/plugin install kavach@kavach
```

Without the engine installed, the plugin stays silent (fails open) and tells you
once per session how to enable it.

## Configure

`~/.kavach/config.yaml` (all optional):

```yaml
policy: personal          # preset name or path to your own policy YAML
prompt_guard: confirm     # confirm | warn | off
tool_input_guard: ask     # ask | mask | warn | off
tool_output_guard: warn   # warn | off
tool_allowlist: [Read, Write, Edit, Glob, Grep, Task, TodoWrite]
```

Env overrides: `KAVACH_POLICY`, `KAVACH_PROMPT_MODE`, `KAVACH_TOOL_INPUT_MODE`,
`KAVACH_TOOL_OUTPUT_MODE`, `KAVACH_TOOL_ALLOWLIST`, `KAVACH_DATA_DIR`.

`/kavach:status` shows recent detections and effective config.

Full docs: [docs/claude-plugin.md](../../docs/claude-plugin.md) in the repo.
