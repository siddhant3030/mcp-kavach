# kavach in Claude Code

The plugin puts the kavach engine at the three places PII can cross into (or
out of) a Claude session. What each layer can actually do is determined by
Claude Code's hook capabilities, so be precise about expectations:

| Surface | Hook | Detect | Ask "are you sure?" | Mask |
|---|---|---|---|---|
| Your prompt | UserPromptSubmit | ✅ | ✅ block + confirm-by-resend | ❌ hooks can't rewrite prompts — you get a masked copy to paste |
| Tool inputs (MCP, Bash, WebFetch) | PreToolUse | ✅ | ✅ native permission dialog | ✅ optional `mask` mode rewrites arguments |
| Tool outputs (MCP results) | PostToolUse | ✅ | ❌ | ❌ hooks can't rewrite outputs — **use `kavach proxy`** |

## Install

```bash
uv tool install mcp-kavach        # or: pip install mcp-kavach
```

In Claude Code:

```
/plugin marketplace add siddhant3030/mcp-kavach
/plugin install kavach@kavach
```

Start a new session. Type a prompt containing an email address — kavach blocks
it, shows the entities it found, and gives you a masked version to copy.
Resend the identical message within 5 minutes to send the original.

If the `kavach` CLI isn't installed, every guard fails **open** (your session
is never broken) and a session-start notice tells you how to enable it.

## The three guards

### 1. Prompt guard (`confirm` by default)

```
> my email is sid@example.org, write me a signature

⛔ kavach blocked this prompt — it contains EMAIL (s***@example.org).

   Masked version you can copy:

   my email is s***@example.org, write me a signature

   To send the original anyway, resend the exact same message within 5 minutes.
```

Modes: `confirm` (block + resend-to-confirm) · `warn` (banner, prompt goes
through) · `off`.

### 2. Tool-input guard (`ask` by default)

When Claude is about to call an MCP tool / Bash / WebFetch with PII in the
arguments, Claude Code shows its native permission dialog with kavach's
reason: *"this call to 'mcp__crm__update' contains EMAIL — share it with the
tool anyway?"*

Modes: `ask` · `mask` (rewrite the arguments with masked values — beware:
this can break tools that legitimately need the real value, e.g. sending an
email) · `warn` · `off`. Local-only tools (Read, Edit, Grep…) are allowlisted
by default.

### 3. Tool-output detector (`warn` by default)

Hooks cannot rewrite a tool result, so when an MCP tool returns PII the
detector warns you and records a hash-only audit event. To actually mask
outputs, wrap the server with the proxy:

## Masking MCP tool outputs with `kavach proxy`

Move your real servers into an upstreams file, e.g. `~/.kavach/upstreams.json`:

```json
{
  "mcpServers": {
    "warehouse": { "command": "npx", "args": ["-y", "@yourorg/warehouse-mcp"] }
  }
}
```

Then point Claude Code (`.mcp.json` or `claude mcp add`) at the proxy instead:

```json
{
  "mcpServers": {
    "warehouse-guarded": {
      "command": "kavach",
      "args": ["proxy", "--config", "/Users/you/.kavach/upstreams.json",
               "--policy", "personal", "--audit", "/Users/you/.local/share/kavach/audit.jsonl"]
    }
  }
}
```

Requires `uv tool install 'mcp-kavach[proxy]'`. With one upstream, tools keep
their original names (1:1 mirroring, no meta-tool). With several upstreams in
one config, fastmcp prefixes tools as `{server}_{tool}` — write policy
`match.tool` globs accordingly. Add `--scan-arguments` to scrub tool inputs at
the proxy too.

## Configuration

`~/.kavach/config.yaml` (env vars override; defaults shown):

```yaml
policy: personal            # preset (personal | ngo-default | strict | dev) or a YAML path
prompt_guard: confirm       # confirm | warn | off
tool_input_guard: ask       # ask | mask | warn | off
tool_output_guard: warn     # warn | off
tool_allowlist: [Read, Write, Edit, Glob, Grep, Task, TodoWrite]
confirm_window_seconds: 300
```

Env: `KAVACH_POLICY`, `KAVACH_PROMPT_MODE`, `KAVACH_TOOL_INPUT_MODE`,
`KAVACH_TOOL_OUTPUT_MODE`, `KAVACH_TOOL_ALLOWLIST` (comma-separated),
`KAVACH_CONFIRM_WINDOW`, `KAVACH_DATA_DIR`, `KAVACH_CONFIG`.

The `personal` preset (plugin default) blocks credentials and
government/financial IDs, partial-masks emails/phones, and allows the rest.
Point `policy:` at your own YAML for org rules (see docs/policy-schema.md).

## Operational notes

- **State** lives in `~/.local/share/kavach/` (`$KAVACH_DATA_DIR` to move):
  `audit.jsonl` (hash-only events), `salt` (HMAC key for audit correlation),
  `pending-*.json` (confirm-by-resend state), `hook-errors.log`.
- **Fail-open by design**: any internal error in a hook logs and exits 0.
  A guard that crashes someone's session gets uninstalled; one that misses an
  edge case gets a bug report.
- **Latency**: each guard is a short-lived Python process (~150–300 ms). The
  detection itself is sub-millisecond (compiled regex + checksums).
- **`/kavach:status`** summarizes recent detections and effective config.
- POSIX shells only for now (macOS/Linux/WSL); a `.cmd` shim for native
  Windows is a welcome contribution.
