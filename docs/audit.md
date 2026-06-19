# The audit log

Every time virelia detects PII — in a prompt, a tool input, or a tool result —
it records an audit event. The log is the compliance story: it answers
"which categories of personal data left toward a model provider, when, and
what did virelia do about it?" without ever storing the data itself.

## What is in an event

| field | example | meaning |
|---|---|---|
| `ts` | `2026-03-01T12:00:00+00:00` | when it happened (UTC) |
| `policy` | `personal` | policy in effect |
| `tool` | `mcp__gmail__search` | tool (or `UserPromptSubmit`) involved |
| `direction` | `request` / `result` | data going to the tool, or coming back |
| `entity_type` | `EMAIL`, `AADHAAR` | category of personal data |
| `tier`, `confidence` | `1`, `0.95` | which detector tier fired and how sure it was |
| `rule_id` | `email-default` | the policy rule that decided the action |
| `action` | `mask`, `redact`, `block` | what virelia did |
| `json_path`, `start`, `end` | `$.messages[0].from`, `3`, `22` | where in the payload (offsets, not content) |
| `value_hmac` | `ab12…` | salted HMAC-SHA256 of the detected value |

## What is deliberately NOT in it

The plaintext. No raw emails, phone numbers, Aadhaar numbers — ever. The only
trace of the value is `value_hmac`, a keyed hash with a random per-machine
salt (stored in `$VIRELIA_DATA_DIR/salt`, mode 0600). That is enough to tell
"the same value appeared in five events" without being able to read it, and it
cannot be reversed or brute-forced without the salt. The log is safe to show
to anyone who is allowed to see the redacted output.

## Where it goes

By default, hooks append JSON lines to
`${VIRELIA_DATA_DIR:-$HOME/.local/share/virelia}/audit.jsonl`.

You can point the audit stream somewhere else — the destination's shape picks
the backend:

| destination | backend |
|---|---|
| `…/audit.jsonl` (or any other path) | JSONL, append-only |
| `…/audit.db`, `.sqlite`, `.sqlite3` | SQLite (WAL mode, indexed) |
| `postgres://user:pass@host/db` | Postgres (needs `pip install 'virelia[postgres]'`) |

Set it for the hooks with the `VIRELIA_AUDIT` env var or `audit:` in
`~/.virelia/config.yaml`, and for the proxy with `virelia proxy --audit DEST`.

## Reading it

```console
$ virelia audit report --since 2026-01-01 --until 2026-03-31
audit report — /Users/you/.local/share/virelia/audit.jsonl
142 events · 2026-01-03 14:02 → 2026-03-29 17:51 UTC

ENTITY    EVENTS  MASK  REDACT  BLOCK
EMAIL         87    87       0      0
PHONE_IN      31     0      31      0
AADHAAR       18     0       6     12
PAN            6     6       0      0

ACTION  EVENTS
mask        93
redact      37
block       12

TOOL                EVENTS
mcp__gmail__search      88
UserPromptSubmit        36
mcp__sheets__read       18
```

That one command answers the quarterly question: which categories of personal
data headed toward a model provider, and what happened to them.

`--policy NAME` filters to events recorded under one policy, and `--source`
reads any JSONL file, SQLite file, or `postgres://` URL (auto-detected the
same way as the sinks).

To watch detections live during a session:

```console
$ virelia audit tail
tailing /Users/you/.local/share/virelia/audit.jsonl — Ctrl-C to stop
2026-06-12T09:14:03Z  mask         EMAIL            mcp__gmail__search       result   email-default
2026-06-12T09:14:41Z  block        AADHAAR          UserPromptSubmit         request  aadhaar-strict
```

Dates accept ISO format (`2026-01-01` or `2026-01-01T09:00:00+05:30`); a bare
date is read as UTC.
