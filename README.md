<div align="center">

```
██╗  ██╗ █████╗ ██╗   ██╗ █████╗  ██████╗██╗  ██╗
██║ ██╔╝██╔══██╗██║   ██║██╔══██╗██╔════╝██║  ██║
█████╔╝ ███████║██║   ██║███████║██║     ███████║
██╔═██╗ ██╔══██║╚██╗ ██╔╝██╔══██║██║     ██╔══██║
██║  ██╗██║  ██║ ╚████╔╝ ██║  ██║╚██████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

**The PII guardrail for AI agents — nothing personal leaves your machine unmasked.**

prompts · tool calls · MCP traffic — detect → ask → mask · checksum-validated · hash-only audit · local-first · Apache-2.0

[![CI](https://github.com/siddhant3030/mcp-kavach/actions/workflows/ci.yml/badge.svg)](https://github.com/siddhant3030/mcp-kavach/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-kavach)](https://pypi.org/project/mcp-kavach/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

</div>

*Kavach* (कवच) means armor. You type your email into a Claude session, or an
MCP tool dumps warehouse rows with phone numbers into the model's context —
and that data is now in a third-party prompt log. kavach sits at every door
and asks first.

## Use it in Claude Code (60 seconds)

```bash
pip install mcp-kavach        # or: uv tool install mcp-kavach
```

Inside Claude Code:

```
/plugin marketplace add siddhant3030/mcp-kavach
/plugin install kavach@kavach
```

Now try it — type a prompt with an email in it:

```
> my email is sid@example.org, write me a signature

⛔ kavach blocked this prompt — it contains EMAIL (s***@example.org).

   Masked version you can copy:
   ┌────────────────────────────────────────────────────┐
   │ my email is s***@example.org, write me a signature │
   └────────────────────────────────────────────────────┘
   To send the original anyway, resend the exact same message within 5 minutes.
```

Three guards ship enabled:

| | Where | Default behavior |
|---|---|---|
| 🛑 **Prompt guard** | your messages | block + masked copy + confirm-by-resend |
| ❓ **Tool-input guard** | MCP / Bash / WebFetch calls | native "share this anyway?" dialog |
| 📢 **Tool-output detector** | MCP results | warning + hash-only audit (mask via `kavach proxy`, below) |

Everything is configurable per-guard (`ask`/`mask`/`warn`/`off`) — see
[docs/claude-plugin.md](docs/claude-plugin.md). No `kavach` CLI installed →
the plugin stays silent and never breaks your session.

## Mask MCP tool *outputs* with the proxy

Claude Code hooks can't rewrite a tool result, so kavach ships an MCP gateway:
wrap any server you can't modify, tools are mirrored 1:1, and every result is
scrubbed before the model sees it.

```json
{ "mcpServers": { "warehouse-guarded": {
    "command": "kavach",
    "args": ["proxy", "--config", "~/.kavach/upstreams.json", "--policy", "ngo-default"]
}}}
```

```
tool returns                              model sees
{"name": "Lakshmi Devi",          →       {"name": "[MASKED:PERSON_NAME]",
 "phone": "+91 98765 43210",      →        "phone": "+** ***** *3210",
 "aadhaar": "2345 6789 0124",     →        "aadhaar": "[BLOCKED:ngo-default/govt-financial-block]",
 "village": "Rampur"}             →        "village": "Rampur"}
```

The model still reasons fine — counts, dates, villages intact. The person
doesn't leak. Requires `pip install 'mcp-kavach[proxy]'`.

## What it detects

| Entity | Validation | | Entity | Validation |
|---|---|---|---|---|
| EMAIL | format | | AADHAAR 🇮🇳 | **Verhoeff checksum** |
| PHONE (IN + intl) | digit boundaries | | PAN 🇮🇳 | holder-type check |
| CREDIT_CARD | **Luhn checksum** | | IFSC 🇮🇳 | format |
| IP_ADDRESS | octet range | | AWS / GitHub / JWT secrets | anchored formats |
| PERSON_NAME, ADDRESS, DOB, BANK_ACCOUNT, GOVT_ID | column-name heuristics (structured data) | | | |

Checksums kill most false positives (a random 12-digit number is rejected
unless it passes Verhoeff). Try it:

```bash
$ kavach scan "call me at 9876543210 or lakshmi@example.org"
call me at ******3210 or l***@example.org

ENTITY           ACTION        RULE                     TIER CONF
PHONE            partial_mask  contact-partial          1    0.90
EMAIL            partial_mask  contact-partial          1    0.95
```

## Policies are YAML, not code

```yaml
name: my-org
defaults:
  unknown_entity_action: mask        # fail closed
rules:
  - id: contact-partial
    entities: [EMAIL, PHONE]
    action: partial_mask             # l***@example.org, ******3210
  - id: ids-block
    entities: [AADHAAR, PAN, CREDIT_CARD]
    action: block
    message: "Government/financial IDs don't go to the model. Org policy."
  - id: notes-redact
    match: { tool: "get_beneficiar*", json_path: "$.rows[*].notes" }
    action: redact                   # structural rule — zero text scanning
```

Actions `allow | partial_mask | mask | redact | block`, first-match-wins,
`scope: result` refuses a whole payload. Four shipped presets: `personal`
(plugin default), `ngo-default`, `strict`, `dev`.
Reference: [docs/policy-schema.md](docs/policy-schema.md).

## Audit you can show your auditor

Every detection is logged with entity type, detector tier, confidence, the
rule that fired, JSON path, offsets — and a **salted HMAC instead of the
value**. The log is safe to show to anyone cleared to see the redacted
output. "Which categories of personal data left our infrastructure toward a
model provider this quarter?" is one query. `/kavach:status` summarizes it
inside Claude Code.

## Where kavach sits

Of the four agent-guardrail stages — data collection, model training,
**agent tools & actions**, prompt/response — kavach owns stage 3 at the MCP
protocol layer, where structured tool traffic actually exists. LLM gateways
(Portkey, Kong) guard stage 4; nothing open-source guarded stage 3. Built for
sovereignty-sensitive deployments (NGOs under India's DPDP Act): fully
self-hosted, no vendor vault, no SaaS calls, every dependency permissive OSS.

## Honest limitations (v0.2)

- **No NER yet** — free-text names/addresses are caught only via column-name
  heuristics; a name inside a paragraph gets through. India-tuned NER is the
  next milestone. Don't let regex create false confidence.
- Prompt guard can't *rewrite* prompts (Claude Code hook limitation) — it
  blocks and hands you the masked copy.
- Tool-output hook can't *unsend* — it warns; true masking needs the proxy.
- Checksums shrink false positives, can't zero them; confidence is never 1.0.
- Protects against **accidental** exposure, not malicious servers or prompt
  injection: [docs/threat-model.md](docs/threat-model.md).

## Library use (any Python agent, 3 lines)

```python
from mcp_kavach import Engine, load_preset

engine = Engine(load_preset("ngo-default"))
result = engine.scan_result("get_beneficiaries", rows)   # masked payload + audit events
```

## Development

```bash
uv sync && uv run pytest && uv run ruff check .
```

128+ tests including a golden corpus of synthetic, checksum-valid records
(no real personal data anywhere). Contributions welcome — especially
detectors for more ID systems and an India-tuned NER pack:
[CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

NER tier (Presidio + India-tuned recognizers) → reversible tokenization
vault with rehydration at trusted sinks → SQLite/Postgres audit sinks +
`kavach audit` CLI → policy packs (DPDP, GDPR, HIPAA-lite) → multilingual.

## License

Apache-2.0 — code, presets, docs, corpus, everything. All dependencies are
permissively-licensed OSS and every feature is self-hostable; that's policy,
not accident ([CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md)).
