# mcp-kavach

**A privacy guardrail layer for MCP tool traffic.** *Kavach* (कवच) means armor.

mcp-kavach sits between your MCP tools and the model: tool results are scanned for
personal data *before* they reach the LLM, tool arguments are scrubbed *before* they
reach the tool, and every decision is recorded in an audit trail that never stores
the raw values. Policies are declarative YAML — per entity type, per tool, per field.

Built for organizations that handle beneficiary data — NGOs, health programs, social-sector
data platforms — with an **India-first entity pack** (Aadhaar with Verhoeff checksum
validation, PAN, IFSC) for DPDP Act compliance, alongside the universal set (emails,
phones, cards with Luhn validation, IPs, credentials). Fully open source, fully
self-hostable: sensitive data never touches a third-party vendor.

## Where it sits

Of the four stages where agent guardrails live — data collection, model training,
**agent tools & actions**, and prompt/response — this project owns stage 3, at the MCP
protocol layer. That is the stage where structured tool traffic exists and where no
open-source project had planted a flag. LLM gateways (Portkey, Bifrost, Kong) guard
stage 4; data-platform tooling guards stages 1–2.

## Quickstart

```bash
pip install mcp-kavach
```

```python
from mcp_kavach import Engine, load_preset

engine = Engine(load_preset("ngo-default"))

raw = {"rows": [{
    "name": "Lakshmi Devi",
    "phone": "+91 98765 43210",
    "aadhaar": "2345 6789 0124",
    "village": "Rampur",
}]}

result = engine.scan_result("get_beneficiaries", raw)
print(result.payload)
# {"rows": [{
#     "name": "[MASKED:PERSON_NAME]",
#     "phone": "+** ***** *3210",
#     "aadhaar": "[BLOCKED:ngo-default/govt-financial-block]",
#     "village": "Rampur",
# }]}

for event in result.events:
    print(event.json_path, event.entity_type, event.action.value, event.value_hmac[:12])
# $.rows[0].name     PERSON_NAME  mask          3f2a9c...   ← never the raw value
```

The model still reasons fine over the masked rows — counts, dates, and villages are
intact — but the personal data never left your infrastructure.

## Policies

```yaml
name: ngo-default
defaults:
  unknown_entity_action: mask        # fail closed
rules:
  - id: contact-partial
    entities: [EMAIL, PHONE]
    action: partial_mask             # l***@example.org, +** ***** *3210
  - id: govt-financial-block
    entities: [AADHAAR, PAN, CREDIT_CARD]
    action: block
    message: "This field contained a government or financial ID and was blocked."
  - id: beneficiary-notes
    match: { tool: "get_beneficiar*", json_path: "$.rows[*].notes" }
    action: redact                   # structural rule — no text scanning at all
```

Actions: `allow | partial_mask | mask | redact | block`. Rules apply first-match-wins
in file order; `block` with `scope: result` withholds the entire payload. Three presets
ship in the package: `ngo-default`, `strict`, `dev`. Full reference:
[docs/policy-schema.md](docs/policy-schema.md).

## How detection works

Tiered, so you only pay for what the policy needs:

| Tier | Cost | What runs |
|------|------|-----------|
| 0 | µs | Structural rules (JSON-path, no text scanning) + column-name heuristics |
| 1 | sub-ms | Compiled regex with checksum gates: Aadhaar (Verhoeff), cards (Luhn), PAN, IFSC, email, phone, IP, AWS/GitHub/JWT credentials |
| 2 | *(planned)* | NER (Presidio/spaCy) for free-text names and addresses |
| 3 | *(planned, opt-in)* | LLM-based detection — local-model capable, never hard-wired to a commercial API |

MCP traffic is structured JSON — kavach exploits that. Detection runs per string leaf
(keys and types are never touched, so payload schemas stay valid), and a column named
`aadhaar` is caught in microseconds without scanning a byte of text.

## Honest limitations (v0.1)

- **No NER yet.** Free-text Indian person names and addresses are caught only by
  column-name heuristics (`name`, `father_name`, `address`, …) — a name buried inside
  a `notes` paragraph will get through. Don't let regex create a false sense of security.
- **Engine only.** The FastMCP middleware adapter and standalone proxy are the next
  milestones; today you call `scan_request()`/`scan_result()` yourself (~10 lines —
  see `src/mcp_kavach/adapters/__init__.py` for the contract).
- **No reversible tokenization yet.** The vault ("rehydration") is designed but not built.
- Checksums shrink false positives but can't eliminate them (~10% of random same-length
  numbers pass any single checksum), and confidence is never 1.0.
- This protects against **accidental PII exposure to the model provider**. It does not
  protect against a malicious MCP server or prompt-injection exfiltration — see
  [docs/threat-model.md](docs/threat-model.md).

## Audit without leaking

Every event stores: entity type, detector tier, confidence, the policy rule that fired,
the action, the JSON path and character offsets, and a **salted HMAC** of the raw value
(set `KAVACH_HMAC_SALT` for cross-run correlation). Never the plaintext. The audit log
is safe to show to anyone who can see the redacted output — including funders and
auditors. "Show me every category of personal data that left our infrastructure this
quarter" is one query.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
```

The test suite includes a golden corpus of labeled synthetic payloads
(`tests/fixtures/corpus/`) — synthetic NGO beneficiary records with
checksum-valid Aadhaar/PAN/card numbers. No real personal data anywhere.

## Roadmap

NER tier with an India-tuned recognizer pack → reversible tokenization vault +
rehydration API → FastMCP middleware adapter → standalone MCP proxy (1:1 tool
mirroring) → SQLite/Postgres audit sinks + CLI (`kavach test`, `kavach audit tail`) →
policy packs (DPDP, GDPR).

## License

Apache-2.0. Every aspect of this project — code, presets, docs, test corpus — is open
source, and all dependencies are permissively-licensed OSS. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the dependency policy.
