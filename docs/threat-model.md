# Threat model

Be honest about what this protects against. A privacy tool that overstates its
coverage is worse than no tool — it manufactures false confidence.

## What mcp-kavach protects against

**Accidental exposure of personal data to the model provider** (and to anything else
downstream of the model: transcripts, traces, completions logs). The scenario: an
agent calls a legitimate tool, the tool legitimately returns warehouse rows, and
beneficiary PII rides along into the prompt. kavach scrubs the tool result before the
model sees it, and scrubs tool arguments before the tool (and its logs) see them.

Secondarily: **compliance evidence**. The hash-only audit trail answers "which
categories of personal data left our infrastructure toward a model provider, when,
through which tool" without itself becoming a PII store.

## What it does NOT protect against

- **A malicious MCP server.** A hostile tool can exfiltrate data on its own; kavach
  only filters what flows through the MCP message path it wraps.
- **Prompt-injection exfiltration.** If injected instructions get the model to call
  an outbound tool with data it already legitimately saw, that's an agent-security
  problem — pair kavach with a prompt-injection gateway; that's a different layer.
- **An attacker with access to the host.** kavach runs in-process; it is not a
  sandbox or a DLP boundary.
- **Inference from unmasked context.** "The only beneficiary in Rampur who missed a
  checkup" can identify a person without any masked field leaking. Re-identification
  risk in small populations is real and out of scope for field-level masking.

## Known detection gaps (v0.1)

- **Free-text names and addresses** are caught only when the *column name* signals
  them (`name`, `father_name`, `address`, …). A name inside a `notes` paragraph gets
  through until the NER tier ships. spaCy's English models also have materially lower
  recall on Indian names — an India-tuned recognizer pack is on the roadmap.
- **Checksum false positives/negatives.** ~10% of random 12-digit numbers pass
  Verhoeff; mitigations (digit-boundary lookarounds, first-digit filter, grouped-run
  slicing checks) shrink but don't eliminate this. Confidence is never 1.0.
- **Unprefixed secrets.** Only anchored credential formats ship (AKIA/ASIA keys,
  `ghp_`/`github_pat_` tokens, JWTs). AWS *secret* keys and generic API keys are
  40-odd unanchored base64 characters — detecting them by regex is a false-positive
  machine, so we don't claim to.
- **Type fidelity.** A blocked/masked numeric leaf becomes a marker *string* —
  intentional (the model should see *why* a value is absent), but downstream code
  that re-parses payload types must tolerate it.

## Trust boundaries and invariants

- **Audit events never contain plaintext.** Only `audit.hmac_value()` touches the raw
  string; events store a salted HMAC (salt from `KAVACH_HMAC_SALT` — set it, or
  per-instance random salts break cross-run correlation). The audit log is safe to
  show to anyone cleared to see the redacted output.
- **The policy file is attacker-adjacent input**: parsed with `yaml.safe_load`,
  validated with `extra=forbid`, path grammar checked at load time.
- **Fail closed**: unknown detected entities default to `mask`; unparseable policies
  refuse to load rather than degrade.
- The engine never mutates the caller's payload and never rewrites JSON keys.
- When the reversible vault ships, it becomes the honeypot — the classic failure mode
  of redaction layers. Its key management will get a dedicated security review before
  any release advertises rehydration.
