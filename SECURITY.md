# Security policy

## Reporting a vulnerability

Email **dalgo-engineering@projecttech4dev.org** with details. Please do not
open a public issue for anything that could expose users' personal data. We
aim to acknowledge within 72 hours.

Especially interested in: detection bypasses (PII that should be caught by a
shipped preset but isn't), plaintext leaking into audit events or hook
messages, and vault/key-handling issues once the rehydration vault ships.

## Security invariants (tested in CI)

- Audit events never contain plaintext — only entity types, offsets, and
  salted HMACs. Only `audit.hmac_value()` ever touches a raw value.
- Hook messages re-expose at most a partial-masked preview, never the value.
- Policy YAML is parsed with `yaml.safe_load` and validated `extra=forbid`.
- The engine never mutates caller payloads and never rewrites JSON keys.
- Hooks fail open (a crash never blocks a session); the proxy fails closed
  (an engine failure withholds the result).

## Scope honesty

kavach protects against *accidental* PII exposure to a model provider. It is
not a sandbox, not a DLP boundary, and does not defend against malicious MCP
servers or prompt-injection exfiltration — see docs/threat-model.md.
