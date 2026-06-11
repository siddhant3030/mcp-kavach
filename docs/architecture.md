# Architecture

## Overview

mcp-kavach is a transport-agnostic guardrail engine wrapped (eventually) by thin
transport adapters. The engine operates on plain Python values — dict/list/str/scalars —
never on MCP SDK types, so an adapter only marshals payloads in and out.

```
                ┌─────────────────────────────────────────────┐
                │             GUARDRAIL ENGINE                │
 MCP client ──▶ │  Policy      Detector        Transformer    │ ──▶ tool /
 (agent)        │  Resolver ─▶ Pipeline     ─▶ (mask/redact/  │     upstream server
            ◀── │  (rules,     T0 structural   partial/block) │ ◀──
                │  defaults)   T1 regex            │          │
                │              T2 NER*             ▼          │
                │              T3 LLM*        Audit events    │
                │                             (hash-only)     │
                └─────────────────────────────────────────────┘
                          * planned, behind extras
```

## The scan pipeline (`engine.py:_scan`)

1. **Walk** the payload tree, yielding `(path, value)` for every scalar leaf.
   Keys are never scanned as text; bool/None leaves are skipped.
2. **Tier 0 — structural policy rules.** Rules with a `match:` block are tested
   against the tool name (fnmatch glob) and the leaf path (`pathmatch.py`). A match
   pins an action with confidence 1.0 — no text scanning. A `block` rule with
   `scope: result` short-circuits the whole scan immediately.
3. **Tier 0 — structural detectors.** `ColumnNameDetector` flags whole values by the
   field name that holds them (`aadhaar`, `father_name`, …) — the only way to catch
   free-text names/addresses before the NER tier exists.
4. **Tier 1 — regex detectors** run per string leaf (and on `str(value)` for numeric
   leaves, which then get whole-value treatment). Checksummed entities (Aadhaar →
   Verhoeff, cards → Luhn) reject candidates in `validate()`.
5. **Resolve.** Each span gets an action: pinned rule > first entity rule in file
   order > `defaults.unknown_entity_action`. Spans below `defaults.min_confidence`
   are dropped.
6. **Transform.** Per leaf, overlapping findings are clustered (transitive overlap);
   the cluster takes the highest-severity action (block > redact > mask >
   partial_mask > allow) over the union extent, and replacements apply right-to-left.
   The payload is rebuilt — the caller's object is never mutated.
7. **Audit.** One event per finding: entity type, tier, confidence, rule id, action,
   rendered path, offsets, salted HMAC of the matched text. Plaintext never enters an
   event; only `audit.hmac_value()` touches the raw string.

## Performance posture

Detection cost is policy-driven. When `unknown_entity_action: allow` (dev posture)
the engine prunes detectors to the entities rules actually act on; in every other
posture all detectors run, because an entity must be *found* to be default-masked
(fail closed). Tier 0 is O(path checks); Tier 1 is compiled-regex over leaf strings.
The future NER/LLM tiers will be lazy-loaded behind `[ner]`/`[llm]` extras and gated
by policy so the base path stays sub-millisecond.

## Adapter contract (future milestone)

An adapter has three responsibilities (see `src/mcp_kavach/adapters/__init__.py`):
scan arguments before the tool runs, scan the result before it returns, and surface
`result.blocked` as a refusal. Planned adapters:

- **FastMCP 3.x middleware** (`on_call_tool` hook) for servers you control.
  ⚠️ The FastMCP 1.x bundled in the official `mcp` SDK (`mcp.server.fastmcp`) has
  **no middleware system** — servers built on it (e.g. dalgo-mcp as of mid-2026)
  need either a migration to standalone FastMCP or a tool-wrapper shim that
  decorates each registered tool function.
- **Standalone proxy** that fronts upstream MCP servers you can't modify, mirroring
  their tools 1:1 (no `run_tool` meta-tool — native discovery UX is preserved).

## Open-source guarantee

All tiers, including planned ones, must be self-hostable with OSS components:
Presidio/spaCy for NER, local models (Ollama/vLLM) for the LLM tier. No feature may
require a proprietary service. See CONTRIBUTING.md for the dependency policy.
