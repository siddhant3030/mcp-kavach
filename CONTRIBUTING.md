# Contributing to mcp-kavach

## Development setup

```bash
git clone <repo-url> && cd mcp-kavach
uv sync          # installs the package editable + dev tools
uv run pytest    # full suite, including the golden corpus
uv run ruff check .
```

## Open-source-only dependency policy

Every aspect of this project must remain open source and self-hostable. Concretely:

1. **New dependencies must carry a permissive OSS license** (MIT, BSD, Apache-2.0).
   Check before adding; note the license in the PR description.
2. **No feature may require a proprietary service.** Optional integrations are fine
   only if a self-hosted/local path exists and is the default — e.g. the future LLM
   detector tier must work with local models (Ollama/vLLM), never be hard-wired to a
   commercial API.
3. **The base install stays light**: stdlib + pydantic + pyyaml. Anything heavier
   (NER models, OTel, proxy server) goes behind an extra (`mcp-kavach[ner]`, …).

## Adding a detector

1. Subclass `RegexDetector` in `src/mcp_kavach/detectors/` (or `StructuralDetector`
   for Tier-0 path/key-based detection). Use checksum gates in `validate()` where the
   entity has one, and digit-boundary lookarounds on every numeric pattern.
2. Register the instance in `detectors/__init__.py` (`ALL_DETECTORS` /
   `STRUCTURAL_DETECTORS`) — that also makes the entity name valid in policies.
3. Add positive *and negative* cases to `tests/test_detectors.py` (the negatives —
   substrings of longer digit runs, checksum failures — are the ones that matter).
4. If the entity warrants it, extend a golden-corpus fixture in
   `tests/fixtures/corpus/` with **synthetic** data only. Never commit a real
   identifier, even an expired one.

## Adding or changing policy presets

Presets live in `src/mcp_kavach/policies/` and ship as package data. Every preset must
load cleanly in `tests/test_policy.py::TestPresets` and any new behavior needs an
engine-level test.

## Privacy invariants (do not break)

- Audit events must never contain plaintext values — only `audit.hmac_value()` ever
  touches the raw string.
- The engine must never mutate the caller's payload.
- JSON keys and value types are never scanned or rewritten (whole-value replacement on
  non-string leaves is the one documented exception).
- Policy YAML is parsed with `yaml.safe_load` only.
