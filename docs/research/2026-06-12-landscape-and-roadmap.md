# Landscape research & roadmap — June 2026

> Deep-research report: 5 search angles, 23 sources fetched, 109 claims extracted,
> 25 claims adversarially verified by 3-vote panels (19 confirmed, 6 refuted).
> Findings below cite only claims that survived verification; refuted claims are
> listed at the end so they don't silently re-enter our messaging.
> **Snapshot warning:** this space is consolidating fast (Snyk acquired Invariant
> June 2025; Portkey's MCP Gateway launched Jan 2026; IBM ContextForge hit GA
> May 2026). Figures will stale within months.

## Executive summary

The MCP-layer enforcement bet is sound and independently validated: Lasso's
mcp-gateway, Invariant's mcp-scan/Guardrails (now Snyk), IBM ContextForge, and
Portkey's new MCP Gateway all converged on intercepting MCP traffic with pre/post
hooks. But every one of them is either a centralized enterprise gateway,
cloud-API-gated for its strongest protections, or focused on behavioral threats
(prompt injection) rather than data minimization.

virelia's defensible niche is the **fully-local, Apache-2.0, end-to-end stack**:
India-specific checksum-validated detectors (absent from every competitor
surveyed, including ContextForge's PIIFilterPlugin — zero code hits for
luhn/aadhaar/verhoeff), tiered YAML policy actions, and a salted-HMAC audit log,
aimed at sovereignty-sensitive and DPDP-bound deployments.

## Landscape

| Tool | Layer | Detection | Masking / reversibility | Model | Traction (Jun 2026) |
|---|---|---|---|---|---|
| **Lasso mcp-gateway** | MCP proxy (multi-server orchestrator, not 1:1 wrapper) | Local regex secret masking + Presidio PII plugin; strongest guardrails (injection, custom policy) gated behind `LASSO_API_KEY` cloud calls | Masking, no reversibility | MIT core + commercial cloud | ~376★ |
| **Invariant mcp-scan / Guardrails** (Snyk) | MCP client scanner + transparent gateway proxy (stdio/SSE/HTTP) | Python-inspired DSL rules, behavior-focused (prompt injection, banned content); `pii()` rule is detect-and-block only | Block, **no masking** | Apache-2.0; acquired by Snyk Jun 24 2025 | ~427★ (guardrails) |
| **IBM ContextForge** | Centralized MCP/A2A/REST gateway (Docker/K8s/Redis) | PIIFilterPlugin: regex for SSN/credit-card/email/phone, Rust-backed; **no checksum validation, no India IDs** | redact / partial / hash / tokenize strategies | Apache-2.0, GA v1.0.3 (Jun 10 2026) | ~3.9k★, 698 forks |
| **Portkey Gateway + MCP Gateway** | Hosted LLM gateway; MCP control plane launched Jan 21 2026 | 50+ advertised guardrails; launch blog claims PII redaction + compliance policies on MCP interactions | Hosted enterprise feature | MIT core + hosted | ~12k★ |
| **LiteLLM** | LLM gateway | Presidio Analyzer + Anonymizer (separate containers) | `output_parse_pii` rehydrates masked entities **per-request, in-memory** — pre_call mode only, known bugs (issues #6247, #22821) | OSS | large |
| **NeMo Guardrails** | LLM conversation rails | Presidio-backed sensitive-data rails | Built-ins limited to refuse or irreversible mask; custom actions possible | OSS (NVIDIA) | large |
| **Presidio** | Library (analyzer/anonymizer/structured/image) | NER + regex + checksum recognizers, context enhancement | Operators incl. encrypt (per-call, no cross-call consistency) | MIT | de-facto standard |

Verification notes: claims that mcp-scan's proxy already does PII detection
(0–3), that Portkey's *base* gateway commoditizes PII redaction (1–2), and that
NeMo leaves the tool-call layer unaddressed (0–3) were **refuted** — do not
assert them.

## Approach assessment

**The enforcement layer is right.** Four independent, funded teams arrived at
MCP-traffic interception with pre/post hooks. ContextForge's plugin framework
converged on the *exact* hook placement virelia uses — `prompt_pre/post_fetch`,
`tool_pre/post_invoke`, `resource_pre/post_fetch` — validating prompts, tool
inputs, and tool outputs as the correct MCP-lifecycle enforcement points
(implemented centrally there; client-side/local here).

**The tiered detection design matches research consensus.** arXiv 2510.07551
(Oct 2025): "Pure regex methods lack semantic understanding, while
transformer-based NER models suffer from limited PII type coverage" — distinct
failure modes that neither tier resolves alone, supporting structural rules +
checksum regex + NER layering. (The companion RECAP F1 numbers did not survive
verification; cite only the qualitative finding.)

**Off-the-shelf detection is measurably weak on Indian identifiers.** arXiv
2504.12308 (51k predictions across Presidio/Piiranha/Starpii on multi-geography
adversarial data): models detected no PII at all in 28% of aggregate cases
(inflated by Starpii; Presidio's span detection is far better at 1–9%
non-identification), but Presidio misclassified entity *type* in 82.0–92.3% of
cases per feature dimension — bank accounts labeled DATE/PERSON, UPI IDs labeled
EMAIL — partly because **no entity label exists for Indian types like UPI IDs or
vehicle registrations**. Caveats: non-peer-reviewed preprint, semi-synthetic
data. Implication either way: a plain Presidio NER tier is not a differentiator
(Lasso, LiteLLM, NeMo already wrap it) and is weak exactly where virelia's users
need it. India-tuned recognizers are the point.

## Gap analysis — what's genuinely unserved

1. **Fully-local, no-cloud-API, end-to-end OSS stack.** Every MCP-layer
   competitor is centralized-enterprise (ContextForge, Portkey), cloud-gated for
   its strongest protections (Lasso), or behavior-focused without masking
   (Invariant/Snyk). Nobody serves the developer-side, sovereignty-first
   deployment.
2. **India-specific checksummed detection.** Zero competitors ship
   Aadhaar/Verhoeff, PAN, IFSC, or GSTIN validation. This plus the measured
   Presidio weakness on Indian types is an open lane.
3. **Reversible, consistent tokenization at the MCP layer.** LiteLLM's
   per-request rehydration is the only partial precedent anywhere, and it's
   buggy and gateway-side. No MCP-layer tool offers a consistent-token vault.
4. **Audit/compliance reporting for AI data flows.** ContextForge has general
   observability; nobody produces a privacy-specific, hash-only audit trail
   designed to be shown to an auditor.
5. **DPDP mapping — unverified.** The DPDP research angle produced **no
   surviving verified claims** on what the 2025 Rules concretely require. The
   policy-pack recommendation currently rests on project context, not legal
   research. Commission a dedicated legal-requirements pass before building it.

## Prioritized roadmap (6–12 months)

**Double down — the differentiated core (now):**
- India ID coverage: GSTIN (#4), UPI/EPIC/Passport/ABHA (#8)
- Audit CLI + SQLite sink (#6) — the compliance story made tangible
- Adversarial corpus (#9) + Presidio benchmark (#10) — **elevate from p2 to
  p1**: no published India-PII benchmark exists; producing the first is both
  engineering QA and the project's strongest positioning asset
- DPDP requirements mapping (new issue) — legal-requirements research *before*
  the policy pack

**Ship with differentiation, not vanilla (next):**
- NER tier (#7) — only with India-tuned custom recognizers; plain Presidio is
  commoditized
- Consistent-token vault (#3) — the feature with no MCP-layer equivalent
  anywhere; LiteLLM's per-request rehydration is the only partial precedent

**Keep — the adoption wedge:**
- PyPI release (#1), demo GIF (#2), Claude Code plugin polish, Dalgo case study
  (#14) — the local-first developer wedge is the segment competitors ignore

**Deprioritize (v2 at best):**
- HTTP/SSE proxy mode (#11) and broad framework adapters (#12) — the
  centralized-gateway segment is owned by IBM and Portkey, who will outspend an
  OSS project there. Stay developer-side.

**Positioning statement:**
> The local-first, audit-ready PII guardrail for AI agents in
> sovereignty-sensitive and DPDP-regulated environments — checksum-validated
> India identifiers, tiered policies, and reversible tokenization, with no cloud
> API in the loop.

## Risks

- **Portkey encroachment (highest):** its Jan-2026 MCP Gateway launch blog
  already advertises PII redaction and compliance policies on MCP interactions.
  Mitigation: it's a hosted enterprise control plane; the local-first segment
  remains open.
- **Well-funded consolidation:** Snyk × Invariant, IBM ContextForge GA. The MCP
  security layer is being bought, not just built.
- **Platform absorption:** if the MCP spec or Anthropic ship native
  guardrail/PII hooks, the hook-guard layer compresses. The durable moats are
  the vault, the India detectors, and the audit trail — not the hooks.
- **Detection overconfidence:** the benchmark numbers above are from
  non-peer-reviewed preprints on semi-synthetic data; our own #9/#10 work is the
  fix, and the "Honest limitations" posture should continue.

## Open questions (next research passes)

1. What do the notified DPDP Rules 2025 concretely require (breach
   notification, consent artifacts, audit trails, cross-border transfer), and
   which virelia features map to which clauses?
2. Any signal that the MCP spec, Anthropic, or major MCP clients plan native
   guardrail/PII hooks?
3. Actual precision/recall of virelia's checksum tier vs Presidio-with-custom-
   recognizers on Indian identifiers (= the #9/#10 benchmark).
4. Demand-side validation: real-world appetite for local-first vs hosted MCP
   security among Indian NGOs / sovereignty-sensitive deployments (the Dalgo
   case study, #14, is the instrument). All verified claims measured supply,
   not demand.

## Refuted claims (do not assert)

| Claim | Vote |
|---|---|
| Lasso's local stack details (specific plugin composition as stated) | 0–3 |
| mcp-scan proxy already does PII detection on tool calls | 0–3 |
| Portkey base gateway commoditizes PII redaction | 1–2 |
| NeMo leaves the tool-call/MCP layer entirely unaddressed | 0–3 |
| RECAP hybrid beats fine-tuned NER by 82% (specific F1 figures) | 0–3 |
| Fine-tuned NER F1 0.360 across 13 locales (specific figure) | 1–2 |

## Key sources

- https://github.com/lasso-security/mcp-gateway (primary)
- https://github.com/invariantlabs-ai/mcp-scan · https://invariantlabs-ai.github.io/docs/mcp-scan/ (primary)
- https://github.com/invariantlabs-ai/invariant · https://labs.snyk.io/resources/snyk-labs-invariant-labs/ (primary)
- https://github.com/IBM/mcp-context-forge · https://ibm.github.io/mcp-context-forge/using/plugins/plugins/ (primary)
- https://github.com/portkey-ai/gateway · https://portkey.ai/blog/introducing-the-mcp-gateway/ (primary/vendor)
- https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2 · https://docs.litellm.ai/docs/tutorials/presidio_pii_masking (primary)
- https://docs.nvidia.com/nemo/guardrails/0.15.0/user-guides/community/presidio.html (primary; 0.15.0 URL now 404s — see GitHub docs path)
- arXiv 2510.07551 (Rajgarhia et al., Oct 2025) — regex/NER failure modes (preprint)
- arXiv 2504.12308 — multi-geography PII masker benchmark, 51k predictions (preprint)
- https://github.com/microsoft/presidio-research (primary)
- https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa (primary; no claims survived verification)
