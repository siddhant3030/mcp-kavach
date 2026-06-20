# Universal positioning — June 2026

> Deep-research report (second pass), framed deliberately AWAY from India/DPDP.
> 5 search angles, 22 sources fetched, 108 claims extracted, 25 adversarially
> verified — **25 confirmed, 0 killed**. The brief explicitly instructed the
> researchers to say so plainly if the universal positioning is weak. It is.
> Mid-2026 snapshot; this space moves monthly.

## The uncomfortable headline

**The universal positioning is weaker than the [prior India-centric report](2026-06-12-landscape-and-roadmap.md) claimed.** Nearly every individual capability virelia has is *already shipped* by a free, local-first, model-agnostic open-source competitor. The reversible tokenization we previously called "near-unique" is **not** unique on the prompt side — two MIT-licensed tools do it today.

This does not mean the project is pointless. It means the honest differentiator is narrow and specific, and the marketing line has to change.

## 1. The problem is real (this part holds up)

Secrets and PII routinely enter LLM prompts and agent tool traffic, reach providers, and persist in logs:

- **Snyk** scanned the entire ClawHub skills marketplace: **283 of 3,984 skills (7.1%) had critical credential/PII flaws**; data is sent to providers and persists in verbose logs and conversation history. [snyk.io](https://snyk.io/blog/openclaw-skills-credential-leaks-research/)
- Retention is real and not always under your control: **Anthropic 7-day, OpenAI 30-day**, plus a **June 2025 US court order requiring OpenAI to retain even deleted chats**.
- Independent reporting: **~26% of uploads to GenAI tools contain sensitive data** (up >4 points in three months). [financialcontent](https://markets.financialcontent.com/winslow/article/bizwire-2025-11-13-over-a-quarter-26-of-uploads-to-genai-tools-contain-sensitive-data), [cyberhaven](https://www.cyberhaven.com/blog/sensitive-data-flowing-into-ai-tools)

People recognize this pain and are building tools for it. That's the good news and the bad news — the demand is validated, and so the supply has arrived.

## 2. Capability matrix — what already exists

Scored on the seven properties that define virelia's pitch:

| Tool | Local-first | Model-agnostic | Masks (not just detect) | Covers typed prompts | Covers any MCP server | Reversible tokens | OSS + free |
|---|---|---|---|---|---|---|---|
| **virelia** | ✅ | ✅ | ✅ | ✅ (Claude Code hooks) | ✅ (proxy) | ✅ (vault + rehydrate) | ✅ Apache-2.0 |
| **ceil-dlp** (MIT) | ✅ | ✅ | ✅ | ✅ | ❌ LiteLLM-bound, no native MCP | ✅ rehydrates | ✅ |
| **LLM Guard** (MIT, ProtectAI) | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Vault + Deanonymize | ✅ |
| **Prompt Armour** | ✅ client-side | ✅ web chats | ✅ | ✅ browser only | ❌ | partial | extension (closed, ~36 users) |
| **mcp-server-conceal** | ✅ | ✅ | ✅ | ❌ | ✅ wraps any MCP server | ❌ **one-way only** | ✅ |
| **Lasso mcp-gateway** | ✅ (base/Presidio tier) | ✅ | ✅ Presidio | ❌ | ✅ | ❌ no rehydration | core OSS, strong tiers cloud-gated |
| **LiteLLM Presidio** | ✅ | ✅ | ✅ | ✅ (proxy) | ✅ `pre_mcp_call` hook | ⚠️ restores, but generic non-unique tokens, per-request, no vault, bugs #6247/#22821 | ✅ |
| **Snyk Agent Scan** (ex-mcp-scan) | ❌ cloud token | ✅ | ❌ **scan only** | ❌ | scan | ❌ | cloud-gated |

Key distinctions the research sharpened:
- **scan/alert ≠ block ≠ mask/transform.** Snyk Agent Scan only *scans* (injection/poisoning/malware) and needs a cloud token. It is not a redaction competitor.
- **one-way pseudonymization ≠ reversible tokenization.** `mcp-server-conceal` gives consistent placeholders but the mapping is deliberately **one-way** — the tool result can never be un-masked. That may be a feature for some users, but it's not rehydration.
- **per-request restore ≠ a vault.** LiteLLM restores PII in responses but with generic, non-unique tokens, per-request, no persistent store — so it can't keep "the same person" stable across calls.

## 3. Where this AGREES and DISAGREES with the prior report

- **DISAGREES** — prior report said reversible tokenization was "near-unique" and "the feature with no equivalent anywhere." On the **prompt side that is false**: ceil-dlp and LLM Guard both do reversible anonymization today, MIT-licensed. Don't market the vault as unique in general.
- **AGREES** — at the **MCP layer specifically**, reversible tokenization with rehydration still has no clean equivalent (conceal is one-way; Lasso has none; LiteLLM is per-request/non-unique). The prior "gap 3" survives, but only when scoped tightly to MCP.
- **AGREES** — the MCP-layer enforcement bet is sound; multiple funded teams converged on it.
- **NEW** — the India/DPDP detectors are still genuinely absent from all these competitors. That's now reframed: not the *reason to exist*, but a real *secondary* edge for whoever needs it.

## 4. The one genuinely-unserved thing

> **No single tool covers BOTH typed prompts AND any-transport MCP tool traffic, in one local-first Apache-2.0 engine, with reversible tokenization on both surfaces.**

Each rival covers a subset:
- prompts + reversible, but no MCP → ceil-dlp, LLM Guard
- any MCP server + masking, but one-way / no prompt side → conceal, Lasso
- both surfaces but weak reversibility and buggy → LiteLLM

virelia is the only one that (claims to) do all of it with one policy engine and one audit trail. **That is the line — but it's an "absence" argument** (nobody else bundles all seven), which is the weakest kind of moat. See risks.

## 5. Positioning (no India, no DPDP)

> **An open-source, fully-local guardrail that masks personal data and secrets in both your typed LLM prompts *and* any MCP server's tool traffic — with reversible tokenization so the model still reasons over consistent placeholders, and nothing leaves your machine to a cloud redactor.**

The two-word version: **one guard, both doors** — what you type, and what your tools return.

### Personas who feel this most
1. **The privacy-conscious individual developer** on a CLI/IDE who pastes logs, DB dumps, and customer data into Claude/ChatGPT and wants a local net — without trusting another SaaS to see it first.
2. **The self-hoster** wrapping their own or third-party MCP servers, who needs tool *outputs* (DB rows, file contents, API responses) scrubbed before the agent sees them.
3. **The small team** that needs a hash-only audit trail of what categories of data crossed toward a model — without standing up an enterprise gateway.

## 6. Risks to this positioning (read these honestly)

- **Parity is one PR away.** conceal could add rehydration; LiteLLM already ships an MCP guardrail hook; ceil-dlp / LLM Guard already commoditize prompt-side reversibility. The "only one that combines all" claim could evaporate in a weekend.
- **Platform absorption.** Native PII hooks in the MCP spec, or built-in redaction from Anthropic/OpenAI, would compress the hook-guard layer. **OpenAI already launched an open-source on-device data-sanitization "Privacy Filter" model** ([venturebeat](https://venturebeat.com/data/openai-launches-privacy-filter)) — the platforms are moving into this space.
- **"Combines all" is an absence argument**, not a capability rivals *can't* match. Moats built on "nobody else bundles this yet" are temporary.
- **Some of our edge is recent/unproven.** The combination needs to actually work end-to-end and be demonstrated, or it's just a feature list.

## 7. So what should change

1. **Drop "unique reversible tokenization" from any general claim.** Keep it only scoped to the MCP layer, and lead with the *combination*, not the feature.
2. **Make "one guard, both doors" the headline** — the dual-surface coverage (prompts + MCP) under one policy/audit engine is the true, if narrow, differentiator. Prove it with a single demo that shows the same policy catching a typed prompt AND a tool result.
3. **Treat India/DPDP detectors as a bundled bonus**, not the identity — exactly as you wanted.
4. **Move fast on the combination and on polish** (install, demo, docs), because the technical moat is thin and time-sensitive. Adoption and being the obvious, well-documented default matters more than any single feature here.
5. **Watch the platforms.** If MCP or the model vendors ship native redaction, pivot toward what they won't: the local-first audit trail, the cross-surface policy, and reversibility.

## Caveats on this research
Prompt Armour's "100% client-side" claim is unaudited solo-dev self-attestation (~36 users). Lasso's breadth is vendor-published. ContextForge / Portkey / NeMo were not re-verified this pass (covered in the prior report). No demand-side evidence was gathered — this measured *supply* (what exists), not *demand* (whether users want one tool vs several). Two arXiv/blog sources are non-peer-reviewed.

## Sources
- https://snyk.io/blog/openclaw-skills-credential-leaks-research/ (primary)
- https://github.com/dorcha-inc/ceil-dlp (primary) · arXiv 2511.13319
- https://protectai.com/llm-guard · https://github.com/protectai/llm-guard/blob/main/docs/output_scanners/deanonymize.md (primary)
- https://chromewebstore.google.com/detail/prompt-armour (primary)
- https://github.com/gbrigandi/mcp-server-conceal (primary)
- https://github.com/lasso-security/mcp-gateway (primary)
- https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2 (primary)
- https://github.com/invariantlabs-ai/mcp-scan (primary)
- https://venturebeat.com/data/openai-launches-privacy-filter (secondary)
- https://www.helpnetsecurity.com/2026/05/01/open-source-pii-privacy-proxy/ (secondary)
- https://www.cyberhaven.com/blog/sensitive-data-flowing-into-ai-tools (secondary)
- https://markets.financialcontent.com/winslow/article/bizwire-2025-11-13-over-a-quarter-26-of-uploads-to-genai-tools-contain-sensitive-data (secondary)
