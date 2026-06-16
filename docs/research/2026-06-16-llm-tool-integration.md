# LLM-tool integration — June 2026

> Deep-research report: how mcp-kavach plugs into the major coding/agent tools,
> where each leaks, and whether one interception surface covers them all.
> 5 angles, 23 sources, 101 claims extracted, 25 verified (**24 confirmed,
> 1 killed**). Mid-2026 snapshot; per-tool capabilities are version-dependent
> and move fast. Builds on
> [universal-positioning](2026-06-15-universal-positioning.md) and the
> [landscape report](2026-06-12-landscape-and-roadmap.md).

## Headline

**Yes — there is a universal interception surface, and it's two proxies, not nine plugins.**

1. **Egress LLM-API proxy** on the `*_BASE_URL` / `HTTP(S)_PROXY` env vars covers **typed prompts** for nearly every tool at once.
2. **Masking MCP proxy** (kavach already has this) covers **tool traffic** for every tool that speaks MCP.

Together they deliver "one guard, both doors, *any* tool." The gap is real: **no major tool redacts PII/secrets before sending to the provider.** But the egress idea is **not greenfield** — at least three OSS projects already do egress redaction across these same tools, so the differentiator is the *unified engine*, not the surface.

## The universal surface (confirmed)

A local proxy set via the base-URL / proxy env vars intercepts outbound LLM traffic for nearly every coding agent. This is proven prior-art across **14+ tools**:

- **claude-tap** rewrites `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` / `ANTHROPIC_BEDROCK_BASE_URL` to `127.0.0.1` (reverse-proxy) or injects `HTTPS_PROXY`/`HTTP_PROXY` into the child (forward-proxy) — across Claude Code, Codex CLI, Gemini CLI, Cursor CLI, and more. (Tap only — redacts auth headers, *not* bodies — so it proves interception, not masking.)
- **claude-code-redact**, **AegisGate**, **AI Security Gateway** independently implement the *same* base-URL pattern **with redaction**.

**Reversible tokenization at the egress works** and preserves model coherence: claude-code-redact maps a value to a deterministic token (SHA-256), keeps the reverse map *in proxy memory only* (no disk), redacts before transmission, un-redacts the response locally. This is exactly kavach's vault concept, applied at the API egress instead of the MCP layer.

> ⚠️ One overreach was **refuted 0-3**: that a base-URL proxy captures "everything" for Claude Code/OpenCode. It doesn't — coverage is broad but not total. Don't market it as capturing all traffic.

## Per-tool integration matrix

| Tool | Speaks MCP | Hooks/plugins | Base-URL / proxy egress | Built-in PII redaction | kavach today |
|---|---|---|---|---|---|
| **Claude Code** | ✅ | ✅ UserPromptSubmit/Pre/PostToolUse | ✅ `ANTHROPIC_BASE_URL` | ❌ | ✅ **plugin shipped** + MCP proxy |
| **Codex CLI** | ✅ `[mcp_servers.*]` | ✅ Pre/PostToolUse (guardrail, not full boundary) | ✅ `openai_base_url` (needs `/v1`) | ❌ (only env-var/file exclusion) | ✅ MCP proxy today; hooks + egress = small build |
| **Cline** | ✅ | partial | ✅ OpenAI-compatible Base URL field | ❌ | ✅ via MCP proxy / egress |
| **Continue** | ✅ | config | ✅ `apiBase: http://localhost:.../v1` | ❌ | ✅ via MCP proxy / egress |
| **Cursor** | ✅ | limited | ⚠️ traffic transits Cursor infra even with own key | ❌ (Privacy Mode = opt-out; `.cursorignore` best-effort) | ⚠️ MCP proxy; egress unclear |
| **GitHub Copilot** | partial | ❌ | ⚠️ BYOK yes; custom base URL was blocked (#7518, later added) — version-dependent | ❌ | ⚠️ version-dependent |
| **Gemini CLI / Aider / Windsurf** | mostly ✅ | varies | mostly ✅ (referenced via multi-tool proxies, not individually re-verified) | ❌ | likely via egress/MCP — **needs per-tool verification** |

(Cells marked "needs verification" were referenced through the multi-tool proxy support lists, not checked against each tool's own docs this pass — see open questions.)

## The gap kavach addresses (real, and honest about limits)

**No major tool redacts PII/secret content before sending to the provider** — confirmed for Cursor, Codex CLI, and Cline. What they offer instead:
- Cursor: Privacy Mode (training/retention opt-out) + best-effort `.cursorignore`.
- Codex: an OpenTelemetry `log_user_prompt=false` toggle, a `KEY/SECRET/TOKEN` glob that only controls which **env vars subprocesses inherit**, and filesystem deny-read for `.env`/SSH/AWS.
- Cline: nothing documented.

None of these is model-I/O redaction. (The "*only*" framing was 2-1, not unanimous, because file-exclusion exists — so say "no content redaction," not "no protection at all.") Data sent to providers persists in logs/retention (per the prior report: Anthropic 7-day, OpenAI 30-day + court-ordered retention).

## But the surface has competitors

The egress-redaction proxy is **not** a novel idea — it's an emerging category:
- **AegisGate** — drop-in proxy, OpenAI *and* Anthropic protocol (with conversion, so Claude Code routes through one proxy), 50+ PII categories, incremental streaming checks, named support for Cursor/Claude Code/Codex via base-URL + MCP + agent-skill. (~40★, existence-proof not battle-tested.)
- **AI Security Gateway** — OpenAI-SDK-compatible drop-in, Presidio 13 entity types + key/secret detectors, self-hosted Docker, streaming preserved. (~20★.)
- **claude-code-redact** — reversible in-memory tokenization, Claude Code-focused.

So this echoes the universal-positioning verdict: **individual capabilities exist; kavach's only defensible edge is the combination** — one Apache-2.0 engine, one policy language, one audit trail, one vault, applied across *all three* surfaces (Claude Code hooks + MCP proxy + egress API proxy). None of the above spans both the MCP tool-output layer and the prompt-egress layer with shared policy/audit/reversible-vault.

## Concrete integration plan

**Surface 1 — egress LLM-API proxy (NEW build).** A `kavach gateway` that speaks OpenAI `/v1` and Anthropic `/v1/messages`, runs the existing engine on request bodies (redact/tokenize) and un-redacts responses from the in-memory vault. Users point any tool at it via `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` / `HTTP_PROXY`. This single component delivers typed-prompt coverage for Codex, Cline, Continue, Gemini CLI, and more — reusing the engine, policies, and vault already built.

**Surface 2 — MCP masking proxy (SHIPPED).** Already wraps any MCP server; document registering it in Codex's `[mcp_servers.*]`, Cline, Continue, etc., not just Claude Code.

**Surface 3 — per-tool hooks (SHIPPED for Claude Code; cheap for Codex).** Codex's Pre/PostToolUse hooks mirror Claude Code's; the existing hook handlers port with mostly I/O-shape translation.

**Sequence:** document Surfaces 2+3 across tools *now* (zero/low code), build Surface 1 (the egress gateway) as the flagship that makes "any LLM tool" literally true.

## Risks (read honestly)

- **Engineering:** streaming/SSE must be intercepted incrementally (doable — AegisGate/AISG prove it — but non-trivial); a self-signed proxy cert needs `NODE_EXTRA_CA_CERTS` or plain `http://localhost` (SDKs reject untrusted TLS); base-URL env vars are read once at process start; Codex's `openai_base_url` must include `/v1`.
- **Competitive:** AegisGate and AI Security Gateway already occupy this surface; "parity is one PR away" applies here too.
- **Platform:** tools adding native redaction, or fully-closed tools (Cursor relays through its own infra) with no clean local interception point.
- **Overclaim:** the egress proxy does *not* capture "everything" (refuted) — be precise about coverage per tool.

## Open questions
1. Concrete per-tool keys for **Gemini CLI, Aider, Windsurf** (MCP? base-URL? hooks?) — inferred from multi-tool proxy lists, not individually verified.
2. Does **Cursor** expose a real configurable base URL, or only its own backend relay? Are MCP/hooks a cleaner kavach surface there?
3. How robust is reversible egress tokenization under **function-calling / structured-output** payloads across OpenAI Responses vs Anthropic Messages?
4. Current (2026) state of **Copilot** custom-endpoint support (#7518 closed, capability version-dependent).

## Key sources
- https://github.com/liaohch3/claude-tap (primary) · https://github.com/paroque28/claude-code-redact (primary)
- https://github.com/ax128/AegisGate · https://github.com/aisecuritygateway/aisecuritygateway (primary)
- https://developers.openai.com/codex/config-advanced · /codex/mcp · /codex/hooks · /codex/agent-approvals-security (primary)
- https://docs.cline.bot/provider-config/openai-compatible · https://docs.continue.dev/customize/model-providers/top-level/openai (primary)
- https://cursor.com/help/security-and-privacy/privacy (primary)
- https://github.com/microsoft/vscode-copilot-release/issues/7518 (primary, time-sensitive)
- https://blog.logrocket.com/build-local-ai-proxy-redact-pii-before-llms/ (blog)
