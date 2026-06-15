"""Guardrail engine: walk a tool payload, detect, resolve policy, transform.

Transport-agnostic by design — payloads are plain Python values
(dict/list/str/scalars), never MCP SDK types, so an MCP middleware or proxy
adapter only needs to call scan_request()/scan_result() around a tool call.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import secrets as _secrets
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from typing import Any, Literal

from mcp_kavach.audit import AuditSink, hmac_value
from mcp_kavach.detectors import ALL_DETECTORS, STRUCTURAL_DETECTORS, Detector
from mcp_kavach.detectors.base import StructuralDetector
from mcp_kavach.detectors.ner import NER_ENTITY_TYPES, NER_ONLY_ENTITY_TYPES
from mcp_kavach.detectors.normalize import normalize_digits
from mcp_kavach.models import (
    Action,
    AuditEvent,
    Finding,
    FlowEvent,
    GuardrailResult,
    PathTuple,
    Span,
)
from mcp_kavach.pathmatch import CompiledPath, compile_path, render_path
from mcp_kavach.policy.schema import Policy, Rule
from mcp_kavach.transform import TokenVault, transform_text, transform_whole_value

logger = logging.getLogger("mcp_kavach")

_SCANNABLE = (str, int, float)  # bool is excluded explicitly (it subclasses int)


class Engine:
    def __init__(
        self,
        policy: Policy,
        *,
        sink: AuditSink | None = None,
        hmac_salt: bytes | None = None,
        extra_detectors: Iterable[Detector] = (),
        extra_structural: Iterable[StructuralDetector] = (),
        vault: TokenVault | None = None,
        monitor: bool = False,
        monitor_payloads: Literal["masked"] | None = None,
    ) -> None:
        if monitor_payloads not in (None, "masked"):
            raise ValueError(f"monitor_payloads must be 'masked' or None, got {monitor_payloads!r}")
        self.policy = policy
        self.sink = sink
        self.vault = vault
        self.monitor = monitor
        self.monitor_payloads = monitor_payloads
        self._warned_no_vault = False
        salt = hmac_salt or os.environ.get("KAVACH_HMAC_SALT", "").encode() or None
        if salt is None:
            salt = _secrets.token_bytes(32)
            logger.warning(
                "KAVACH_HMAC_SALT not set; using a random per-instance salt — "
                "audit HMACs will not correlate across runs"
            )
        self._salt = salt
        self._detectors = [*ALL_DETECTORS, *extra_detectors]
        self._structural = [*STRUCTURAL_DETECTORS, *extra_structural]
        self._match_rules: list[tuple[Rule, CompiledPath]] = [
            (r, compile_path(r.match.json_path)) for r in policy.rules if r.match
        ]
        self._entity_rules = [r for r in policy.rules if r.entities]
        if policy.defaults.unknown_entity_action is Action.ALLOW:
            # Only in allow-mode is it safe to skip detectors the policy
            # never acts on; otherwise everything must be found to be
            # default-masked (fail closed).
            covered = {e for r in self._entity_rules for e in r.entities}
            self._detectors = [d for d in self._detectors if d.entity_type in covered]
            self._covered_structural_entities = covered
        else:
            self._covered_structural_entities = None
        self._ner_entities = self._ner_wanted()
        self._ner: Detector | None = None
        self._ner_loaded = False

    # -- public API ---------------------------------------------------------

    def scan_result(
        self, tool_name: str, payload: Any, context: dict | None = None
    ) -> GuardrailResult:
        """Scrub a tool result before it reaches the model."""
        return self._scan(tool_name, payload, "result")

    def scan_request(
        self, tool_name: str, args: Any, context: dict | None = None
    ) -> GuardrailResult:
        """Scrub tool arguments before they reach the tool."""
        return self._scan(tool_name, args, "request")

    # -- pipeline -----------------------------------------------------------

    def _scan(
        self, tool: str, payload: Any, direction: Literal["request", "result"]
    ) -> GuardrailResult:
        findings: list[Finding] = []
        leaf_text: dict[PathTuple, str] = {}

        for path, value in _walk(payload):
            scannable = isinstance(value, _SCANNABLE) and not isinstance(value, bool)
            text = value if isinstance(value, str) else str(value)
            if scannable:
                leaf_text[path] = text

            # Tier 0: structural policy rules pin an action by path alone.
            pinned = self._match_path_rule(tool, path)
            if pinned is not None:
                if pinned.action is Action.BLOCK and pinned.scope == "result":
                    blocked = self._blocked(tool, direction, pinned, path, text, findings)
                    return self._flow(tool, direction, payload, blocked)
                findings.append(
                    Finding(
                        span=Span(0, len(text), "STRUCTURAL", 1.0, 0, "policy_match"),
                        path=path,
                        resolved_action=self._effective(pinned.action),
                        rule_id=pinned.id,
                    )
                )

            if not scannable:
                continue

            # Tier 0: structural detectors (column-name heuristics).
            spans = [s for d in self._structural for s in d.detect_node(path, value)]
            # Tier 1: regex detectors over the leaf text. Unicode digits are
            # normalized to ASCII first — a 1:1, length-preserving mapping, so
            # the spans index correctly into the original `text`, which is
            # what the transformer rewrites (and the audit HMAC hashes).
            ascii_text = normalize_digits(text)
            spans += [s for d in self._detectors for s in d.detect(ascii_text)]
            # Tier 2: NER over free text — no-op unless the [ner] extra is
            # installed and the policy needs it (see _ner_wanted). Sees the
            # same digit-normalized copy so its context recognizers match
            # Indic-script numbers; offsets stay valid (length-preserving).
            if isinstance(value, str):
                spans += self._ner_spans(ascii_text)

            for span in spans:
                if span.confidence < self.policy.defaults.min_confidence:
                    continue
                if (
                    self._covered_structural_entities is not None
                    and span.tier == 0
                    and span.entity_type not in self._covered_structural_entities
                ):
                    continue
                action, rule = self._resolve(span.entity_type)
                if action is Action.BLOCK and rule is not None and rule.scope == "result":
                    blocked = self._blocked(tool, direction, rule, path, text, findings, span)
                    return self._flow(tool, direction, payload, blocked)
                findings.append(
                    Finding(
                        span=span,
                        path=path,
                        resolved_action=self._effective(action),
                        rule_id=rule.id if rule else None,
                    )
                )

        events = [self._event(tool, direction, f, leaf_text) for f in findings]
        new_payload = _rebuild(payload, (), _group(findings), self.policy.name, self.vault)
        for event in events:
            self._emit(event)
        result = GuardrailResult(payload=new_payload, events=events)
        return self._flow(tool, direction, payload, result)

    def _ner_wanted(self) -> frozenset[str]:
        """Entities the NER tier should look for; empty disables the tier.

        Mirrors the detector pruning above: in allow-mode only entities the
        policy acts on are kept. With defaults.ner: auto, the tier stays off
        unless that leaves an entity tiers 0-1 can't find in free text.
        """
        mode = self.policy.defaults.ner
        if mode is False:
            return frozenset()
        wanted = NER_ENTITY_TYPES
        if self._covered_structural_entities is not None:
            wanted &= self._covered_structural_entities
        if mode == "auto" and not wanted & NER_ONLY_ENTITY_TYPES:
            return frozenset()
        return frozenset(wanted)

    def _ner_spans(self, text: str) -> list[Span]:
        if not self._ner_loaded:
            self._ner_loaded = True  # one load attempt per engine
            if self._ner_entities:
                from mcp_kavach.detectors.ner import load_ner_detector

                self._ner = load_ner_detector(self._ner_entities)
        return self._ner.detect(text) if self._ner is not None else []

    def _match_path_rule(self, tool: str, path: PathTuple) -> Rule | None:
        from mcp_kavach.pathmatch import matches

        for rule, compiled in self._match_rules:
            if fnmatch.fnmatch(tool, rule.match.tool) and matches(compiled, path):
                return rule  # first match wins, in policy file order
        return None

    def _effective(self, action: Action) -> Action:
        """Fail-safe: tokenize needs a vault; without one, degrade to mask
        so the value is still hidden (just not consistently or reversibly).
        Findings and audit events record the action actually applied."""
        if action is Action.TOKENIZE and self.vault is None:
            if not self._warned_no_vault:
                self._warned_no_vault = True
                logger.warning(
                    "policy %r uses action 'tokenize' but no vault is configured; "
                    "falling back to 'mask' — pass Engine(vault=Vault(...)) or "
                    "use --vault to enable consistent tokens",
                    self.policy.name,
                )
            return Action.MASK
        return action

    def _resolve(self, entity_type: str) -> tuple[Action, Rule | None]:
        for rule in self._entity_rules:
            if entity_type in rule.entities:
                return rule.action, rule  # first match wins, in policy file order
        return self.policy.defaults.unknown_entity_action, None

    def _blocked(
        self,
        tool: str,
        direction: Literal["request", "result"],
        rule: Rule,
        path: PathTuple,
        text: str,
        findings: list[Finding],
        span: Span | None = None,
    ) -> GuardrailResult:
        span = span or Span(0, len(text), "STRUCTURAL", 1.0, 0, "policy_match")
        finding = Finding(span=span, path=path, resolved_action=Action.BLOCK, rule_id=rule.id)
        reason = rule.message or (
            f"{direction} withheld by policy {self.policy.name!r} (rule {rule.id!r})"
        )
        events = [
            self._event(tool, direction, f, {path: text}) for f in [*findings, finding]
        ]
        for event in events:
            self._emit(event)
        return GuardrailResult(
            payload={
                "error": "blocked by mcp-kavach",
                "policy": self.policy.name,
                "rule": rule.id,
                "message": reason,
            },
            blocked=True,
            block_reason=reason,
            events=events,
        )

    def _event(
        self,
        tool: str,
        direction: Literal["request", "result"],
        f: Finding,
        leaf_text: dict[PathTuple, str],
    ) -> AuditEvent:
        text = leaf_text.get(f.path, "")
        return AuditEvent(
            ts=datetime.now(timezone.utc),
            policy=self.policy.name,
            tool=tool,
            direction=direction,
            entity_type=f.span.entity_type,
            tier=f.span.tier,
            confidence=f.span.confidence,
            rule_id=f.rule_id,
            action=f.resolved_action,
            json_path=render_path(f.path),
            start=f.span.start,
            end=f.span.end,
            value_hmac=hmac_value(self._salt, text[f.span.start : f.span.end]),
        )

    def _flow(
        self,
        tool: str,
        direction: Literal["request", "result"],
        payload: Any,
        result: GuardrailResult,
    ) -> GuardrailResult:
        """Emit one flow event per scanned payload when monitoring is on.
        With monitor_payloads="masked" it carries the POST-transform payload
        (what actually crossed) — for a block, that is just the block marker."""
        if not self.monitor or self.sink is None:
            return result
        leaf_count = chars = 0
        for _, value in _walk(payload):
            leaf_count += 1
            if isinstance(value, _SCANNABLE) and not isinstance(value, bool):
                chars += len(value if isinstance(value, str) else str(value))
        masked = None
        if self.monitor_payloads == "masked":
            out = result.payload
            if not isinstance(out, str):
                out = json.dumps(out, ensure_ascii=False, default=str)
            masked = out
        self.sink.emit(
            FlowEvent(
                ts=datetime.now(timezone.utc),
                policy=self.policy.name,
                tool=tool,
                direction=(
                    "prompt"
                    if tool == "UserPromptSubmit"
                    else "tool_input" if direction == "request" else "tool_output"
                ),
                payload_chars=chars,
                leaf_count=leaf_count,
                findings_count=len(result.events),
                actions=tuple(sorted({e.action.value for e in result.events})),
                payload_masked=masked,
            )
        )
        return result

    def _emit(self, event: AuditEvent) -> None:
        if self.sink is not None:
            self.sink.emit(event)


def _walk(node: Any, path: PathTuple = ()) -> Iterator[tuple[PathTuple, Any]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, (*path, key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _walk(value, (*path, i))
    else:
        yield path, node


def _group(findings: list[Finding]) -> dict[PathTuple, list[Finding]]:
    grouped: dict[PathTuple, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.path, []).append(f)
    return grouped


def _rebuild(
    node: Any,
    path: PathTuple,
    findings_by_path: dict[PathTuple, list[Finding]],
    policy_name: str,
    vault: TokenVault | None = None,
) -> Any:
    """Recreate the payload with transformations applied — never mutates."""
    if isinstance(node, dict):
        return {
            k: _rebuild(v, (*path, k), findings_by_path, policy_name, vault)
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [
            _rebuild(v, (*path, i), findings_by_path, policy_name, vault)
            for i, v in enumerate(node)
        ]
    findings = [
        f for f in findings_by_path.get(path, []) if f.resolved_action is not Action.ALLOW
    ]
    if not findings:
        return node
    if isinstance(node, str):
        return transform_text(node, findings, policy_name, vault)
    return transform_whole_value(node, findings, policy_name, vault)
