"""Apply resolved actions to leaf values.

Overlapping findings on one leaf are clustered (transitive overlap) and the
cluster takes the highest-severity action over the union extent — naive
sequential replacement would corrupt offsets. Replacements are applied
right-to-left so earlier offsets stay valid.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from mcp_kavach.models import SEVERITY, Action, Finding


class TokenVault(Protocol):
    """What the transformer needs from a vault — see mcp_kavach.vault."""

    def token_for(self, entity_type: str, value: str) -> str: ...

# Entities where keeping the last 4 digits preserves enough signal for a
# human to confirm identity without exposing the value.
_KEEP_LAST4 = {"PHONE", "AADHAAR", "CREDIT_CARD", "BANK_ACCOUNT", "GOVT_ID"}


@dataclass
class Cluster:
    start: int
    end: int
    action: Action
    lead: Finding  # highest-severity finding; supplies entity/rule for the marker


def merge_clusters(findings: list[Finding]) -> list[Cluster]:
    """Cluster transitively-overlapping findings for a single leaf."""
    actionable = sorted(
        (f for f in findings if f.resolved_action is not Action.ALLOW),
        key=lambda f: f.span.start,
    )
    clusters: list[Cluster] = []
    for f in actionable:
        if clusters and f.span.start < clusters[-1].end:
            cluster = clusters[-1]
            cluster.end = max(cluster.end, f.span.end)
            if _rank(f) > _rank(cluster.lead):
                cluster.action = f.resolved_action
                cluster.lead = f
        else:
            clusters.append(Cluster(f.span.start, f.span.end, f.resolved_action, f))
    return clusters


def _rank(f: Finding) -> tuple[int, float]:
    return (SEVERITY[f.resolved_action], f.span.confidence)


def partial_mask(value: str, entity_type: str) -> str:
    if entity_type == "EMAIL":
        local, _, domain = value.partition("@")
        if domain:
            return (local[:1] or "*") + "***@" + domain
        return f"[MASKED:{entity_type}]"
    if entity_type in _KEEP_LAST4:
        out: list[str] = []
        digits_kept = 0
        for ch in reversed(value):
            if ch.isdigit():
                digits_kept += 1
                out.append(ch if digits_kept <= 4 else "*")
            else:
                out.append(ch)
        return "".join(reversed(out))
    # No template that safely preserves anything — fall back to a full mask.
    return f"[MASKED:{entity_type}]"


def replacement_text(
    cluster: Cluster, original: str, policy_name: str, vault: TokenVault | None = None
) -> str:
    entity = cluster.lead.span.entity_type
    if cluster.action is Action.MASK:
        return f"[MASKED:{entity}]"
    if cluster.action is Action.TOKENIZE:
        if vault is None:  # fail-safe; the engine normally downgrades earlier
            return f"[MASKED:{entity}]"
        return vault.token_for(entity, original[cluster.start : cluster.end])
    if cluster.action is Action.REDACT:
        return "[REDACTED]"
    if cluster.action is Action.BLOCK:
        rule = cluster.lead.rule_id or "default"
        return f"[BLOCKED:{policy_name}/{rule}]"
    if cluster.action is Action.PARTIAL_MASK:
        return partial_mask(original[cluster.start : cluster.end], entity)
    raise ValueError(f"no replacement for action {cluster.action}")


def transform_text(
    text: str, findings: list[Finding], policy_name: str, vault: TokenVault | None = None
) -> str:
    """Apply all actionable findings to one string leaf."""
    for cluster in sorted(merge_clusters(findings), key=lambda c: c.start, reverse=True):
        rep = replacement_text(cluster, text, policy_name, vault)
        text = text[: cluster.start] + rep + text[cluster.end :]
    return text


def transform_whole_value(
    value: object,
    findings: list[Finding],
    policy_name: str,
    vault: TokenVault | None = None,
) -> object:
    """Replace a non-string leaf entirely. Returns a marker string — the
    JSON type change is intentional and documented in the threat model:
    legibility for the model beats schema purity here."""
    lead = max(
        (f for f in findings if f.resolved_action is not Action.ALLOW),
        key=_rank,
        default=None,
    )
    if lead is None:
        return value
    cluster = Cluster(0, len(str(value)), lead.resolved_action, lead)
    return replacement_text(cluster, str(value), policy_name, vault)
