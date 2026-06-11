"""Human-readable summaries of detections for hook messages.

Previews use partial_mask so the message itself never re-exposes the value.
"""

from __future__ import annotations

from mcp_kavach.models import Action, AuditEvent
from mcp_kavach.transform import partial_mask


def summarize_events(events: list[AuditEvent], text: str | None = None) -> str:
    """E.g. 'EMAIL (l***@example.org), PHONE (******3210)'."""
    by_entity: dict[str, str] = {}
    for e in events:
        if e.action is Action.ALLOW or e.entity_type in by_entity:
            continue
        preview = ""
        if text is not None and e.json_path == "$":
            masked = partial_mask(text[e.start : e.end], e.entity_type)
            if not masked.startswith("[MASKED"):
                preview = masked
        by_entity[e.entity_type] = preview
    return ", ".join(
        f"{entity} ({preview})" if preview else entity
        for entity, preview in sorted(by_entity.items())
    )
