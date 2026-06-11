"""Tier 0 column-name detector.

Flags whole leaf values based on the name of the field that holds them —
the only way to catch free-text PII (Indian person names, addresses) without
an NER model. Pattern list ported from dalgo-mcp's pii.py and regrouped by
entity type. Confidence is moderate (0.6): a column *named* like PII usually
holds PII, but the value itself was never inspected.
"""

from __future__ import annotations

import re

from mcp_kavach.detectors.base import StructuralDetector
from mcp_kavach.models import PathTuple, Span

_COLUMN_ENTITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"aadha?ar", re.I), "AADHAAR"),
    (re.compile(r"pan.?(card|no|num)", re.I), "PAN"),
    (re.compile(r"ifsc", re.I), "IFSC"),
    (
        re.compile(
            r"passport|voter.?id|ration.?card|\bssn\b|social.?security"
            r"|national.?id|driving.?licen",
            re.I,
        ),
        "GOVT_ID",
    ),
    (re.compile(r"e.?mail", re.I), "EMAIL"),
    (re.compile(r"phone|mobile|telephone|whatsapp|contact", re.I), "PHONE"),
    (re.compile(r"name|guardian", re.I), "PERSON_NAME"),
    (re.compile(r"address|street|house.?no|pin.?code|zip.?code|postal", re.I), "ADDRESS"),
    (re.compile(r"account.?(no|num)|bank.?account|card.?number", re.I), "BANK_ACCOUNT"),
    (re.compile(r"date.?of.?birth|\bdob\b|birth.?date", re.I), "DOB"),
]

# Columns whose names merely *contain* a PII-ish word but conventionally
# hold non-personal values. Fail-closed bias means this list stays short.
_EXEMPT_KEYS = re.compile(
    r"^(file|host|tool|table|column|schema|field|model|repo|branch|package"
    r"|server|database|db|index|dataset|pipeline|chart|dashboard|report)[\s_.-]?name$",
    re.I,
)


class ColumnNameDetector(StructuralDetector):
    name = "column_name"

    def detect_node(self, path: PathTuple, value: object) -> list[Span]:
        key = next((seg for seg in reversed(path) if isinstance(seg, str)), None)
        if key is None or value is None or value == "":
            return []
        if _EXEMPT_KEYS.match(key):
            return []
        text = value if isinstance(value, str) else str(value)
        for pattern, entity_type in _COLUMN_ENTITY_PATTERNS:
            if pattern.search(key):
                return [
                    Span(
                        start=0,
                        end=len(text),
                        entity_type=entity_type,
                        confidence=0.6,
                        tier=self.tier,
                        detector=self.name,
                    )
                ]
        return []

    def entity_types(self) -> frozenset[str]:
        return frozenset(entity for _, entity in _COLUMN_ENTITY_PATTERNS)
