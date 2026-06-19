"""Regex detector base. Patterns compile at import; ``validate`` lets a
subclass gate candidates with a checksum or adjust confidence."""

from __future__ import annotations

import re
from typing import ClassVar

from virelia.detectors.base import Detector
from virelia.models import Span


class RegexDetector(Detector):
    pattern: ClassVar[re.Pattern[str]]
    confidence: ClassVar[float] = 0.9

    def validate(self, match: re.Match[str]) -> float | None:
        """Return the confidence for this match, or None to reject it."""
        return self.confidence

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for m in self.pattern.finditer(text):
            conf = self.validate(m)
            if conf is None:
                continue
            spans.append(
                Span(
                    start=m.start(),
                    end=m.end(),
                    entity_type=self.entity_type,
                    confidence=conf,
                    tier=self.tier,
                    detector=self.name,
                )
            )
        return spans
