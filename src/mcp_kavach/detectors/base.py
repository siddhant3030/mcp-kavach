"""Detector interfaces.

Two kinds of detectors exist, matching the tier model:

- ``Detector`` (Tier 1+) scans a single leaf *string* and returns spans.
- ``StructuralDetector`` (Tier 0) sees ``(path, value)`` nodes during the
  JSON walk — it never scans text, so it costs microseconds per leaf.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from mcp_kavach.models import PathTuple, Span


class Detector(ABC):
    name: ClassVar[str]
    entity_type: ClassVar[str]
    tier: ClassVar[int] = 1

    @abstractmethod
    def detect(self, text: str) -> list[Span]: ...


class StructuralDetector(ABC):
    """May emit spans of multiple entity types (e.g. by column name)."""

    name: ClassVar[str]
    tier: ClassVar[int] = 0

    @abstractmethod
    def detect_node(self, path: PathTuple, value: object) -> list[Span]: ...

    @abstractmethod
    def entity_types(self) -> frozenset[str]:
        """All entity types this detector can emit (for registry/pruning)."""
