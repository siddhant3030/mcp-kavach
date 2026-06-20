"""Built-in detector registry."""

from __future__ import annotations

from virelia.detectors.base import Detector, StructuralDetector
from virelia.detectors.entities import (
    AadhaarDetector,
    CreditCardDetector,
    EmailDetector,
    IfscDetector,
    IndianMobileDetector,
    IntlPhoneDetector,
    IpAddressDetector,
    PanDetector,
)
from virelia.detectors.ner import NER_ENTITY_TYPES
from virelia.detectors.secrets import (
    AwsAccessKeyDetector,
    GithubTokenDetector,
    JwtDetector,
)
from virelia.detectors.structural import ColumnNameDetector

ALL_DETECTORS: list[Detector] = [
    EmailDetector(),
    IndianMobileDetector(),
    IntlPhoneDetector(),
    AadhaarDetector(),
    PanDetector(),
    IfscDetector(),
    CreditCardDetector(),
    IpAddressDetector(),
    AwsAccessKeyDetector(),
    GithubTokenDetector(),
    JwtDetector(),
]

STRUCTURAL_DETECTORS: list[StructuralDetector] = [ColumnNameDetector()]


def known_entity_types() -> frozenset[str]:
    # NER entities are always policy-addressable, even without the [ner]
    # extra installed — the rules just never fire.
    types = {d.entity_type for d in ALL_DETECTORS} | NER_ENTITY_TYPES
    for s in STRUCTURAL_DETECTORS:
        types |= s.entity_types()
    return frozenset(types)


__all__ = [
    "ALL_DETECTORS",
    "STRUCTURAL_DETECTORS",
    "Detector",
    "StructuralDetector",
    "known_entity_types",
]
