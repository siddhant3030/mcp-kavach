"""Tier 1 PII detectors, including the India pack (Aadhaar, PAN, IFSC).

All numeric patterns use digit-boundary lookarounds so substrings of longer
digit runs (timestamps, order IDs) never fire. Checksummed entities
(Aadhaar/Verhoeff, cards/Luhn) reject candidates that fail the checksum —
confidence is still never 1.0 because ~10% of random same-length numbers
pass any single checksum.
"""

from __future__ import annotations

import re

from virelia.detectors.checksums import luhn_valid, verhoeff_valid
from virelia.detectors.regex import RegexDetector


class EmailDetector(RegexDetector):
    name = "email"
    entity_type = "EMAIL"
    confidence = 0.95
    pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class IndianMobileDetector(RegexDetector):
    """Indian mobile numbers start with 6-9; optional +91/0 prefix."""

    name = "phone_in"
    entity_type = "PHONE"
    confidence = 0.9
    pattern = re.compile(r"(?<![\d+])(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")


class IntlPhoneDetector(RegexDetector):
    """International numbers; requires a + country code to keep precision."""

    name = "phone_intl"
    entity_type = "PHONE"
    confidence = 0.7
    pattern = re.compile(r"(?<![\d\w])\+\d{1,3}[\s-]?\d{2,4}(?:[\s-]?\d{2,4}){1,3}(?!\d)")


class AadhaarDetector(RegexDetector):
    name = "aadhaar"
    entity_type = "AADHAAR"
    confidence = 0.85
    # 12 digits, first 2-9, optionally grouped in 4s with a consistent separator.
    pattern = re.compile(r"(?<!\d)[2-9]\d{3}([\s-]?)\d{4}\1\d{4}(?!\d)")

    def validate(self, match: re.Match[str]) -> float | None:
        if not verhoeff_valid(match.group(0)):
            return None
        sep = match.group(1)
        if sep:
            # Reject slices of a longer grouped digit run (e.g. the first 12
            # digits of a grouped 16-digit card number).
            text, s, e = match.string, match.start(), match.end()
            if s >= 2 and text[s - 1] == sep and text[s - 2].isdigit():
                return None
            if e + 1 < len(text) and text[e] == sep and text[e + 1].isdigit():
                return None
            return 0.95
        return self.confidence


class PanDetector(RegexDetector):
    """Indian Permanent Account Number: AAAPL1234C."""

    name = "pan"
    entity_type = "PAN"
    confidence = 0.85
    pattern = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
    _HOLDER_TYPES = set("ABCFGHLJPT")  # legal 4th-character values

    def validate(self, match: re.Match[str]) -> float | None:
        return 0.9 if match.group(0)[3] in self._HOLDER_TYPES else 0.6


class IfscDetector(RegexDetector):
    """Bank branch codes: 4 letters, literal 0, 6 alphanumerics."""

    name = "ifsc"
    entity_type = "IFSC"
    confidence = 0.8
    pattern = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")


class CreditCardDetector(RegexDetector):
    name = "credit_card"
    entity_type = "CREDIT_CARD"
    confidence = 0.95
    pattern = re.compile(r"(?<![\d.])(?:\d[\s-]?){12,18}\d(?![\d.])")

    def validate(self, match: re.Match[str]) -> float | None:
        digits = re.sub(r"\D", "", match.group(0))
        if not 13 <= len(digits) <= 19 or not luhn_valid(digits):
            return None
        return self.confidence


class IpAddressDetector(RegexDetector):
    name = "ip_address"
    entity_type = "IP_ADDRESS"
    confidence = 0.9
    pattern = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

    def validate(self, match: re.Match[str]) -> float | None:
        if all(int(octet) <= 255 for octet in match.group(0).split(".")):
            return self.confidence
        return None
