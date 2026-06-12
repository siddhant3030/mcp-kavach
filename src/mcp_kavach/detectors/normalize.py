"""Unicode digit normalization for Tier 1 scanning.

PII typed with Indic digits (Devanagari ९८७६५४३२१०, Bengali, Tamil, Gujarati,
Arabic-Indic, …) would sail past ASCII-only patterns. Every character in the
Unicode ``Nd`` (decimal digit) category is exactly one codepoint and maps to
exactly one ASCII digit, so ``str.translate`` with this table is strictly
length-preserving: span offsets found on the normalized copy index correctly
into the *original* leaf string, which is what the transformer rewrites.
Checksums (Verhoeff/Luhn) consequently also run on plain ASCII digits, because
detectors only ever see the normalized text.

Characters that are numeric but not decimal digits (superscripts, circled
numbers, Roman numerals) are deliberately left unchanged.
"""

from __future__ import annotations

import unicodedata


class _DigitTable(dict):
    """Lazy ``str.translate`` table: Nd codepoint → ASCII digit, else identity.

    Built on demand via ``unicodedata.decimal`` instead of a precomputed scan
    of all of Unicode; each codepoint is resolved once and cached.
    """

    def __missing__(self, codepoint: int) -> str:
        ch = chr(codepoint)
        value = unicodedata.decimal(ch, None)
        result = ch if value is None else str(value)
        self[codepoint] = result
        return result


_TABLE = _DigitTable()


def normalize_digits(text: str) -> str:
    """Replace every Unicode decimal digit with its ASCII twin.

    1:1 per codepoint, so ``len(normalize_digits(s)) == len(s)`` always —
    offsets against the result are valid against the original. ASCII-only
    strings (the common case) are returned as-is without copying.
    """
    if text.isascii():
        return text
    return text.translate(_TABLE)
