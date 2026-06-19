"""Multilingual first slice: Indic digit normalization + Hindi field names.

The contract under test: a Devanagari-digit phone or Aadhaar is detected and
masked exactly like its ASCII twin, and the normalization that makes this
possible is strictly length-preserving so spans always index correctly into
the original (un-normalized) leaf string.
"""

import sys
import unicodedata

from conftest import INVALID_AADHAAR, VALID_AADHAAR

from virelia.detectors.checksums import verhoeff_valid
from virelia.detectors.entities import AadhaarDetector, IndianMobileDetector
from virelia.detectors.normalize import normalize_digits
from virelia.detectors.structural import ColumnNameDetector
from virelia.models import Action

_DEVANAGARI_ZERO = 0x0966  # ०


def to_devanagari(text: str) -> str:
    return "".join(
        chr(_DEVANAGARI_ZERO + int(ch)) if ch.isdigit() else ch for ch in text
    )


ASCII_PHONE = "9876543210"
DEV_PHONE = to_devanagari(ASCII_PHONE)  # ९८७६५४३२१०
DEV_AADHAAR = to_devanagari(VALID_AADHAAR)  # २३४५६७८९०१२४ (Verhoeff-valid)


class TestNormalizeDigits:
    def test_devanagari_to_ascii(self):
        assert normalize_digits(DEV_PHONE) == ASCII_PHONE

    def test_ascii_passthrough_is_same_object(self):
        s = "no digits to translate, 123"
        assert normalize_digits(s) is s

    def test_every_unicode_decimal_digit_maps_one_to_one(self):
        """Offset-safety property: each Nd codepoint becomes exactly one
        ASCII digit, so translation can never shift offsets."""
        checked = 0
        for cp in range(sys.maxunicode + 1):
            ch = chr(cp)
            if unicodedata.category(ch) != "Nd":
                continue
            out = normalize_digits(ch)
            assert len(out) == 1, f"U+{cp:04X} changed length"
            assert out == str(unicodedata.decimal(ch)), f"U+{cp:04X} wrong digit"
            checked += 1
        assert checked > 600  # Nd spans dozens of scripts

    def test_mixed_script_preserves_length_and_non_digits(self):
        s = "नाम: लक्ष्मी, फ़ोन ९८७६५४३२१० (alt ٠١٢٣, bn ৯৮)"
        out = normalize_digits(s)
        assert len(out) == len(s)
        for i, (a, b) in enumerate(zip(s, out, strict=True)):
            if unicodedata.category(a) == "Nd":
                assert b == str(unicodedata.decimal(a)), f"index {i}"
            else:
                assert a == b, f"non-digit changed at index {i}"

    def test_non_decimal_numerics_untouched(self):
        # Superscript two, circled five, Roman numeral — numeric but not Nd.
        assert normalize_digits("x² ⑤ Ⅻ") == "x² ⑤ Ⅻ"


class TestDevanagariDetectors:
    def test_checksum_runs_on_normalized_ascii(self):
        assert verhoeff_valid(normalize_digits(DEV_AADHAAR))

    def test_phone_span_offsets_match_ascii_twin(self):
        dev, ascii_ = f"call {DEV_PHONE} now", f"call {ASCII_PHONE} now"
        [dev_span] = IndianMobileDetector().detect(normalize_digits(dev))
        [ascii_span] = IndianMobileDetector().detect(ascii_)
        assert (dev_span.start, dev_span.end) == (ascii_span.start, ascii_span.end)
        assert dev[dev_span.start : dev_span.end] == DEV_PHONE

    def test_aadhaar_detected_after_normalization(self):
        spans = AadhaarDetector().detect(normalize_digits(f"aadhaar {DEV_AADHAAR} on file"))
        assert [s.entity_type for s in spans] == ["AADHAAR"]

    def test_checksum_invalid_devanagari_aadhaar_rejected(self):
        assert AadhaarDetector().detect(normalize_digits(to_devanagari(INVALID_AADHAAR))) == []


class TestEngineEndToEnd:
    def test_devanagari_phone_masked_like_ascii_twin(self, engine):
        dev = engine.scan_result("t", {"note": f"call {DEV_PHONE}"})
        twin = engine.scan_result("t", {"note": f"call {ASCII_PHONE}"})
        assert dev.payload["note"] == "call ******३२१०"
        assert twin.payload["note"] == "call ******3210"
        assert [(e.entity_type, e.action, e.start, e.end) for e in dev.events] == [
            (e.entity_type, e.action, e.start, e.end) for e in twin.events
        ]

    def test_devanagari_aadhaar_blocked_like_ascii_twin(self, engine):
        dev = engine.scan_result("t", {"note": DEV_AADHAAR})
        twin = engine.scan_result("t", {"note": VALID_AADHAAR})
        assert dev.payload == twin.payload  # block marker carries no digits
        assert DEV_AADHAAR not in str(dev.payload)
        assert any(
            e.entity_type == "AADHAAR" and e.action is Action.BLOCK for e in dev.events
        )

    def test_mixed_script_text_outside_span_is_untouched(self, engine):
        result = engine.scan_result("t", {"note": f"संपर्क {DEV_PHONE} पर करें"})
        assert result.payload["note"] == "संपर्क ******३२१० पर करें"

    def test_devanagari_text_without_pii_passes_through(self, engine):
        payload = {"note": "रामपुर गाँव में शिविर १२ बजे"}
        result = engine.scan_result("t", payload)
        assert result.payload == payload


class TestHindiColumnNames:
    def detected(self, key):
        spans = ColumnNameDetector().detect_node(("rows", 0, key), "some value")
        return spans[0].entity_type if spans else None

    def test_devanagari_keys(self):
        assert self.detected("नाम") == "PERSON_NAME"
        assert self.detected("फ़ोन") == "PHONE"  # फ़ोन, combining nukta
        assert self.detected("फ़ोन") == "PHONE"  # फ़ोन, precomposed
        assert self.detected("फोन") == "PHONE"  # फोन, no nukta
        assert self.detected("पता") == "ADDRESS"
        assert self.detected("आधार") == "AADHAAR"
        assert self.detected("जन्मतिथि") == "DOB"
        assert self.detected("खाता") == "BANK_ACCOUNT"

    def test_romanized_keys(self):
        assert self.detected("naam") == "PERSON_NAME"
        assert self.detected("pataa") == "ADDRESS"
        assert self.detected("pata") == "ADDRESS"
        assert self.detected("khata_number") == "BANK_ACCOUNT"
        assert self.detected("janm_tithi") == "DOB"
        assert self.detected("janmtithi") == "DOB"

    def test_short_romanizations_are_word_bounded(self):
        assert self.detected("patang_id") is None  # 'pata' only as a substring
        assert self.detected("sukhata") is None  # 'khata' only as a substring

    def test_hindi_row_masked_end_to_end(self, engine):
        result = engine.scan_result(
            "get_beneficiaries", {"rows": [{"नाम": "लक्ष्मी देवी", "गाँव": "रामपुर"}]}
        )
        assert result.payload["rows"][0]["नाम"] == "[MASKED:PERSON_NAME]"
        assert result.payload["rows"][0]["गाँव"] == "रामपुर"
