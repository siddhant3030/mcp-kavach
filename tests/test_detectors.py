from conftest import INVALID_AADHAAR, VALID_AADHAAR

from virelia.detectors.entities import (
    AadhaarDetector,
    CreditCardDetector,
    EmailDetector,
    IfscDetector,
    IndianMobileDetector,
    IpAddressDetector,
    PanDetector,
)
from virelia.detectors.secrets import (
    AwsAccessKeyDetector,
    GithubTokenDetector,
    JwtDetector,
)
from virelia.detectors.structural import ColumnNameDetector


def entities(detector, text):
    return [(text[s.start : s.end], s.entity_type) for s in detector.detect(text)]


class TestEmail:
    def test_detects_in_sentence(self):
        spans = EmailDetector().detect("Contact lakshmi.devi@example.org today")
        assert len(spans) == 1
        assert spans[0].entity_type == "EMAIL"

    def test_no_false_positive(self):
        assert EmailDetector().detect("no at sign here") == []


class TestPhone:
    def test_indian_mobile_with_country_code(self):
        assert entities(IndianMobileDetector(), "call +91 98765 43210 now") == [
            ("+91 98765 43210", "PHONE")
        ]

    def test_bare_ten_digits(self):
        assert entities(IndianMobileDetector(), "phone: 9876543210.") == [
            ("9876543210", "PHONE")
        ]

    def test_not_inside_longer_digit_run(self):
        assert IndianMobileDetector().detect("order 982020123456789012345 shipped") == []

    def test_landline_style_not_matched_by_mobile_detector(self):
        # Starts with 0-prefix but the subscriber digit is outside 6-9.
        assert IndianMobileDetector().detect("044-2345-6789") == []


class TestAadhaar:
    def test_ungrouped(self):
        spans = AadhaarDetector().detect(f"aadhaar {VALID_AADHAAR} on file")
        assert [s.entity_type for s in spans] == ["AADHAAR"]
        assert spans[0].confidence == 0.85

    def test_grouped_has_higher_confidence(self):
        grouped = f"{VALID_AADHAAR[:4]} {VALID_AADHAAR[4:8]} {VALID_AADHAAR[8:]}"
        spans = AadhaarDetector().detect(grouped)
        assert len(spans) == 1
        assert spans[0].confidence == 0.95

    def test_checksum_failure_rejected(self):
        assert AadhaarDetector().detect(INVALID_AADHAAR) == []

    def test_not_inside_longer_digit_run(self):
        assert AadhaarDetector().detect(f"99{VALID_AADHAAR}") == []
        assert AadhaarDetector().detect(f"{VALID_AADHAAR}99") == []

    def test_not_a_slice_of_grouped_card_number(self):
        grouped16 = f"{VALID_AADHAAR[:4]} {VALID_AADHAAR[4:8]} {VALID_AADHAAR[8:]} 5678"
        assert AadhaarDetector().detect(grouped16) == []

    def test_preceded_by_short_number_still_detected(self):
        assert len(AadhaarDetector().detect(f"row 3 {VALID_AADHAAR}")) == 1


class TestPan:
    def test_valid_pan(self):
        spans = PanDetector().detect("PAN ABCPK4321L registered")
        assert len(spans) == 1
        assert spans[0].confidence == 0.9  # 4th char 'P' is a legal holder type

    def test_unusual_holder_type_lower_confidence(self):
        spans = PanDetector().detect("code ABCXK4321L here")
        assert len(spans) == 1
        assert spans[0].confidence == 0.6

    def test_lowercase_not_matched(self):
        assert PanDetector().detect("abcpk4321l") == []


class TestIfsc:
    def test_valid(self):
        assert len(IfscDetector().detect("transfer via SBIN0001234")) == 1

    def test_missing_zero_rejected(self):
        assert IfscDetector().detect("SBIN1001234") == []


class TestCreditCard:
    def test_luhn_valid_grouped(self):
        spans = CreditCardDetector().detect("card 4111 1111 1111 1111 charged")
        assert [s.entity_type for s in spans] == ["CREDIT_CARD"]

    def test_luhn_invalid_rejected(self):
        assert CreditCardDetector().detect("card 4111 1111 1111 1112 charged") == []


class TestIpAddress:
    def test_valid(self):
        assert len(IpAddressDetector().detect("host 10.0.0.12 up")) == 1

    def test_octet_out_of_range(self):
        assert IpAddressDetector().detect("999.1.1.1") == []

    def test_not_inside_longer_dotted_run(self):
        assert IpAddressDetector().detect("1.2.3.4.5") == []


class TestSecrets:
    def test_aws_access_key(self):
        assert len(AwsAccessKeyDetector().detect("key AKIAIOSFODNN7EXAMPLE")) == 1

    def test_github_token(self):
        token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        assert len(GithubTokenDetector().detect(f"use {token}")) == 1

    def test_jwt(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        assert len(JwtDetector().detect(f"Bearer {jwt}")) == 1


class TestColumnNameDetector:
    def test_pii_columns_flagged(self):
        d = ColumnNameDetector()
        cases = {
            ("rows", 0, "name"): "PERSON_NAME",
            ("rows", 0, "father_name"): "PERSON_NAME",
            ("rows", 0, "phone"): "PHONE",
            ("rows", 0, "aadhaar"): "AADHAAR",
            ("rows", 0, "aadhar_no"): "AADHAAR",
            ("rows", 0, "pan_number"): "PAN",
            ("rows", 0, "address"): "ADDRESS",
            ("rows", 0, "dob"): "DOB",
            ("rows", 0, "bank_account"): "BANK_ACCOUNT",
        }
        for path, expected in cases.items():
            spans = d.detect_node(path, "some value")
            assert [s.entity_type for s in spans] == [expected], path

    def test_span_covers_whole_value(self):
        spans = ColumnNameDetector().detect_node(("name",), "Lakshmi Devi")
        assert (spans[0].start, spans[0].end) == (0, len("Lakshmi Devi"))

    def test_technical_name_columns_exempt(self):
        d = ColumnNameDetector()
        for key in ["file_name", "filename", "hostname", "table_name", "schema_name"]:
            assert d.detect_node((key,), "value") == [], key

    def test_non_pii_columns_ignored(self):
        d = ColumnNameDetector()
        assert d.detect_node(("village",), "Rampur") == []
        assert d.detect_node(("last_checkup",), "2026-01-12") == []

    def test_list_value_under_pii_column(self):
        spans = ColumnNameDetector().detect_node(("phone", 0), "9876543210")
        assert [s.entity_type for s in spans] == ["PHONE"]

    def test_empty_value_skipped(self):
        assert ColumnNameDetector().detect_node(("name",), "") == []
        assert ColumnNameDetector().detect_node(("name",), None) == []
