"""End-to-end NER tier tests against real presidio + spaCy.

Skipped entirely unless the [ner] extra and an English spaCy model are
installed (neither is present in base CI)."""

import pytest

pytest.importorskip("presidio_analyzer")

from mcp_kavach import Engine, load_preset  # noqa: E402
from mcp_kavach.detectors import ner  # noqa: E402

if not any(ner._find_spec(m) for m in ner._SPACY_MODELS):
    pytest.skip("no spaCy English model installed", allow_module_level=True)


@pytest.fixture(scope="module")
def engine():
    return Engine(load_preset("ngo-default"), hmac_salt=b"ner-it")


def test_name_inside_free_text_is_masked(engine):
    result = engine.scan_result(
        "get_notes", {"notes": "Spoke to Lakshmi Devi about the next health checkup."}
    )
    assert "Lakshmi" not in result.payload["notes"]
    assert "[MASKED:PERSON_NAME]" in result.payload["notes"]
    assert any(e.entity_type == "PERSON_NAME" and e.tier == 2 for e in result.events)


def test_upi_id_flagged_only_with_payment_context(engine):
    flagged = engine.scan_result("t", {"msg": "send the upi payment to ramesh77@oksbi"})
    assert "ramesh77@oksbi" not in str(flagged.payload)
    assert any(e.entity_type == "UPI_ID" for e in flagged.events)

    plain = engine.scan_result("t", {"msg": "the handle is someuser@oksbi"})
    assert not any(e.entity_type == "UPI_ID" for e in plain.events)


def test_t2_confidence_never_reaches_checksum_tier(engine):
    result = engine.scan_result(
        "t", {"notes": "Lakshmi Devi from Mumbai paid via upi to ramesh77@oksbi"}
    )
    t2 = [e for e in result.events if e.tier == 2]
    assert t2
    assert all(e.confidence <= ner.NER_MAX_CONFIDENCE for e in t2)


def test_base_detectors_unaffected(engine):
    result = engine.scan_result("t", {"email": "a@b.co"})
    assert result.payload["email"] == "a***@b.co"
