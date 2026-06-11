"""Golden-corpus runner: each fixture is a labeled payload with the
detections the engine must produce and raw values that must never survive."""

import json
from pathlib import Path

import pytest

from mcp_kavach import Engine, load_preset

CORPUS_DIR = Path(__file__).parent / "fixtures" / "corpus"
FIXTURES = sorted(CORPUS_DIR.glob("*.json"))


@pytest.mark.parametrize("fixture_path", FIXTURES, ids=lambda p: p.stem)
def test_corpus(fixture_path):
    fixture = json.loads(fixture_path.read_text())
    engine = Engine(load_preset(fixture["policy"]), hmac_salt=b"corpus-salt")

    scan = engine.scan_result if fixture["direction"] == "result" else engine.scan_request
    result = scan(fixture["tool"], fixture["payload"])

    caught = {(e.json_path, e.entity_type, e.action.value) for e in result.events}
    for exp in fixture["expected"]:
        key = (exp["path"], exp["entity_type"], exp["action"])
        assert key in caught, f"missing detection {key}; got {sorted(caught)}"

    serialized = json.dumps(result.payload) + json.dumps(
        [e.model_dump(mode="json") for e in result.events]
    )
    for raw in fixture["must_not_appear"]:
        assert raw not in serialized, f"raw value leaked: {raw!r}"


def test_corpus_is_not_empty():
    assert FIXTURES, "golden corpus has no fixtures"
