"""Unit tests for the T2 NER tier. Presidio is faked throughout — these run
(and the base engine must behave identically) without the [ner] extra."""

from types import SimpleNamespace

from virelia import Engine, load_preset, parse_policy
from virelia.detectors import known_entity_types, ner
from virelia.models import Span

TEXT = "My name is Lakshmi Devi and I live in Mumbai"


def presidio_result(entity, start, end, score):
    return SimpleNamespace(entity_type=entity, start=start, end=end, score=score)


class FakeAnalyzer:
    def __init__(self, results=()):
        self.results = list(results)
        self.calls = []

    def analyze(self, *, text, language, entities):
        self.calls.append((text, language, tuple(entities)))
        return self.results


class TestNerDetector:
    def test_maps_entities_and_caps_confidence_below_checksum_tier(self):
        analyzer = FakeAnalyzer(
            [presidio_result("PERSON", 11, 23, 0.99), presidio_result("LOCATION", 38, 44, 0.5)]
        )
        det = ner.NerDetector(analyzer, frozenset({"PERSON_NAME", "ADDRESS"}))
        assert det.detect(TEXT) == [
            Span(11, 23, "PERSON_NAME", ner.NER_MAX_CONFIDENCE, 2, "presidio_ner"),
            Span(38, 44, "ADDRESS", 0.5, 2, "presidio_ner"),
        ]
        assert ner.NER_MAX_CONFIDENCE < 0.85  # Verhoeff/Luhn matches score 0.85+

    def test_requests_only_wanted_presidio_entities(self):
        analyzer = FakeAnalyzer()
        ner.NerDetector(analyzer, frozenset({"PERSON_NAME", "UPI_ID"})).detect("hi")
        assert analyzer.calls == [("hi", "en", ("IN_UPI_ID", "PERSON"))]

    def test_unmapped_presidio_entities_are_dropped(self):
        analyzer = FakeAnalyzer([presidio_result("US_SSN", 0, 4, 0.9)])
        assert ner.NerDetector(analyzer, frozenset({"PERSON_NAME"})).detect("text") == []


class TestLoader:
    def test_returns_none_without_presidio(self, monkeypatch):
        monkeypatch.setattr(ner, "_analyzer", None)
        monkeypatch.setattr(ner, "_analyzer_failed", False)
        monkeypatch.setattr(ner, "_find_spec", lambda name: None)
        assert ner.load_ner_detector(frozenset({"PERSON_NAME"})) is None

    def test_returns_none_for_entities_outside_ner_vocabulary(self):
        assert ner.load_ner_detector(frozenset({"EMAIL", "JWT"})) is None

    def test_build_failure_disables_tier_without_raising(self, monkeypatch):
        monkeypatch.setattr(ner, "_analyzer", None)
        monkeypatch.setattr(ner, "_analyzer_failed", False)
        monkeypatch.setattr(ner, "_find_spec", lambda name: object())

        def boom():
            raise RuntimeError("no spaCy model")

        monkeypatch.setattr(ner, "_build_analyzer", boom)
        assert ner.load_ner_detector(frozenset({"PERSON_NAME"})) is None
        assert ner._analyzer_failed  # cached: no rebuild attempt per scan

    def test_ner_entities_are_policy_addressable(self):
        assert known_entity_types() >= ner.NER_ENTITY_TYPES


class TestEngineIntegration:
    def _patch_loader(self, monkeypatch, detector):
        calls = []

        def loader(entities):
            calls.append(entities)
            return detector

        monkeypatch.setattr(ner, "load_ner_detector", loader)
        return calls

    def test_free_text_name_masked_under_ngo_default(self, monkeypatch, ngo_policy):
        analyzer = FakeAnalyzer([presidio_result("PERSON", 11, 23, 0.85)])
        det = ner.NerDetector(analyzer, frozenset({"PERSON_NAME"}))
        calls = self._patch_loader(monkeypatch, det)
        engine = Engine(ngo_policy, hmac_salt=b"s")
        result = engine.scan_result("get_notes", {"notes": TEXT})
        assert "Lakshmi Devi" not in result.payload["notes"]
        assert "[MASKED:PERSON_NAME]" in result.payload["notes"]
        event = next(e for e in result.events if e.entity_type == "PERSON_NAME")
        assert event.tier == 2
        assert event.confidence == ner.NER_MAX_CONFIDENCE
        # Fail-closed policy: every NER entity is requested.
        assert calls == [ner.NER_ENTITY_TYPES]

    def test_loader_called_once_across_scans(self, monkeypatch, ngo_policy):
        calls = self._patch_loader(monkeypatch, None)
        engine = Engine(ngo_policy, hmac_salt=b"s")
        engine.scan_result("t", {"a": "free text"})
        engine.scan_result("t", {"b": "more text"})
        assert len(calls) == 1

    def test_numeric_leaves_never_reach_ner(self, monkeypatch, ngo_policy):
        analyzer = FakeAnalyzer()
        det = ner.NerDetector(analyzer, frozenset({"PERSON_NAME"}))
        self._patch_loader(monkeypatch, det)
        Engine(ngo_policy, hmac_salt=b"s").scan_result("t", {"count": 42})
        assert analyzer.calls == []

    def test_allow_mode_policy_without_ner_entities_skips_loader(self, monkeypatch):
        calls = self._patch_loader(monkeypatch, None)
        engine = Engine(load_preset("dev"), hmac_salt=b"s")  # allow-mode, no NER entities
        engine.scan_result("t", {"notes": "free text"})
        assert calls == []

    def test_allow_mode_policy_with_person_rule_prunes_request(self, monkeypatch):
        calls = self._patch_loader(monkeypatch, None)
        policy = parse_policy(
            {
                "name": "p",
                "defaults": {"unknown_entity_action": "allow"},
                "rules": [{"id": "n", "entities": ["PERSON_NAME"], "action": "mask"}],
            }
        )
        Engine(policy, hmac_salt=b"s").scan_result("t", {"notes": "free text"})
        assert calls == [frozenset({"PERSON_NAME"})]

    def test_ner_false_disables_tier(self, monkeypatch, ngo_policy):
        calls = self._patch_loader(monkeypatch, None)
        policy = ngo_policy.model_copy(deep=True)
        policy.defaults.ner = False
        Engine(policy, hmac_salt=b"s").scan_result("t", {"notes": "free text"})
        assert calls == []

    def test_ner_true_forces_tier_in_allow_mode(self, monkeypatch):
        calls = self._patch_loader(monkeypatch, None)
        policy = parse_policy(
            {
                "name": "p",
                "defaults": {"unknown_entity_action": "allow", "ner": True},
                "rules": [{"id": "a", "entities": ["AADHAAR"], "action": "mask"}],
            }
        )
        Engine(policy, hmac_salt=b"s").scan_result("t", {"notes": "free text"})
        # auto would skip (AADHAAR is T1-findable); true loads anyway.
        assert calls == [frozenset({"AADHAAR"})]

    def test_defaults_ner_parses_from_yaml_values(self):
        for value in ("auto", True, False):
            policy = parse_policy({"name": "p", "defaults": {"ner": value}})
            assert policy.defaults.ner == value
