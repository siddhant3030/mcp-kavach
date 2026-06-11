import copy
import json

from conftest import VALID_AADHAAR

from mcp_kavach import Engine, InMemorySink, load_preset, parse_policy
from mcp_kavach.models import Action

GROUPED_AADHAAR = f"{VALID_AADHAAR[:4]} {VALID_AADHAAR[4:8]} {VALID_AADHAAR[8:]}"

ROW = {
    "name": "Lakshmi Devi",
    "phone": "+91 98765 43210",
    "aadhaar": GROUPED_AADHAAR,
    "village": "Rampur",
    "last_checkup": "2026-01-12",
}


class TestScanResult:
    def test_beneficiary_row_end_to_end(self, engine):
        result = engine.scan_result("get_beneficiaries", {"rows": [ROW]})
        out = result.payload["rows"][0]

        assert out["name"] == "[MASKED:PERSON_NAME]"
        assert out["phone"] == "+** ***** *3210"
        assert out["aadhaar"] == "[BLOCKED:ngo-default/govt-financial-block]"
        assert out["village"] == "Rampur"
        assert out["last_checkup"] == "2026-01-12"
        assert not result.blocked
        assert result.modified

    def test_audit_events_cover_detections(self, engine):
        result = engine.scan_result("get_beneficiaries", {"rows": [ROW]})
        caught = {(e.json_path, e.entity_type, e.action) for e in result.events}
        assert ("$.rows[0].name", "PERSON_NAME", Action.MASK) in caught
        assert ("$.rows[0].aadhaar", "AADHAAR", Action.BLOCK) in caught
        assert any(e.json_path == "$.rows[0].phone" and e.action is Action.PARTIAL_MASK
                   for e in result.events)

    def test_no_plaintext_anywhere_in_output(self, engine):
        result = engine.scan_result("get_beneficiaries", {"rows": [ROW]})
        serialized = json.dumps(result.payload) + json.dumps(
            [e.model_dump(mode="json") for e in result.events]
        )
        for raw in ["Lakshmi Devi", VALID_AADHAAR, GROUPED_AADHAAR, "98765 43210"]:
            assert raw not in serialized, raw

    def test_input_payload_not_mutated(self, engine):
        payload = {"rows": [copy.deepcopy(ROW)]}
        snapshot = copy.deepcopy(payload)
        engine.scan_result("get_beneficiaries", payload)
        assert payload == snapshot

    def test_clean_payload_untouched(self, engine):
        payload = {"status": "ok", "count": 42, "flags": [True, None]}
        result = engine.scan_result("health_check", payload)
        assert result.payload == payload
        assert result.events == []
        assert not result.modified

    def test_allow_rule_keeps_value_but_audits(self, engine):
        result = engine.scan_result("get_infra", {"endpoint": "10.0.0.12"})
        assert result.payload["endpoint"] == "10.0.0.12"
        assert any(
            e.entity_type == "IP_ADDRESS" and e.action is Action.ALLOW for e in result.events
        )
        assert not result.modified

    def test_numeric_leaf_gets_whole_value_replacement(self, engine):
        result = engine.scan_result("get_rows", {"rows": [{"aadhaar": int(VALID_AADHAAR)}]})
        assert result.payload["rows"][0]["aadhaar"] == "[BLOCKED:ngo-default/govt-financial-block]"

    def test_events_go_to_sink(self, ngo_policy):
        sink = InMemorySink()
        engine = Engine(ngo_policy, sink=sink, hmac_salt=b"s")
        result = engine.scan_result("t", {"email": "a@b.co"})
        assert sink.events == result.events
        assert len(sink.events) >= 1


class TestBlockedResult:
    def test_result_scope_block_short_circuits(self):
        engine = Engine(load_preset("strict"), hmac_salt=b"s")
        token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        result = engine.scan_result("get_config", {"note": f"use {token}"})
        assert result.blocked
        assert result.payload["error"] == "blocked by mcp-kavach"
        assert result.payload["rule"] == "secrets-kill"
        assert "credential" in result.block_reason
        assert token not in json.dumps(result.payload)


class TestScanRequest:
    def test_arguments_scrubbed(self, engine):
        result = engine.scan_request("search", {"query": "mail lakshmi@example.org please"})
        assert result.payload["query"] == "mail l***@example.org please"
        assert result.events[0].direction == "request"


class TestPolicyBehaviors:
    def test_structural_match_rule_tier0(self):
        policy = parse_policy(
            {
                "name": "structural",
                "defaults": {"unknown_entity_action": "allow"},
                "rules": [
                    {
                        "id": "addr",
                        "match": {"tool": "get_beneficiar*", "json_path": "$.rows[*].notes"},
                        "action": "redact",
                    }
                ],
            }
        )
        engine = Engine(policy, hmac_salt=b"s")
        payload = {"rows": [{"notes": "lives near the temple"}]}
        result = engine.scan_result("get_beneficiaries", payload)
        assert result.payload["rows"][0]["notes"] == "[REDACTED]"
        # Tool glob must gate the rule.
        other = engine.scan_result("get_villages", payload)
        assert other.payload == payload

    def test_first_match_wins_in_file_order(self):
        policy = parse_policy(
            {
                "name": "order",
                "rules": [
                    {"id": "first", "entities": ["EMAIL"], "action": "redact"},
                    {"id": "second", "entities": ["EMAIL"], "action": "allow"},
                ],
            }
        )
        result = Engine(policy, hmac_salt=b"s").scan_result("t", {"email": "a@b.co"})
        email_events = [e for e in result.events if e.entity_type == "EMAIL"]
        assert all(e.rule_id == "first" and e.action is Action.REDACT for e in email_events)

    def test_unknown_entity_fail_closed(self):
        policy = parse_policy({"name": "closed", "rules": []})
        result = Engine(policy, hmac_salt=b"s").scan_result("t", {"email": "a@b.co"})
        assert result.payload["email"] == "[MASKED:EMAIL]"
        assert all(e.rule_id is None for e in result.events)

    def test_dev_policy_allows_uncovered_entities(self):
        engine = Engine(load_preset("dev"), hmac_salt=b"s")
        result = engine.scan_result("t", {"email": "a@b.co", "aadhaar": VALID_AADHAAR})
        assert result.payload["email"] == "a@b.co"
        assert result.payload["aadhaar"] == "[MASKED:AADHAAR]"

    def test_min_confidence_drops_low_findings(self):
        policy = parse_policy(
            {
                "name": "highconf",
                "defaults": {"min_confidence": 0.7},
                "rules": [{"id": "n", "entities": ["PERSON_NAME"], "action": "mask"}],
            }
        )
        # Column-name findings carry confidence 0.6 — below the bar.
        result = Engine(policy, hmac_salt=b"s").scan_result("t", {"name": "Lakshmi"})
        assert result.payload["name"] == "Lakshmi"
        assert result.events == []
