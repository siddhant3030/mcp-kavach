import pytest

from mcp_kavach import PolicyError, load_policy, load_preset, parse_policy
from mcp_kavach.models import Action


def base(**overrides):
    data = {
        "name": "test",
        "rules": [{"id": "r1", "entities": ["EMAIL"], "action": "mask"}],
    }
    data.update(overrides)
    return data


class TestPresets:
    @pytest.mark.parametrize("name", ["ngo-default", "strict", "dev"])
    def test_shipped_presets_load(self, name):
        policy = load_preset(name)
        assert policy.name == name

    def test_unknown_preset(self):
        with pytest.raises(PolicyError, match="unknown preset"):
            load_preset("nope")

    def test_ngo_default_fails_closed(self):
        assert load_preset("ngo-default").defaults.unknown_entity_action is Action.MASK


class TestValidation:
    def test_minimal_policy(self):
        policy = parse_policy(base())
        assert policy.rules[0].action is Action.MASK
        assert policy.defaults.unknown_entity_action is Action.MASK

    def test_policy_wrapper_key_accepted(self):
        assert parse_policy({"policy": base()}).name == "test"

    def test_bad_action_is_readable(self):
        with pytest.raises(PolicyError) as exc:
            parse_policy(base(rules=[{"id": "r1", "entities": ["EMAIL"], "action": "obliterate"}]))
        message = str(exc.value)
        assert "rules.0.action" in message
        assert "Traceback" not in message

    def test_unknown_entity_rejected(self):
        with pytest.raises(PolicyError, match="AADHAR"):
            parse_policy(base(rules=[{"id": "r1", "entities": ["AADHAR"], "action": "mask"}]))

    def test_extra_entities_extend_known_set(self):
        policy = parse_policy(
            base(rules=[{"id": "r1", "entities": ["CUSTOM"], "action": "mask"}]),
            extra_entities=["CUSTOM"],
        )
        assert policy.rules[0].entities == ["CUSTOM"]

    def test_duplicate_rule_ids_rejected(self):
        with pytest.raises(PolicyError, match="duplicate rule id"):
            parse_policy(
                base(
                    rules=[
                        {"id": "r1", "entities": ["EMAIL"], "action": "mask"},
                        {"id": "r1", "entities": ["PHONE"], "action": "mask"},
                    ]
                )
            )

    def test_rule_needs_entities_or_match(self):
        with pytest.raises(PolicyError, match="entities"):
            parse_policy(base(rules=[{"id": "r1", "action": "mask"}]))

    def test_result_scope_requires_block(self):
        with pytest.raises(PolicyError, match="scope 'result'"):
            rule = {"id": "r1", "entities": ["EMAIL"], "action": "mask", "scope": "result"}
            parse_policy(base(rules=[rule]))

    def test_bad_json_path_rejected(self):
        with pytest.raises(PolicyError, match="json_path"):
            parse_policy(
                base(rules=[{"id": "r1", "match": {"json_path": "rows.x"}, "action": "block"}])
            )

    def test_unknown_top_level_key_rejected(self):
        with pytest.raises(PolicyError):
            parse_policy(base(detectors={"tiers": ["regex"]}))


class TestLoadFromFile:
    def test_load_yaml_file(self, tmp_path):
        f = tmp_path / "p.yaml"
        f.write_text(
            "name: filetest\nrules:\n  - id: r1\n    entities: [EMAIL]\n    action: redact\n"
        )
        policy = load_policy(f)
        assert policy.name == "filetest"
        assert policy.rules[0].action is Action.REDACT

    def test_error_names_the_file(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("name: x\nrules:\n  - id: r1\n    entities: [EMAIL]\n    action: nope\n")
        with pytest.raises(PolicyError, match="bad.yaml"):
            load_policy(f)
