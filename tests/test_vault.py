import io
import json
import logging
import sys

import pytest

from virelia import Engine, parse_policy
from virelia.cli.main import main
from virelia.models import Action, Finding, Span
from virelia.transform import merge_clusters
from virelia.vault import Vault, rehydrate

TOKENIZE_POLICY = {
    "name": "tok",
    "defaults": {"unknown_entity_action": "allow"},
    "rules": [
        {"id": "names", "entities": ["PERSON_NAME"], "action": "tokenize"},
        {"id": "phones", "entities": ["PHONE"], "action": "tokenize"},
    ],
}


@pytest.fixture
def vault(tmp_path):
    with Vault(tmp_path / "vault.db") as v:
        yield v


@pytest.fixture
def tok_engine(vault):
    return Engine(parse_policy(TOKENIZE_POLICY), hmac_salt=b"s", vault=vault)


class TestTokenConsistency:
    def test_same_value_same_token_within_one_scan(self, tok_engine):
        payload = {"rows": [{"name": "Lakshmi Devi"}, {"name": "Lakshmi Devi"}]}
        result = tok_engine.scan_result("get_rows", payload)
        rows = result.payload["rows"]
        assert rows[0]["name"] == "[PERSON_NAME_1]"
        assert rows[1]["name"] == "[PERSON_NAME_1]"

    def test_same_value_same_token_across_two_scans(self, tok_engine):
        first = tok_engine.scan_result("t", {"name": "Lakshmi Devi"})
        second = tok_engine.scan_result("t", {"name": "Lakshmi Devi"})
        assert first.payload["name"] == second.payload["name"] == "[PERSON_NAME_1]"

    def test_different_values_get_distinct_tokens(self, tok_engine):
        result = tok_engine.scan_result(
            "t", {"rows": [{"name": "Lakshmi Devi"}, {"name": "Ravi Kumar"}]}
        )
        names = [r["name"] for r in result.payload["rows"]]
        assert names == ["[PERSON_NAME_1]", "[PERSON_NAME_2]"]

    def test_counters_are_per_entity_type(self, vault):
        assert vault.token_for("PERSON_NAME", "Lakshmi Devi") == "[PERSON_NAME_1]"
        assert vault.token_for("PHONE", "+91 98765 43210") == "[PHONE_1]"

    def test_tokens_survive_vault_reopen(self, tmp_path):
        with Vault(tmp_path / "v.db") as v:
            token = v.token_for("PERSON_NAME", "Lakshmi Devi")
        with Vault(tmp_path / "v.db") as v:
            assert v.token_for("PERSON_NAME", "Lakshmi Devi") == token

    def test_no_plaintext_in_tokenized_payload(self, tok_engine):
        result = tok_engine.scan_result("t", {"name": "Lakshmi Devi"})
        assert "Lakshmi" not in json.dumps(result.payload)

    def test_audit_records_tokenize_action(self, tok_engine):
        result = tok_engine.scan_result("t", {"name": "Lakshmi Devi"})
        assert any(e.action is Action.TOKENIZE for e in result.events)


class TestScopes:
    def test_scopes_have_independent_mappings(self, tmp_path):
        path = tmp_path / "v.db"
        with Vault(path, scope="session-a") as a, Vault(path, scope="session-b") as b:
            assert a.token_for("PERSON_NAME", "Lakshmi Devi") == "[PERSON_NAME_1]"
            assert a.token_for("PERSON_NAME", "Ravi Kumar") == "[PERSON_NAME_2]"
            # Same counter restarts per scope; same token, different value.
            assert b.token_for("PERSON_NAME", "Ravi Kumar") == "[PERSON_NAME_1]"
            assert a.rehydrate("[PERSON_NAME_1]") == "Lakshmi Devi"
            assert b.rehydrate("[PERSON_NAME_1]") == "Ravi Kumar"


class TestRehydrate:
    def test_round_trip_through_engine(self, tok_engine, vault):
        payload = {
            "rows": [
                {"name": "Lakshmi Devi", "note": "call +91 98765 43210 today"},
                {"name": "Lakshmi Devi", "count": 3},
            ]
        }
        result = tok_engine.scan_result("get_rows", payload)
        assert result.payload != payload
        assert vault.rehydrate(result.payload) == payload

    def test_unknown_tokens_pass_through(self, vault):
        assert vault.rehydrate("hello [PERSON_NAME_99] and [NOT_A_TOKEN]") == (
            "hello [PERSON_NAME_99] and [NOT_A_TOKEN]"
        )

    def test_module_level_helper(self, tmp_path):
        path = tmp_path / "v.db"
        with Vault(path) as v:
            token = v.token_for("EMAIL", "lakshmi@example.org")
        assert rehydrate(f"mail {token}", path=path) == "mail lakshmi@example.org"

    def test_non_string_scalars_untouched(self, vault):
        assert vault.rehydrate({"n": 3, "ok": True, "x": None}) == {
            "n": 3,
            "ok": True,
            "x": None,
        }


class TestRehydrateCli:
    def test_reads_file_writes_stdout(self, tmp_path, capsys):
        path = tmp_path / "v.db"
        with Vault(path) as v:
            token = v.token_for("PERSON_NAME", "Lakshmi Devi")
        doc = tmp_path / "out.txt"
        doc.write_text(f"summary for {token}\n")
        assert main(["rehydrate", str(doc), "--vault", str(path)]) == 0
        assert capsys.readouterr().out == "summary for Lakshmi Devi\n"

    def test_reads_stdin(self, tmp_path, capsys, monkeypatch):
        path = tmp_path / "v.db"
        with Vault(path) as v:
            token = v.token_for("PHONE", "+91 98765 43210")
        monkeypatch.setattr(sys, "stdin", io.StringIO(f"call {token}"))
        assert main(["rehydrate", "--vault", str(path)]) == 0
        assert capsys.readouterr().out == "call +91 98765 43210"


class TestFailSafe:
    def test_tokenize_without_vault_falls_back_to_mask(self, caplog):
        engine = Engine(parse_policy(TOKENIZE_POLICY), hmac_salt=b"s")
        with caplog.at_level(logging.WARNING, logger="virelia"):
            result = engine.scan_result("t", {"name": "Lakshmi Devi"})
        assert result.payload["name"] == "[MASKED:PERSON_NAME]"
        assert any("tokenize" in r.message for r in caplog.records)
        # The audit trail records what actually happened.
        assert all(e.action is not Action.TOKENIZE for e in result.events)
        assert any(e.action is Action.MASK for e in result.events)


class TestFilePermissions:
    def test_vault_and_key_are_owner_only(self, tmp_path):
        path = tmp_path / "v.db"
        with Vault(path) as v:
            v.token_for("PERSON_NAME", "Lakshmi Devi")
        assert (path.stat().st_mode & 0o777) == 0o600
        assert (path.with_suffix(".key").stat().st_mode & 0o777) == 0o600


class TestSeverity:
    @staticmethod
    def _finding(action, entity="PHONE"):
        return Finding(
            span=Span(0, 10, entity, 0.9, 1, "test"),
            path=("f",),
            resolved_action=action,
            rule_id="r",
        )

    def test_tokenize_outranks_mask_but_not_redact(self):
        wins_over_mask = merge_clusters(
            [self._finding(Action.MASK), self._finding(Action.TOKENIZE)]
        )
        assert wins_over_mask[0].action is Action.TOKENIZE
        loses_to_redact = merge_clusters(
            [self._finding(Action.TOKENIZE), self._finding(Action.REDACT)]
        )
        assert loses_to_redact[0].action is Action.REDACT
