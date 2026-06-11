from mcp_kavach.models import Action, Finding, Span
from mcp_kavach.transform import merge_clusters, partial_mask, transform_text


def finding(start, end, entity="PHONE", action=Action.MASK, conf=0.9, rule="r1"):
    return Finding(
        span=Span(start, end, entity, conf, 1, "test"),
        path=("field",),
        resolved_action=action,
        rule_id=rule,
    )


class TestMergeClusters:
    def test_overlap_takes_highest_severity_over_union(self):
        clusters = merge_clusters(
            [
                finding(0, 10, action=Action.PARTIAL_MASK),
                finding(5, 15, entity="AADHAAR", action=Action.BLOCK, rule="r2"),
            ]
        )
        assert len(clusters) == 1
        assert (clusters[0].start, clusters[0].end) == (0, 15)
        assert clusters[0].action is Action.BLOCK
        assert clusters[0].lead.span.entity_type == "AADHAAR"

    def test_same_severity_higher_confidence_leads(self):
        clusters = merge_clusters(
            [
                finding(0, 15, conf=0.6, action=Action.PARTIAL_MASK),
                finding(0, 10, conf=0.9, action=Action.PARTIAL_MASK, rule="r2"),
            ]
        )
        assert len(clusters) == 1
        assert clusters[0].lead.rule_id == "r2"

    def test_disjoint_spans_stay_separate(self):
        assert len(merge_clusters([finding(0, 4), finding(10, 14)])) == 2

    def test_allow_findings_dropped(self):
        assert merge_clusters([finding(0, 4, action=Action.ALLOW)]) == []

    def test_transitive_overlap(self):
        clusters = merge_clusters([finding(0, 6), finding(5, 11), finding(10, 16)])
        assert len(clusters) == 1
        assert (clusters[0].start, clusters[0].end) == (0, 16)


class TestTransformText:
    def test_multiple_replacements_right_to_left(self):
        text = "a@b.co and c@d.co"
        out = transform_text(
            text,
            [
                finding(0, 6, entity="EMAIL", action=Action.MASK),
                finding(11, 17, entity="EMAIL", action=Action.MASK),
            ],
            "p",
        )
        assert out == "[MASKED:EMAIL] and [MASKED:EMAIL]"

    def test_redact_and_block_markers(self):
        assert transform_text("secret", [finding(0, 6, action=Action.REDACT)], "p") == "[REDACTED]"
        assert (
            transform_text("secret", [finding(0, 6, action=Action.BLOCK, rule="r9")], "p")
            == "[BLOCKED:p/r9]"
        )

    def test_partial_mask_inline(self):
        text = "call 9876543210 now"
        out = transform_text(
            text, [finding(5, 15, entity="PHONE", action=Action.PARTIAL_MASK)], "p"
        )
        assert out == "call ******3210 now"


class TestPartialMask:
    def test_phone_keeps_last_four_and_separators(self):
        assert partial_mask("+91 98765 43210", "PHONE") == "+** ***** *3210"

    def test_email_keeps_first_char_and_domain(self):
        assert partial_mask("lakshmi@example.org", "EMAIL") == "l***@example.org"

    def test_aadhaar_grouped(self):
        assert partial_mask("2345 6789 0124", "AADHAAR") == "**** **** 0124"

    def test_no_template_falls_back_to_mask(self):
        assert partial_mask("Lakshmi Devi", "PERSON_NAME") == "[MASKED:PERSON_NAME]"
