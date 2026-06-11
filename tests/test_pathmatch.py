import pytest

from mcp_kavach.pathmatch import PathPatternError, compile_path, matches, render_path


def match(pattern, path):
    return matches(compile_path(pattern), path)


class TestCompile:
    @pytest.mark.parametrize(
        "bad",
        ["rows.aadhaar", "$.rows[x]", "$.", "$", "$rows", "$.rows[1.5]"],
    )
    def test_invalid_patterns_raise(self, bad):
        with pytest.raises(PathPatternError):
            compile_path(bad)


class TestMatch:
    def test_wildcard_index(self):
        assert match("$.rows[*].aadhaar", ("rows", 3, "aadhaar"))
        assert not match("$.rows[*].aadhaar", ("rows", "x", "aadhaar"))
        assert not match("$.rows[*].aadhaar", ("rows", "aadhaar"))

    def test_literal_index(self):
        assert match("$.rows[2].name", ("rows", 2, "name"))
        assert not match("$.rows[2].name", ("rows", 3, "name"))

    def test_wildcard_key(self):
        assert match("$.*.name", ("user", "name"))
        assert not match("$.*.name", (0, "name"))

    def test_recursive_descent(self):
        assert match("$..phone", ("phone",))
        assert match("$..phone", ("a", 2, "phone"))
        assert match("$..phone", ("a", "b", "c", "phone"))
        assert not match("$..phone", ("a", "phones"))

    def test_descent_in_middle(self):
        assert match("$.rows..aadhaar", ("rows", 0, "nested", "aadhaar"))
        assert not match("$.rows..aadhaar", ("other", 0, "aadhaar"))

    def test_exact_match_required_at_end(self):
        assert not match("$.rows", ("rows", 0))
        assert match("$.rows[*]", ("rows", 0))

    def test_string_index_does_not_match_int_segment(self):
        assert not match("$.rows[3]", ("rows", "3"))


class TestRender:
    def test_render(self):
        assert render_path(("rows", 3, "aadhaar")) == "$.rows[3].aadhaar"
        assert render_path(()) == "$"
