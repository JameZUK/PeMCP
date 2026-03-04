"""Unit tests for hex pattern regex conversion."""
import re
import pytest

# Import the helper directly from the module
from arkana.mcp.tools_strings import _hex_pattern_to_regex


class TestHexPatternToRegex:
    def test_simple_pattern(self):
        regex = _hex_pattern_to_regex("4D 5A")
        assert re.match(regex, b"\x4d\x5a", re.DOTALL)

    def test_wildcard(self):
        regex = _hex_pattern_to_regex("4D ?? 5A")
        assert re.match(regex, b"\x4d\x00\x5a", re.DOTALL)
        assert re.match(regex, b"\x4d\xff\x5a", re.DOTALL)

    def test_all_wildcards(self):
        regex = _hex_pattern_to_regex("?? ?? ??")
        assert re.match(regex, b"\x00\x00\x00", re.DOTALL)

    def test_single_byte(self):
        regex = _hex_pattern_to_regex("FF")
        assert re.match(regex, b"\xff", re.DOTALL)

    def test_no_match(self):
        regex = _hex_pattern_to_regex("4D 5A")
        assert not re.match(regex, b"\x4d\x5b", re.DOTALL)

    def test_pattern_in_data(self):
        regex = _hex_pattern_to_regex("DE AD ?? EF")
        data = b"\x00\x00\xde\xad\x42\xef\x00\x00"
        matches = list(re.finditer(regex, data, re.DOTALL))
        assert len(matches) == 1
        assert matches[0].start() == 2

    def test_empty_pattern_raises(self):
        with pytest.raises(ValueError, match="Empty hex pattern"):
            _hex_pattern_to_regex("")

    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError, match="Invalid hex token"):
            _hex_pattern_to_regex("ZZ")

    def test_wrong_length_token_raises(self):
        with pytest.raises(ValueError, match="Invalid hex token"):
            _hex_pattern_to_regex("4D5A")

    def test_too_long_pattern_raises(self):
        pattern = " ".join(["AA"] * 201)
        with pytest.raises(ValueError, match="Pattern too long"):
            _hex_pattern_to_regex(pattern)

    def test_single_question_mark_wildcard(self):
        """Single ? should also work as wildcard."""
        regex = _hex_pattern_to_regex("4D ? 5A")
        assert re.match(regex, b"\x4d\xff\x5a", re.DOTALL)

    def test_case_insensitive_hex(self):
        regex_lower = _hex_pattern_to_regex("4d 5a")
        regex_upper = _hex_pattern_to_regex("4D 5A")
        data = b"\x4d\x5a"
        assert re.match(regex_lower, data, re.DOTALL)
        assert re.match(regex_upper, data, re.DOTALL)
