"""Unit tests for pemcp/utils.py — utility functions."""
import datetime
import math
import re
import pytest

pefile = pytest.importorskip("pefile", reason="pefile not installed")

from pemcp.utils import (
    shannon_entropy,
    format_timestamp,
    get_symbol_type_str,
    get_symbol_storage_class_str,
    validate_regex_pattern,
    safe_regex_search,
    _safe_slice,
    safe_print,
)

_HAS_SYM_DTYPE = hasattr(pefile, "IMAGE_SYM_DTYPE_POINTER")


# ---------------------------------------------------------------------------
# shannon_entropy
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_data(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_byte(self):
        # All identical bytes -> zero entropy
        assert shannon_entropy(b"\x00" * 100) == 0.0

    def test_two_equal_values(self):
        # 50/50 split of two values -> entropy = 1.0
        data = b"\x00" * 50 + b"\x01" * 50
        assert abs(shannon_entropy(data) - 1.0) < 1e-6

    def test_all_256_bytes(self):
        # Every byte value once -> maximum entropy = 8.0
        data = bytes(range(256))
        assert abs(shannon_entropy(data) - 8.0) < 1e-6

    def test_entropy_range(self):
        # Random-ish data should have entropy between 0 and 8
        data = b"The quick brown fox jumps over the lazy dog"
        result = shannon_entropy(data)
        assert 0.0 < result <= 8.0

    def test_single_byte_value(self):
        # Single byte: entropy = 0.0 (only one symbol)
        assert shannon_entropy(b"\xff") == 0.0

    def test_ascii_text_entropy(self):
        # Typical ASCII text has moderate entropy (roughly 3-5 bits)
        data = b"Hello, World! This is a test string for entropy measurement."
        result = shannon_entropy(data)
        assert 3.0 < result < 6.0


# ---------------------------------------------------------------------------
# format_timestamp
# ---------------------------------------------------------------------------

class TestFormatTimestamp:
    def test_zero_timestamp(self):
        result = format_timestamp(0)
        assert "No timestamp" in result or "invalid" in result.lower()

    def test_negative_timestamp(self):
        result = format_timestamp(-1)
        assert "Invalid" in result

    def test_non_integer(self):
        result = format_timestamp("abc")
        assert "Invalid" in result

    def test_valid_timestamp(self):
        # 2020-01-01 00:00:00 UTC = 1577836800
        result = format_timestamp(1577836800)
        assert "2020-01-01" in result
        assert "UTC" in result

    def test_very_old_timestamp(self):
        # Timestamp before 1980 -> flagged as unusual
        result = format_timestamp(1)
        assert "unusual" in result.lower() or "1970" in result

    def test_far_future_timestamp(self):
        # Timestamp far in the future -> flagged as unusual
        future = int(
            (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 25)).timestamp()
        )
        result = format_timestamp(future)
        assert "unusual" in result.lower()

    def test_overflow_timestamp(self):
        # Very large timestamp that might overflow
        result = format_timestamp(99999999999999)
        assert "Invalid" in result or "unusual" in result.lower()


# ---------------------------------------------------------------------------
# get_symbol_type_str
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_SYM_DTYPE, reason="pefile version lacks IMAGE_SYM_DTYPE_* constants")
class TestGetSymbolTypeStr:
    def test_null_type(self):
        result = get_symbol_type_str(0x0)
        assert isinstance(result, str) and len(result) > 0

    def test_function_type_0x20(self):
        # Special case: sym_type == 0x20 returns "FUNCTION"
        result = get_symbol_type_str(0x20)
        assert "FUNCTION" in result

    def test_returns_string(self):
        for val in [0x0, 0x1, 0x4, 0xF, 0x20, 0xFF]:
            result = get_symbol_type_str(val)
            assert isinstance(result, str)


# ---------------------------------------------------------------------------
# get_symbol_storage_class_str
# ---------------------------------------------------------------------------

class TestGetSymbolStorageClassStr:
    def test_null_class(self):
        assert get_symbol_storage_class_str(0) == "NULL"

    def test_external_class(self):
        assert get_symbol_storage_class_str(2) == "EXTERNAL"

    def test_static_class(self):
        assert get_symbol_storage_class_str(3) == "STATIC"

    def test_function_class(self):
        assert get_symbol_storage_class_str(101) == "FUNCTION"

    def test_file_class(self):
        assert get_symbol_storage_class_str(103) == "FILE"

    def test_unknown_class(self):
        result = get_symbol_storage_class_str(999)
        assert "UNKNOWN" in result


# ---------------------------------------------------------------------------
# _safe_slice
# ---------------------------------------------------------------------------

class TestSafeSlice:
    def test_list(self):
        assert _safe_slice([1, 2, 3, 4, 5], 3) == [1, 2, 3]

    def test_tuple(self):
        assert _safe_slice((1, 2, 3, 4), 2) == (1, 2)

    def test_dict(self):
        d = {"a": 1, "b": 2, "c": 3}
        result = _safe_slice(d, 2)
        assert len(result) == 2
        assert isinstance(result, dict)

    def test_string(self):
        assert _safe_slice("hello world", 5) == "hello"

    def test_set(self):
        result = _safe_slice({1, 2, 3, 4, 5}, 3)
        assert isinstance(result, set)
        assert len(result) == 3

    def test_frozenset(self):
        result = _safe_slice(frozenset({1, 2, 3}), 2)
        assert isinstance(result, frozenset)
        assert len(result) == 2

    def test_n_larger_than_collection(self):
        assert _safe_slice([1, 2], 10) == [1, 2]

    def test_empty_list(self):
        assert _safe_slice([], 5) == []

    def test_non_iterable_returns_unchanged(self):
        assert _safe_slice(42, 5) == 42

    def test_generator(self):
        gen = (x for x in range(10))
        result = _safe_slice(gen, 3)
        assert result == [0, 1, 2]


# ---------------------------------------------------------------------------
# validate_regex_pattern
# ---------------------------------------------------------------------------

class TestValidateRegexPattern:
    def test_valid_simple_pattern(self):
        # Should not raise
        validate_regex_pattern(r"hello.*world")

    def test_valid_complex_pattern(self):
        validate_regex_pattern(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b")

    def test_too_long_pattern(self):
        with pytest.raises(ValueError, match="too long"):
            validate_regex_pattern("a" * 1001)

    def test_exactly_max_length(self):
        # Should not raise at exactly 1000 chars
        validate_regex_pattern("a" * 1000)

    def test_nested_quantifiers_rejected(self):
        with pytest.raises(ValueError, match="nested quantifiers"):
            validate_regex_pattern(r"(a+)+")

    def test_nested_quantifiers_star(self):
        with pytest.raises(ValueError, match="nested quantifiers"):
            validate_regex_pattern(r"(a*)*")

    def test_invalid_regex_syntax(self):
        with pytest.raises(ValueError, match="Invalid regex"):
            validate_regex_pattern(r"[unclosed")

    def test_simple_quantifiers_allowed(self):
        # Simple (non-nested) quantifiers should be fine
        validate_regex_pattern(r"a+b*c?d{2,5}")

    def test_empty_pattern(self):
        # Empty pattern is valid regex
        validate_regex_pattern("")


# ---------------------------------------------------------------------------
# safe_regex_search
# ---------------------------------------------------------------------------

class TestSafeRegexSearch:
    def test_basic_match(self):
        pattern = re.compile(r"hello")
        result = safe_regex_search(pattern, "say hello world")
        assert result is not None
        assert result.group() == "hello"

    def test_no_match(self):
        pattern = re.compile(r"xyz")
        result = safe_regex_search(pattern, "hello world")
        assert result is None

    def test_group_capture(self):
        pattern = re.compile(r"(\d+)")
        result = safe_regex_search(pattern, "abc 123 def")
        assert result is not None
        assert result.group(1) == "123"

    def test_empty_text(self):
        pattern = re.compile(r"test")
        result = safe_regex_search(pattern, "")
        assert result is None

    def test_empty_pattern_matches(self):
        pattern = re.compile(r"")
        result = safe_regex_search(pattern, "any text")
        assert result is not None


# ---------------------------------------------------------------------------
# safe_print
# ---------------------------------------------------------------------------

class TestSafePrint:
    def test_basic_print(self, capsys):
        safe_print("hello")
        captured = capsys.readouterr()
        assert "hello" in captured.out

    def test_with_prefix(self, capsys):
        safe_print("world", verbose_prefix="[INFO] ")
        captured = capsys.readouterr()
        assert "[INFO] world" in captured.out
