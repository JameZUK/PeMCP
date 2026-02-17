"""Unit tests for pemcp/utils.py — utility functions."""
import datetime
import math
import pytest

pefile = pytest.importorskip("pefile", reason="pefile not installed")

from pemcp.utils import (
    shannon_entropy,
    format_timestamp,
    get_symbol_type_str,
    get_symbol_storage_class_str,
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
