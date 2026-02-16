"""Unit tests for Go binary analysis tool helpers."""
import pytest
from pemcp.mcp.tools_go import _safe_str, _safe_int


class TestSafeStr:
    def test_string_passthrough(self):
        assert _safe_str("hello") == "hello"

    def test_int_to_str(self):
        assert _safe_str(42) == "42"

    def test_none_returns_none(self):
        assert _safe_str(None) is None

    def test_bytes_to_str(self):
        assert _safe_str(b"hello") == "b'hello'"

    def test_custom_object(self):
        class Obj:
            def __str__(self):
                return "custom"
        assert _safe_str(Obj()) == "custom"

    def test_fallback_on_str_error(self):
        class BadStr:
            def __str__(self):
                raise RuntimeError("fail")
        assert _safe_str(BadStr(), "fallback") == "fallback"


class TestSafeInt:
    def test_int_passthrough(self):
        assert _safe_int(42) == 42

    def test_none_returns_none(self):
        assert _safe_int(None) is None

    def test_string_decimal(self):
        assert _safe_int("100") == 100

    def test_string_hex(self):
        assert _safe_int("0x401000") == 0x401000

    def test_float_to_int(self):
        assert _safe_int(3.14) == 3

    def test_non_numeric_returns_none(self):
        assert _safe_int("not_a_number") is None

    def test_empty_string_returns_none(self):
        assert _safe_int("") is None

    def test_custom_object_returns_none(self):
        class Obj:
            pass
        assert _safe_int(Obj()) is None
