"""Unit tests for Go binary analysis tool helpers."""
import os
import tempfile
import pytest

pytest.importorskip("pefile", reason="pefile not installed")

from arkana.mcp.tools_go import _safe_str, _safe_int, _go_string_scan


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


class TestGoStringScan:
    def _make_binary(self, content: bytes) -> str:
        """Write content to a temp file and return path."""
        fd, path = tempfile.mkstemp(suffix=".elf")
        os.write(fd, content)
        os.close(fd)
        return path

    def test_detects_go_with_multiple_markers(self):
        data = b"\x00" * 100 + b"runtime.main" + b"\x00" * 50 + b"runtime.goexit"
        path = self._make_binary(data)
        try:
            result = _go_string_scan(path)
            assert result["is_go_binary"] is True
            assert result["detection_method"] == "string_scan"
            assert result["marker_count"] >= 2
        finally:
            os.unlink(path)

    def test_detects_go_version(self):
        data = b"\x00" * 100 + b"go1.21.5" + b"\x00" * 50 + b"runtime.main"
        path = self._make_binary(data)
        try:
            result = _go_string_scan(path)
            assert result["is_go_binary"] is True
            assert result["go_version"] == "go1.21.5"
        finally:
            os.unlink(path)

    def test_not_go_on_empty_binary(self):
        data = b"\x00" * 200
        path = self._make_binary(data)
        try:
            result = _go_string_scan(path)
            assert result["is_go_binary"] is False
            assert result["marker_count"] == 0
        finally:
            os.unlink(path)

    def test_single_marker_not_enough(self):
        data = b"\x00" * 100 + b"runtime.main"
        path = self._make_binary(data)
        try:
            result = _go_string_scan(path)
            assert result["is_go_binary"] is False
            assert result["marker_count"] == 1
        finally:
            os.unlink(path)

    def test_version_alone_is_sufficient(self):
        data = b"\x00" * 100 + b"go1.22.0"
        path = self._make_binary(data)
        try:
            result = _go_string_scan(path)
            assert result["is_go_binary"] is True
            assert result["go_version"] == "go1.22.0"
        finally:
            os.unlink(path)
