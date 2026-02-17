"""Unit tests for Rust binary analysis — string-based fallback detection."""
import os
import struct
import tempfile
import pytest

pytest.importorskip("pefile", reason="pefile not installed")

from pemcp.mcp.tools_rust import _rust_string_scan


class TestRustStringScan:
    """Tests for the fallback Rust string scanner used on stripped binaries."""

    def _make_binary(self, content: bytes) -> str:
        """Create a temp file with the given content and return its path."""
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, content)
        os.close(fd)
        return path

    def test_detects_rust_panic_and_alloc(self):
        data = b"\x00" * 100 + b"rust_begin_unwind" + b"\x00" * 50 + b"__rust_alloc" + b"\x00" * 100
        path = self._make_binary(data)
        try:
            result = _rust_string_scan(path)
            assert result["is_rust_binary"] is True
            assert result["marker_count"] >= 2
            assert "rust_begin_unwind (panic handler)" in result["markers_found"]
            assert "__rust_alloc (Rust allocator)" in result["markers_found"]
        finally:
            os.unlink(path)

    def test_detects_rustc_version(self):
        data = b"\x00" * 200 + b"rustc/1.75.0 (abcdef123 2024-01-01)" + b"\x00" * 200
        # Add a second marker so is_rust_binary is True
        data += b"__rust_alloc" + b"\x00" * 100
        path = self._make_binary(data)
        try:
            result = _rust_string_scan(path)
            assert result["rustc_version"] is not None
            assert "1.75.0" in result["rustc_version"]
        finally:
            os.unlink(path)

    def test_detects_core_panicking(self):
        data = b"\x00" * 50 + b"core::panicking" + b"\x00" * 50 + b"std::rt::lang_start" + b"\x00" * 50
        path = self._make_binary(data)
        try:
            result = _rust_string_scan(path)
            assert result["is_rust_binary"] is True
            assert "core::panicking" in result["markers_found"]
            assert "std::rt::lang_start (Rust entry point)" in result["markers_found"]
        finally:
            os.unlink(path)

    def test_not_rust_when_no_markers(self):
        data = b"\x00" * 500 + b"just some random bytes" + b"\x00" * 500
        path = self._make_binary(data)
        try:
            result = _rust_string_scan(path)
            assert result["is_rust_binary"] is False
            assert result["marker_count"] == 0
        finally:
            os.unlink(path)

    def test_not_rust_with_single_marker(self):
        """A single marker is insufficient — could be coincidental."""
        data = b"\x00" * 100 + b"__rust_alloc" + b"\x00" * 100
        path = self._make_binary(data)
        try:
            result = _rust_string_scan(path)
            assert result["is_rust_binary"] is False
            assert result["marker_count"] == 1
        finally:
            os.unlink(path)

    def test_detects_markers_deep_in_binary(self):
        """Markers beyond the old 4096-byte scan range should be found."""
        # Place markers at offset 100KB
        data = b"\x00" * (100 * 1024) + b"rust_begin_unwind" + b"\x00" * 50 + b"core::panicking" + b"\x00" * 100
        path = self._make_binary(data)
        try:
            result = _rust_string_scan(path)
            assert result["is_rust_binary"] is True
        finally:
            os.unlink(path)

    def test_empty_file(self):
        path = self._make_binary(b"")
        try:
            result = _rust_string_scan(path)
            assert result["is_rust_binary"] is False
        finally:
            os.unlink(path)
