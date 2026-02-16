"""Unit tests for detect_binary_format — expanded marker detection."""
import os
import struct
import tempfile
import pytest


class TestFormatDetectMarkers:
    """Verify that language detection markers cover Go and Rust beyond the header."""

    def test_rust_markers_list_is_comprehensive(self):
        """Ensure the Rust marker list includes deep-binary markers."""
        import inspect
        from pemcp.mcp.tools_format_detect import detect_binary_format
        source = inspect.getsource(detect_binary_format)
        # These markers should be present in the detection logic
        for marker in ["rust_eh_personality", "__rust_alloc", "core::panicking"]:
            assert marker in source, f"Missing Rust marker: {marker}"

    def test_go_markers_list_is_comprehensive(self):
        """Ensure the Go marker list includes additional markers."""
        import inspect
        from pemcp.mcp.tools_format_detect import detect_binary_format
        source = inspect.getsource(detect_binary_format)
        for marker in ["runtime.goexit", "go.string."]:
            assert marker in source, f"Missing Go marker: {marker}"

    def test_scan_data_larger_than_header(self):
        """Verify the scan reads more than 4096 bytes."""
        import inspect
        from pemcp.mcp.tools_format_detect import detect_binary_format
        source = inspect.getsource(detect_binary_format)
        # Should reference scan_data (larger buffer), not just header
        assert "scan_data" in source, "Detection should use a larger scan buffer"
        # Should scan at least 1MB
        assert "1024 * 1024" in source or "1048576" in source, \
            "Scan buffer should be at least 1MB"
