"""Tests for list_samples pagination, subdirectory, and safety."""
import os
import tempfile
import pytest

from arkana.mcp.tools_samples import (
    _build_file_entry,
    _format_size,
)
from arkana.constants import MAX_LIST_SAMPLES_LIMIT


class TestFormatSize:
    def test_bytes(self):
        assert _format_size(500) == "500 B"

    def test_kilobytes(self):
        assert _format_size(2048) == "2.0 KB"

    def test_megabytes(self):
        assert _format_size(5_242_880) == "5.0 MB"


class TestBuildFileEntry:
    def test_builds_entry(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"MZ" + b"\x00" * 100)
            f.flush()
            try:
                entry = _build_file_entry(f.name, os.path.dirname(f.name))
                assert entry["name"].endswith(".bin")
                assert entry["size_bytes"] == 102
                assert "size_human" in entry
                assert "modified" in entry
                assert "format_hint" in entry
            finally:
                os.unlink(f.name)


class TestMaxLimit:
    def test_constant_exists(self):
        assert MAX_LIST_SAMPLES_LIMIT == 500
