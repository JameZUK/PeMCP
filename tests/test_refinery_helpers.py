"""Unit tests for arkana/mcp/_refinery_helpers.py — offset/artifact helpers."""
import hashlib
import os
import threading

import pytest

from arkana.state import AnalyzerState, set_current_state


# ---------------------------------------------------------------------------
# Helpers to set up a fake loaded file for offset-based reads
# ---------------------------------------------------------------------------

class MockPEForHelpers:
    """Minimal mock that exposes __data__ like pefile.PE."""
    def __init__(self, data: bytes):
        self.__data__ = data


def _setup_state_with_data(data: bytes) -> AnalyzerState:
    """Create an AnalyzerState with a mock PE object loaded."""
    s = AnalyzerState()
    s.pe_object = MockPEForHelpers(data)
    s.filepath = "/fake/test.bin"
    set_current_state(s)
    return s


# ---------------------------------------------------------------------------
# _get_data_from_hex_or_file_with_offset
# ---------------------------------------------------------------------------

class TestGetDataFromHexOrFileWithOffset:
    def setup_method(self):
        # 256 bytes: 0x00..0xFF
        self.test_data = bytes(range(256))
        self.state = _setup_state_with_data(self.test_data)

    def teardown_method(self):
        set_current_state(None)

    def test_hex_takes_priority(self):
        from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset
        result = _get_data_from_hex_or_file_with_offset(
            data_hex="AABBCC",
            file_offset="0x00",
            length=3,
        )
        assert result == bytes.fromhex("AABBCC")

    def test_file_offset_and_length(self):
        from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset
        result = _get_data_from_hex_or_file_with_offset(
            file_offset="0x10",
            length=4,
        )
        assert result == bytes([0x10, 0x11, 0x12, 0x13])

    def test_file_offset_decimal(self):
        from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset
        result = _get_data_from_hex_or_file_with_offset(
            file_offset="16",
            length=2,
        )
        assert result == bytes([0x10, 0x11])

    def test_file_offset_without_length(self):
        from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset
        result = _get_data_from_hex_or_file_with_offset(
            file_offset="0xFE",
        )
        # Should return from 0xFE to end (2 bytes)
        assert result == bytes([0xFE, 0xFF])

    def test_full_file_when_no_params(self):
        from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset
        result = _get_data_from_hex_or_file_with_offset()
        assert result == self.test_data

    def test_offset_out_of_bounds(self):
        from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset
        with pytest.raises(ValueError, match="out of bounds"):
            _get_data_from_hex_or_file_with_offset(file_offset="0x200")

    def test_offset_plus_length_exceeds_file(self):
        from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset
        with pytest.raises(ValueError, match="exceeds file size"):
            _get_data_from_hex_or_file_with_offset(file_offset="0xFE", length=10)

    def test_negative_offset(self):
        from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset
        with pytest.raises(ValueError, match="out of bounds"):
            _get_data_from_hex_or_file_with_offset(file_offset="-1")

    def test_zero_length(self):
        from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset
        with pytest.raises(ValueError, match="length must be positive"):
            _get_data_from_hex_or_file_with_offset(file_offset="0x00", length=0)


# ---------------------------------------------------------------------------
# _detect_file_type
# ---------------------------------------------------------------------------

class TestDetectFileType:
    def test_pe(self):
        from arkana.mcp._refinery_helpers import _detect_file_type
        assert _detect_file_type(b"MZ\x90\x00") == "pe"

    def test_elf(self):
        from arkana.mcp._refinery_helpers import _detect_file_type
        assert _detect_file_type(b"\x7fELF\x02") == "elf"

    def test_macho_64(self):
        from arkana.mcp._refinery_helpers import _detect_file_type
        assert _detect_file_type(b"\xcf\xfa\xed\xfe") == "macho"

    def test_zip(self):
        from arkana.mcp._refinery_helpers import _detect_file_type
        assert _detect_file_type(b"PK\x03\x04") == "zip"

    def test_unknown(self):
        from arkana.mcp._refinery_helpers import _detect_file_type
        assert _detect_file_type(b"\x00\x00\x00\x00") is None

    def test_empty(self):
        from arkana.mcp._refinery_helpers import _detect_file_type
        assert _detect_file_type(b"") is None


# ---------------------------------------------------------------------------
# _write_output_and_register_artifact
# ---------------------------------------------------------------------------

class TestWriteOutputAndRegisterArtifact:
    def setup_method(self):
        self.state = AnalyzerState()
        self.state.allowed_paths = None  # No restriction
        set_current_state(self.state)

    def teardown_method(self):
        set_current_state(None)

    def test_writes_file_and_registers(self, tmp_path):
        from arkana.mcp._refinery_helpers import _write_output_and_register_artifact
        data = b"MZ\x90\x00" + b"\x00" * 100
        out = tmp_path / "output.bin"

        meta = _write_output_and_register_artifact(
            str(out), data, "test_tool", "Test description",
        )

        # File written
        assert out.exists()
        assert out.read_bytes() == data

        # Metadata correct
        assert meta["size"] == len(data)
        assert meta["sha256"] == hashlib.sha256(data).hexdigest()
        assert meta["md5"] == hashlib.md5(data).hexdigest()
        assert meta["detected_type"] == "pe"
        assert meta["artifact_id"].startswith("art_")
        assert meta["path"] == str(out.resolve())

        # Registered in state
        arts = self.state.get_artifacts()
        assert len(arts) == 1
        assert arts[0]["source_tool"] == "test_tool"

    def test_creates_parent_dirs(self, tmp_path):
        from arkana.mcp._refinery_helpers import _write_output_and_register_artifact
        out = tmp_path / "deep" / "nested" / "dir" / "output.bin"
        _write_output_and_register_artifact(
            str(out), b"test data", "tool", "desc",
        )
        assert out.exists()

    def test_path_restriction_enforced(self, tmp_path):
        from arkana.mcp._refinery_helpers import _write_output_and_register_artifact
        self.state.allowed_paths = [str(tmp_path / "allowed")]
        with pytest.raises(RuntimeError, match="Access denied"):
            _write_output_and_register_artifact(
                "/etc/evil.bin", b"bad", "tool", "desc",
            )

    def test_size_limit_enforced(self, tmp_path):
        from arkana.mcp._refinery_helpers import _write_output_and_register_artifact
        from arkana.constants import MAX_ARTIFACT_FILE_SIZE
        # We can't allocate 100MB in a test, so patch the constant
        import arkana.mcp._refinery_helpers as mod
        original = mod.MAX_ARTIFACT_FILE_SIZE
        try:
            mod.MAX_ARTIFACT_FILE_SIZE = 10  # 10 bytes
            with pytest.raises(RuntimeError, match="artifact limit"):
                _write_output_and_register_artifact(
                    str(tmp_path / "big.bin"), b"x" * 20, "tool", "desc",
                )
        finally:
            mod.MAX_ARTIFACT_FILE_SIZE = original
