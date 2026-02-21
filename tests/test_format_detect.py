"""Unit tests for detect_binary_format — expanded marker detection."""
import os
import struct
import tempfile
import pytest

pytest.importorskip("pefile", reason="pefile not installed")

from pemcp.mcp._format_helpers import detect_format_from_magic, get_magic_hint


# ---------------------------------------------------------------------------
# detect_format_from_magic (shared utility)
# ---------------------------------------------------------------------------

class TestDetectFormatFromMagic:
    def test_pe(self):
        assert detect_format_from_magic(b'MZ\x90\x00') == "pe"

    def test_elf(self):
        assert detect_format_from_magic(b'\x7fELF') == "elf"

    def test_macho_32_le(self):
        assert detect_format_from_magic(b'\xce\xfa\xed\xfe') == "macho"

    def test_macho_64_le(self):
        assert detect_format_from_magic(b'\xcf\xfa\xed\xfe') == "macho"

    def test_macho_32_be(self):
        assert detect_format_from_magic(b'\xfe\xed\xfa\xce') == "macho"

    def test_macho_64_be(self):
        assert detect_format_from_magic(b'\xfe\xed\xfa\xcf') == "macho"

    def test_macho_fat(self):
        assert detect_format_from_magic(b'\xca\xfe\xba\xbe') == "macho"

    def test_macho_fat_swapped(self):
        assert detect_format_from_magic(b'\xbe\xba\xfe\xca') == "macho"

    def test_unknown(self):
        assert detect_format_from_magic(b'\x00\x00\x00\x00') == "unknown"

    def test_short_input(self):
        assert detect_format_from_magic(b'\x00') == "unknown"

    def test_empty_input(self):
        assert detect_format_from_magic(b'') == "unknown"


# ---------------------------------------------------------------------------
# get_magic_hint (file-based format hint)
# ---------------------------------------------------------------------------

class TestGetMagicHint:
    def test_pe_file(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b'MZ' + b'\x00' * 100)
        assert get_magic_hint(str(f)) == "PE"

    def test_elf_file(self, tmp_path):
        f = tmp_path / "test.elf"
        f.write_bytes(b'\x7fELF' + b'\x00' * 100)
        assert get_magic_hint(str(f)) == "ELF"

    def test_macho_file(self, tmp_path):
        f = tmp_path / "test.macho"
        f.write_bytes(b'\xce\xfa\xed\xfe' + b'\x00' * 100)
        assert get_magic_hint(str(f)) == "Mach-O"

    def test_zip_file(self, tmp_path):
        f = tmp_path / "test.zip"
        f.write_bytes(b'PK\x03\x04' + b'\x00' * 100)
        assert get_magic_hint(str(f)) == "ZIP/Archive"

    def test_pdf_file(self, tmp_path):
        f = tmp_path / "test.pdf"
        f.write_bytes(b'%PDF-1.4' + b'\x00' * 100)
        assert get_magic_hint(str(f)) == "PDF"

    def test_gzip_file(self, tmp_path):
        f = tmp_path / "test.gz"
        f.write_bytes(b'\x1f\x8b\x08' + b'\x00' * 100)
        assert get_magic_hint(str(f)) == "GZIP"

    def test_unknown_format(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b'\xde\xad\xbe\xef')
        assert get_magic_hint(str(f)) == "Unknown"

    def test_nonexistent_file(self):
        assert get_magic_hint("/nonexistent/path/file.bin") == "Unreadable"


class TestFormatDetectMarkers:
    """Verify that language detection markers cover Go and Rust beyond the header."""

    def test_rust_markers_list_is_comprehensive(self):
        """Ensure the Rust marker list includes deep-binary markers."""
        import inspect
        import pemcp.mcp.tools_format_detect as fmt_mod
        source = inspect.getsource(fmt_mod)
        # These markers should be present in the detection module
        for marker in ["rust_eh_personality", "__rust_alloc", "core::panicking"]:
            assert marker in source, f"Missing Rust marker: {marker}"

    def test_go_markers_list_is_comprehensive(self):
        """Ensure the Go marker list includes additional markers."""
        import inspect
        import pemcp.mcp.tools_format_detect as fmt_mod
        source = inspect.getsource(fmt_mod)
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
