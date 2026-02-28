"""Tests for pemcp.mcp._format_helpers — format detection and magic hints."""
import os
import tempfile
import pytest

from pemcp.mcp._format_helpers import detect_format_from_magic, get_magic_hint, _check_lib, _get_filepath


class TestDetectFormatFromMagic:
    """Test magic-byte format detection."""

    def test_pe_magic(self):
        assert detect_format_from_magic(b'MZ\x90\x00') == "pe"

    def test_elf_magic(self):
        assert detect_format_from_magic(b'\x7fELF') == "elf"

    def test_macho_32_le(self):
        assert detect_format_from_magic(b'\xce\xfa\xed\xfe') == "macho"

    def test_macho_64_le(self):
        assert detect_format_from_magic(b'\xcf\xfa\xed\xfe') == "macho"

    def test_macho_32_be(self):
        assert detect_format_from_magic(b'\xfe\xed\xfa\xce') == "macho"

    def test_macho_64_be(self):
        assert detect_format_from_magic(b'\xfe\xed\xfa\xcf') == "macho"

    def test_macho_fat_be(self):
        assert detect_format_from_magic(b'\xca\xfe\xba\xbe') == "macho"

    def test_macho_fat_le(self):
        assert detect_format_from_magic(b'\xbe\xba\xfe\xca') == "macho"

    def test_unknown_magic(self):
        assert detect_format_from_magic(b'\x00\x00\x00\x00') == "unknown"

    def test_empty_bytes(self):
        assert detect_format_from_magic(b'') == "unknown"

    def test_single_byte(self):
        assert detect_format_from_magic(b'\x7f') == "unknown"

    def test_short_mz(self):
        """Two bytes 'MZ' should still detect PE."""
        assert detect_format_from_magic(b'MZ') == "pe"


class TestGetMagicHint:
    """Test file-based format hint detection."""

    def _write_tmp(self, content: bytes) -> str:
        fd, path = tempfile.mkstemp()
        os.write(fd, content)
        os.close(fd)
        return path

    def test_pe_hint(self):
        path = self._write_tmp(b'MZ\x90\x00' + b'\x00' * 100)
        try:
            assert get_magic_hint(path) == "PE"
        finally:
            os.unlink(path)

    def test_elf_hint(self):
        path = self._write_tmp(b'\x7fELF' + b'\x00' * 100)
        try:
            assert get_magic_hint(path) == "ELF"
        finally:
            os.unlink(path)

    def test_macho_hint(self):
        path = self._write_tmp(b'\xcf\xfa\xed\xfe' + b'\x00' * 100)
        try:
            assert get_magic_hint(path) == "Mach-O"
        finally:
            os.unlink(path)

    def test_zip_hint(self):
        path = self._write_tmp(b'PK\x03\x04' + b'\x00' * 100)
        try:
            assert get_magic_hint(path) == "ZIP/Archive"
        finally:
            os.unlink(path)

    def test_gzip_hint(self):
        path = self._write_tmp(b'\x1f\x8b\x08\x00' + b'\x00' * 100)
        try:
            assert get_magic_hint(path) == "GZIP"
        finally:
            os.unlink(path)

    def test_pdf_hint(self):
        path = self._write_tmp(b'%PDF-1.4' + b'\x00' * 100)
        try:
            assert get_magic_hint(path) == "PDF"
        finally:
            os.unlink(path)

    def test_ole_hint(self):
        path = self._write_tmp(b'\xd0\xcf\x11\xe0' + b'\x00' * 100)
        try:
            assert get_magic_hint(path) == "OLE/MS-CFB"
        finally:
            os.unlink(path)

    def test_cgc_hint(self):
        path = self._write_tmp(b'\x7fCGC' + b'\x00' * 100)
        try:
            assert get_magic_hint(path) == "CGC"
        finally:
            os.unlink(path)

    def test_unknown_hint(self):
        path = self._write_tmp(b'\x00\x01\x02\x03')
        try:
            assert get_magic_hint(path) == "Unknown"
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        assert get_magic_hint("/nonexistent/path/to/file") == "Unreadable"


class TestCheckLib:
    """Test _check_lib raises RuntimeError when library unavailable."""

    def test_available(self):
        _check_lib("mylib", True, "test_tool")  # should not raise

    def test_unavailable(self):
        with pytest.raises(RuntimeError, match="mylib.*not installed"):
            _check_lib("mylib", False, "test_tool")

    def test_custom_pip_name(self):
        with pytest.raises(RuntimeError, match="pip install custom-pkg"):
            _check_lib("mylib", False, "test_tool", pip_name="custom-pkg")


class TestGetFilepath:
    """Test _get_filepath path resolution."""

    def test_no_file_raises(self):
        from unittest.mock import patch, MagicMock
        from pemcp.state import AnalyzerState
        mock_state = AnalyzerState()
        with patch("pemcp.mcp._format_helpers.state", mock_state):
            with pytest.raises(RuntimeError, match="No file specified"):
                _get_filepath(None)

    def test_nonexistent_explicit_file_raises(self):
        from unittest.mock import patch, MagicMock
        from pemcp.state import AnalyzerState
        mock_state = AnalyzerState()
        mock_state.allowed_paths = ["/tmp"]
        with patch("pemcp.mcp._format_helpers.state", mock_state):
            with pytest.raises(RuntimeError, match="File not found"):
                _get_filepath("/tmp/nonexistent_file_12345.bin")
