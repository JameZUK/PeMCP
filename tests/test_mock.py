"""Unit tests for pemcp/mock.py — MockPE class for shellcode mode."""
import pytest

from pemcp.mock import MockPE


class TestMockPE:
    def setup_method(self):
        self.data = b"\x90\x90\xcc\x00\x01\x02\x03\xff"
        self.mock_pe = MockPE(self.data)

    def test_init_data(self):
        assert self.mock_pe.__data__ == self.data

    def test_empty_sections(self):
        assert self.mock_pe.sections == []

    def test_none_headers(self):
        assert self.mock_pe.DOS_HEADER is None
        assert self.mock_pe.NT_HEADERS is None
        assert self.mock_pe.OPTIONAL_HEADER is None
        assert self.mock_pe.FILE_HEADER is None

    def test_empty_directories(self):
        assert self.mock_pe.DIRECTORY_ENTRY_IMPORT == []
        assert self.mock_pe.DIRECTORY_ENTRY_EXPORT is None
        assert self.mock_pe.DIRECTORY_ENTRY_RESOURCE is None
        assert self.mock_pe.DIRECTORY_ENTRY_DEBUG == []
        assert self.mock_pe.DIRECTORY_ENTRY_TLS is None

    def test_get_warnings(self):
        warnings = self.mock_pe.get_warnings()
        assert isinstance(warnings, list)
        assert len(warnings) == 1
        assert "Shellcode" in warnings[0]

    def test_close(self):
        # close() should not raise
        self.mock_pe.close()

    def test_get_overlay_data_start_offset(self):
        assert self.mock_pe.get_overlay_data_start_offset() is None

    def test_generate_checksum(self):
        assert self.mock_pe.generate_checksum() == 0

    def test_get_data_full(self):
        result = self.mock_pe.get_data()
        assert result == self.data

    def test_get_data_with_offset(self):
        result = self.mock_pe.get_data(offset=2)
        assert result == self.data[2:]

    def test_get_data_with_offset_and_length(self):
        result = self.mock_pe.get_data(offset=1, length=3)
        assert result == self.data[1:4]

    def test_get_data_offset_beyond_length(self):
        result = self.mock_pe.get_data(offset=100)
        assert result == b""

    def test_empty_data(self):
        mock = MockPE(b"")
        assert mock.__data__ == b""
        assert mock.get_data() == b""
        assert mock.generate_checksum() == 0
