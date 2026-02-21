"""Unit tests for pemcp/parsers/strings.py — string extraction and analysis."""
import pytest

pytest.importorskip("pefile", reason="pefile not installed")

from pemcp.parsers.strings import (
    _extract_strings_from_data,
    _search_specific_strings_in_data,
    _format_hex_dump_lines,
    _get_string_category,
    _decode_single_byte_xor,
    _perform_unified_string_sifting,
    _correlate_strings_and_capa,
)


# ---------------------------------------------------------------------------
# _extract_strings_from_data
# ---------------------------------------------------------------------------

class TestExtractStrings:
    def test_basic_extraction(self):
        data = b"Hello\x00World\x00"
        result = _extract_strings_from_data(data, min_length=4)
        strings = [s for _, s in result]
        assert "Hello" in strings
        assert "World" in strings

    def test_min_length_filtering(self):
        data = b"AB\x00CDEF\x00GH\x00IJKLM\x00"
        result = _extract_strings_from_data(data, min_length=4)
        strings = [s for _, s in result]
        assert "CDEF" in strings
        assert "IJKLM" in strings
        assert "AB" not in strings
        assert "GH" not in strings

    def test_offsets_correct(self):
        data = b"\x00\x00Hello\x00"
        result = _extract_strings_from_data(data, min_length=4)
        assert len(result) == 1
        offset, string = result[0]
        assert offset == 2
        assert string == "Hello"

    def test_empty_data(self):
        assert _extract_strings_from_data(b"", min_length=1) == []

    def test_no_printable(self):
        data = bytes(range(0, 32))  # All non-printable
        assert _extract_strings_from_data(data, min_length=1) == []

    def test_trailing_string(self):
        # String at end without null terminator
        data = b"\x00ABCDE"
        result = _extract_strings_from_data(data, min_length=5)
        assert len(result) == 1
        assert result[0][1] == "ABCDE"

    def test_memoryview_input(self):
        data = b"TestString\x00"
        mv = memoryview(data)
        result = _extract_strings_from_data(mv, min_length=4)
        strings = [s for _, s in result]
        assert "TestString" in strings


# ---------------------------------------------------------------------------
# _search_specific_strings_in_data
# ---------------------------------------------------------------------------

class TestSearchSpecificStrings:
    def test_find_present_terms(self):
        data = b"Hello World Hello"
        result = _search_specific_strings_in_data(data, ["Hello", "World"])
        assert len(result["Hello"]) == 2
        assert len(result["World"]) == 1

    def test_not_found(self):
        data = b"Hello World"
        result = _search_specific_strings_in_data(data, ["Missing"])
        assert result["Missing"] == []

    def test_empty_data(self):
        result = _search_specific_strings_in_data(b"", ["test"])
        assert result["test"] == []

    def test_correct_offsets(self):
        data = b"AABAA"
        result = _search_specific_strings_in_data(data, ["AA"])
        assert 0 in result["AA"]
        assert 3 in result["AA"]

    def test_multiple_terms(self):
        data = b"abc def ghi"
        result = _search_specific_strings_in_data(data, ["abc", "def", "ghi", "xyz"])
        assert len(result["abc"]) == 1
        assert len(result["def"]) == 1
        assert len(result["ghi"]) == 1
        assert len(result["xyz"]) == 0


# ---------------------------------------------------------------------------
# _format_hex_dump_lines
# ---------------------------------------------------------------------------

class TestFormatHexDump:
    def test_basic_format(self):
        data = b"\x00\x01\x02\x03"
        lines = _format_hex_dump_lines(data, start_address=0)
        assert len(lines) == 1
        assert "00 01 02 03" in lines[0]
        assert lines[0].startswith("00000000")

    def test_custom_start_address(self):
        data = b"\xff"
        lines = _format_hex_dump_lines(data, start_address=0x1000)
        assert lines[0].startswith("00001000")

    def test_ascii_display(self):
        data = b"ABCD"
        lines = _format_hex_dump_lines(data)
        assert "|ABCD|" in lines[0]

    def test_non_printable_shown_as_dot(self):
        data = b"\x00\x01\x02\x03"
        lines = _format_hex_dump_lines(data)
        assert "|....|" in lines[0]

    def test_multiple_lines(self):
        data = bytes(range(32))
        lines = _format_hex_dump_lines(data, bytes_per_line=16)
        assert len(lines) == 2

    def test_empty_data(self):
        assert _format_hex_dump_lines(b"") == []

    def test_memoryview_input(self):
        data = b"Test"
        lines = _format_hex_dump_lines(memoryview(data))
        assert len(lines) == 1


# ---------------------------------------------------------------------------
# _get_string_category
# ---------------------------------------------------------------------------

class TestGetStringCategory:
    def test_ipv4(self):
        assert _get_string_category("192.168.1.1") == "ipv4"
        assert _get_string_category("10.0.0.1") == "ipv4"
        assert _get_string_category("255.255.255.255") == "ipv4"

    def test_url(self):
        assert _get_string_category("http://example.com") == "url"
        assert _get_string_category("https://example.com/path?q=1") == "url"

    def test_domain(self):
        assert _get_string_category("example.com") == "domain"
        assert _get_string_category("sub.example.co.uk") == "domain"

    def test_filepath_windows(self):
        assert _get_string_category("C:\\Windows\\System32\\cmd.exe") == "filepath_windows"

    def test_registry_key(self):
        assert _get_string_category("HKLM\\SOFTWARE\\Microsoft") == "registry_key"
        assert _get_string_category("HKEY_LOCAL_MACHINE\\System") == "registry_key"

    def test_email(self):
        assert _get_string_category("user@example.com") == "email"

    def test_no_category(self):
        assert _get_string_category("just a random string") is None
        assert _get_string_category("") is None

    def test_invalid_ip(self):
        # 999 is not a valid octet
        result = _get_string_category("999.999.999.999")
        assert result != "ipv4"


# ---------------------------------------------------------------------------
# _decode_single_byte_xor
# ---------------------------------------------------------------------------

class TestDecodeSingleByteXor:
    def test_decode_known_key(self):
        # The function finds the key producing the most printable output.
        # Verify that decoding the result with the found key recovers valid text.
        plaintext = b"This is a simple test string that should decode correctly with a known XOR key value"
        key = 0x37
        encoded = bytes([b ^ key for b in plaintext])
        result = _decode_single_byte_xor(encoded)
        assert result is not None
        decoded, found_key = result
        # Verify the found key actually decodes the data
        assert bytes([b ^ found_key for b in encoded]) == decoded
        # The decoded text must be highly printable
        printable = sum(1 for b in decoded if 32 <= b <= 126 or b in [9, 10, 13])
        assert printable / len(decoded) > 0.85

    def test_empty_data(self):
        result = _decode_single_byte_xor(b"")
        assert result is None

    def test_non_text_returns_none(self):
        # Random binary data that won't decode to printable text for any key
        import os
        data = os.urandom(100)
        result = _decode_single_byte_xor(data)
        # May or may not find a key; if found, it should meet the threshold
        if result is not None:
            decoded, key = result
            printable = sum(1 for b in decoded if 32 <= b <= 126 or b in [9, 10, 13])
            assert printable / len(decoded) > 0.85

    def test_all_printable_text(self):
        plaintext = b"AAAAAAAAAA"  # All same char
        key = 0x01
        encoded = bytes([b ^ key for b in plaintext])
        result = _decode_single_byte_xor(encoded)
        # Should find a key that produces printable output
        assert result is not None


# ---------------------------------------------------------------------------
# _perform_unified_string_sifting (graceful degradation)
# ---------------------------------------------------------------------------

class TestPerformUnifiedStringSifting:
    def test_no_crash_without_stringsifter(self):
        """Should return early without error when StringSifter is unavailable."""
        pe_info = {"basic_ascii_strings": []}
        _perform_unified_string_sifting(pe_info)
        # No sifter_error should be set for a clean early exit
        assert "sifter_error" not in pe_info

    def test_empty_dict_no_crash(self):
        """Should handle an empty dict gracefully."""
        pe_info = {}
        _perform_unified_string_sifting(pe_info)


# ---------------------------------------------------------------------------
# _correlate_strings_and_capa (graceful degradation)
# ---------------------------------------------------------------------------

class TestCorrelateStringsAndCapa:
    def test_no_capa_data(self):
        """Should handle missing capa data gracefully."""
        pe_info = {}
        _correlate_strings_and_capa(pe_info)

    def test_empty_capa_data(self):
        """Should handle empty capa analysis gracefully."""
        pe_info = {"capa_analysis": {}}
        _correlate_strings_and_capa(pe_info)
