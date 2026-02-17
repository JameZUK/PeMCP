"""Parametrized unit tests — broader coverage via @pytest.mark.parametrize."""
import math
import pytest

pytest.importorskip("pefile", reason="pefile not installed")

from pemcp.hashing import SSDeep, ssdeep_hasher
from pemcp.parsers.strings import (
    _get_string_category,
    _extract_strings_from_data,
    _format_hex_dump_lines,
)
from pemcp.utils import shannon_entropy, format_timestamp, get_symbol_storage_class_str
from pemcp.state import AnalyzerState


# ---------------------------------------------------------------------------
# Shannon entropy — parametrized edge cases
# ---------------------------------------------------------------------------

class TestShannonEntropyParametrized:
    @pytest.mark.parametrize("data,expected", [
        (b"", 0.0),
        (b"\x00", 0.0),
        (b"\x00" * 1000, 0.0),
        (b"\xff" * 500, 0.0),
        (bytes(range(256)), 8.0),
        (bytes(range(256)) * 10, 8.0),
    ])
    def test_known_entropy_values(self, data, expected):
        result = shannon_entropy(data)
        assert abs(result - expected) < 1e-6, f"Expected {expected}, got {result}"

    @pytest.mark.parametrize("data", [
        b"AAAA",
        b"Hello World!",
        b"The quick brown fox jumps over the lazy dog",
        bytes(range(128)),
        b"\x00\xff" * 100,
    ])
    def test_entropy_within_bounds(self, data):
        result = shannon_entropy(data)
        assert 0.0 <= result <= 8.0


# ---------------------------------------------------------------------------
# format_timestamp — parametrized
# ---------------------------------------------------------------------------

class TestFormatTimestampParametrized:
    @pytest.mark.parametrize("ts,expected_substring", [
        (1577836800, "2020-01-01"),     # 2020-01-01 00:00:00 UTC
        (1609459200, "2021-01-01"),     # 2021-01-01
        (946684800, "2000-01-01"),      # Y2K
        (0, "No timestamp"),            # epoch zero
    ])
    def test_valid_timestamps(self, ts, expected_substring):
        result = format_timestamp(ts)
        assert expected_substring in result

    @pytest.mark.parametrize("ts", [
        -1, -100, -999999,
        "abc", None, [], {},
        3.14,
    ])
    def test_invalid_timestamps(self, ts):
        result = format_timestamp(ts)
        assert "Invalid" in result or "invalid" in result.lower()


# ---------------------------------------------------------------------------
# get_symbol_storage_class_str — parametrized
# ---------------------------------------------------------------------------

class TestSymbolStorageClassParametrized:
    @pytest.mark.parametrize("value,expected", [
        (0, "NULL"),
        (1, "AUTOMATIC"),
        (2, "EXTERNAL"),
        (3, "STATIC"),
        (4, "REGISTER"),
        (5, "EXTERNAL_DEF"),
        (6, "LABEL"),
        (100, "BLOCK"),
        (101, "FUNCTION"),
        (103, "FILE"),
        (105, "WEAK_EXTERNAL"),
    ])
    def test_known_classes(self, value, expected):
        result = get_symbol_storage_class_str(value)
        assert expected in result

    @pytest.mark.parametrize("value", [999, 255, -1, 50])
    def test_unknown_classes(self, value):
        result = get_symbol_storage_class_str(value)
        assert "UNKNOWN" in result


# ---------------------------------------------------------------------------
# String categorization — parametrized
# ---------------------------------------------------------------------------

class TestStringCategoryParametrized:
    @pytest.mark.parametrize("string,expected_category", [
        # IPv4 addresses
        ("192.168.1.1", "ipv4"),
        ("10.0.0.1", "ipv4"),
        ("172.16.0.100", "ipv4"),
        ("8.8.8.8", "ipv4"),
        # URLs
        ("http://example.com", "url"),
        ("https://malware.com/payload.bin", "url"),
        ("ftp://files.example.org/data", "url"),
        # Domains
        ("example.com", "domain"),
        ("evil.ru", "domain"),
        ("c2server.onion", "domain"),
        # Windows paths
        ("C:\\Windows\\System32\\cmd.exe", "filepath_windows"),
        ("D:\\Users\\admin\\malware.exe", "filepath_windows"),
        # Registry keys
        ("HKLM\\SOFTWARE\\Microsoft", "registry_key"),
        ("HKCU\\Software\\Classes", "registry_key"),
        ("HKEY_LOCAL_MACHINE\\System", "registry_key"),
        # Emails
        ("user@example.com", "email"),
        ("admin@evil.org", "email"),
        # No category
        ("just a random string", None),
        ("", None),
        ("12345", None),
    ])
    def test_categorization(self, string, expected_category):
        result = _get_string_category(string)
        assert result == expected_category, f"'{string}' categorized as {result}, expected {expected_category}"

    @pytest.mark.parametrize("invalid_ip", [
        "999.999.999.999",
        "256.1.1.1",
        "1.2.3.999",
    ])
    def test_invalid_ips_not_ipv4(self, invalid_ip):
        result = _get_string_category(invalid_ip)
        assert result != "ipv4"


# ---------------------------------------------------------------------------
# SSDeep hashing — parametrized inputs
# ---------------------------------------------------------------------------

class TestSSDeepParametrized:
    @pytest.mark.parametrize("data", [
        b"A" * 100,
        b"B" * 1000,
        b"Hello World " * 200,
        bytes(range(256)) * 20,
        b"\x00" * 500,
    ])
    def test_hash_format(self, data):
        result = ssdeep_hasher.hash(data)
        parts = result.split(":")
        assert len(parts) == 3, f"Hash should have 3 colon-separated parts: {result}"
        assert int(parts[0]) >= SSDeep.BLOCKSIZE_MIN

    @pytest.mark.parametrize("data", [
        b"deterministic " * 100,
        b"\xff" * 200,
        bytes(range(256)),
    ])
    def test_deterministic(self, data):
        h1 = ssdeep_hasher.hash(data)
        h2 = ssdeep_hasher.hash(data)
        assert h1 == h2


# ---------------------------------------------------------------------------
# Levenshtein distance — parametrized
# ---------------------------------------------------------------------------

class TestLevenshteinParametrized:
    @pytest.mark.parametrize("s1,s2,expected", [
        ("", "", 0),
        ("abc", "abc", 0),
        ("abc", "", 3),
        ("", "abc", 3),
        ("abc", "abd", 1),
        ("abc", "abcd", 1),
        ("kitten", "sitting", 3),
        ("a", "b", 1),
    ])
    def test_known_distances(self, s1, s2, expected):
        assert ssdeep_hasher._levenshtein(s1, s2) == expected


# ---------------------------------------------------------------------------
# String extraction — parametrized min_length
# ---------------------------------------------------------------------------

class TestExtractStringsParametrized:
    @pytest.mark.parametrize("min_length,expected_count", [
        (1, 4),   # All: "AB", "CDEF", "GH", "IJKLM"
        (2, 4),   # "AB", "CDEF", "GH", "IJKLM"
        (3, 2),   # "CDEF", "IJKLM"
        (4, 2),   # "CDEF", "IJKLM"
        (5, 1),   # "IJKLM"
        (6, 0),   # None
    ])
    def test_min_length_filtering(self, min_length, expected_count):
        data = b"AB\x00CDEF\x00GH\x00IJKLM\x00"
        result = _extract_strings_from_data(data, min_length=min_length)
        assert len(result) == expected_count


# ---------------------------------------------------------------------------
# Hex dump formatting — parametrized
# ---------------------------------------------------------------------------

class TestHexDumpParametrized:
    @pytest.mark.parametrize("data_len,bytes_per_line,expected_lines", [
        (0, 16, 0),
        (1, 16, 1),
        (16, 16, 1),
        (17, 16, 2),
        (32, 16, 2),
        (48, 16, 3),
    ])
    def test_line_count(self, data_len, bytes_per_line, expected_lines):
        data = bytes(range(data_len % 256)) if data_len > 0 else b""
        if data_len > 256:
            data = data * (data_len // 256 + 1)
        data = data[:data_len]
        lines = _format_hex_dump_lines(data, bytes_per_line=bytes_per_line)
        assert len(lines) == expected_lines


# ---------------------------------------------------------------------------
# AnalyzerState path sandboxing — parametrized
# ---------------------------------------------------------------------------

class TestPathSandboxingParametrized:
    @pytest.mark.parametrize("allowed,path,should_raise", [
        (["/tmp/safe"], "/tmp/safe/file.bin", False),
        (["/tmp/safe"], "/tmp/safe", False),
        (["/tmp/safe"], "/etc/passwd", True),
        (["/tmp/safe"], "/tmp/unsafe/file.bin", True),
        (["/tmp/a", "/tmp/b"], "/tmp/a/file.bin", False),
        (["/tmp/a", "/tmp/b"], "/tmp/b/file.bin", False),
        (["/tmp/a", "/tmp/b"], "/tmp/c/file.bin", True),
    ])
    def test_sandbox_paths(self, allowed, path, should_raise):
        s = AnalyzerState()
        s.allowed_paths = allowed
        if should_raise:
            with pytest.raises(RuntimeError, match="Access denied"):
                s.check_path_allowed(path)
        else:
            s.check_path_allowed(path)  # Should not raise

    def test_no_restriction_allows_all(self):
        s = AnalyzerState()
        s.allowed_paths = None
        s.check_path_allowed("/any/path")
        s.check_path_allowed("/etc/passwd")
        s.check_path_allowed("/root/.ssh/id_rsa")
