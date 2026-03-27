"""Tests for gopclntab parser — header parsing, function walking, error handling."""
import struct
import unittest

from arkana.parsers.go_pclntab import (
    parse_gopclntab,
    _parse_header,
    _find_by_section_name,
    _find_by_magic_scan,
    _decode_varint,
    _decode_pcdata,
    _read_cstring,
    _read_u32,
    _read_ptr,
    _parse_elf_section_headers,
    _parse_macho_section_headers,
    _PcHeader,
    _MAX_FUNCTIONS,
    _GOPCLNTAB_MAGICS,
)


# ---------------------------------------------------------------------------
# Helpers for building synthetic gopclntab data
# ---------------------------------------------------------------------------

def _build_header_v120(nfunc=5, nfiles=2, ptr_size=8, quantum=1,
                       text_start=0x401000, big_endian=False):
    """Build a synthetic Go 1.20+ gopclntab header."""
    e = ">" if big_endian else "<"
    ps_fmt = f"{e}Q" if ptr_size == 8 else f"{e}I"
    magic = b"\xf1\xff\xff\xff" if not big_endian else b"\xff\xff\xff\xf1"
    hdr = magic
    hdr += struct.pack("BBBB", 0, 0, quantum, ptr_size)
    hdr += struct.pack(ps_fmt, nfunc)       # nfunc
    hdr += struct.pack(ps_fmt, nfiles)      # nfiles
    hdr += struct.pack(ps_fmt, text_start)  # textStart
    hdr += struct.pack(ps_fmt, 0)           # funcnameOffset
    hdr += struct.pack(ps_fmt, 0)           # cuOffset
    hdr += struct.pack(ps_fmt, 0)           # filetabOffset
    hdr += struct.pack(ps_fmt, 0)           # pctabOffset
    hdr += struct.pack(ps_fmt, 0)           # pclnOffset
    return hdr


def _build_header_v118(nfunc=5, ptr_size=8, quantum=1, text_start=0x401000):
    """Build a synthetic Go 1.18 gopclntab header."""
    magic = b"\xf0\xff\xff\xff"
    hdr = magic + struct.pack("BBBB", 0, 0, quantum, ptr_size)
    ps_fmt = "<Q" if ptr_size == 8 else "<I"
    hdr += struct.pack(ps_fmt, nfunc)       # nfunc
    hdr += struct.pack(ps_fmt, 0)           # nfiles
    hdr += struct.pack(ps_fmt, text_start)  # textStart
    for _ in range(5):
        hdr += struct.pack(ps_fmt, 0)       # remaining offsets
    return hdr


def _build_header_v116(nfunc=5, ptr_size=8, quantum=1):
    """Build a synthetic Go 1.16 gopclntab header."""
    magic = b"\xfa\xff\xff\xff"
    hdr = magic + struct.pack("BBBB", 0, 0, quantum, ptr_size)
    ps_fmt = "<Q" if ptr_size == 8 else "<I"
    hdr += struct.pack(ps_fmt, nfunc)  # nfunc
    hdr += struct.pack(ps_fmt, 0)      # nfiles
    for _ in range(5):
        hdr += struct.pack(ps_fmt, 0)  # remaining offsets
    return hdr


def _build_header_v12(nfunc=5, ptr_size=8, quantum=1):
    """Build a synthetic Go 1.2 gopclntab header."""
    magic = b"\xfb\xff\xff\xff"
    hdr = magic + struct.pack("BBBB", 0, 0, quantum, ptr_size)
    ps_fmt = "<Q" if ptr_size == 8 else "<I"
    hdr += struct.pack(ps_fmt, nfunc)  # nfunc
    return hdr


# ---------------------------------------------------------------------------
# Header parsing tests
# ---------------------------------------------------------------------------

class TestHeaderParsing(unittest.TestCase):
    """Test _parse_header for all 4 Go versions."""

    def test_v120_64bit_le(self):
        hdr = _build_header_v120(nfunc=42, ptr_size=8, text_start=0x500000)
        errors = []
        h = _parse_header(hdr, 0, errors)
        self.assertIsNotNone(h)
        self.assertEqual(h.version, "1.20+")
        self.assertTrue(h.is_120)
        self.assertEqual(h.nfunc, 42)
        self.assertEqual(h.ptr_size, 8)
        self.assertEqual(h.quantum, 1)
        self.assertEqual(h.text_start, 0x500000)
        self.assertFalse(h.big_endian)
        self.assertEqual(errors, [])

    def test_v120_32bit_le(self):
        hdr = _build_header_v120(nfunc=10, ptr_size=4, text_start=0x401000)
        errors = []
        h = _parse_header(hdr, 0, errors)
        self.assertIsNotNone(h)
        self.assertEqual(h.ptr_size, 4)
        self.assertEqual(h.nfunc, 10)

    def test_v120_big_endian(self):
        hdr = _build_header_v120(nfunc=7, ptr_size=8, big_endian=True)
        errors = []
        h = _parse_header(hdr, 0, errors)
        self.assertIsNotNone(h)
        self.assertTrue(h.big_endian)
        self.assertEqual(h.nfunc, 7)

    def test_v118(self):
        hdr = _build_header_v118(nfunc=20, text_start=0x600000)
        errors = []
        h = _parse_header(hdr, 0, errors)
        self.assertIsNotNone(h)
        self.assertTrue(h.is_118)
        self.assertEqual(h.version, "1.18")
        self.assertEqual(h.nfunc, 20)
        self.assertEqual(h.text_start, 0x600000)

    def test_v116(self):
        hdr = _build_header_v116(nfunc=15)
        errors = []
        h = _parse_header(hdr, 0, errors)
        self.assertIsNotNone(h)
        self.assertTrue(h.is_116)
        self.assertEqual(h.version, "1.16")
        self.assertEqual(h.nfunc, 15)
        self.assertEqual(h.text_start, 0)

    def test_v12(self):
        hdr = _build_header_v12(nfunc=100)
        errors = []
        h = _parse_header(hdr, 0, errors)
        self.assertIsNotNone(h)
        self.assertTrue(h.is_12)
        self.assertEqual(h.version, "1.2")
        self.assertEqual(h.nfunc, 100)

    def test_v12_32bit(self):
        hdr = _build_header_v12(nfunc=50, ptr_size=4)
        errors = []
        h = _parse_header(hdr, 0, errors)
        self.assertIsNotNone(h)
        self.assertEqual(h.ptr_size, 4)
        self.assertEqual(h.nfunc, 50)

    def test_invalid_magic(self):
        data = b"\x00\x00\x00\x00\x00\x00\x01\x08"
        errors = []
        h = _parse_header(data, 0, errors)
        self.assertIsNone(h)
        self.assertTrue(any("Unknown gopclntab magic" in e for e in errors))

    def test_invalid_ptr_size(self):
        data = b"\xf1\xff\xff\xff\x00\x00\x01\x03"  # ptrSize=3
        errors = []
        h = _parse_header(data, 0, errors)
        self.assertIsNone(h)
        self.assertTrue(any("Invalid pointer size" in e for e in errors))

    def test_invalid_quantum(self):
        data = b"\xf1\xff\xff\xff\x00\x00\x03\x08"  # quantum=3
        errors = []
        h = _parse_header(data, 0, errors)
        self.assertIsNone(h)
        self.assertTrue(any("Invalid quantum" in e for e in errors))

    def test_bad_padding(self):
        data = b"\xf1\xff\xff\xff\x01\x00\x01\x08"  # pad1=1
        errors = []
        h = _parse_header(data, 0, errors)
        self.assertIsNone(h)
        self.assertTrue(any("Invalid padding" in e for e in errors))

    def test_truncated_data(self):
        errors = []
        h = _parse_header(b"\xf1\xff\xff", 0, errors)
        self.assertIsNone(h)
        self.assertTrue(any("truncated" in e.lower() for e in errors))

    def test_truncated_v116_body(self):
        """Valid 8-byte header but body too short for Go 1.16."""
        data = b"\xfa\xff\xff\xff\x00\x00\x01\x08" + b"\x00" * 4
        errors = []
        h = _parse_header(data, 0, errors)
        self.assertIsNone(h)
        self.assertTrue(any("Truncated" in e for e in errors))

    def test_arm_quantum(self):
        """ARM uses quantum=4."""
        hdr = _build_header_v120(nfunc=5, quantum=4)
        errors = []
        h = _parse_header(hdr, 0, errors)
        self.assertIsNotNone(h)
        self.assertEqual(h.quantum, 4)


# ---------------------------------------------------------------------------
# Varint / pcdata tests
# ---------------------------------------------------------------------------

class TestVarint(unittest.TestCase):

    def test_zero(self):
        val, consumed = _decode_varint(b"\x00", 0)
        self.assertEqual(val, 0)
        self.assertEqual(consumed, 1)

    def test_one(self):
        val, consumed = _decode_varint(b"\x01", 0)
        self.assertEqual(val, 1)

    def test_127(self):
        val, consumed = _decode_varint(b"\x7f", 0)
        self.assertEqual(val, 127)

    def test_128(self):
        val, consumed = _decode_varint(b"\x80\x01", 0)
        self.assertEqual(val, 128)

    def test_300(self):
        val, consumed = _decode_varint(b"\xac\x02", 0)
        self.assertEqual(val, 300)

    def test_empty_data(self):
        val, consumed = _decode_varint(b"", 0)
        self.assertEqual(val, 0)
        self.assertEqual(consumed, 0)

    def test_truncated(self):
        """High bit set but no continuation byte."""
        val, consumed = _decode_varint(b"\x80", 0)
        self.assertEqual(consumed, 1)

    def test_offset(self):
        """Decode at non-zero offset."""
        val, consumed = _decode_varint(b"\x00\x00\x05", 2)
        self.assertEqual(val, 5)
        self.assertEqual(consumed, 1)


class TestPcdata(unittest.TestCase):

    def test_empty(self):
        entries = list(_decode_pcdata(b"", 0, 1))
        self.assertEqual(entries, [])

    def test_single_entry(self):
        # Encode: value_delta=2 (zig-zag: 4), pc_delta=10
        data = b"\x04\x0a"
        entries = list(_decode_pcdata(data, 0, 1))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], 10)  # pc
        self.assertEqual(entries[0][1], 1)   # value: -1 + 2 = 1


# ---------------------------------------------------------------------------
# Section lookup tests
# ---------------------------------------------------------------------------

class TestSectionLookup(unittest.TestCase):

    def test_find_gopclntab_elf(self):
        sections = [
            {"name": ".text", "offset": 0, "size": 1000, "vaddr": 0x401000},
            {"name": ".gopclntab", "offset": 1000, "size": 500, "vaddr": 0x402000},
        ]
        data = b"\x00" * 2000
        result = _find_by_section_name(data, sections)
        self.assertIsNotNone(result)
        self.assertEqual(result, (1000, 500))

    def test_find_gopclntab_macho(self):
        sections = [{"name": "__gopclntab", "offset": 100, "size": 200, "vaddr": 0}]
        data = b"\x00" * 500
        result = _find_by_section_name(data, sections)
        self.assertIsNotNone(result)

    def test_find_data_rel_ro(self):
        sections = [{"name": ".data.rel.ro.gopclntab", "offset": 50, "size": 100, "vaddr": 0}]
        data = b"\x00" * 200
        result = _find_by_section_name(data, sections)
        self.assertIsNotNone(result)

    def test_no_match(self):
        sections = [{"name": ".text", "offset": 0, "size": 1000, "vaddr": 0}]
        data = b"\x00" * 1000
        result = _find_by_section_name(data, sections)
        self.assertIsNone(result)

    def test_section_too_small(self):
        sections = [{"name": ".gopclntab", "offset": 0, "size": 8, "vaddr": 0}]
        data = b"\x00" * 100
        result = _find_by_section_name(data, sections)
        self.assertIsNone(result)

    def test_section_out_of_bounds(self):
        sections = [{"name": ".gopclntab", "offset": 900, "size": 500, "vaddr": 0}]
        data = b"\x00" * 100
        result = _find_by_section_name(data, sections)
        self.assertIsNone(result)


class TestMagicScan(unittest.TestCase):

    def test_valid_magic_found(self):
        # Embed valid Go 1.20+ header in data
        header = b"\xf1\xff\xff\xff\x00\x00\x01\x08"
        data = b"\x00" * 100 + header + b"\x00" * 100
        result = _find_by_magic_scan(data)
        self.assertEqual(result, 100)

    def test_no_magic(self):
        data = b"\x00" * 1000
        result = _find_by_magic_scan(data)
        self.assertIsNone(result)

    def test_invalid_candidate_bad_ptrsize(self):
        # Magic present but ptrSize=3 (invalid)
        data = b"\x00" * 50 + b"\xf1\xff\xff\xff\x00\x00\x01\x03" + b"\x00" * 50
        result = _find_by_magic_scan(data)
        self.assertIsNone(result)

    def test_invalid_candidate_bad_quantum(self):
        data = b"\x00" * 50 + b"\xf1\xff\xff\xff\x00\x00\x03\x08" + b"\x00" * 50
        result = _find_by_magic_scan(data)
        self.assertIsNone(result)

    def test_invalid_candidate_bad_padding(self):
        data = b"\x00" * 50 + b"\xf1\xff\xff\xff\x01\x00\x01\x08" + b"\x00" * 50
        result = _find_by_magic_scan(data)
        self.assertIsNone(result)

    def test_multiple_candidates_first_valid_used(self):
        # First: invalid (bad ptrSize), second: valid
        bad = b"\xf1\xff\xff\xff\x00\x00\x01\x03"
        good = b"\xf1\xff\xff\xff\x00\x00\x01\x08"
        data = b"\x00" * 50 + bad + b"\x00" * 50 + good + b"\x00" * 50
        result = _find_by_magic_scan(data)
        self.assertEqual(result, 50 + len(bad) + 50)  # second occurrence


# ---------------------------------------------------------------------------
# Error handling / safety tests
# ---------------------------------------------------------------------------

class TestParseGopclntabSafety(unittest.TestCase):

    def test_empty_data_returns_none(self):
        result = parse_gopclntab(b"")
        self.assertIsNone(result)

    def test_short_data_returns_none(self):
        result = parse_gopclntab(b"\x00" * 10)
        self.assertIsNone(result)

    def test_pe_without_gopclntab_returns_none(self):
        result = parse_gopclntab(b"MZ" + b"\x00" * 200)
        self.assertIsNone(result)

    def test_nfunc_zero_returns_empty(self):
        hdr = _build_header_v120(nfunc=0)
        # Embed header in enough padding for section
        data = hdr + b"\x00" * 200
        sections = [{"name": ".gopclntab", "offset": 0, "size": len(data), "vaddr": 0}]
        result = parse_gopclntab(data, sections)
        self.assertIsNotNone(result)
        self.assertEqual(result["function_count"], 0)
        self.assertEqual(result["functions"], [])
        self.assertEqual(result["go_version_hint"], "1.20+")

    def test_truncated_function_table_partial_results(self):
        """Valid header claiming 100 functions but data is too short."""
        hdr = _build_header_v12(nfunc=100, ptr_size=8)
        # Only enough space for ~2 entries (each entry = 16 bytes)
        data = hdr + b"\x00" * 40
        sections = [{"name": ".gopclntab", "offset": 0, "size": len(data), "vaddr": 0}]
        result = parse_gopclntab(data, sections)
        self.assertIsNotNone(result)
        # Should have parse_errors about truncation
        self.assertTrue(any("truncated" in e.lower() or "Truncated" in e for e in result.get("parse_errors", [])))

    def test_corrupt_utf8_name_lossy_decode(self):
        """Function name with invalid UTF-8 bytes should decode with replacement."""
        name = _read_cstring(b"\xff\xfe\x41\x00", 0)
        self.assertIn("A", name)  # At least the ASCII part survives
        self.assertIn("\ufffd", name)  # Replacement character for invalid bytes

    def test_name_offset_out_of_bounds(self):
        """Name offset pointing outside data should return empty string."""
        name = _read_cstring(b"hello\x00", 100)
        self.assertEqual(name, "")

    def test_negative_offset_cstring(self):
        name = _read_cstring(b"hello\x00", -5)
        self.assertEqual(name, "")

    def test_nfunc_exceeds_max_capped(self):
        """nfunc > _MAX_FUNCTIONS should be capped with parse_errors."""
        # Build header with absurd nfunc
        magic = b"\xfb\xff\xff\xff"
        hdr = magic + struct.pack("BBBB", 0, 0, 1, 8)
        hdr += struct.pack("<Q", _MAX_FUNCTIONS + 100)  # nfunc
        data = hdr + b"\x00" * 1000
        sections = [{"name": ".gopclntab", "offset": 0, "size": len(data), "vaddr": 0}]
        result = parse_gopclntab(data, sections)
        self.assertIsNotNone(result)
        self.assertTrue(any("capped" in e.lower() for e in result.get("parse_errors", [])))

    def test_magic_scan_fallback_when_no_sections(self):
        """When no sections provided, falls back to magic scan."""
        padding_before = b"\x00" * 100
        # Build a minimal valid header
        hdr = _build_header_v120(nfunc=0)
        data = padding_before + hdr + b"\x00" * 200
        result = parse_gopclntab(data)  # No sections
        self.assertIsNotNone(result)
        self.assertEqual(result["go_version_hint"], "1.20+")

    def test_none_sections_handled(self):
        """sections=None should not crash."""
        hdr = _build_header_v120(nfunc=0)
        data = hdr + b"\x00" * 200
        result = parse_gopclntab(data, None)
        # Should try magic scan and find it at offset 0
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# ELF / Mach-O section parser tests
# ---------------------------------------------------------------------------

class TestElfSectionParser(unittest.TestCase):

    def test_non_elf_returns_empty(self):
        result = _parse_elf_section_headers(b"MZ" + b"\x00" * 100)
        self.assertEqual(result, [])

    def test_short_data_returns_empty(self):
        result = _parse_elf_section_headers(b"\x7fELF")
        self.assertEqual(result, [])

    def test_empty_returns_empty(self):
        result = _parse_elf_section_headers(b"")
        self.assertEqual(result, [])


class TestMachoSectionParser(unittest.TestCase):

    def test_non_macho_returns_empty(self):
        result = _parse_macho_section_headers(b"MZ" + b"\x00" * 100)
        self.assertEqual(result, [])

    def test_short_data_returns_empty(self):
        result = _parse_macho_section_headers(b"\xfe\xed\xfa\xce")
        self.assertEqual(result, [])

    def test_empty_returns_empty(self):
        result = _parse_macho_section_headers(b"")
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# Package name extraction tests
# ---------------------------------------------------------------------------

class TestPackageExtraction(unittest.TestCase):

    def test_simple_function(self):
        from arkana.mcp.tools_go import _extract_go_package
        self.assertEqual(_extract_go_package("main.main"), "main")

    def test_nested_package(self):
        from arkana.mcp.tools_go import _extract_go_package
        self.assertEqual(_extract_go_package("crypto/tls.(*Conn).Read"), "crypto/tls")

    def test_method_receiver(self):
        from arkana.mcp.tools_go import _extract_go_package
        self.assertEqual(_extract_go_package("net/http.(*Server).Serve"), "net/http")

    def test_no_dot(self):
        from arkana.mcp.tools_go import _extract_go_package
        self.assertEqual(_extract_go_package("runtime"), "unknown")

    def test_empty_name(self):
        from arkana.mcp.tools_go import _extract_go_package
        self.assertEqual(_extract_go_package(""), "unknown")

    def test_stdlib_init(self):
        from arkana.mcp.tools_go import _extract_go_package
        self.assertEqual(_extract_go_package("runtime.init"), "runtime")


# ---------------------------------------------------------------------------
# Read helpers edge cases
# ---------------------------------------------------------------------------

class TestReadHelpers(unittest.TestCase):

    def test_read_u32_out_of_bounds(self):
        self.assertIsNone(_read_u32(b"\x00\x00", 0))

    def test_read_u32_negative_offset(self):
        self.assertIsNone(_read_u32(b"\x01\x00\x00\x00", -1))

    def test_read_ptr_4(self):
        val = _read_ptr(b"\x01\x00\x00\x00", 0, 4)
        self.assertEqual(val, 1)

    def test_read_ptr_8(self):
        val = _read_ptr(b"\x01\x00\x00\x00\x00\x00\x00\x00", 0, 8)
        self.assertEqual(val, 1)

    def test_cstring_no_null_terminator(self):
        """String without null terminator returns up to max_len."""
        name = _read_cstring(b"abcdefgh", 0, max_len=4)
        self.assertEqual(name, "abcd")


# ---------------------------------------------------------------------------
# _run_gopclntab adapter tests
# ---------------------------------------------------------------------------

class TestRunGopclntabAdapter(unittest.TestCase):
    """Test the _run_gopclntab adapter function in tools_go.py."""

    def test_returns_none_for_non_go_binary(self):
        """Non-Go binary should return None."""
        import tempfile, os
        from arkana.mcp.tools_go import _run_gopclntab

        fd, path = tempfile.mkstemp(suffix=".exe")
        try:
            os.write(fd, b"MZ" + b"\x00" * 500)
            os.close(fd)
            result = _run_gopclntab(path, limit=20, func_cap=10)
            self.assertIsNone(result)
        finally:
            os.unlink(path)

    def test_returns_result_with_gopclntab_data(self):
        """Binary with valid gopclntab header should return result dict."""
        import tempfile, os
        from arkana.mcp.tools_go import _run_gopclntab
        from unittest.mock import patch

        # Build a minimal Go binary: just a valid header with nfunc=0
        hdr = _build_header_v120(nfunc=0)
        data = hdr + b"\x00" * 500

        fd, path = tempfile.mkstemp(suffix=".elf")
        try:
            os.write(fd, data)
            os.close(fd)
            # Patch state.pe_object to None (not a PE)
            with patch("arkana.mcp.tools_go.state") as mock_state:
                mock_state.pe_object = None
                result = _run_gopclntab(path, limit=20, func_cap=10)
            # nfunc=0 → returns None (no functions)
            self.assertIsNone(result)
        finally:
            os.unlink(path)

    def test_result_format_has_required_keys(self):
        """When gopclntab returns functions, result has all required keys."""
        from arkana.mcp.tools_go import _run_gopclntab
        from unittest.mock import patch

        fake_parsed = {
            "go_version_hint": "1.20+",
            "pointer_size": 8,
            "quantum": 1,
            "functions": [
                {"name": "main.main", "address": 0x401000},
                {"name": "main.init", "address": 0x401100},
                {"name": "crypto/tls.(*Conn).Read", "address": 0x402000},
            ],
            "source_files": ["main.go"],
            "function_count": 3,
            "source_file_count": 1,
            "parse_errors": [],
        }

        with patch("arkana.mcp.tools_go.parse_gopclntab", return_value=fake_parsed), \
             patch("arkana.mcp.tools_go.state") as mock_state, \
             patch("builtins.open", unittest.mock.mock_open(read_data=b"\x00" * 100)):
            mock_state.pe_object = None
            result = _run_gopclntab("/fake/path", limit=20, func_cap=10)

        self.assertIsNotNone(result)
        self.assertTrue(result["is_go_binary"])
        self.assertEqual(result["analysis_method"], "gopclntab")
        self.assertEqual(result["function_count"], 3)
        self.assertIn("packages", result)
        # Check package grouping
        pkg_names = [p["name"] for p in result["packages"]]
        self.assertIn("main", pkg_names)
        self.assertIn("crypto/tls", pkg_names)

    def test_package_grouping_and_caps(self):
        """Functions grouped by package, respecting limit and func_cap."""
        from arkana.mcp.tools_go import _run_gopclntab
        from unittest.mock import patch

        # Create 5 functions across 3 packages
        functions = [
            {"name": f"pkg{i}.func{j}", "address": 0x400000 + i * 0x1000 + j}
            for i in range(3) for j in range(5)
        ]
        fake_parsed = {
            "go_version_hint": "1.18",
            "functions": functions,
            "source_files": [],
            "function_count": 15,
            "source_file_count": 0,
            "parse_errors": [],
        }

        with patch("arkana.mcp.tools_go.parse_gopclntab", return_value=fake_parsed), \
             patch("arkana.mcp.tools_go.state") as mock_state, \
             patch("builtins.open", unittest.mock.mock_open(read_data=b"\x00" * 100)):
            mock_state.pe_object = None
            # limit=2 → only 2 packages returned, func_cap=3 → max 3 funcs per pkg
            result = _run_gopclntab("/fake/path", limit=2, func_cap=3)

        self.assertEqual(len(result["packages"]), 2)
        for pkg in result["packages"]:
            self.assertLessEqual(len(pkg["functions"]), 3)


# ---------------------------------------------------------------------------
# Fallback chain integration tests
# ---------------------------------------------------------------------------

class TestFallbackChainGopclntab(unittest.TestCase):
    """Test gopclntab tier in the go_analyze fallback chain."""

    def test_gopclntab_tier_used_when_others_unavailable(self):
        """When GoReSym and pygore are unavailable, gopclntab should be tried."""
        import asyncio
        from unittest.mock import patch, AsyncMock

        fake_result = {
            "is_go_binary": True,
            "analysis_method": "gopclntab",
            "go_version": "1.20+",
            "function_count": 5,
            "packages": [{"name": "main", "functions": [{"name": "main.main", "address": "0x401000"}], "function_count": 1}],
            "package_count": 1,
        }

        loop = asyncio.new_event_loop()
        try:
            from arkana.mcp.tools_go import go_analyze

            ctx = AsyncMock()
            ctx.info = AsyncMock()

            with patch("arkana.mcp.tools_go.GORESYM_AVAILABLE", False), \
                 patch("arkana.mcp.tools_go.PYGORE_AVAILABLE", False), \
                 patch("arkana.mcp.tools_go._get_filepath", return_value="/fake/go.elf"), \
                 patch("arkana.mcp.tools_go._run_gopclntab", return_value=fake_result) as mock_gop, \
                 patch("arkana.mcp.tools_go._check_mcp_response_size",
                       new_callable=lambda: (lambda: AsyncMock(side_effect=lambda ctx, r, n, *a, **kw: r))()):
                result = loop.run_until_complete(go_analyze(ctx, file_path="/fake/go.elf"))

            mock_gop.assert_called_once()
            self.assertEqual(result["analysis_method"], "gopclntab")
        finally:
            if loop._default_executor is not None:
                loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()

    def test_gopclntab_failure_falls_through_to_string_scan(self):
        """When gopclntab fails, should fall through to string scan."""
        import asyncio
        from unittest.mock import patch, AsyncMock

        loop = asyncio.new_event_loop()
        try:
            from arkana.mcp.tools_go import go_analyze

            ctx = AsyncMock()
            ctx.info = AsyncMock()

            with patch("arkana.mcp.tools_go.GORESYM_AVAILABLE", False), \
                 patch("arkana.mcp.tools_go.PYGORE_AVAILABLE", False), \
                 patch("arkana.mcp.tools_go._get_filepath", return_value="/fake/go.elf"), \
                 patch("arkana.mcp.tools_go._run_gopclntab", side_effect=Exception("parse failed")), \
                 patch("arkana.mcp.tools_go._go_string_scan", return_value={
                     "is_go_binary": True, "analysis_method": "string_scan",
                     "markers_found": ["runtime.main"], "marker_count": 1, "go_version": None,
                 }), \
                 patch("arkana.mcp.tools_go._check_mcp_response_size",
                       new_callable=lambda: (lambda: AsyncMock(side_effect=lambda ctx, r, n, *a, **kw: r))()):
                result = loop.run_until_complete(go_analyze(ctx, file_path="/fake/go.elf"))

            self.assertEqual(result["analysis_method"], "string_scan")
            self.assertIn("fallback_reasons", result)
            self.assertTrue(any("gopclntab" in r for r in result["fallback_reasons"]))
        finally:
            if loop._default_executor is not None:
                loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()


if __name__ == "__main__":
    unittest.main()
