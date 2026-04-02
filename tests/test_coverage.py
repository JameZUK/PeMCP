"""Tests for code coverage import and overlay (tools_coverage.py)."""
import json
import struct
import unittest

from arkana.mcp.tools_coverage import (
    _MAX_COVERAGE_ENTRIES,
    _detect_coverage_format,
    _parse_csv_coverage,
    _parse_drcov,
    _parse_json_coverage,
)


# ---------------------------------------------------------------------------
# Helpers for building synthetic drcov data
# ---------------------------------------------------------------------------

def _build_drcov(modules, blocks):
    """Build a synthetic drcov binary file.

    Args:
        modules: List of (id, base, end, path) tuples.
        blocks: List of (start_offset, size, mod_id) tuples.
    """
    lines = [
        "DRCOV VERSION: 2",
        "DRCOV FLAVOR: drcov-test",
        f"Module Table: version 2, count {len(modules)}",
        "Columns: id, base, end, entry, checksum, timestamp, path",
    ]
    for mod_id, base, end, path in modules:
        lines.append(f" {mod_id}, {hex(base)}, {hex(end)}, 0x0, 0x0, 0x0, {path}")
    lines.append(f"BB Table: {len(blocks)} bbs")
    header = "\n".join(lines) + "\n"

    bb_data = b""
    for start_off, size, mod_id in blocks:
        bb_data += struct.pack("<IHH", start_off, size, mod_id)

    return header.encode("ascii") + bb_data


class TestDrcovParser(unittest.TestCase):
    """Tests for drcov binary format parsing."""

    def test_basic_drcov(self):
        modules = [(0, 0x400000, 0x401000, "/test/binary.exe")]
        blocks = [
            (0x1000, 16, 0),
            (0x1020, 8, 0),
            (0x1040, 32, 0),
        ]
        data = _build_drcov(modules, blocks)
        result = _parse_drcov(data)

        self.assertEqual(result["format"], "drcov")
        self.assertEqual(result["module_count"], 1)
        self.assertEqual(result["block_count"], 3)
        self.assertEqual(result["modules"][0]["name"], "binary.exe")
        self.assertEqual(result["modules"][0]["base"], 0x400000)
        # Blocks should have absolute addresses (module base + offset)
        self.assertEqual(result["blocks"][0]["address"], 0x400000 + 0x1000)
        self.assertEqual(result["blocks"][0]["size"], 16)
        self.assertEqual(result["blocks"][1]["address"], 0x400000 + 0x1020)

    def test_multiple_modules(self):
        modules = [
            (0, 0x400000, 0x410000, "/test/main.exe"),
            (1, 0x7FF000, 0x800000, "/lib/kernel32.dll"),
        ]
        blocks = [
            (0x1000, 8, 0),  # In main.exe
            (0x500, 4, 1),   # In kernel32.dll
        ]
        data = _build_drcov(modules, blocks)
        result = _parse_drcov(data)

        self.assertEqual(result["module_count"], 2)
        self.assertEqual(result["block_count"], 2)
        self.assertEqual(result["blocks"][0]["address"], 0x400000 + 0x1000)
        self.assertEqual(result["blocks"][1]["address"], 0x7FF000 + 0x500)

    def test_empty_blocks(self):
        modules = [(0, 0x400000, 0x401000, "/test/binary.exe")]
        data = _build_drcov(modules, [])
        result = _parse_drcov(data)
        self.assertEqual(result["block_count"], 0)

    def test_missing_bb_table_raises(self):
        with self.assertRaises(ValueError):
            _parse_drcov(b"DRCOV VERSION: 2\nno bb table here\n")

    def test_missing_module_table_raises(self):
        data = b"DRCOV VERSION: 2\nBB Table: 0 bbs\n"
        with self.assertRaises(ValueError):
            _parse_drcov(data)


class TestJsonCoverageParser(unittest.TestCase):
    """Tests for JSON coverage parsing."""

    def test_coverage_array_format(self):
        data = json.dumps({
            "coverage": [
                {"address": "0x401000", "size": 16},
                {"address": "0x401020", "size": 8},
            ]
        }).encode()
        result = _parse_json_coverage(data)
        self.assertEqual(result["format"], "json")
        self.assertEqual(result["block_count"], 2)
        self.assertEqual(result["blocks"][0]["address"], 0x401000)
        self.assertEqual(result["blocks"][0]["size"], 16)

    def test_blocks_format(self):
        data = json.dumps({
            "blocks": [
                {"address": 0x401000, "size": 16},
            ]
        }).encode()
        result = _parse_json_coverage(data)
        self.assertEqual(result["block_count"], 1)

    def test_list_format_with_start_end(self):
        data = json.dumps([
            {"start": "0x401000", "end": "0x401010"},
            {"start": "0x401020", "end": "0x401028"},
        ]).encode()
        result = _parse_json_coverage(data)
        self.assertEqual(result["block_count"], 2)
        self.assertEqual(result["blocks"][0]["address"], 0x401000)
        self.assertEqual(result["blocks"][0]["size"], 16)

    def test_integer_addresses(self):
        data = json.dumps({
            "coverage": [{"address": 4198400, "size": 16}]
        }).encode()
        result = _parse_json_coverage(data)
        self.assertEqual(result["blocks"][0]["address"], 4198400)

    def test_empty_coverage(self):
        data = json.dumps({"coverage": []}).encode()
        result = _parse_json_coverage(data)
        self.assertEqual(result["block_count"], 0)

    def test_invalid_json_raises(self):
        with self.assertRaises(ValueError):
            _parse_json_coverage(b"not json {{{")

    def test_missing_coverage_key_returns_empty(self):
        """JSON with no coverage/blocks key returns zero blocks."""
        result = _parse_json_coverage(json.dumps({"other": "data"}).encode())
        self.assertEqual(result["block_count"], 0)


class TestCsvCoverageParser(unittest.TestCase):
    """Tests for CSV coverage parsing."""

    def test_hex_addresses(self):
        data = b"0x401000,16\n0x401020,8\n"
        result = _parse_csv_coverage(data)
        self.assertEqual(result["format"], "csv")
        self.assertEqual(result["block_count"], 2)
        self.assertEqual(result["blocks"][0]["address"], 0x401000)
        self.assertEqual(result["blocks"][0]["size"], 16)

    def test_decimal_addresses(self):
        data = b"4198400,16\n4198432,8\n"
        result = _parse_csv_coverage(data)
        self.assertEqual(result["block_count"], 2)

    def test_comments_and_headers(self):
        data = b"# Coverage data\naddress,size\n0x401000,16\n"
        result = _parse_csv_coverage(data)
        self.assertEqual(result["block_count"], 1)

    def test_address_only(self):
        data = b"0x401000\n0x401020\n"
        result = _parse_csv_coverage(data)
        self.assertEqual(result["block_count"], 2)
        self.assertEqual(result["blocks"][0]["size"], 1)  # Default size

    def test_empty_file(self):
        result = _parse_csv_coverage(b"")
        self.assertEqual(result["block_count"], 0)

    def test_blank_lines_skipped(self):
        data = b"\n\n0x401000,16\n\n\n"
        result = _parse_csv_coverage(data)
        self.assertEqual(result["block_count"], 1)

    def test_invalid_lines_skipped(self):
        data = b"0x401000,16\nnot_a_number\n0x401020,8\n"
        result = _parse_csv_coverage(data)
        self.assertEqual(result["block_count"], 2)


class TestFormatDetection(unittest.TestCase):
    """Tests for coverage format auto-detection."""

    def test_detect_drcov(self):
        data = b"DRCOV VERSION: 2\nstuff\nBB Table: 0 bbs\n"
        self.assertEqual(_detect_coverage_format(data), "drcov")

    def test_detect_drcov_by_bb_marker(self):
        data = b"some header\nBB Table: 5 bbs\n" + b"\x00" * 40
        self.assertEqual(_detect_coverage_format(data), "drcov")

    def test_detect_json_object(self):
        data = b'{"coverage": []}'
        self.assertEqual(_detect_coverage_format(data), "json")

    def test_detect_json_array(self):
        data = b'[{"address": 0}]'
        self.assertEqual(_detect_coverage_format(data), "json")

    def test_detect_json_with_whitespace(self):
        data = b'  \n  {"coverage": []}'
        self.assertEqual(_detect_coverage_format(data), "json")

    def test_detect_csv_fallback(self):
        data = b"0x401000,16\n0x401020,8\n"
        self.assertEqual(_detect_coverage_format(data), "csv")

    def test_empty_data_is_csv(self):
        self.assertEqual(_detect_coverage_format(b""), "csv")


class TestSafetyCaps(unittest.TestCase):
    """Tests for safety limits."""

    def test_max_entries_constant(self):
        self.assertEqual(_MAX_COVERAGE_ENTRIES, 500_000)

    def test_csv_capped(self):
        # Build CSV with more entries than cap
        lines = [f"0x{0x401000 + i * 4:x},4" for i in range(_MAX_COVERAGE_ENTRIES + 100)]
        data = "\n".join(lines).encode()
        result = _parse_csv_coverage(data)
        self.assertLessEqual(result["block_count"], _MAX_COVERAGE_ENTRIES)


if __name__ == "__main__":
    unittest.main()
