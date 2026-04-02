"""Tests for instruction trace analysis and MBA obfuscation detection (tools_trace_analysis.py).

Covers:
- _parse_pin_trace with synthetic PIN format data
- _parse_csv_trace with synthetic CSV data
- _parse_json_trace with synthetic JSON data
- _detect_trace_format auto-detection
- MBA pattern detection (_MBA_PATTERNS regex matching)
- TRITON_AVAILABLE flag
- Safety caps (_MAX_TRACE_ENTRIES, _MAX_TRACE_FILE_SIZE)
"""
import json
import unittest


class TestParsePinTrace(unittest.TestCase):
    """Test _parse_pin_trace with synthetic PIN format data."""

    def test_basic_pin_format(self):
        from arkana.mcp.tools_trace_analysis import _parse_pin_trace
        text = (
            "i:0x401000:3:8b4508\n"
            "i:0x401003:2:89c1\n"
        )
        entries = _parse_pin_trace(text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["address"], 0x401000)
        self.assertEqual(entries[0]["size"], 3)
        self.assertEqual(entries[0]["bytes"], "8b4508")
        self.assertEqual(entries[1]["address"], 0x401003)
        self.assertEqual(entries[1]["size"], 2)

    def test_pin_format_with_registers(self):
        from arkana.mcp.tools_trace_analysis import _parse_pin_trace
        text = (
            "r:eax=00000001 ebx=00000000\n"
            "i:0x401000:3:8b4508\n"
        )
        entries = _parse_pin_trace(text)
        self.assertEqual(len(entries), 1)
        self.assertIn("registers", entries[0])
        self.assertIn("eax=00000001", entries[0]["registers"])

    def test_pin_format_decimal_address(self):
        from arkana.mcp.tools_trace_analysis import _parse_pin_trace
        text = "i:4198400:3:8b4508\n"
        entries = _parse_pin_trace(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["address"], 4198400)

    def test_pin_format_empty_input(self):
        from arkana.mcp.tools_trace_analysis import _parse_pin_trace
        entries = _parse_pin_trace("")
        self.assertEqual(len(entries), 0)

    def test_pin_format_blank_lines_skipped(self):
        from arkana.mcp.tools_trace_analysis import _parse_pin_trace
        text = "\n\ni:0x401000:3:8b4508\n\n\n"
        entries = _parse_pin_trace(text)
        self.assertEqual(len(entries), 1)

    def test_pin_format_invalid_lines_skipped(self):
        from arkana.mcp.tools_trace_analysis import _parse_pin_trace
        text = (
            "garbage line\n"
            "i:0x401000:3:8b4508\n"
            "i:not_hex:abc:def\n"
        )
        entries = _parse_pin_trace(text)
        # First entry is valid, "not_hex" should fail int() parse
        self.assertGreaterEqual(len(entries), 1)
        self.assertEqual(entries[0]["address"], 0x401000)

    def test_pin_format_respects_max_entries(self):
        from arkana.mcp.tools_trace_analysis import _parse_pin_trace, _MAX_TRACE_ENTRIES
        # Generate more entries than the cap
        lines = [f"i:0x{i:08x}:1:90\n" for i in range(_MAX_TRACE_ENTRIES + 100)]
        text = "".join(lines)
        entries = _parse_pin_trace(text)
        self.assertLessEqual(len(entries), _MAX_TRACE_ENTRIES)


class TestParseCsvTrace(unittest.TestCase):
    """Test _parse_csv_trace with synthetic CSV data."""

    def test_basic_csv_format(self):
        from arkana.mcp.tools_trace_analysis import _parse_csv_trace
        text = (
            "0x401000,8b4508,mov eax ebp+8\n"
            "0x401003,89c1,mov ecx eax\n"
        )
        entries = _parse_csv_trace(text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["address"], 0x401000)
        self.assertEqual(entries[0]["bytes"], "8b4508")
        self.assertEqual(entries[0]["mnemonic"], "mov eax ebp+8")

    def test_csv_without_mnemonic(self):
        from arkana.mcp.tools_trace_analysis import _parse_csv_trace
        text = "0x401000,8b4508\n"
        entries = _parse_csv_trace(text)
        self.assertEqual(len(entries), 1)
        self.assertNotIn("mnemonic", entries[0])

    def test_csv_skips_header(self):
        from arkana.mcp.tools_trace_analysis import _parse_csv_trace
        text = (
            "address,bytes,mnemonic\n"
            "0x401000,8b4508,mov eax,[ebp+8]\n"
        )
        entries = _parse_csv_trace(text)
        self.assertEqual(len(entries), 1)

    def test_csv_skips_comments(self):
        from arkana.mcp.tools_trace_analysis import _parse_csv_trace
        text = (
            "# This is a comment\n"
            "0x401000,8b4508\n"
        )
        entries = _parse_csv_trace(text)
        self.assertEqual(len(entries), 1)

    def test_csv_empty_input(self):
        from arkana.mcp.tools_trace_analysis import _parse_csv_trace
        entries = _parse_csv_trace("")
        self.assertEqual(len(entries), 0)

    def test_csv_computes_size_from_hex(self):
        from arkana.mcp.tools_trace_analysis import _parse_csv_trace
        text = "0x401000,8b4508\n"
        entries = _parse_csv_trace(text)
        # "8b4508" is 6 hex chars = 3 bytes
        self.assertEqual(entries[0]["size"], 3)

    def test_csv_decimal_address(self):
        from arkana.mcp.tools_trace_analysis import _parse_csv_trace
        text = "4198400,8b4508\n"
        entries = _parse_csv_trace(text)
        self.assertEqual(entries[0]["address"], 4198400)

    def test_csv_respects_max_entries(self):
        from arkana.mcp.tools_trace_analysis import _parse_csv_trace, _MAX_TRACE_ENTRIES
        lines = [f"0x{i:08x},90\n" for i in range(_MAX_TRACE_ENTRIES + 100)]
        text = "".join(lines)
        entries = _parse_csv_trace(text)
        self.assertLessEqual(len(entries), _MAX_TRACE_ENTRIES)


class TestParseJsonTrace(unittest.TestCase):
    """Test _parse_json_trace with synthetic JSON data."""

    def test_basic_json_array(self):
        from arkana.mcp.tools_trace_analysis import _parse_json_trace
        data = json.dumps([
            {"address": "0x401000", "bytes": "8b4508", "mnemonic": "mov eax,[ebp+8]"},
            {"address": "0x401003", "bytes": "89c1", "mnemonic": "mov ecx,eax"},
        ]).encode()
        entries = _parse_json_trace(data)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["address"], 0x401000)
        self.assertEqual(entries[0]["bytes"], "8b4508")
        self.assertEqual(entries[0]["mnemonic"], "mov eax,[ebp+8]")

    def test_json_with_trace_wrapper(self):
        """JSON object with 'trace' key should be unwrapped."""
        from arkana.mcp.tools_trace_analysis import _parse_json_trace
        data = json.dumps({
            "trace": [
                {"address": "0x401000", "bytes": "8b4508"},
            ]
        }).encode()
        entries = _parse_json_trace(data)
        self.assertEqual(len(entries), 1)

    def test_json_numeric_address(self):
        from arkana.mcp.tools_trace_analysis import _parse_json_trace
        data = json.dumps([
            {"address": 0x401000, "bytes": "8b4508"},
        ]).encode()
        entries = _parse_json_trace(data)
        self.assertEqual(entries[0]["address"], 0x401000)

    def test_json_alternative_field_names(self):
        """Should accept 'addr', 'ip', 'opcodes' as alternatives."""
        from arkana.mcp.tools_trace_analysis import _parse_json_trace
        data = json.dumps([
            {"addr": "0x401000", "opcodes": "8b4508", "disasm": "mov eax,[ebp+8]"},
        ]).encode()
        entries = _parse_json_trace(data)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["address"], 0x401000)
        self.assertEqual(entries[0]["bytes"], "8b4508")
        self.assertEqual(entries[0]["mnemonic"], "mov eax,[ebp+8]")

    def test_json_ip_field(self):
        from arkana.mcp.tools_trace_analysis import _parse_json_trace
        data = json.dumps([
            {"ip": "0x401000", "bytes": "90"},
        ]).encode()
        entries = _parse_json_trace(data)
        self.assertEqual(entries[0]["address"], 0x401000)

    def test_json_invalid_data_raises(self):
        from arkana.mcp.tools_trace_analysis import _parse_json_trace
        with self.assertRaises(ValueError):
            _parse_json_trace(b"not valid json")

    def test_json_non_array_non_trace_raises(self):
        from arkana.mcp.tools_trace_analysis import _parse_json_trace
        data = json.dumps({"foo": "bar"}).encode()
        with self.assertRaises(ValueError):
            _parse_json_trace(data)

    def test_json_skips_entries_without_address(self):
        from arkana.mcp.tools_trace_analysis import _parse_json_trace
        data = json.dumps([
            {"bytes": "8b4508"},  # no address
            {"address": "0x401000", "bytes": "90"},
        ]).encode()
        entries = _parse_json_trace(data)
        self.assertEqual(len(entries), 1)

    def test_json_respects_max_entries(self):
        from arkana.mcp.tools_trace_analysis import _parse_json_trace, _MAX_TRACE_ENTRIES
        items = [{"address": i, "bytes": "90"} for i in range(_MAX_TRACE_ENTRIES + 100)]
        data = json.dumps(items).encode()
        entries = _parse_json_trace(data)
        self.assertLessEqual(len(entries), _MAX_TRACE_ENTRIES)


class TestDetectTraceFormat(unittest.TestCase):
    """Test _detect_trace_format auto-detection."""

    def test_detects_json_array(self):
        from arkana.mcp.tools_trace_analysis import _detect_trace_format
        data = b'[{"address": "0x401000", "bytes": "90"}]'
        self.assertEqual(_detect_trace_format(data), "json")

    def test_detects_json_object(self):
        from arkana.mcp.tools_trace_analysis import _detect_trace_format
        data = b'{"trace": [{"address": "0x401000"}]}'
        self.assertEqual(_detect_trace_format(data), "json")

    def test_detects_json_with_whitespace(self):
        from arkana.mcp.tools_trace_analysis import _detect_trace_format
        data = b'  \n  [{"address": "0x401000"}]'
        self.assertEqual(_detect_trace_format(data), "json")

    def test_detects_pin_format(self):
        from arkana.mcp.tools_trace_analysis import _detect_trace_format
        data = b"r:eax=00000001\ni:0x401000:3:8b4508\n"
        self.assertEqual(_detect_trace_format(data), "pin")

    def test_detects_pin_without_register_lines(self):
        from arkana.mcp.tools_trace_analysis import _detect_trace_format
        data = b"i:0x401000:3:8b4508\ni:0x401003:2:89c1\n"
        self.assertEqual(_detect_trace_format(data), "pin")

    def test_defaults_to_csv(self):
        from arkana.mcp.tools_trace_analysis import _detect_trace_format
        data = b"0x401000,8b4508,mov eax,[ebp+8]\n"
        self.assertEqual(_detect_trace_format(data), "csv")

    def test_defaults_to_csv_for_unknown(self):
        from arkana.mcp.tools_trace_analysis import _detect_trace_format
        data = b"some random text that isn't any format\n"
        self.assertEqual(_detect_trace_format(data), "csv")


class TestMBAPatternDetection(unittest.TestCase):
    """Test MBA obfuscation pattern matching."""

    def test_xor_via_not_and_or(self):
        """(~x & y) | (x & ~y) should match XOR pattern."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = (~a & b) | (a & ~b);"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["pattern_name"], "xor_via_not_and_or")
        self.assertIn("XOR", detections[0]["simplified_form"])

    def test_xor_via_or_minus_and(self):
        """(x | y) - (x & y) should match XOR pattern."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = (a | b) - (a & b);"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["pattern_name"], "xor_via_or_minus_and")
        self.assertIn("XOR", detections[0]["simplified_form"])

    def test_add_via_and_plus_or(self):
        """(x & y) + (x | y) should match ADD pattern."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = (a & b) + (a | b);"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["pattern_name"], "add_via_and_plus_or")
        self.assertIn("ADD", detections[0]["simplified_form"])

    def test_double_negation(self):
        """~~x should match double negation pattern."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = ~~value;"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["pattern_name"], "double_negation")
        self.assertEqual(detections[0]["confidence"], 0.95)

    def test_tautology_or_not(self):
        """x | ~x should match tautology pattern."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = x | ~x;"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["pattern_name"], "tautology_or_not")
        self.assertEqual(detections[0]["simplified_form"], "-1")

    def test_contradiction_and_not(self):
        """x & ~x should match contradiction pattern."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = x & ~x;"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["pattern_name"], "contradiction_and_not")
        self.assertEqual(detections[0]["simplified_form"], "0")

    def test_algebraic_xor_and_identity(self):
        """(a ^ b) + 2 * (a & b) should match algebraic ADD pattern."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = (a ^ b) + 2 * (a & b);"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["pattern_name"], "algebraic_xor_and_identity")
        self.assertIn("ADD", detections[0]["simplified_form"])

    def test_nested_bitwise_xor_variant(self):
        """(x & ~y) | (~x & y) should match commuted XOR variant."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = (a & ~b) | (~a & b);"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["pattern_name"], "nested_bitwise_xor_variant")
        self.assertIn("XOR", detections[0]["simplified_form"])

    def test_opaque_add_identity(self):
        """(x | y) + (x & y) should match opaque ADD pattern."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = (a | b) + (a & b);"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["pattern_name"], "opaque_add_identity")
        self.assertIn("ADD", detections[0]["simplified_form"])

    def test_no_detection_on_normal_code(self):
        """Normal code should not trigger MBA detections."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = [
            "int x = 5;",
            "int y = x + 10;",
            "if (x > 0) { return y; }",
        ]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 0)

    def test_skips_comments(self):
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = [
            "// (~a & b) | (a & ~b) is XOR",
            "# (~a & b) | (a & ~b) is XOR",
        ]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 0)

    def test_skips_blank_lines(self):
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["", "   ", ""]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 0)

    def test_detection_includes_line_number(self):
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = [
            "int x = 5;",
            "result = (~a & b) | (a & ~b);",
        ]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["line"], 2)

    def test_detection_includes_confidence(self):
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = (~a & b) | (a & ~b);"]
        detections = _scan_for_mba_patterns(lines)
        self.assertIn("confidence", detections[0])
        self.assertGreater(detections[0]["confidence"], 0)

    def test_detection_includes_source_line(self):
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = (~a & b) | (a & ~b);"]
        detections = _scan_for_mba_patterns(lines)
        self.assertIn("source_line", detections[0])
        self.assertIn("(~a & b)", detections[0]["source_line"])

    def test_multiple_patterns_on_different_lines(self):
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = [
            "x = (~a & b) | (a & ~b);",
            "y = (c | d) + (c & d);",
        ]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 2)
        names = {d["pattern_name"] for d in detections}
        self.assertIn("xor_via_not_and_or", names)
        self.assertIn("opaque_add_identity", names)

    def test_simplified_form_substitutes_variables(self):
        """Simplified form should substitute captured variable names."""
        from arkana.mcp.tools_trace_analysis import _scan_for_mba_patterns
        lines = ["result = (~foo & bar) | (foo & ~bar);"]
        detections = _scan_for_mba_patterns(lines)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["simplified_form"], "XOR(foo, bar)")


class TestTritonAvailableFlag(unittest.TestCase):
    """Test TRITON_AVAILABLE flag."""

    def test_flag_exists(self):
        from arkana.mcp.tools_trace_analysis import TRITON_AVAILABLE
        self.assertIsInstance(TRITON_AVAILABLE, bool)

    def test_flag_is_false_without_triton(self):
        """Triton is not installed in test environment, so flag should be False."""
        from arkana.mcp.tools_trace_analysis import TRITON_AVAILABLE
        self.assertFalse(TRITON_AVAILABLE)


class TestSafetyCaps(unittest.TestCase):
    """Test safety cap constants."""

    def test_max_trace_entries_exists(self):
        from arkana.mcp.tools_trace_analysis import _MAX_TRACE_ENTRIES
        self.assertIsInstance(_MAX_TRACE_ENTRIES, int)
        self.assertGreater(_MAX_TRACE_ENTRIES, 0)

    def test_max_trace_entries_value(self):
        from arkana.mcp.tools_trace_analysis import _MAX_TRACE_ENTRIES
        self.assertEqual(_MAX_TRACE_ENTRIES, 100_000)

    def test_max_trace_file_size_exists(self):
        from arkana.mcp.tools_trace_analysis import _MAX_TRACE_FILE_SIZE
        self.assertIsInstance(_MAX_TRACE_FILE_SIZE, int)
        self.assertGreater(_MAX_TRACE_FILE_SIZE, 0)

    def test_max_trace_file_size_value(self):
        from arkana.mcp.tools_trace_analysis import _MAX_TRACE_FILE_SIZE
        # 50 MB
        self.assertEqual(_MAX_TRACE_FILE_SIZE, 50 * 1024 * 1024)


class TestMBAPatterns(unittest.TestCase):
    """Test _MBA_PATTERNS list structure."""

    def test_patterns_list_exists(self):
        from arkana.mcp.tools_trace_analysis import _MBA_PATTERNS
        self.assertIsInstance(_MBA_PATTERNS, list)
        self.assertGreater(len(_MBA_PATTERNS), 0)

    def test_pattern_structure(self):
        from arkana.mcp.tools_trace_analysis import _MBA_PATTERNS
        for pat in _MBA_PATTERNS:
            self.assertIn("name", pat)
            self.assertIn("description", pat)
            self.assertIn("pattern", pat)
            self.assertIn("simplified", pat)
            self.assertIn("confidence", pat)
            self.assertGreater(pat["confidence"], 0)
            self.assertLessEqual(pat["confidence"], 1.0)

    def test_all_patterns_are_compiled_regex(self):
        import re
        from arkana.mcp.tools_trace_analysis import _MBA_PATTERNS
        for pat in _MBA_PATTERNS:
            self.assertIsInstance(pat["pattern"], type(re.compile("")))


class TestComputeTraceStats(unittest.TestCase):
    """Test _compute_trace_stats helper."""

    def test_empty_entries(self):
        from arkana.mcp.tools_trace_analysis import _compute_trace_stats
        result = _compute_trace_stats([])
        self.assertEqual(result["instruction_count"], 0)
        self.assertEqual(result["unique_addresses"], 0)

    def test_basic_stats(self):
        from arkana.mcp.tools_trace_analysis import _compute_trace_stats
        entries = [
            {"address": 0x401000, "mnemonic": "mov eax, [ebp+8]"},
            {"address": 0x401003, "mnemonic": "mov ecx, eax"},
            {"address": 0x401000, "mnemonic": "mov eax, [ebp+8]"},
        ]
        result = _compute_trace_stats(entries)
        self.assertEqual(result["instruction_count"], 3)
        self.assertEqual(result["unique_addresses"], 2)

    def test_address_range(self):
        from arkana.mcp.tools_trace_analysis import _compute_trace_stats
        entries = [
            {"address": 0x401000, "mnemonic": "nop"},
            {"address": 0x402000, "mnemonic": "nop"},
        ]
        result = _compute_trace_stats(entries)
        self.assertEqual(result["address_range"]["start"], hex(0x401000))
        self.assertEqual(result["address_range"]["end"], hex(0x402000))

    def test_mnemonic_frequency(self):
        from arkana.mcp.tools_trace_analysis import _compute_trace_stats
        entries = [
            {"address": 0x401000, "mnemonic": "mov eax, 1"},
            {"address": 0x401003, "mnemonic": "mov ecx, 2"},
            {"address": 0x401006, "mnemonic": "add eax, ecx"},
        ]
        result = _compute_trace_stats(entries)
        top_mnems = {m["mnemonic"]: m["count"] for m in result["top_mnemonics"]}
        self.assertEqual(top_mnems.get("mov"), 2)
        self.assertEqual(top_mnems.get("add"), 1)

    def test_entries_without_mnemonic(self):
        from arkana.mcp.tools_trace_analysis import _compute_trace_stats
        entries = [
            {"address": 0x401000},
            {"address": 0x401003, "mnemonic": ""},
        ]
        result = _compute_trace_stats(entries)
        self.assertEqual(result["instruction_count"], 2)
        self.assertEqual(result["total_unique_mnemonics"], 0)


if __name__ == "__main__":
    unittest.main()
