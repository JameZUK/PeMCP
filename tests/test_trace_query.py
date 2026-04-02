"""Tests for trace query parser and evaluator (scripts/trace_query.py)."""
import os
import sys
import unittest

# trace_query.py lives in scripts/ — add to path
_scripts_dir = os.path.join(os.path.dirname(__file__), "..", "scripts")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

from trace_query import (
    Predicate,
    _MAX_PREDICATES,
    _MAX_SEQUENCE_MATCHES,
    _MAX_SEQUENCE_STEPS,
    _try_numeric,
    evaluate_predicate,
    filter_trace,
    match_sequences,
    parse_query,
    parse_sequence,
    validate_query,
    validate_sequence,
)


# ---------------------------------------------------------------------------
# Sample trace data
# ---------------------------------------------------------------------------

_SAMPLE_TRACE = [
    {"seq": 1, "api": "CreateFileA", "args": {"p0": "test.txt", "p1": "0x80000000", "p2": "0x1"}, "retval": "0x100", "address": "0x401000", "timestamp": 1000.0},
    {"seq": 2, "api": "ReadFile", "args": {"p0": "0x100", "p1": "0x500000", "p2": "0x1000"}, "retval": "0x1", "address": "0x401100", "timestamp": 1001.0},
    {"seq": 3, "api": "VirtualAlloc", "args": {"p0": "0x0", "p1": "0x10000", "p2": "0x3000", "p3": "0x40"}, "retval": "0x10000", "address": "0x401200", "timestamp": 1002.0},
    {"seq": 4, "api": "WriteProcessMemory", "args": {"p0": "0xffffffff", "p1": "0x10000", "p2": "0x500000", "p3": "0x100"}, "retval": "0x1", "address": "0x401300", "timestamp": 1003.0},
    {"seq": 5, "api": "VirtualAlloc", "args": {"p0": "0x0", "p1": "0x1000", "p2": "0x3000", "p3": "0x20"}, "retval": "0x20000", "address": "0x401200", "timestamp": 1004.0},
    {"seq": 6, "api": "CreateRemoteThread", "args": {"p0": "0xffffffff", "p1": "0x0", "p2": "0x0", "p3": "0x10000"}, "retval": "0x200", "address": "0x401400", "timestamp": 1005.0},
    {"seq": 7, "api": "CloseHandle", "args": {"p0": "0x100"}, "retval": "0x1", "address": "0x401500", "timestamp": 1006.0},
]


class TestTryNumeric(unittest.TestCase):
    """Tests for numeric value parsing."""

    def test_decimal(self):
        self.assertEqual(_try_numeric("42"), 42)

    def test_hex(self):
        self.assertEqual(_try_numeric("0x40"), 64)

    def test_hex_uppercase(self):
        self.assertEqual(_try_numeric("0X1000"), 4096)

    def test_float(self):
        self.assertEqual(_try_numeric("3.14"), 3.14)

    def test_non_numeric(self):
        self.assertIsNone(_try_numeric("hello"))

    def test_empty(self):
        self.assertIsNone(_try_numeric(""))

    def test_negative(self):
        self.assertEqual(_try_numeric("-1"), -1)


class TestParseQuery(unittest.TestCase):
    """Tests for query string parsing."""

    def test_single_equals(self):
        preds = parse_query("api=VirtualAlloc")
        self.assertEqual(len(preds), 1)
        self.assertEqual(preds[0].field, "api")
        self.assertEqual(preds[0].op, "=")
        self.assertEqual(preds[0].value, "VirtualAlloc")

    def test_multiple_predicates(self):
        preds = parse_query("api=VirtualAlloc,args.p3=0x40")
        self.assertEqual(len(preds), 2)
        self.assertEqual(preds[0].field, "api")
        self.assertEqual(preds[1].field, "args.p3")
        self.assertEqual(preds[1].value, "0x40")

    def test_not_equals(self):
        preds = parse_query("retval!=0x0")
        self.assertEqual(preds[0].op, "!=")

    def test_substring(self):
        preds = parse_query("api~Write")
        self.assertEqual(preds[0].op, "~")
        self.assertEqual(preds[0].value, "Write")

    def test_greater_than(self):
        preds = parse_query("seq>100")
        self.assertEqual(preds[0].op, ">")
        self.assertEqual(preds[0].value, "100")

    def test_less_than(self):
        preds = parse_query("seq<200")
        self.assertEqual(preds[0].op, "<")

    def test_greater_equal(self):
        preds = parse_query("seq>=5")
        self.assertEqual(preds[0].op, ">=")

    def test_less_equal(self):
        preds = parse_query("timestamp<=1003.0")
        self.assertEqual(preds[0].op, "<=")

    def test_empty_query(self):
        preds = parse_query("")
        self.assertEqual(preds, [])

    def test_whitespace_only(self):
        preds = parse_query("  ")
        self.assertEqual(preds, [])

    def test_whitespace_around_parts(self):
        preds = parse_query(" api = VirtualAlloc , seq > 2 ")
        self.assertEqual(len(preds), 2)
        self.assertEqual(preds[0].field, "api")
        self.assertEqual(preds[0].value, "VirtualAlloc")

    def test_invalid_no_operator(self):
        with self.assertRaises(ValueError):
            parse_query("something")

    def test_invalid_empty_field(self):
        with self.assertRaises(ValueError):
            parse_query("=value")

    def test_invalid_field_chars(self):
        with self.assertRaises(ValueError):
            parse_query("a;b=value")

    def test_too_many_predicates(self):
        q = ",".join(f"seq>{i}" for i in range(_MAX_PREDICATES + 1))
        with self.assertRaises(ValueError):
            parse_query(q)

    def test_deep_field_path_rejected(self):
        with self.assertRaises(ValueError):
            parse_query("a.b.c.d.e=1")

    def test_nested_field(self):
        preds = parse_query("args.p0=test.txt")
        self.assertEqual(preds[0].field, "args.p0")
        self.assertEqual(preds[0].value, "test.txt")

    def test_hex_numeric_precomputed(self):
        preds = parse_query("args.p3=0x40")
        self.assertEqual(preds[0].numeric_value, 64)


class TestEvaluatePredicate(unittest.TestCase):
    """Tests for predicate evaluation against trace entries."""

    def setUp(self):
        self.entry = _SAMPLE_TRACE[2]  # VirtualAlloc, seq=3

    def test_equals_api(self):
        pred = Predicate("api", "=", "VirtualAlloc")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_equals_api_case_insensitive(self):
        pred = Predicate("api", "=", "virtualalloc")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_equals_api_no_match(self):
        pred = Predicate("api", "=", "ReadFile")
        self.assertFalse(evaluate_predicate(self.entry, pred))

    def test_not_equals(self):
        pred = Predicate("api", "!=", "ReadFile")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_not_equals_same(self):
        pred = Predicate("api", "!=", "VirtualAlloc")
        self.assertFalse(evaluate_predicate(self.entry, pred))

    def test_substring_match(self):
        pred = Predicate("api", "~", "Virtual")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_substring_case_insensitive(self):
        pred = Predicate("api", "~", "virtual")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_substring_no_match(self):
        pred = Predicate("api", "~", "Create")
        self.assertFalse(evaluate_predicate(self.entry, pred))

    def test_greater_than_seq(self):
        pred = Predicate("seq", ">", "2")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_greater_than_seq_false(self):
        pred = Predicate("seq", ">", "3")
        self.assertFalse(evaluate_predicate(self.entry, pred))

    def test_less_than(self):
        pred = Predicate("seq", "<", "5")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_greater_equal(self):
        pred = Predicate("seq", ">=", "3")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_less_equal(self):
        pred = Predicate("seq", "<=", "3")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_hex_arg_equals(self):
        """args.p3=0x40 should match hex string '0x40' in entry."""
        pred = Predicate("args.p3", "=", "0x40")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_hex_arg_greater(self):
        pred = Predicate("args.p1", ">", "0x1000")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_nested_args_field(self):
        pred = Predicate("args.p0", "=", "0x0")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_missing_field_not_equals(self):
        """Missing field with != should match."""
        pred = Predicate("nonexistent", "!=", "anything")
        self.assertTrue(evaluate_predicate(self.entry, pred))

    def test_missing_field_equals(self):
        """Missing field with = should not match."""
        pred = Predicate("nonexistent", "=", "anything")
        self.assertFalse(evaluate_predicate(self.entry, pred))

    def test_non_numeric_ordered_comparison(self):
        """Ordered comparison with non-numeric values returns False."""
        pred = Predicate("api", ">", "Virtual")
        self.assertFalse(evaluate_predicate(self.entry, pred))

    def test_timestamp_comparison(self):
        pred = Predicate("timestamp", ">=", "1002.0")
        self.assertTrue(evaluate_predicate(self.entry, pred))


class TestFilterTrace(unittest.TestCase):
    """Tests for filtering a trace against multiple predicates."""

    def test_single_predicate(self):
        preds = parse_query("api=VirtualAlloc")
        result = filter_trace(_SAMPLE_TRACE, preds)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["seq"], 3)
        self.assertEqual(result[1]["seq"], 5)

    def test_compound_predicates_and(self):
        preds = parse_query("api=VirtualAlloc,args.p3=0x40")
        result = filter_trace(_SAMPLE_TRACE, preds)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["seq"], 3)

    def test_range_filter(self):
        preds = parse_query("seq>2,seq<6")
        result = filter_trace(_SAMPLE_TRACE, preds)
        self.assertEqual(len(result), 3)  # seq 3, 4, 5

    def test_empty_predicates(self):
        result = filter_trace(_SAMPLE_TRACE, [])
        self.assertEqual(len(result), len(_SAMPLE_TRACE))

    def test_no_matches(self):
        preds = parse_query("api=NonExistent")
        result = filter_trace(_SAMPLE_TRACE, preds)
        self.assertEqual(len(result), 0)

    def test_substring_filter(self):
        preds = parse_query("api~Close")
        result = filter_trace(_SAMPLE_TRACE, preds)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["api"], "CloseHandle")

    def test_retval_filter(self):
        preds = parse_query("retval=0x10000")
        result = filter_trace(_SAMPLE_TRACE, preds)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["api"], "VirtualAlloc")


class TestParseSequence(unittest.TestCase):
    """Tests for sequence pattern parsing."""

    def test_simple_sequence(self):
        steps = parse_sequence("VirtualAlloc;WriteProcessMemory")
        self.assertEqual(steps, ["virtualalloc", "writeprocessmemory"])

    def test_three_steps(self):
        steps = parse_sequence("VirtualAlloc;WriteProcessMemory;CreateRemoteThread")
        self.assertEqual(len(steps), 3)

    def test_whitespace(self):
        steps = parse_sequence(" VirtualAlloc ; WriteProcessMemory ")
        self.assertEqual(steps, ["virtualalloc", "writeprocessmemory"])

    def test_empty(self):
        steps = parse_sequence("")
        self.assertEqual(steps, [])

    def test_whitespace_only(self):
        steps = parse_sequence("  ;  ;  ")
        self.assertEqual(steps, [])

    def test_too_many_steps(self):
        seq = ";".join(f"api{i}" for i in range(_MAX_SEQUENCE_STEPS + 1))
        with self.assertRaises(ValueError):
            parse_sequence(seq)

    def test_single_step(self):
        steps = parse_sequence("VirtualAlloc")
        self.assertEqual(steps, ["virtualalloc"])


class TestMatchSequences(unittest.TestCase):
    """Tests for ordered API call sequence matching."""

    def test_two_step_sequence(self):
        steps = parse_sequence("VirtualAlloc;WriteProcessMemory")
        matches = match_sequences(_SAMPLE_TRACE, steps)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["start_seq"], 3)
        self.assertEqual(matches[0]["end_seq"], 4)
        self.assertEqual(len(matches[0]["entries"]), 2)

    def test_three_step_sequence(self):
        steps = parse_sequence("VirtualAlloc;WriteProcessMemory;CreateRemoteThread")
        matches = match_sequences(_SAMPLE_TRACE, steps)
        self.assertEqual(len(matches), 1)
        self.assertEqual(len(matches[0]["entries"]), 3)

    def test_no_match(self):
        steps = parse_sequence("CreateRemoteThread;VirtualAlloc")  # wrong order
        matches = match_sequences(_SAMPLE_TRACE, steps)
        self.assertEqual(len(matches), 0)

    def test_substring_matching(self):
        steps = parse_sequence("Virtual;Write")
        matches = match_sequences(_SAMPLE_TRACE, steps)
        self.assertEqual(len(matches), 1)

    def test_empty_steps(self):
        matches = match_sequences(_SAMPLE_TRACE, [])
        self.assertEqual(len(matches), 0)

    def test_empty_entries(self):
        steps = parse_sequence("VirtualAlloc")
        matches = match_sequences([], steps)
        self.assertEqual(len(matches), 0)

    def test_gap_max_enforced(self):
        """With gap_max=0 (unlimited), sequence should still be found."""
        steps = parse_sequence("CreateFile;CreateRemoteThread")
        matches = match_sequences(_SAMPLE_TRACE, steps, gap_max=0)
        self.assertEqual(len(matches), 1)

    def test_gap_max_too_small(self):
        """CreateFile(seq=1) to CreateRemoteThread(seq=6) has gap of 4 entries."""
        steps = parse_sequence("CreateFile;CreateRemoteThread")
        matches = match_sequences(_SAMPLE_TRACE, steps, gap_max=1)
        self.assertEqual(len(matches), 0)

    def test_gap_max_sufficient(self):
        steps = parse_sequence("CreateFile;CreateRemoteThread")
        matches = match_sequences(_SAMPLE_TRACE, steps, gap_max=10)
        self.assertEqual(len(matches), 1)

    def test_non_overlapping_matches(self):
        """Second VirtualAlloc (seq=5) should not be part of first match."""
        steps = parse_sequence("VirtualAlloc;CloseHandle")
        matches = match_sequences(_SAMPLE_TRACE, steps)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["start_seq"], 3)  # First VirtualAlloc
        self.assertEqual(matches[0]["end_seq"], 7)  # CloseHandle

    def test_step_indices_present(self):
        steps = parse_sequence("VirtualAlloc;WriteProcessMemory")
        matches = match_sequences(_SAMPLE_TRACE, steps)
        self.assertIn("step_indices", matches[0])
        self.assertEqual(len(matches[0]["step_indices"]), 2)


class TestValidation(unittest.TestCase):
    """Tests for query/sequence validation functions."""

    def test_valid_query(self):
        self.assertIsNone(validate_query("api=VirtualAlloc"))

    def test_invalid_query(self):
        err = validate_query("no_operator_here")
        self.assertIsNotNone(err)

    def test_valid_sequence(self):
        self.assertIsNone(validate_sequence("VirtualAlloc;WriteProcessMemory"))

    def test_invalid_sequence(self):
        seq = ";".join(f"a{i}" for i in range(_MAX_SEQUENCE_STEPS + 1))
        err = validate_sequence(seq)
        self.assertIsNotNone(err)

    def test_empty_query_valid(self):
        self.assertIsNone(validate_query(""))

    def test_empty_sequence_valid(self):
        self.assertIsNone(validate_sequence(""))


class TestSubstringNotRegex(unittest.TestCase):
    """Verify ~ uses substring matching, not regex (no ReDoS risk)."""

    def test_regex_special_chars_literal(self):
        """Regex metacharacters should be treated as literal substrings."""
        entry = {"api": "Func.Name(test)"}
        pred = Predicate("api", "~", "Func.Name(")
        self.assertTrue(evaluate_predicate(entry, pred))

    def test_regex_quantifier_literal(self):
        entry = {"api": "a{100}"}
        pred = Predicate("api", "~", "a{100}")
        self.assertTrue(evaluate_predicate(entry, pred))

    def test_regex_backslash_literal(self):
        entry = {"api": r"path\to\file"}
        pred = Predicate("api", "~", r"path\to")
        self.assertTrue(evaluate_predicate(entry, pred))


if __name__ == "__main__":
    unittest.main()
