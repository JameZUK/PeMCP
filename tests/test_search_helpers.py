"""Tests for arkana.mcp._search_helpers — search-with-context for lines and instructions."""
import pytest

from arkana.mcp._search_helpers import (
    _build_context_regions,
    search_instructions_with_context,
    search_lines_with_context,
)


# =====================================================================
#  search_lines_with_context
# =====================================================================

class TestSearchLinesWithContext:
    """Tests for the line-based search helper."""

    SAMPLE_LINES = [
        "int main() {",          # 0
        "    int x = 0;",        # 1
        "    x = x ^ 0x41;",     # 2  (xor)
        "    printf(x);",        # 3
        "    return 0;",         # 4
        "}",                     # 5
    ]

    def test_no_matches(self):
        result = search_lines_with_context(self.SAMPLE_LINES, "nonexistent")
        assert result["total_matches"] == 0
        assert result["matched_regions"] == []
        assert result["total_lines"] == 6
        assert result["truncated"] is False

    def test_single_match(self):
        result = search_lines_with_context(self.SAMPLE_LINES, r"\^", context_lines=1)
        assert result["total_matches"] == 1
        regions = result["matched_regions"]
        assert len(regions) == 1
        region = regions[0]
        # Line 2 matches (0-indexed), context_lines=1 → lines 1-3
        assert region["start"] == 2  # 1-based
        assert region["end"] == 4    # 1-based
        # Check items
        assert len(region["items"]) == 3
        assert region["items"][0]["is_match"] is False
        assert region["items"][0]["line_number"] == 2
        assert region["items"][1]["is_match"] is True
        assert region["items"][1]["line_number"] == 3
        assert region["items"][1]["text"] == "    x = x ^ 0x41;"
        assert region["items"][2]["is_match"] is False

    def test_multiple_separate_regions(self):
        lines = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
        # Match "a" (idx 0) and "j" (idx 9) with context_lines=1
        result = search_lines_with_context(lines, "^[aj]$", context_lines=1)
        assert result["total_matches"] == 2
        assert len(result["matched_regions"]) == 2

    def test_overlapping_context_merge(self):
        lines = ["a", "b", "c", "d", "e"]
        # Match "a" (idx 0) and "c" (idx 2) with context_lines=1
        # Region 1: 0-1, Region 2: 1-3 → merged to 0-3
        result = search_lines_with_context(lines, "^[ac]$", context_lines=1)
        assert result["total_matches"] == 2
        assert len(result["matched_regions"]) == 1
        region = result["matched_regions"][0]
        assert region["start"] == 1  # 1-based
        assert region["end"] == 4    # 1-based
        assert len(region["items"]) == 4

    def test_adjacent_context_merge(self):
        lines = ["a", "b", "c", "d", "e"]
        # Match "a" (idx 0) and "d" (idx 3) with context_lines=1
        # Region 1: 0-1, Region 2: 2-4 → adjacent (1+1=2), merged
        result = search_lines_with_context(lines, "^[ad]$", context_lines=1)
        assert result["total_matches"] == 2
        assert len(result["matched_regions"]) == 1

    def test_boundary_start(self):
        lines = ["match", "b", "c"]
        result = search_lines_with_context(lines, "match", context_lines=3)
        assert result["total_matches"] == 1
        region = result["matched_regions"][0]
        assert region["start"] == 1  # clamped to start
        assert len(region["items"]) == 3

    def test_boundary_end(self):
        lines = ["a", "b", "match"]
        result = search_lines_with_context(lines, "match", context_lines=3)
        assert result["total_matches"] == 1
        region = result["matched_regions"][0]
        assert region["end"] == 3  # clamped to end (1-based)

    def test_case_sensitive(self):
        lines = ["XOR operation", "xor key", "OTHER"]
        result = search_lines_with_context(lines, "XOR", case_sensitive=True, context_lines=0)
        assert result["total_matches"] == 1
        assert result["matched_regions"][0]["items"][0]["text"] == "XOR operation"

    def test_case_insensitive_default(self):
        lines = ["XOR operation", "xor key", "OTHER"]
        result = search_lines_with_context(lines, "xor", context_lines=0)
        assert result["total_matches"] == 2

    def test_context_lines_zero(self):
        result = search_lines_with_context(self.SAMPLE_LINES, "printf", context_lines=0)
        assert result["total_matches"] == 1
        region = result["matched_regions"][0]
        assert len(region["items"]) == 1
        assert region["items"][0]["is_match"] is True

    def test_context_lines_clamped_to_max(self):
        """context_lines > MAX_SEARCH_CONTEXT_LINES is clamped to 20."""
        lines = ["a"] * 50
        lines[25] = "MATCH"
        result = search_lines_with_context(lines, "MATCH", context_lines=999)
        region = result["matched_regions"][0]
        # Should have 20 context on each side (clamped), so 41 items
        assert len(region["items"]) == 41

    def test_one_based_line_numbers(self):
        lines = ["first", "second"]
        result = search_lines_with_context(lines, "first", context_lines=0)
        assert result["matched_regions"][0]["items"][0]["line_number"] == 1

    def test_is_match_flags(self):
        lines = ["ctx", "MATCH", "ctx"]
        result = search_lines_with_context(lines, "MATCH", context_lines=1)
        items = result["matched_regions"][0]["items"]
        assert [i["is_match"] for i in items] == [False, True, False]

    def test_max_matches_truncation(self):
        lines = [f"match_{i}" for i in range(10)]
        result = search_lines_with_context(lines, "match", context_lines=0, max_matches=3)
        assert result["total_matches"] == 3
        assert result["truncated"] is True

    def test_empty_lines(self):
        result = search_lines_with_context([], "anything")
        assert result["total_matches"] == 0
        assert result["total_lines"] == 0

    def test_invalid_regex(self):
        with pytest.raises(ValueError, match="Invalid regex"):
            search_lines_with_context(["test"], "[invalid")

    def test_redos_pattern(self):
        with pytest.raises(ValueError, match="nested quantifiers"):
            search_lines_with_context(["test"], "(a+)+b")

    def test_regex_features(self):
        """Regex features like alternation and groups work."""
        lines = ["call CreateFileA", "mov eax, 0", "call WriteFile"]
        result = search_lines_with_context(lines, r"Create\w+|Write\w+", context_lines=0)
        assert result["total_matches"] == 2

    def test_all_lines_match(self):
        lines = ["a", "a", "a"]
        result = search_lines_with_context(lines, "a", context_lines=1)
        assert result["total_matches"] == 3
        # All merge into one region
        assert len(result["matched_regions"]) == 1
        assert len(result["matched_regions"][0]["items"]) == 3


# =====================================================================
#  search_instructions_with_context
# =====================================================================

class TestSearchInstructionsWithContext:
    """Tests for the instruction-based search helper."""

    SAMPLE_INSNS = [
        {"address": "0x1000", "mnemonic": "push", "op_str": "ebp"},
        {"address": "0x1001", "mnemonic": "mov", "op_str": "ebp, esp"},
        {"address": "0x1003", "mnemonic": "xor", "op_str": "eax, eax"},
        {"address": "0x1005", "mnemonic": "call", "op_str": "0x2000", "call_target": "CreateFileA"},
        {"address": "0x100a", "mnemonic": "pop", "op_str": "ebp"},
        {"address": "0x100b", "mnemonic": "ret", "op_str": ""},
    ]

    def test_mnemonic_match(self):
        result = search_instructions_with_context(self.SAMPLE_INSNS, "xor", context_lines=0)
        assert result["total_matches"] == 1
        insns = result["matched_regions"][0]["instructions"]
        assert insns[0]["mnemonic"] == "xor"
        assert insns[0]["is_match"] is True

    def test_op_str_match(self):
        result = search_instructions_with_context(self.SAMPLE_INSNS, "ebp, esp", context_lines=0)
        assert result["total_matches"] == 1

    def test_call_target_match(self):
        result = search_instructions_with_context(self.SAMPLE_INSNS, "CreateFileA", context_lines=0)
        assert result["total_matches"] == 1
        insns = result["matched_regions"][0]["instructions"]
        assert insns[0]["call_target"] == "CreateFileA"

    def test_label_string_match(self):
        insns = [{"mnemonic": "nop", "op_str": "", "label": "loop_start"}]
        result = search_instructions_with_context(insns, "loop_start", context_lines=0)
        assert result["total_matches"] == 1

    def test_label_dict_match(self):
        insns = [{"mnemonic": "nop", "op_str": "", "label": {"name": "crypto_init", "category": "analysis"}}]
        result = search_instructions_with_context(insns, "crypto_init", context_lines=0)
        assert result["total_matches"] == 1

    def test_no_matches(self):
        result = search_instructions_with_context(self.SAMPLE_INSNS, "nonexistent")
        assert result["total_matches"] == 0
        assert result["matched_regions"] == []
        assert result["total_instructions"] == 6

    def test_context_merging(self):
        result = search_instructions_with_context(self.SAMPLE_INSNS, "xor|call", context_lines=1)
        # xor at idx 2, call at idx 3 → context [1-4] merged
        assert result["total_matches"] == 2
        assert len(result["matched_regions"]) == 1

    def test_instruction_index_in_output(self):
        result = search_instructions_with_context(self.SAMPLE_INSNS, "xor", context_lines=0)
        insn = result["matched_regions"][0]["instructions"][0]
        assert insn["instruction_index"] == 2

    def test_region_keys(self):
        """Regions use start_index/end_index/instructions instead of start/end/items."""
        result = search_instructions_with_context(self.SAMPLE_INSNS, "xor", context_lines=1)
        region = result["matched_regions"][0]
        assert "start_index" in region
        assert "end_index" in region
        assert "instructions" in region
        assert "start" not in region
        assert "items" not in region

    def test_truncation(self):
        insns = [{"mnemonic": "nop", "op_str": ""} for _ in range(10)]
        result = search_instructions_with_context(insns, "nop", context_lines=0, max_matches=3)
        assert result["total_matches"] == 3
        assert result["truncated"] is True

    def test_empty_instructions(self):
        result = search_instructions_with_context([], "anything")
        assert result["total_matches"] == 0
        assert result["total_instructions"] == 0


# =====================================================================
#  _build_context_regions
# =====================================================================

class TestBuildContextRegions:
    """Tests for the internal region merging helper."""

    def test_single_match(self):
        items = ["a", "b", "c", "d", "e"]
        fmt = lambda idx, item, is_match: {"text": item, "is_match": is_match}
        regions = _build_context_regions(items, [2], 1, format_item=fmt)
        assert len(regions) == 1
        assert regions[0]["start"] == 2  # 1-based
        assert regions[0]["end"] == 4
        assert len(regions[0]["items"]) == 3

    def test_all_lines_match(self):
        items = ["a", "b", "c"]
        fmt = lambda idx, item, is_match: {"text": item, "is_match": is_match}
        regions = _build_context_regions(items, [0, 1, 2], 0, format_item=fmt)
        # context=0, all match → should be one merged region
        assert len(regions) == 1
        assert all(r["is_match"] for r in regions[0]["items"])

    def test_empty_indices(self):
        items = ["a", "b"]
        fmt = lambda idx, item, is_match: {"text": item, "is_match": is_match}
        regions = _build_context_regions(items, [], 1, format_item=fmt)
        assert regions == []

    def test_zero_based(self):
        items = ["a", "b", "c"]
        fmt = lambda idx, item, is_match: {"idx": idx, "is_match": is_match}
        regions = _build_context_regions(items, [1], 0, format_item=fmt, one_based=False)
        assert regions[0]["start"] == 1  # 0-based
        assert regions[0]["end"] == 1
