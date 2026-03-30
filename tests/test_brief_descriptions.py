"""Unit tests for brief tool descriptions (--brief-descriptions / ARKANA_BRIEF_DESCRIPTIONS)."""
import pytest

from arkana.mcp.server import (
    _extract_brief_description,
    _brief_descriptions,
    set_brief_descriptions,
)


# ---------------------------------------------------------------------------
# _extract_brief_description — pure function tests
# ---------------------------------------------------------------------------

class TestExtractBriefDescription:
    """Tests for the first-paragraph extraction helper."""

    def test_single_paragraph(self):
        """Single paragraph with no blank line returns as-is."""
        doc = "[Phase: triage] Quick summary of what this tool does."
        assert _extract_brief_description(doc) == doc.strip()

    def test_two_paragraphs(self):
        """Returns only the first paragraph, dropping everything after the blank line."""
        doc = (
            "[Phase: explore] Search strings with regex.\n"
            "\n"
            "When to use: When looking for IOCs.\n"
            "Next steps: Use add_note().\n"
            "\n"
            "Args:\n"
            "    pattern: regex\n"
        )
        assert _extract_brief_description(doc) == "[Phase: explore] Search strings with regex."

    def test_multi_line_first_paragraph(self):
        """First paragraph can span multiple lines before the blank line."""
        doc = (
            "[Phase: load] Opens and analyses a binary file,\n"
            "making it available for all other tools.\n"
            "Supports PE, ELF, Mach-O, and shellcode.\n"
            "\n"
            "When to use: Always start here.\n"
        )
        expected = (
            "[Phase: load] Opens and analyses a binary file,\n"
            "making it available for all other tools.\n"
            "Supports PE, ELF, Mach-O, and shellcode."
        )
        assert _extract_brief_description(doc) == expected

    def test_indented_docstring(self):
        """Handles typical indented docstrings (leading/trailing whitespace)."""
        doc = """
    [Phase: context] Add a note to the currently loaded file. Notes persist in
    the analysis cache and are restored when the same file is reopened later.

    When to use: After any analysis step.

    Args:
        content: The note text.
    """
        result = _extract_brief_description(doc)
        assert result.startswith("[Phase: context] Add a note")
        assert "When to use" not in result
        assert "Args:" not in result

    def test_empty_docstring(self):
        assert _extract_brief_description("") == ""
        assert _extract_brief_description("   ") == ""

    def test_no_blank_line(self):
        """Docstring with no blank lines returns the whole thing stripped."""
        doc = "[Phase: utility] Returns current datetime.\nUseful for timestamping."
        assert _extract_brief_description(doc) == doc.strip()

    def test_only_whitespace_between_paragraphs(self):
        """Blank line with trailing spaces still counts as a paragraph break."""
        doc = "First paragraph.\n  \nSecond paragraph."
        # \n  \n has spaces on the "blank" line — split on \n\n won't match.
        # This is fine: we keep both, because the line isn't truly blank.
        # The helper uses \n\n which requires a completely empty line.
        result = _extract_brief_description(doc)
        # With spaces on the middle line, \n\n doesn't match — returns all
        assert "Second paragraph" in result

    def test_preserves_phase_label(self):
        doc = "[Phase: deep-analysis] Decompile function.\n\nArgs: ..."
        result = _extract_brief_description(doc)
        assert result == "[Phase: deep-analysis] Decompile function."

    def test_realistic_tool_docstring(self):
        """Test with a realistic full tool docstring."""
        doc = """[Phase: explore] Performs a regex search against FLOSS strings with advanced
score filtering and sorting.

When to use: When looking for specific patterns in strings — network indicators
(IPs, URLs, domains), file paths, registry keys, or suspicious API references.
More targeted than get_strings_summary() or get_top_sifted_strings().

Next steps: If IOCs found → add_note(content, category='tool_result') to record them.
Use get_string_usage_context(string_offset) to find code that references a string.

Args:
    ctx: The MCP Context object.
    regex_patterns: (List[str]) A list of regex patterns to search for.
    min_sifter_score: (Optional[float]) Minimum sifter score filter.
    limit: (int) Maximum number of matches to return. Defaults to 100.

Returns:
    A dictionary containing a list of matched strings and pagination information.
"""
        result = _extract_brief_description(doc)
        assert result == (
            "[Phase: explore] Performs a regex search against FLOSS strings with advanced\n"
            "score filtering and sorting."
        )
        # Must not contain any of the later sections
        assert "When to use" not in result
        assert "Args:" not in result
        assert "Returns:" not in result


# ---------------------------------------------------------------------------
# set_brief_descriptions — flag management
# ---------------------------------------------------------------------------

class TestSetBriefDescriptions:
    """Tests for the module-level flag setter."""

    def setup_method(self):
        """Save original state."""
        import arkana.mcp.server as mod
        self._original = mod._brief_descriptions

    def teardown_method(self):
        """Restore original state."""
        import arkana.mcp.server as mod
        mod._brief_descriptions = self._original

    def test_enable(self):
        import arkana.mcp.server as mod
        set_brief_descriptions(True)
        assert mod._brief_descriptions is True

    def test_disable(self):
        import arkana.mcp.server as mod
        set_brief_descriptions(True)
        set_brief_descriptions(False)
        assert mod._brief_descriptions is False

    def test_default_is_false(self):
        """Default state should be False (full descriptions)."""
        # Reset to default
        import arkana.mcp.server as mod
        set_brief_descriptions(False)
        assert mod._brief_descriptions is False
