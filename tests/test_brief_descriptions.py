"""Unit tests for brief tool descriptions (--brief-descriptions / ARKANA_BRIEF_DESCRIPTIONS)."""
import pytest

from arkana.mcp.server import (
    _extract_brief_description,
    _brief_descriptions,
    set_brief_descriptions,
)


# ---------------------------------------------------------------------------
# _extract_brief_description — compact line extraction
# ---------------------------------------------------------------------------

class TestExtractCompactLine:
    """Tests for ---compact: line extraction (primary path)."""

    def test_compact_line_extracted(self):
        doc = (
            "[Phase: triage] Full description here.\n"
            "    ---compact: auto-triage: risk, packing, imports | needs: file\n"
            "\n"
            "When to use: ...\n"
        )
        assert _extract_brief_description(doc) == "auto-triage: risk, packing, imports | needs: file"

    def test_compact_line_no_leading_whitespace(self):
        doc = (
            "[Phase: explore] Full description.\n"
            "---compact: regex search FLOSS strings | filter: score\n"
            "\n"
            "Args:\n"
        )
        assert _extract_brief_description(doc) == "regex search FLOSS strings | filter: score"

    def test_compact_line_heavy_indent(self):
        """Handles typical docstring indentation."""
        doc = """
    [Phase: context] Add a note to the currently loaded file.
    ---compact: add persistent note | categories: general, function, ioc, hypothesis

    When to use: ...
    """
        result = _extract_brief_description(doc)
        assert result == "add persistent note | categories: general, function, ioc, hypothesis"

    def test_compact_line_minimal(self):
        doc = "Summary.\n---compact: do thing\n\nArgs:"
        assert _extract_brief_description(doc) == "do thing"

    def test_compact_line_with_needs(self):
        doc = "Desc.\n---compact: decompile function | search, digest | needs: angr\n\nWhen:"
        assert _extract_brief_description(doc) == "decompile function | search, digest | needs: angr"

    def test_compact_line_pipes_preserved(self):
        doc = "Desc.\n---compact: a | b | c | needs: d\n"
        assert _extract_brief_description(doc) == "a | b | c | needs: d"

    def test_compact_wins_over_first_paragraph(self):
        """Even if first paragraph exists, compact line takes priority."""
        doc = (
            "[Phase: explore] This is a very long first paragraph that describes "
            "what the tool does in great detail with many words.\n"
            "---compact: short version\n"
            "\n"
            "When to use: ..."
        )
        assert _extract_brief_description(doc) == "short version"


# ---------------------------------------------------------------------------
# _extract_brief_description — fallback to first paragraph
# ---------------------------------------------------------------------------

class TestExtractFallback:
    """Tests for first-paragraph fallback when no ---compact: line exists."""

    def test_no_compact_falls_back_to_first_paragraph(self):
        doc = (
            "[Phase: explore] Search strings with regex.\n"
            "\n"
            "When to use: When looking for IOCs.\n"
        )
        assert _extract_brief_description(doc) == "[Phase: explore] Search strings with regex."

    def test_single_paragraph_no_compact(self):
        doc = "[Phase: triage] Quick summary."
        assert _extract_brief_description(doc) == doc.strip()

    def test_empty_docstring(self):
        assert _extract_brief_description("") == ""
        assert _extract_brief_description("   ") == ""

    def test_no_blank_line_no_compact(self):
        doc = "First line.\nSecond line."
        assert _extract_brief_description(doc) == doc.strip()


# ---------------------------------------------------------------------------
# set_brief_descriptions — flag management
# ---------------------------------------------------------------------------

class TestSetBriefDescriptions:
    """Tests for the module-level flag setter."""

    def setup_method(self):
        import arkana.mcp.server as mod
        self._original = mod._brief_descriptions

    def teardown_method(self):
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
        import arkana.mcp.server as mod
        set_brief_descriptions(False)
        assert mod._brief_descriptions is False
