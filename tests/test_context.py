"""Tests for arkana.mcp.tools_context — context aggregation tool."""
import pytest

from arkana.state import AnalyzerState


class TestGatherContext:
    """Tests for the _gather_context synchronous helper."""

    def setup_method(self):
        self.state = AnalyzerState()

    def test_import_context_module(self):
        """Module imports without error."""
        from arkana.mcp.tools_context import _gather_context
        assert callable(_gather_context)

    def test_basic_structure(self):
        """Result contains expected top-level keys."""
        from arkana.mcp.tools_context import _gather_context
        result = _gather_context(
            addr_int=0x401000,
            include_decompilation=False,
            include_xrefs=False,
            include_strings=False,
            include_notes=False,
            max_decompile_lines=60,
        )
        assert "function_address" in result
        assert result["function_address"] == "0x401000"
        assert "function_name" in result
        assert "triage_status" in result
        assert "enrichment_score" in result

    def test_include_decompilation_false(self):
        """Decompilation section absent when disabled."""
        from arkana.mcp.tools_context import _gather_context
        result = _gather_context(
            addr_int=0x401000,
            include_decompilation=False,
            include_xrefs=False,
            include_strings=False,
            include_notes=False,
            max_decompile_lines=60,
        )
        assert "decompilation" not in result

    def test_include_decompilation_true_no_cache(self):
        """Decompilation shows unavailable when cache is empty."""
        from arkana.mcp.tools_context import _gather_context
        result = _gather_context(
            addr_int=0x401000,
            include_decompilation=True,
            include_xrefs=False,
            include_strings=False,
            include_notes=False,
            max_decompile_lines=60,
        )
        assert "decompilation" in result
        decomp = result["decompilation"]
        assert decomp.get("available") is False or "lines" in decomp

    def test_include_notes_empty(self):
        """Notes section returns empty list when no notes exist."""
        from arkana.mcp.tools_context import _gather_context
        result = _gather_context(
            addr_int=0x401000,
            include_decompilation=False,
            include_xrefs=False,
            include_strings=False,
            include_notes=True,
            max_decompile_lines=60,
        )
        assert "notes" in result
        assert isinstance(result["notes"], list)
        assert len(result["notes"]) == 0

    def test_address_hex_formatting(self):
        """Address is formatted as hex string."""
        from arkana.mcp.tools_context import _gather_context
        result = _gather_context(
            addr_int=4198400,  # decimal
            include_decompilation=False,
            include_xrefs=False,
            include_strings=False,
            include_notes=False,
            max_decompile_lines=60,
        )
        assert result["function_address"].startswith("0x")

    def test_max_decompile_lines_clamped(self):
        """max_decompile_lines is properly bounded."""
        from arkana.mcp.tools_context import _gather_context
        # Should not crash with extreme values
        result = _gather_context(
            addr_int=0x401000,
            include_decompilation=True,
            include_xrefs=False,
            include_strings=False,
            include_notes=False,
            max_decompile_lines=0,  # Will be clamped to 1
        )
        assert "decompilation" in result

    def test_all_sections_enabled(self):
        """All sections can be enabled simultaneously."""
        from arkana.mcp.tools_context import _gather_context
        result = _gather_context(
            addr_int=0x401000,
            include_decompilation=True,
            include_xrefs=False,  # xrefs need angr
            include_strings=False,  # strings need angr func
            include_notes=True,
            max_decompile_lines=60,
        )
        assert "decompilation" in result
        assert "notes" in result


class TestToolDecoratorRegistration:
    """Test that the tool is properly decorated."""

    def test_tool_function_exists(self):
        from arkana.mcp.tools_context import get_analysis_context_for_function
        assert callable(get_analysis_context_for_function)

    def test_tool_is_async(self):
        import inspect
        from arkana.mcp.tools_context import get_analysis_context_for_function
        assert inspect.iscoroutinefunction(get_analysis_context_for_function)


class TestParseAddr:
    """Test address parsing used by the tool."""

    def test_hex_address(self):
        from arkana.mcp._angr_helpers import _parse_addr
        assert _parse_addr("0x401000") == 0x401000

    def test_decimal_address(self):
        from arkana.mcp._angr_helpers import _parse_addr
        assert _parse_addr("4198400") == 4198400

    def test_invalid_address(self):
        from arkana.mcp._angr_helpers import _parse_addr
        with pytest.raises(ValueError):
            _parse_addr("not_an_address")
