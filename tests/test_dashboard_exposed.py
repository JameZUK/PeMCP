"""Tests for arkana.mcp.tools_dashboard_exposed — MCP wrappers for dashboard data functions."""
import pytest

from arkana.state import AnalyzerState, _default_state, _session_registry


class TestSearchDecompiledCode:
    """Tests for the search_decompiled_code MCP tool wrapper."""

    def test_import(self):
        from arkana.mcp.tools_dashboard_exposed import search_decompiled_code
        assert callable(search_decompiled_code)

    def test_is_async(self):
        import asyncio
        from arkana.mcp.tools_dashboard_exposed import search_decompiled_code
        assert asyncio.iscoroutinefunction(search_decompiled_code)

    def test_validate_regex_pattern_imported(self):
        """validate_regex_pattern is available for query validation."""
        from arkana.utils import validate_regex_pattern
        # Valid pattern should not raise
        validate_regex_pattern("test.*pattern")

    def test_validate_regex_rejects_nested_quantifiers(self):
        from arkana.utils import validate_regex_pattern
        with pytest.raises(ValueError, match="nested quantifiers"):
            validate_regex_pattern("(a+)+b")

    def test_validate_regex_rejects_long_patterns(self):
        from arkana.utils import validate_regex_pattern
        with pytest.raises(ValueError, match="too long"):
            validate_regex_pattern("a" * 1100)


class TestGetEntropyAnalysis:
    """Tests for the get_entropy_analysis MCP tool wrapper."""

    def test_import(self):
        from arkana.mcp.tools_dashboard_exposed import get_entropy_analysis
        assert callable(get_entropy_analysis)

    def test_is_async(self):
        import asyncio
        from arkana.mcp.tools_dashboard_exposed import get_entropy_analysis
        assert asyncio.iscoroutinefunction(get_entropy_analysis)


class TestGenerateReport:
    """Tests for the generate_report MCP tool wrapper."""

    def test_import(self):
        from arkana.mcp.tools_dashboard_exposed import generate_report
        assert callable(generate_report)

    def test_is_async(self):
        import asyncio
        from arkana.mcp.tools_dashboard_exposed import generate_report
        assert asyncio.iscoroutinefunction(generate_report)


class TestDashboardStateApi:
    """Tests for the underlying state_api functions used by the wrappers."""

    def test_search_decompiled_code_exists(self):
        from arkana.dashboard.state_api import search_decompiled_code
        assert callable(search_decompiled_code)

    def test_search_empty_query(self):
        from arkana.dashboard.state_api import search_decompiled_code
        result = search_decompiled_code("", 50)
        assert result["total_matches"] == 0
        assert result["results"] == []

    def test_search_whitespace_query(self):
        from arkana.dashboard.state_api import search_decompiled_code
        result = search_decompiled_code("   ", 50)
        assert result["total_matches"] == 0

    def test_get_entropy_data_exists(self):
        from arkana.dashboard.state_api import get_entropy_data
        assert callable(get_entropy_data)

    def test_generate_report_text_exists(self):
        from arkana.dashboard.state_api import generate_report_text
        assert callable(generate_report_text)

    def test_generate_report_no_file(self):
        """Report should indicate unavailable when no file is loaded."""
        from arkana.dashboard.state_api import generate_report_text
        # Save and clear state
        saved_registry = dict(_session_registry)
        _session_registry.clear()
        old_fp = _default_state.filepath
        old_pd = _default_state.pe_data
        _default_state.filepath = None
        _default_state.pe_data = None
        try:
            result = generate_report_text()
            assert result["available"] is False
        finally:
            _default_state.filepath = old_fp
            _default_state.pe_data = old_pd
            _session_registry.clear()
            _session_registry.update(saved_registry)
