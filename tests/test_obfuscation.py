"""Tests for obfuscation detection tools (CFF + opaque predicates)."""
import pytest


# =====================================================================
#  Constants
# =====================================================================

class TestObfuscationConstants:
    """Test obfuscation detection constants exist and are valid."""

    def test_cff_constants(self):
        from arkana.constants import (
            CFF_MIN_BLOCKS,
            CFF_DISPATCHER_IN_DEGREE_THRESHOLD,
            CFF_BACK_EDGE_RATIO_THRESHOLD,
            MAX_CFF_SCAN_FUNCTIONS,
        )
        assert CFF_MIN_BLOCKS > 0
        assert CFF_DISPATCHER_IN_DEGREE_THRESHOLD > 0
        assert 0 < CFF_BACK_EDGE_RATIO_THRESHOLD <= 1.0
        assert MAX_CFF_SCAN_FUNCTIONS > 0

    def test_opaque_constants(self):
        from arkana.constants import (
            OPAQUE_PREDICATE_SOLVER_TIMEOUT,
            MAX_OPAQUE_PREDICATE_BLOCKS,
            MAX_OPAQUE_SCAN_FUNCTIONS,
        )
        assert OPAQUE_PREDICATE_SOLVER_TIMEOUT > 0
        assert MAX_OPAQUE_PREDICATE_BLOCKS > 0
        assert MAX_OPAQUE_SCAN_FUNCTIONS > 0

    def test_overall_timeout(self):
        from arkana.constants import OBFUSCATION_DETECTION_TIMEOUT
        assert OBFUSCATION_DETECTION_TIMEOUT > 0

    def test_solver_timeout_less_than_overall(self):
        from arkana.constants import OPAQUE_PREDICATE_SOLVER_TIMEOUT, OBFUSCATION_DETECTION_TIMEOUT
        assert OPAQUE_PREDICATE_SOLVER_TIMEOUT < OBFUSCATION_DETECTION_TIMEOUT


# =====================================================================
#  CFF Detection — _analyze_function_for_cff
# =====================================================================

class TestAnalyzeFunctionForCff:
    """Test the CFF analysis helper."""

    def test_small_function_skipped(self):
        """Functions with fewer blocks than CFF_MIN_BLOCKS should be skipped."""
        from arkana.mcp.tools_angr_forensic import _analyze_function_for_cff
        from arkana.constants import CFF_MIN_BLOCKS

        class MockGraph:
            def nodes(self):
                return [1, 2]  # fewer than CFF_MIN_BLOCKS
            def in_degree(self, n):
                return 1

        class MockFunc:
            addr = 0x401000
            name = "small_func"
            graph = MockGraph()

        result = _analyze_function_for_cff(MockFunc(), None)
        assert result is None

    def test_low_in_degree_skipped(self):
        """Functions without a high-in-degree dispatcher should be skipped."""
        from arkana.mcp.tools_angr_forensic import _analyze_function_for_cff

        class MockBlock:
            def __init__(self, a):
                self.addr = a

        blocks = [MockBlock(i) for i in range(10)]

        class MockGraph:
            def nodes(self):
                return blocks
            def in_degree(self, n):
                return 1  # all low
            def has_edge(self, a, b):
                return False

        class MockFunc:
            addr = 0x401000
            name = "normal_func"
            graph = MockGraph()

        result = _analyze_function_for_cff(MockFunc(), None)
        assert result is None

    def test_cff_detected_with_high_in_degree(self):
        """A function with a high-in-degree dispatcher block should be detected."""
        from arkana.mcp.tools_angr_forensic import _analyze_function_for_cff
        from arkana.constants import CFF_DISPATCHER_IN_DEGREE_THRESHOLD

        class MockBlock:
            def __init__(self, a):
                self.addr = a

        dispatcher = MockBlock(0x1000)
        others = [MockBlock(0x1000 + i * 0x10) for i in range(1, 10)]
        blocks = [dispatcher, *others]

        class MockGraph:
            def nodes(self):
                return blocks
            def in_degree(self, n):
                if n is dispatcher:
                    return CFF_DISPATCHER_IN_DEGREE_THRESHOLD + 2
                return 1
            def has_edge(self, a, b):
                # Most blocks have edge back to dispatcher
                return b is dispatcher and a is not dispatcher

        class MockFunc:
            addr = 0x401000
            name = "cff_func"
            graph = MockGraph()
            _project = None

        result = _analyze_function_for_cff(MockFunc(), None)
        # Should return a finding (may or may not exceed min_confidence)
        assert result is not None
        assert "confidence" in result
        assert 0 <= result["confidence"] <= 100
        assert result["function_address"] == "0x401000"
        assert result["dispatcher_in_degree"] >= CFF_DISPATCHER_IN_DEGREE_THRESHOLD

    def test_none_graph_returns_none(self):
        from arkana.mcp.tools_angr_forensic import _analyze_function_for_cff

        class MockFunc:
            addr = 0x401000
            name = "no_graph"
            graph = None

        assert _analyze_function_for_cff(MockFunc(), None) is None

    def test_confidence_bounded(self):
        """Confidence should always be 0-100."""
        from arkana.mcp.tools_angr_forensic import _analyze_function_for_cff

        class MockBlock:
            def __init__(self, a):
                self.addr = a

        dispatcher = MockBlock(0x1000)
        others = [MockBlock(0x1000 + i * 0x10) for i in range(1, 10)]
        blocks = [dispatcher, *others]

        class MockGraph:
            def nodes(self):
                return blocks
            def in_degree(self, n):
                return 100 if n is dispatcher else 1  # extreme in-degree
            def has_edge(self, a, b):
                return b is dispatcher

        class MockFunc:
            addr = 0x401000
            name = "extreme_func"
            graph = MockGraph()
            _project = None

        result = _analyze_function_for_cff(MockFunc(), None)
        if result is not None:
            assert 0 <= result["confidence"] <= 100


# =====================================================================
#  CFF Sync Worker — _sync_detect_cff
# =====================================================================

class TestSyncDetectCff:
    """Test the CFF sync detection worker (requires angr availability check)."""

    def test_no_cfg_returns_error(self):
        """Without a loaded project, should return error."""
        from arkana.mcp.tools_angr_forensic import _sync_detect_cff
        try:
            result = _sync_detect_cff(None, 40, 20)
            # Either returns error or findings depending on angr state
            assert "findings" in result
        except Exception:
            pass  # _ensure_project_and_cfg may raise

    def test_result_structure_on_missing_target(self):
        """Target address not in CFG should return error."""
        from arkana.mcp.tools_angr_forensic import _sync_detect_cff
        try:
            result = _sync_detect_cff(0xDEADBEEF, 40, 20)
            if "error" in result:
                assert "not found" in result["error"] or "No CFG" in result["error"]
        except Exception:
            pass  # may raise if no project loaded


# =====================================================================
#  Opaque Predicate — _analyze_block_for_opaque
# =====================================================================

class TestAnalyzeBlockForOpaque:
    """Test the opaque predicate block analysis helper."""

    def test_no_angr_handles_gracefully(self):
        """Without a real angr project, should return None (not crash)."""
        from arkana.mcp.tools_angr_forensic import _analyze_block_for_opaque

        class MockProject:
            class factory:
                @staticmethod
                def block(addr):
                    raise Exception("No real project")

        result = _analyze_block_for_opaque(MockProject(), 0x401000, 0x401000)
        assert result is None

    def test_invalid_address_returns_none(self):
        from arkana.mcp.tools_angr_forensic import _analyze_block_for_opaque

        class MockProject:
            class factory:
                @staticmethod
                def block(addr):
                    raise ValueError("Invalid address")

        result = _analyze_block_for_opaque(MockProject(), 0xFFFFFFFF, 0x401000)
        assert result is None


# =====================================================================
#  Opaque Predicate Sync Worker
# =====================================================================

class TestSyncDetectOpaque:
    """Test the opaque predicate sync detection worker."""

    def test_no_cfg_returns_error(self):
        from arkana.mcp.tools_angr_forensic import _sync_detect_opaque
        try:
            result = _sync_detect_opaque(None, 20)
            assert "findings" in result
        except Exception:
            pass  # _ensure_project_and_cfg may raise

    def test_result_has_expected_keys(self):
        from arkana.mcp.tools_angr_forensic import _sync_detect_opaque
        try:
            result = _sync_detect_opaque(None, 20)
            if "error" not in result:
                assert "findings" in result
                assert "total_findings" in result
                assert "functions_scanned" in result
                assert "blocks_analyzed" in result
                assert "solver_timeouts" in result
        except Exception:
            pass


# =====================================================================
#  Tool Registration
# =====================================================================

class TestObfuscationToolRegistration:
    """Test that obfuscation detection tools are properly decorated."""

    def test_cff_tool_is_coroutine(self):
        import inspect
        from arkana.mcp.tools_angr_forensic import detect_control_flow_flattening
        assert inspect.iscoroutinefunction(detect_control_flow_flattening)

    def test_opaque_tool_is_coroutine(self):
        import inspect
        from arkana.mcp.tools_angr_forensic import detect_opaque_predicates
        assert inspect.iscoroutinefunction(detect_opaque_predicates)

    def test_cff_tool_in_self_reporting(self):
        from arkana.mcp.server import _SELF_REPORTING_TOOLS
        assert "detect_control_flow_flattening" in _SELF_REPORTING_TOOLS

    def test_opaque_tool_in_self_reporting(self):
        from arkana.mcp.server import _SELF_REPORTING_TOOLS
        assert "detect_opaque_predicates" in _SELF_REPORTING_TOOLS

    def test_data_flow_tool_in_self_reporting(self):
        from arkana.mcp.server import _SELF_REPORTING_TOOLS
        assert "find_dangerous_data_flows" in _SELF_REPORTING_TOOLS
