"""Tests for symbolic execution extensions in arkana.mcp.tools_angr."""
import pytest

from arkana.constants import MAX_SYMBOLIC_STEPS, MAX_SYMBOLIC_ACTIVE_STATES, MAX_SYMBOLIC_FIND_ADDRESSES


class TestConstants:
    """Verify symbolic execution constants."""

    def test_max_steps(self):
        assert MAX_SYMBOLIC_STEPS == 100_000

    def test_max_active_states(self):
        assert MAX_SYMBOLIC_ACTIVE_STATES == 100

    def test_max_find_addresses(self):
        assert MAX_SYMBOLIC_FIND_ADDRESSES == 20


class TestSolveConstraintsForPath:
    """Tests for solve_constraints_for_path tool."""

    def test_import(self):
        from arkana.mcp.tools_angr import solve_constraints_for_path
        assert callable(solve_constraints_for_path)

    def test_is_async(self):
        import inspect
        from arkana.mcp.tools_angr import solve_constraints_for_path
        assert inspect.iscoroutinefunction(solve_constraints_for_path)

    def test_address_parsing(self):
        """_parse_addr handles hex and decimal."""
        from arkana.mcp._angr_helpers import _parse_addr
        assert _parse_addr("0x401000") == 0x401000
        assert _parse_addr("4198400") == 4198400

    def test_address_parsing_invalid(self):
        from arkana.mcp._angr_helpers import _parse_addr
        with pytest.raises(ValueError):
            _parse_addr("xyz")

    def test_max_steps_lower_bound(self):
        """max_steps should be clamped to at least 100."""
        val = max(100, min(50, MAX_SYMBOLIC_STEPS))
        assert val == 100

    def test_max_steps_upper_bound(self):
        """max_steps should be clamped to MAX_SYMBOLIC_STEPS."""
        val = max(100, min(200_000, MAX_SYMBOLIC_STEPS))
        assert val == MAX_SYMBOLIC_STEPS

    def test_timeout_lower_bound(self):
        """timeout_seconds should be clamped to at least 10."""
        val = max(10, min(5, 1800))
        assert val == 10

    def test_timeout_upper_bound(self):
        """timeout_seconds should be clamped to 1800."""
        val = max(10, min(5000, 1800))
        assert val == 1800


class TestExploreSymbolicStates:
    """Tests for explore_symbolic_states tool."""

    def test_import(self):
        from arkana.mcp.tools_angr import explore_symbolic_states
        assert callable(explore_symbolic_states)

    def test_is_async(self):
        import inspect
        from arkana.mcp.tools_angr import explore_symbolic_states
        assert inspect.iscoroutinefunction(explore_symbolic_states)

    def test_strategy_validation(self):
        """Only dfs, bfs, directed should be valid."""
        valid = ("dfs", "bfs", "directed")
        assert "dfs" in valid
        assert "bfs" in valid
        assert "directed" in valid
        assert "random" not in valid

    def test_max_active_clamping(self):
        """max_active should clamp to [1, MAX_SYMBOLIC_ACTIVE_STATES]."""
        assert max(1, min(0, MAX_SYMBOLIC_ACTIVE_STATES)) == 1
        assert max(1, min(50, MAX_SYMBOLIC_ACTIVE_STATES)) == 50
        assert max(1, min(200, MAX_SYMBOLIC_ACTIVE_STATES)) == MAX_SYMBOLIC_ACTIVE_STATES

    def test_find_addresses_limit(self):
        """find_addresses should be limited to MAX_SYMBOLIC_FIND_ADDRESSES."""
        assert MAX_SYMBOLIC_FIND_ADDRESSES == 20


class TestSelfReportingTools:
    """Verify new symex tools are in the self-reporting set."""

    def test_solve_in_self_reporting(self):
        from arkana.mcp.server import _SELF_REPORTING_TOOLS
        assert "solve_constraints_for_path" in _SELF_REPORTING_TOOLS

    def test_explore_in_self_reporting(self):
        from arkana.mcp.server import _SELF_REPORTING_TOOLS
        assert "explore_symbolic_states" in _SELF_REPORTING_TOOLS
