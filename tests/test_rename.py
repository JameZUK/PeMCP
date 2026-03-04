"""Unit tests for rename/label state accessors."""
import pytest
from arkana.state import AnalyzerState


@pytest.fixture
def state():
    return AnalyzerState()


class TestFunctionRename:
    def test_rename_function(self, state):
        result = state.rename_function("0x401000", "main")
        assert result["address"] == "0x401000"
        assert result["new_name"] == "main"
        assert result["type"] == "function"
        assert state.renames["functions"]["0x401000"] == "main"

    def test_rename_function_normalises_case(self, state):
        state.rename_function("0xABCD", "func_a")
        assert "0xabcd" in state.renames["functions"]

    def test_rename_function_overwrites(self, state):
        state.rename_function("0x401000", "old_name")
        state.rename_function("0x401000", "new_name")
        assert state.renames["functions"]["0x401000"] == "new_name"

    def test_get_function_display_name(self, state):
        assert state.get_function_display_name("0x401000") is None
        state.rename_function("0x401000", "main")
        assert state.get_function_display_name("0x401000") == "main"

    def test_get_function_display_name_case_insensitive(self, state):
        state.rename_function("0xABCD", "func")
        assert state.get_function_display_name("0xabcd") == "func"


class TestVariableRename:
    def test_rename_variable(self, state):
        result = state.rename_variable("0x401000", "v1", "buffer")
        assert result["function_address"] == "0x401000"
        assert result["old_name"] == "v1"
        assert result["new_name"] == "buffer"
        assert state.renames["variables"]["0x401000"]["v1"] == "buffer"

    def test_multiple_variables_same_function(self, state):
        state.rename_variable("0x401000", "v1", "buf")
        state.rename_variable("0x401000", "v2", "size")
        assert len(state.renames["variables"]["0x401000"]) == 2


class TestLabels:
    def test_add_label(self, state):
        result = state.add_label("0x401000", "entry", "general")
        assert result["address"] == "0x401000"
        assert result["name"] == "entry"
        assert result["category"] == "general"
        assert "0x401000" in state.renames["labels"]

    def test_add_label_with_category(self, state):
        state.add_label("0x401000", "c2_init", "c2")
        assert state.renames["labels"]["0x401000"]["category"] == "c2"


class TestGetAndDelete:
    def test_get_renames_all(self, state):
        state.rename_function("0x401000", "main")
        state.add_label("0x402000", "test", "general")
        renames = state.get_renames()
        assert "functions" in renames
        assert "labels" in renames
        assert "variables" in renames

    def test_get_renames_filtered(self, state):
        state.rename_function("0x401000", "main")
        renames = state.get_renames("functions")
        assert "functions" in renames
        assert "variables" not in renames

    def test_delete_function_rename(self, state):
        state.rename_function("0x401000", "main")
        assert state.delete_rename("0x401000", "function") is True
        assert state.renames["functions"] == {}

    def test_delete_nonexistent(self, state):
        assert state.delete_rename("0x999", "function") is False

    def test_delete_label(self, state):
        state.add_label("0x401000", "test", "general")
        assert state.delete_rename("0x401000", "label") is True

    def test_delete_variable(self, state):
        state.rename_variable("0x401000", "v1", "buf")
        assert state.delete_rename("0x401000", "variable") is True


class TestSnapshot:
    def test_snapshot_returns_copy(self, state):
        state.rename_function("0x401000", "main")
        snap = state.get_all_renames_snapshot()
        snap["functions"]["0x401000"] = "modified"
        assert state.renames["functions"]["0x401000"] == "main"


class TestClear:
    def test_clear_renames(self, state):
        state.rename_function("0x401000", "main")
        state.rename_variable("0x402000", "v1", "buf")
        state.add_label("0x403000", "test", "general")
        count = state.clear_renames()
        assert count == 3
        assert state.renames == {"functions": {}, "variables": {}, "labels": {}}
