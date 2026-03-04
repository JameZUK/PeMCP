"""Unit tests for rename substitution helpers."""
import pytest
from unittest.mock import patch, MagicMock
from arkana.state import AnalyzerState
from arkana.mcp._rename_helpers import (
    apply_function_renames_to_lines,
    apply_variable_renames_to_lines,
    get_display_name,
)


@pytest.fixture
def mock_state():
    """Create a mock state with renames configured."""
    state = AnalyzerState()
    state.rename_function("0x401000", "decrypt_config")
    state.rename_function("0x402000", "resolve_api")
    state.rename_variable("0x401000", "v1", "key_buffer")
    state.rename_variable("0x401000", "v2", "encrypted_data")
    return state


class TestApplyFunctionRenames:
    def test_sub_prefix(self, mock_state):
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=mock_state):
            lines = ["  call sub_401000", "  jmp sub_402000"]
            result = apply_function_renames_to_lines(lines)
            assert result[0] == "  call decrypt_config"
            assert result[1] == "  jmp resolve_api"

    def test_fun_prefix(self, mock_state):
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=mock_state):
            lines = ["FUN_401000()"]
            result = apply_function_renames_to_lines(lines)
            assert result[0] == "decrypt_config()"

    def test_no_match_unchanged(self, mock_state):
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=mock_state):
            lines = ["  mov eax, 0x12345"]
            result = apply_function_renames_to_lines(lines)
            assert result[0] == "  mov eax, 0x12345"

    def test_no_renames_passthrough(self):
        empty_state = AnalyzerState()
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=empty_state):
            lines = ["sub_401000()"]
            result = apply_function_renames_to_lines(lines)
            assert result[0] == "sub_401000()"

    def test_multiple_on_same_line(self, mock_state):
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=mock_state):
            lines = ["sub_401000(sub_402000())"]
            result = apply_function_renames_to_lines(lines)
            assert result[0] == "decrypt_config(resolve_api())"


class TestApplyVariableRenames:
    def test_basic_rename(self, mock_state):
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=mock_state):
            lines = ["  v1 = malloc(v2);"]
            result = apply_variable_renames_to_lines(lines, "0x401000")
            assert result[0] == "  key_buffer = malloc(encrypted_data);"

    def test_no_renames_for_address(self, mock_state):
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=mock_state):
            lines = ["  v1 = 0;"]
            result = apply_variable_renames_to_lines(lines, "0x999999")
            assert result[0] == "  v1 = 0;"

    def test_word_boundary(self, mock_state):
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=mock_state):
            lines = ["  v1_extra = v1;"]
            result = apply_variable_renames_to_lines(lines, "0x401000")
            # v1_extra should NOT be renamed, but v1 at end should be
            assert "key_buffer_extra" not in result[0]
            assert "key_buffer;" in result[0]


class TestGetDisplayName:
    def test_with_rename(self, mock_state):
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=mock_state):
            assert get_display_name("0x401000", "sub_401000") == "decrypt_config"

    def test_without_rename(self, mock_state):
        with patch("arkana.mcp._rename_helpers.get_current_state", return_value=mock_state):
            assert get_display_name("0x999", "sub_999") == "sub_999"
