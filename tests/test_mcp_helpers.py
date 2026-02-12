"""Unit tests for MCP server helpers and validation functions."""
import pytest

from pemcp.mcp._angr_helpers import _parse_addr, _raise_on_error_dict
from pemcp.mcp._format_helpers import _check_lib
from pemcp.mcp.server import _check_pe_loaded, _check_data_key_available
from pemcp.state import AnalyzerState, set_current_state


@pytest.fixture(autouse=True)
def clean_state():
    """Ensure a clean state for each test."""
    s = AnalyzerState()
    set_current_state(s)
    yield s
    set_current_state(None)


# ---------------------------------------------------------------------------
# _parse_addr
# ---------------------------------------------------------------------------

class TestParseAddr:
    def test_hex_string(self):
        assert _parse_addr("0x401000") == 0x401000

    def test_decimal_string(self):
        assert _parse_addr("100") == 100

    def test_hex_without_prefix(self):
        # "401000" without 0x is treated as decimal by int(x, 0)
        assert _parse_addr("0x401000") == 4198400

    def test_invalid_string(self):
        with pytest.raises(ValueError, match="Invalid"):
            _parse_addr("not_an_address")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            _parse_addr("")

    def test_custom_name(self):
        with pytest.raises(ValueError, match="target"):
            _parse_addr("xyz", name="target")

    def test_negative_hex(self):
        assert _parse_addr("-0x1") == -1

    def test_zero(self):
        assert _parse_addr("0") == 0
        assert _parse_addr("0x0") == 0


# ---------------------------------------------------------------------------
# _raise_on_error_dict
# ---------------------------------------------------------------------------

class TestRaiseOnErrorDict:
    def test_non_error_dict_passthrough(self):
        data = {"key": "value", "other": 123}
        assert _raise_on_error_dict(data) == data

    def test_error_dict_raises(self):
        with pytest.raises(RuntimeError, match="something went wrong"):
            _raise_on_error_dict({"error": "something went wrong"})

    def test_error_dict_with_hint(self):
        with pytest.raises(RuntimeError, match="bad thing.*try again"):
            _raise_on_error_dict({"error": "bad thing", "hint": "try again"})

    def test_non_dict_passthrough(self):
        assert _raise_on_error_dict("hello") == "hello"
        assert _raise_on_error_dict(42) == 42
        assert _raise_on_error_dict(None) is None

    def test_dict_with_error_key_but_many_keys(self):
        # More than 3 keys -> not treated as error dict
        data = {"error": "msg", "a": 1, "b": 2, "c": 3}
        assert _raise_on_error_dict(data) == data

    def test_list_passthrough(self):
        data = [1, 2, 3]
        assert _raise_on_error_dict(data) == data


# ---------------------------------------------------------------------------
# _check_lib
# ---------------------------------------------------------------------------

class TestCheckLib:
    def test_available_lib_no_error(self):
        # Should not raise
        _check_lib("lief", True, "test_tool")

    def test_unavailable_lib_raises(self):
        with pytest.raises(RuntimeError, match="lief"):
            _check_lib("lief", False, "test_tool")

    def test_custom_pip_name(self):
        with pytest.raises(RuntimeError, match="pip install my-package"):
            _check_lib("mylib", False, "test_tool", pip_name="my-package")


# ---------------------------------------------------------------------------
# _check_pe_loaded
# ---------------------------------------------------------------------------

class TestCheckPeLoaded:
    def test_no_file_loaded_raises(self, clean_state):
        with pytest.raises(RuntimeError, match="No file is currently loaded"):
            _check_pe_loaded("test_tool")

    def test_pe_data_none_raises(self, clean_state):
        clean_state.filepath = "/test.exe"
        clean_state.pe_data = None
        with pytest.raises(RuntimeError, match="No file is currently loaded"):
            _check_pe_loaded("test_tool")

    def test_filepath_none_raises(self, clean_state):
        clean_state.filepath = None
        clean_state.pe_data = {"some": "data"}
        with pytest.raises(RuntimeError, match="No file is currently loaded"):
            _check_pe_loaded("test_tool")

    def test_loaded_no_error(self, clean_state):
        clean_state.filepath = "/test.exe"
        clean_state.pe_data = {"some": "data"}
        # Should not raise
        _check_pe_loaded("test_tool")


# ---------------------------------------------------------------------------
# _check_data_key_available
# ---------------------------------------------------------------------------

class TestCheckDataKeyAvailable:
    def test_key_present_no_error(self, clean_state):
        clean_state.filepath = "/test.exe"
        clean_state.pe_data = {"file_hashes": {"md5": "abc"}}
        _check_data_key_available("file_hashes", "test_tool")

    def test_key_missing_raises(self, clean_state):
        clean_state.filepath = "/test.exe"
        clean_state.pe_data = {"other_key": "value"}
        with pytest.raises(RuntimeError, match="not available"):
            _check_data_key_available("file_hashes", "test_tool")

    def test_skipped_analysis_hint(self, clean_state):
        clean_state.filepath = "/test.exe"
        clean_state.pe_data = {"other": "data"}
        with pytest.raises(RuntimeError, match="skip-floss"):
            _check_data_key_available("floss_analysis", "test_tool")

    def test_no_file_loaded_raises(self, clean_state):
        with pytest.raises(RuntimeError, match="No file"):
            _check_data_key_available("file_hashes", "test_tool")
