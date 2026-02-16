"""Unit tests for triage helper functions — compiler detection and mode normalization."""
import pytest
from unittest.mock import patch, MagicMock

from pemcp.state import AnalyzerState


# ---------------------------------------------------------------------------
# Compiler / Language Detection
# ---------------------------------------------------------------------------

class TestTriageCompilerLanguage:
    """Tests for _triage_compiler_language detection logic."""

    def _call_detection(self, pe_data, all_string_values=None):
        """Helper to invoke _triage_compiler_language with mocked state."""
        if all_string_values is None:
            all_string_values = set()

        mock_state = AnalyzerState()
        mock_state.pe_data = pe_data

        with patch("pemcp.mcp.tools_triage.state", mock_state):
            from pemcp.mcp.tools_triage import _triage_compiler_language
            return _triage_compiler_language(all_string_values)

    def test_go_detected_from_section_names(self):
        pe_data = {
            "sections": [
                {"name": ".text", "name_str": ".text"},
                {"name": ".gopclntab", "name_str": ".gopclntab"},
            ]
        }
        result, risk = self._call_detection(pe_data)
        assert "Go" in result["detected_languages"]
        assert risk == 0

    def test_go_detected_from_strings(self):
        pe_data = {"sections": []}
        strings = {"runtime.main called from Go program", "other string"}
        result, _ = self._call_detection(pe_data, strings)
        assert "Go" in result["detected_languages"]

    def test_rust_detected_from_section_names(self):
        pe_data = {
            "sections": [
                {"name": ".rustc", "name_str": ".rustc"},
            ]
        }
        result, _ = self._call_detection(pe_data)
        assert "Rust" in result["detected_languages"]

    def test_rust_detected_from_strings(self):
        pe_data = {"sections": []}
        strings = {"core::panicking::panic handler", "other"}
        result, _ = self._call_detection(pe_data, strings)
        assert "Rust" in result["detected_languages"]

    def test_dotnet_detected_from_com_descriptor(self):
        pe_data = {"sections": [], "com_descriptor": {"flags_list": ["ILONLY"]}}
        result, _ = self._call_detection(pe_data)
        assert ".NET" in result["detected_languages"]

    def test_msvc_detected_from_rich_header(self):
        pe_data = {
            "sections": [],
            "rich_header": {
                "decoded_values": [
                    {"product_id_dec": 259, "build_number": 30148, "count": 1, "raw_comp_id": "0x1030000"},
                ]
            }
        }
        result, _ = self._call_detection(pe_data)
        assert "MSVC" in result["detected_languages"]

    def test_delphi_detected_from_rich_header(self):
        pe_data = {
            "sections": [],
            "rich_header": {
                "decoded_values": [
                    {"product_id_dec": 2, "build_number": 100, "count": 1, "raw_comp_id": "0x20064"},
                ]
            }
        }
        result, _ = self._call_detection(pe_data)
        assert "Delphi" in result["detected_languages"]

    def test_unknown_when_no_indicators(self):
        pe_data = {"sections": []}
        result, _ = self._call_detection(pe_data)
        assert result["detected_languages"] == ["Unknown / native C/C++"]

    def test_empty_sections_no_crash(self):
        pe_data = {"sections": None}
        result, _ = self._call_detection(pe_data, set())
        assert isinstance(result["detected_languages"], list)

    def test_multiple_languages_detected(self):
        pe_data = {
            "sections": [{"name": ".gopclntab", "name_str": ".gopclntab"}],
            "com_descriptor": {"flags_list": []},
        }
        strings = {"core::panicking is a Rust panic"}
        result, _ = self._call_detection(pe_data, strings)
        langs = result["detected_languages"]
        assert "Go" in langs
        assert "Rust" in langs
        assert ".NET" in langs


# ---------------------------------------------------------------------------
# Mode Normalization
# ---------------------------------------------------------------------------

class TestTriageModeNormalization:
    """Verify that the PE parser mode values match what triage expects."""

    def test_pe_parser_mode_is_pe(self):
        """The PE parser must set mode='pe' for normal PE files."""
        # This test verifies the fix for the critical pe_executable vs pe bug
        from pemcp.parsers.pe import _parse_pe_to_dict
        # We can't call the full parser without pefile, but we can check the
        # source code for the correct mode string
        import inspect
        source = inspect.getsource(_parse_pe_to_dict)
        assert '"pe_executable"' not in source, \
            "Parser still uses 'pe_executable' instead of 'pe'"
        assert '"pe"' in source, "Parser must set mode to 'pe'"

    def test_shellcode_mode_is_shellcode(self):
        """The PE parser must set mode='shellcode' for raw/shellcode files."""
        import inspect
        from pemcp.parsers.pe import _parse_pe_to_dict
        source = inspect.getsource(_parse_pe_to_dict)
        assert '"shellcode_raw"' not in source, \
            "Parser still uses 'shellcode_raw' instead of 'shellcode'"
        assert '"shellcode"' in source, "Parser must set mode to 'shellcode'"


# ---------------------------------------------------------------------------
# Rich Header Key Consistency
# ---------------------------------------------------------------------------

class TestRichHeaderKeys:
    """Verify triage reads the correct keys from Rich header data."""

    def test_triage_reads_decoded_values_key(self):
        """_triage_rich_header must use 'decoded_values' (not 'decoded_entries')."""
        import inspect
        from pemcp.mcp.tools_triage import _triage_rich_header
        source = inspect.getsource(_triage_rich_header)
        assert "decoded_values" in source, \
            "Triage must use 'decoded_values' key to match parser output"

    def test_triage_reads_product_id_dec(self):
        """_triage_rich_header must use 'product_id_dec' or 'raw_comp_id'."""
        import inspect
        from pemcp.mcp.tools_triage import _triage_rich_header
        source = inspect.getsource(_triage_rich_header)
        assert "product_id_dec" in source or "raw_comp_id" in source, \
            "Triage must use actual parser field names (product_id_dec, raw_comp_id)"
