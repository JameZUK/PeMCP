"""Tests for Speakeasy 0-API-call diagnostic messages.

Source-structure tests verifying that diagnostic strings exist in the
shellcode and PE emulation functions.
"""

import inspect
import textwrap

import pytest


class TestShellcodeDiagnosticExists:
    """Verify emulate_shellcode_with_speakeasy has 0-API diagnostic."""

    def setup_method(self):
        from arkana.mcp.tools_new_libs import emulate_shellcode_with_speakeasy
        self.source = inspect.getsource(emulate_shellcode_with_speakeasy)

    def test_checks_total_api_calls_zero(self):
        assert 'total_api_calls' in self.source
        assert '"diagnostic"' in self.source or "'diagnostic'" in self.source

    def test_mentions_peb_walking(self):
        assert 'PEB walking' in self.source

    def test_mentions_direct_syscalls(self):
        assert 'direct syscall' in self.source

    def test_suggests_alternative_tools(self):
        assert 'disassemble_raw_bytes' in self.source
        assert 'scan_for_api_hashes' in self.source
        assert 'emulate_shellcode_with_qiling' in self.source

    def test_suggests_hex_pattern_search(self):
        assert 'search_hex_pattern' in self.source

    def test_guards_against_error_responses(self):
        """Diagnostic should not be added when result contains an error."""
        assert '"error" not in result' in self.source


class TestPEDiagnosticExists:
    """Verify emulate_pe_with_windows_apis has 0-API diagnostic for non-packed case."""

    def setup_method(self):
        from arkana.mcp.tools_new_libs import emulate_pe_with_windows_apis
        self.source = inspect.getsource(emulate_pe_with_windows_apis)

    def test_has_packed_warning(self):
        """Existing packed-binary warning should still be present."""
        assert 'appears packed' in self.source
        assert 'auto_unpack_pe' in self.source

    def test_has_non_packed_diagnostic(self):
        assert '"diagnostic"' in self.source or "'diagnostic'" in self.source

    def test_mentions_peb_walking(self):
        assert 'PEB walking' in self.source

    def test_suggests_alternative_tools(self):
        assert 'decompile_function_with_angr' in self.source
        assert 'scan_for_api_hashes' in self.source
        assert 'emulate_binary_with_qiling' in self.source

    def test_suggests_anti_debug_check(self):
        assert 'find_anti_debug_comprehensive' in self.source

    def test_guards_against_error_responses(self):
        assert '"error" not in result' in self.source
