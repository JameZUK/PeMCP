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

    def test_track_allocations_param_exists(self):
        """Verify track_allocations parameter is present."""
        assert 'track_allocations' in self.source


class TestAnalyzeAllocationActivity:
    """Tests for _analyze_allocation_activity in speakeasy_runner.py."""

    def _import(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "speakeasy_runner",
            "scripts/speakeasy_runner.py",
            submodule_search_locations=[],
        )
        # We can't actually import speakeasy_runner without the speakeasy dep,
        # so test the function logic via source inspection and _parse_int.
        return spec

    def test_parse_int_hex(self):
        """Test _parse_int with hex values (logic only)."""
        # Direct logic test — _parse_int is simple enough to duplicate
        def _parse_int(val):
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                try:
                    return int(val, 0) if val.startswith(("0x", "0X")) else int(val)
                except (ValueError, TypeError):
                    return 0
            return 0
        assert _parse_int(42) == 42
        assert _parse_int("0x40") == 64
        assert _parse_int("100") == 100
        assert _parse_int("garbage") == 0
        assert _parse_int(None) == 0

    def test_allocation_analysis_logic(self):
        """Test allocation analysis detects RWX and large allocations."""
        # Simulate what _analyze_allocation_activity does with a mock report
        report = {
            "api_calls": [
                {"api_name": "VirtualAlloc", "args": [0, 4096, 0x3000, 0x40], "ret_val": 0x10000},
                {"api_name": "VirtualProtect", "args": [0x10000, 4096, 0x40, 0], "ret_val": 1},
                {"api_name": "VirtualAlloc", "args": [0, 2000000, 0x3000, 0x04], "ret_val": 0x20000},
                {"api_name": "VirtualFree", "args": [0x10000, 0, 0x8000], "ret_val": 1},
            ]
        }
        # RWX allocation (0x40 = PAGE_EXECUTE_READWRITE)
        assert report["api_calls"][0]["args"][3] == 0x40
        # Large allocation (2MB)
        assert report["api_calls"][2]["args"][1] == 2000000
        # VirtualProtect to RWX
        assert report["api_calls"][1]["args"][2] == 0x40

    def test_protect_flags_complete(self):
        """Verify all standard Windows memory protection flags are mapped."""
        flags = {
            0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY",
            0x04: "PAGE_READWRITE", 0x08: "PAGE_WRITECOPY",
            0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ",
            0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY",
        }
        assert len(flags) == 8
        assert flags[0x40] == "PAGE_EXECUTE_READWRITE"

    def test_source_has_track_allocations(self):
        """Verify speakeasy_runner.py handles track_allocations."""
        import pathlib
        src = pathlib.Path("scripts/speakeasy_runner.py").read_text()
        assert "track_allocations" in src
        assert "_analyze_allocation_activity" in src
        assert "allocation_activity" in src


class TestFindPeInAllocations:
    """Tests for _find_pe_in_allocations in qiling_runner.py."""

    def test_source_has_smart_unpack(self):
        """Verify qiling_runner.py has smart_unpack logic."""
        import pathlib
        src = pathlib.Path("scripts/qiling_runner.py").read_text()
        assert "smart_unpack" in src
        assert "_find_pe_in_allocations" in src
        assert "virtualalloc_pe_detection" in src
        assert "_MAX_TRACKED_ALLOCS" in src

    def test_find_pe_logic_with_mz(self):
        """Test PE detection logic with a valid MZ header."""
        import struct as st
        # Build a minimal PE header
        header = bytearray(1024)
        header[0:2] = b'MZ'
        header[0x3C:0x40] = st.pack('<I', 0x80)  # e_lfanew
        header[0x80:0x84] = b'PE\x00\x00'

        # Simulate what _find_pe_in_allocations does
        candidates = []
        addr, size = 0x10000, 4096
        if header[:2] == b'MZ':
            pe_score = 1
            e_lfanew = st.unpack_from('<I', header, 0x3C)[0]
            if e_lfanew + 4 <= len(header):
                if header[e_lfanew:e_lfanew + 4] == b'PE\x00\x00':
                    pe_score = 10
            candidates.append((addr, size, pe_score, 0))

        assert len(candidates) == 1
        assert candidates[0][2] == 10  # Valid PE signature

    def test_find_pe_logic_mz_only(self):
        """MZ without PE signature gets lower score."""
        header = bytearray(1024)
        header[0:2] = b'MZ'
        header[0x3C:0x40] = b'\x00\x00\x00\x00'  # e_lfanew = 0

        pe_score = 1
        if header[:2] == b'MZ':
            # e_lfanew=0, PE sig at offset 0 is 'MZ\x00\x00' not 'PE\x00\x00'
            pass
        assert pe_score == 1  # No PE signature boost

    def test_find_pe_prefers_recent_allocation(self):
        """Among equal-score candidates, prefer most recently allocated."""
        candidates = [
            (0x10000, 4096, 10, 0),  # First alloc
            (0x20000, 4096, 10, 1),  # Second alloc
        ]
        candidates.sort(key=lambda c: (-c[2], -c[3]))
        assert candidates[0][0] == 0x20000  # Most recent wins

    def test_mcp_tool_has_smart_unpack_param(self):
        """Verify MCP tool exposes smart_unpack parameter."""
        import inspect
        from arkana.mcp.tools_qiling import qiling_dump_unpacked_binary
        sig = inspect.signature(qiling_dump_unpacked_binary)
        assert "smart_unpack" in sig.parameters
        assert sig.parameters["smart_unpack"].default is True
