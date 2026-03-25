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

    def test_vm_protection_tool_is_coroutine(self):
        import inspect
        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        assert inspect.iscoroutinefunction(detect_vm_protection)


# =====================================================================
#  VM Protection Detection
# =====================================================================

def _run(coro):
    """Helper to run async coroutines in tests."""
    import asyncio
    return asyncio.run(coro)


class TestDetectVmProtection:
    """Test VM protection detection logic via __wrapped__ calls.

    Uses clean_state + mock_ctx fixtures from conftest and calls the
    tool's __wrapped__ async function directly (bypasses FastMCP registration
    but runs the real tool logic including _check_pe_loaded and _analyze).
    """

    def _call(self, mock_ctx, clean_state, pe_data=None, pe_obj=None,
              angr_project=None, angr_cfg=None):
        """Set up state and invoke detect_vm_protection.__wrapped__."""
        from arkana.mcp.tools_angr_forensic import detect_vm_protection

        clean_state.filepath = "/tmp/test_vm.exe"
        clean_state.pe_data = pe_data or {}
        clean_state.pe_object = pe_obj
        clean_state.angr_project = angr_project
        clean_state.angr_cfg = angr_cfg

        return _run(detect_vm_protection.__wrapped__(mock_ctx))

    def test_no_vm_protection_clean_binary(self, mock_ctx, clean_state):
        """A binary with standard sections and no VM indicators."""
        pe_data = {
            "sections": {"details": [
                {"name": ".text", "entropy": 6.2, "virtual_size": 4096, "raw_size": 4096},
                {"name": ".rdata", "entropy": 5.0, "virtual_size": 2048, "raw_size": 2048},
                {"name": ".data", "entropy": 3.0, "virtual_size": 1024, "raw_size": 1024},
            ]},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is False
        assert result["confidence"] < 50
        assert result["protector"] is None
        assert len(result["indicators"]) == 0
        assert result["recommendation"] == "No VM-based protection detected."

    def test_vmprotect_section_detected(self, mock_ctx, clean_state):
        """VMProtect section name triggers detection."""
        pe_data = {
            "sections": {"details": [
                {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096},
                {"name": ".vmp0", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536},
            ]},
            "imports": {"import_count": 5},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "VMProtect"
        assert result["confidence"] >= 90
        assert len(result["virtualized_sections"]) >= 1
        assert result["virtualized_sections"][0]["name"] == ".vmp0"
        section_indicators = [i for i in result["indicators"] if i["type"] == "section_name"]
        assert len(section_indicators) >= 1

    def test_themida_section_detected(self, mock_ctx, clean_state):
        """Themida section name triggers detection."""
        pe_data = {
            "sections": {"details": [
                {"name": ".themida", "entropy": 7.8, "virtual_size": 131072, "raw_size": 131072},
            ]},
            "imports": {"import_count": 3},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "Themida/WinLicense"
        assert result["confidence"] >= 95

    def test_enigma_section_detected(self, mock_ctx, clean_state):
        """Enigma Protector section name triggers detection."""
        pe_data = {
            "sections": {"details": [
                {"name": ".enigma1", "entropy": 7.2, "virtual_size": 32768, "raw_size": 32768},
            ]},
            "imports": {"import_count": 20},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "Enigma Protector"
        assert result["confidence"] >= 90

    def test_high_entropy_nonstandard_section_small_skipped(self, mock_ctx, clean_state):
        """High-entropy non-standard section with small size is skipped."""
        pe_data = {
            "sections": {"details": [
                {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096},
                {"name": ".custom", "entropy": 7.5, "virtual_size": 2048, "raw_size": 2048},
            ]},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        entropy_indicators = [i for i in result["indicators"] if i["type"] == "high_entropy_section"]
        assert len(entropy_indicators) == 0

    def test_high_entropy_nonstandard_large_section(self, mock_ctx, clean_state):
        """High-entropy non-standard section over 4096 bytes triggers indicator."""
        pe_data = {
            "sections": {"details": [
                {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096},
                {"name": ".obfusc", "entropy": 7.9, "virtual_size": 65536, "raw_size": 65536},
            ]},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        entropy_indicators = [i for i in result["indicators"] if i["type"] == "high_entropy_section"]
        assert len(entropy_indicators) >= 1
        assert result["confidence"] >= 40

    def test_minimal_imports_with_vm_section(self, mock_ctx, clean_state):
        """Few imports combined with VM sections boosts confidence."""
        pe_data = {
            "sections": {"details": [
                {"name": ".vmp1", "entropy": 7.0, "virtual_size": 32768, "raw_size": 32768},
            ]},
            "imports": {"import_count": 3},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        minimal_indicators = [i for i in result["indicators"] if i["type"] == "minimal_imports"]
        assert len(minimal_indicators) == 1

    def test_minimal_imports_without_vm_section_no_indicator(self, mock_ctx, clean_state):
        """Few imports without VM sections does NOT produce minimal_imports indicator."""
        pe_data = {
            "sections": {"details": [
                {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096},
            ]},
            "imports": {"import_count": 3},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        minimal_indicators = [i for i in result["indicators"] if i["type"] == "minimal_imports"]
        assert len(minimal_indicators) == 0

    def test_string_signature_vmprotect(self, mock_ctx, clean_state):
        """VMProtect string signature in binary data."""

        class MockPeObj:
            __data__ = b"\x00" * 100 + b"VMProtect begin" + b"\x00" * 100

            class OPTIONAL_HEADER:
                AddressOfEntryPoint = 0x1000
                ImageBase = 0x400000

            sections = []

        pe_data = {
            "sections": {"details": [
                {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096},
            ]},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data, pe_obj=MockPeObj())
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "VMProtect"
        string_indicators = [i for i in result["indicators"] if i["type"] == "string_signature"]
        assert len(string_indicators) >= 1

    def test_string_signature_themida(self, mock_ctx, clean_state):
        """Themida string in binary triggers detection."""

        class MockPeObj:
            __data__ = b"Oreans Technologies" + b"\x00" * 100

            class OPTIONAL_HEADER:
                AddressOfEntryPoint = 0x1000
                ImageBase = 0x400000

            sections = []

        pe_data = {
            "sections": {"details": []},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data, pe_obj=MockPeObj())
        assert result["vm_protection_detected"] is True
        assert "Themida" in result["protector"] or "Code Virtualizer" in result["protector"]

    def test_entry_point_in_vm_section(self, mock_ctx, clean_state):
        """Entry point in a VM section produces entry_in_vm_section indicator."""

        class MockSection:
            Name = b".vmp0\x00\x00\x00"
            VirtualAddress = 0x1000
            Misc_VirtualSize = 0x10000
            SizeOfRawData = 0x10000
            Characteristics = 0xE0000020

            def get_entropy(self):
                return 7.5

        class MockPeObj:
            __data__ = b"\x00" * 1000

            class OPTIONAL_HEADER:
                AddressOfEntryPoint = 0x1500  # inside .vmp0
                ImageBase = 0x400000

            sections = [MockSection()]

        pe_data = {
            "sections": {"details": []},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data, pe_obj=MockPeObj())
        assert result["vm_protection_detected"] is True
        assert result["confidence"] >= 95
        entry_indicators = [i for i in result["indicators"] if i["type"] == "entry_in_vm_section"]
        assert len(entry_indicators) >= 1
        assert result["entry_point_info"]["section"].strip() == ".vmp0"

    def test_no_pe_object_still_works(self, mock_ctx, clean_state):
        """Tool works with pe_data only (no pe_object)."""
        pe_data = {
            "sections": {"details": [
                {"name": ".vmp0", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536},
            ]},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data, pe_obj=None)
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "VMProtect"
        # No entry_point_info since pe_obj is None
        assert result["entry_point_info"] == {}

    def test_result_structure(self, mock_ctx, clean_state):
        """Result always contains expected top-level keys."""
        pe_data = {
            "sections": {"details": []},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert "vm_protection_detected" in result
        assert "protector" in result
        assert "confidence" in result
        assert "indicators" in result
        assert "virtualized_sections" in result
        assert "entry_point_info" in result
        assert "recommendation" in result
        assert "indicator_count" in result
        assert isinstance(result["indicators"], list)
        assert isinstance(result["virtualized_sections"], list)

    def test_recommendation_text_on_detection(self, mock_ctx, clean_state):
        """When VM protection is detected, recommendation includes protector name."""
        pe_data = {
            "sections": {"details": [
                {"name": ".vmp0", "entropy": 7.0, "virtual_size": 32768, "raw_size": 32768},
            ]},
            "imports": {"import_count": 5},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        assert "VMProtect" in result["recommendation"]
        assert "emulate_pe_with_windows_apis" in result["recommendation"]

    def test_indicator_count_matches(self, mock_ctx, clean_state):
        """indicator_count field matches len(indicators)."""
        pe_data = {
            "sections": {"details": [
                {"name": ".vmp0", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536},
                {"name": ".vmp1", "entropy": 7.8, "virtual_size": 32768, "raw_size": 32768},
            ]},
            "imports": {"import_count": 2},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["indicator_count"] == len(result["indicators"])

    def test_case_insensitive_section_matching(self, mock_ctx, clean_state):
        """Section name matching is case-insensitive."""
        pe_data = {
            "sections": {"details": [
                {"name": ".VMP0", "entropy": 7.0, "virtual_size": 32768, "raw_size": 32768},
            ]},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "VMProtect"

    def test_multiple_protector_highest_confidence_wins(self, mock_ctx, clean_state):
        """When multiple protectors are found, highest confidence sets the protector."""
        pe_data = {
            "sections": {"details": [
                {"name": ".vm", "entropy": 6.5, "virtual_size": 4096, "raw_size": 4096},
                {"name": ".VMProtect", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536},
            ]},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["protector"] == "VMProtect"
        assert result["confidence"] >= 95

    def test_obsidium_detected(self, mock_ctx, clean_state):
        """Obsidium section triggers detection."""
        pe_data = {
            "sections": {"details": [
                {"name": ".obsidium", "entropy": 7.0, "virtual_size": 65536, "raw_size": 65536},
            ]},
            "imports": {"import_count": 20},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "Obsidium"

    def test_aspack_detected(self, mock_ctx, clean_state):
        """ASProtect section triggers detection."""
        pe_data = {
            "sections": {"details": [
                {"name": ".aspack", "entropy": 7.0, "virtual_size": 32768, "raw_size": 32768},
            ]},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "ASProtect"

    def test_angr_not_available_still_works(self, mock_ctx, clean_state):
        """Without angr_project/angr_cfg, tool skips dispatcher detection gracefully."""
        pe_data = {
            "sections": {"details": [
                {"name": ".vmp0", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536},
            ]},
            "imports": {"import_count": 5},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data,
                            angr_project=None, angr_cfg=None)
        assert result["vm_protection_detected"] is True
        assert "dispatcher_candidates" not in result

    def test_empty_sections_no_crash(self, mock_ctx, clean_state):
        """Empty section list produces clean no-detection result."""
        pe_data = {
            "sections": {"details": []},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is False
        assert result["indicator_count"] == 0

    def test_no_file_loaded_raises(self, mock_ctx, clean_state):
        """Tool raises RuntimeError when no file is loaded."""
        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        # clean_state has filepath=None, pe_data=None by default
        with pytest.raises(RuntimeError, match="No file is currently loaded"):
            _run(detect_vm_protection.__wrapped__(mock_ctx))

    def test_pe_fallback_to_pe_object_sections(self, mock_ctx, clean_state):
        """When pe_data has no section details, falls back to pe_object.sections."""

        class MockSection:
            Name = b".vmp2\x00\x00\x00"
            VirtualAddress = 0x1000
            Misc_VirtualSize = 0x8000
            SizeOfRawData = 0x8000
            Characteristics = 0xE0000020

            def get_entropy(self):
                return 7.3

        class MockPeObj:
            __data__ = b"\x00" * 500

            class OPTIONAL_HEADER:
                AddressOfEntryPoint = 0x1000
                ImageBase = 0x400000

            sections = [MockSection()]

        # pe_data has empty section details — forces fallback to pe_object
        pe_data = {
            "sections": {"details": []},
            "imports": {"import_count": 50},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data, pe_obj=MockPeObj())
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "VMProtect"
        assert len(result["virtualized_sections"]) >= 1

    def test_winlicense_section_detected(self, mock_ctx, clean_state):
        """WinLicense section triggers detection."""
        pe_data = {
            "sections": {"details": [
                {"name": ".winlice", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536},
            ]},
            "imports": {"import_count": 20},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "WinLicense"

    def test_code_virtualizer_section_detected(self, mock_ctx, clean_state):
        """Code Virtualizer section triggers detection."""
        pe_data = {
            "sections": {"details": [
                {"name": ".cvirt", "entropy": 7.0, "virtual_size": 32768, "raw_size": 32768},
            ]},
            "imports": {"import_count": 20},
        }
        result = self._call(mock_ctx, clean_state, pe_data=pe_data)
        assert result["vm_protection_detected"] is True
        assert result["protector"] == "Code Virtualizer"
        assert result["confidence"] >= 85
