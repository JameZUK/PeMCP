"""Tests for detect_vm_protection enhancements in tools_angr_forensic.py.

Covers:
- Protection option detection for Themida, VMProtect, Enigma
- Import obfuscation score calculation
- Recommendation generation for different protectors
- Section signature matching logic
- State setup/teardown following Arkana test patterns
"""
import asyncio
import os
import unittest
from unittest.mock import MagicMock

import pytest

pytest.importorskip("pefile", reason="pefile not installed")

from arkana.state import AnalyzerState, _current_state_var
import arkana.state as state_mod


def _run(coro):
    """Helper to run async coroutines in tests."""
    return asyncio.run(coro)


class TestVMProtectionDetection(unittest.TestCase):
    """Test detect_vm_protection with mock state."""

    def setUp(self):
        self._saved_default = state_mod._default_state
        self._saved_ctx_token = _current_state_var.set(None)

        self.state = AnalyzerState()
        self.state.filepath = "/tmp/test_sample.exe"
        self.state.pe_data = {
            "mode": "pe",
            "sections": [],
            "imports": [],
            "file_size": 100000,
        }
        # Mock pe_object with minimal structure
        self.state.pe_object = MagicMock()
        self.state.pe_object.sections = []
        self.state.pe_object.__data__ = b"\x00" * 1024
        self.state.pe_object.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        self.state.pe_object.OPTIONAL_HEADER.ImageBase = 0x400000
        self.state.angr_project = None
        self.state.angr_cfg = None
        state_mod._default_state = self.state

    def tearDown(self):
        state_mod._default_state = self._saved_default
        _current_state_var.reset(self._saved_ctx_token)

    def test_no_protection_detected(self):
        """Standard binary with normal sections should report no VM protection."""
        self.state.pe_data["sections"] = [
            {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096, "characteristics": 0x60000020},
            {"name": ".rdata", "entropy": 5.0, "virtual_size": 2048, "raw_size": 2048, "characteristics": 0x40000040},
            {"name": ".data", "entropy": 3.0, "virtual_size": 1024, "raw_size": 1024, "characteristics": 0xC0000040},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": f"api{i}"} for i in range(30)]},
            {"dll": "user32.dll", "symbols": [{"name": f"api{i}"} for i in range(20)]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertFalse(result["vm_protection_detected"])
        self.assertEqual(result["recommendation"], "No VM-based protection detected.")

    def test_vmprotect_section_detected(self):
        """Binary with .vmp0 section should be detected as VMProtect."""
        self.state.pe_data["sections"] = [
            {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096, "characteristics": 0x60000020},
            {"name": ".vmp0", "entropy": 7.8, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": "LoadLibraryA"}, {"name": "GetProcAddress"}]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertTrue(result["vm_protection_detected"])
        self.assertEqual(result["protector"], "VMProtect")
        self.assertGreaterEqual(result["confidence"], 90)

    def test_vmprotect_virtualization_option(self):
        """VMProtect with high-entropy .vmp sections should report virtualization option."""
        self.state.pe_data["sections"] = [
            {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096, "characteristics": 0x60000020},
            {"name": ".vmp0", "entropy": 7.8, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": "LoadLibraryA"}, {"name": "GetProcAddress"}]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        option_names = {opt["option"] for opt in result.get("protection_options", [])}
        self.assertIn("virtualization", option_names)

    def test_vmprotect_import_protection_option(self):
        """VMProtect with < 5 imports should report import_protection option."""
        self.state.pe_data["sections"] = [
            {"name": ".vmp0", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": "LoadLibraryA"}]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        option_names = {opt["option"] for opt in result.get("protection_options", [])}
        self.assertIn("import_protection", option_names)

    def test_vmprotect_recommendation_with_virtualization(self):
        """VMProtect with virtualization should recommend behavioral analysis."""
        self.state.pe_data["sections"] = [
            {"name": ".vmp0", "entropy": 7.9, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": "LoadLibraryA"}, {"name": "GetProcAddress"}]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertIn("behavioral analysis", result["recommendation"].lower())
        self.assertIn("VMProtect", result["recommendation"])

    def test_themida_section_detected(self):
        """Binary with .themida section should be detected as Themida."""
        self.state.pe_data["sections"] = [
            {"name": ".themida", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": "LoadLibraryA"}]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertTrue(result["vm_protection_detected"])
        self.assertIn("Themida", result["protector"])

    def test_themida_anti_dump_option(self):
        """Themida should always report anti_dump as default-on."""
        self.state.pe_data["sections"] = [
            {"name": ".themida", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = []

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        option_names = {opt["option"] for opt in result.get("protection_options", [])}
        self.assertIn("anti_dump", option_names)

    def test_themida_api_wrapping_option(self):
        """Themida with very few kernel32/ntdll imports should report api_wrapping."""
        self.state.pe_data["sections"] = [
            {"name": ".themida", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": "ExitProcess"}]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        option_names = {opt["option"] for opt in result.get("protection_options", [])}
        self.assertIn("api_wrapping", option_names)

    def test_themida_recommendation_with_api_wrapping(self):
        """Themida with api_wrapping should recommend anti-VM emulation."""
        self.state.pe_data["sections"] = [
            {"name": ".themida", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": "ExitProcess"}]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertIn("anti-vm bypasses", result["recommendation"].lower())

    def test_enigma_section_detected(self):
        """Binary with .enigma1 section should be detected as Enigma Protector."""
        self.state.pe_data["sections"] = [
            {"name": ".enigma1", "entropy": 7.2, "virtual_size": 32768, "raw_size": 32768, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": f"api{i}"} for i in range(20)]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertTrue(result["vm_protection_detected"])
        self.assertEqual(result["protector"], "Enigma Protector")

    def test_enigma_anti_vm_option(self):
        """Enigma with sections present should report anti_vm option."""
        self.state.pe_data["sections"] = [
            {"name": ".enigma1", "entropy": 7.2, "virtual_size": 32768, "raw_size": 32768, "characteristics": 0xE0000060},
            {"name": ".enigma2", "entropy": 7.5, "virtual_size": 16384, "raw_size": 16384, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": f"api{i}"} for i in range(20)]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        option_names = {opt["option"] for opt in result.get("protection_options", [])}
        self.assertIn("anti_vm", option_names)

    def test_enigma_virtualization_option_high_entropy(self):
        """Enigma with high-entropy sections should report virtualization."""
        self.state.pe_data["sections"] = [
            {"name": ".enigma1", "entropy": 7.5, "virtual_size": 32768, "raw_size": 32768, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": f"api{i}"} for i in range(20)]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        option_names = {opt["option"] for opt in result.get("protection_options", [])}
        self.assertIn("virtualization", option_names)

    def test_import_obfuscation_score_no_imports(self):
        """Zero imports should give maximum obfuscation score (1.0)."""
        self.state.pe_data["sections"] = [
            {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096, "characteristics": 0x60000020},
        ]
        self.state.pe_data["imports"] = []

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertEqual(result["import_obfuscation_score"], 1.0)

    def test_import_obfuscation_score_many_imports(self):
        """50+ imports should give zero or very low obfuscation score."""
        self.state.pe_data["sections"] = [
            {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096, "characteristics": 0x60000020},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": f"api{i}"} for i in range(50)]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertEqual(result["import_obfuscation_score"], 0.0)

    def test_import_obfuscation_score_partial(self):
        """10 imports out of 50 expected baseline should yield score of 0.8."""
        self.state.pe_data["sections"] = [
            {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096, "characteristics": 0x60000020},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": f"api{i}"} for i in range(10)]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertEqual(result["import_obfuscation_score"], 0.8)

    def test_minimal_imports_indicator(self):
        """Very few imports with VM sections should generate minimal_imports indicator."""
        self.state.pe_data["sections"] = [
            {"name": ".vmp0", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": "LoadLibraryA"}, {"name": "GetProcAddress"}]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        indicator_types = {ind["type"] for ind in result["indicators"]}
        self.assertIn("minimal_imports", indicator_types)

    def test_high_entropy_nonstandard_section(self):
        """Non-standard section with entropy > 7.0 should generate indicator."""
        self.state.pe_data["sections"] = [
            {"name": ".text", "entropy": 6.0, "virtual_size": 4096, "raw_size": 4096, "characteristics": 0x60000020},
            {"name": ".weird", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": f"api{i}"} for i in range(50)]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        indicator_types = {ind["type"] for ind in result["indicators"]}
        self.assertIn("high_entropy_section", indicator_types)

    def test_indicator_count_field(self):
        """Result should include indicator_count matching indicators list."""
        self.state.pe_data["sections"] = [
            {"name": ".vmp0", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": "LoadLibraryA"}]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertEqual(result["indicator_count"], len(result["indicators"]))

    def test_section_sigs_source_contains_known_patterns(self):
        """Verify the source code contains expected VM section signature entries."""
        forensic_path = os.path.join(
            os.path.dirname(__file__), "..", "arkana", "mcp", "tools_angr_forensic.py"
        )
        with open(forensic_path) as f:
            source = f.read()
        # Check key section signatures exist in source
        self.assertIn('".vmp0"', source)
        self.assertIn('".vmp1"', source)
        self.assertIn('".themida"', source)
        self.assertIn('".enigma1"', source)
        self.assertIn('".enigma2"', source)
        self.assertIn('".obsidium"', source)
        self.assertIn('".cvirt"', source)
        self.assertIn('"VMProtect"', source)
        self.assertIn('"Themida/WinLicense"', source)
        self.assertIn('"Code Virtualizer"', source)
        self.assertIn('"Enigma Protector"', source)

    def test_default_recommendation_for_generic_protector(self):
        """A protector that is not Themida/VMProtect/Enigma gets the generic recommendation."""
        self.state.pe_data["sections"] = [
            {"name": ".obsidium", "entropy": 7.2, "virtual_size": 32768, "raw_size": 32768, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": f"api{i}"} for i in range(20)]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        self.assertTrue(result["vm_protection_detected"])
        self.assertIn("detect_packing()", result["recommendation"])
        self.assertIn("emulate_pe_with_windows_apis()", result["recommendation"])

    def test_vmprotect_mutation_option(self):
        """VMProtect with high .text entropy and no .vmp sections should detect mutation."""
        # VMProtect detected via string signature
        self.state.pe_object.__data__ = b"VMProtect begin" + b"\x00" * 1024
        self.state.pe_data["sections"] = [
            {"name": ".text", "entropy": 7.0, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0x60000020},
        ]
        self.state.pe_data["imports"] = [
            {"dll": "kernel32.dll", "symbols": [{"name": f"api{i}"} for i in range(20)]},
        ]

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        option_names = {opt["option"] for opt in result.get("protection_options", [])}
        self.assertIn("mutation", option_names)

    def test_themida_string_encryption_option(self):
        """Themida with very low string count should detect string_encryption."""
        self.state.pe_data["sections"] = [
            {"name": ".themida", "entropy": 7.5, "virtual_size": 65536, "raw_size": 65536, "characteristics": 0xE0000060},
        ]
        self.state.pe_data["imports"] = []
        self.state.pe_data["file_size"] = 500000  # 500KB binary
        self.state.pe_data["strings"] = ["a", "b"]  # Extremely few strings

        from arkana.mcp.tools_angr_forensic import detect_vm_protection
        result = _run(detect_vm_protection(MagicMock()))
        option_names = {opt["option"] for opt in result.get("protection_options", [])}
        self.assertIn("string_encryption", option_names)


if __name__ == "__main__":
    unittest.main()
