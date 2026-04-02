"""Tests for Frida JS template generation functions (_frida_templates.py).

Covers:
- generate_stalker_coverage_js (drcov and json formats)
- generate_anti_vm_bypass_js (registry key bypass, SMBIOS scrub)
- generate_injection_detector_js (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
- generate_api_logger_js (specific APIs, backtrace inclusion)
- generate_frida_stalker_script tool existence and compact description
"""
import os
import unittest


class TestStalkerCoverageJs(unittest.TestCase):
    """Test generate_stalker_coverage_js output."""

    def test_returns_non_empty_string(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js()
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_contains_stalker_follow(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js()
        self.assertIn("Stalker.follow", result)

    def test_drcov_format(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js(output_format="drcov")
        self.assertIn("DRCOV VERSION", result)
        self.assertIn("BB Table", result)
        self.assertIn("drcov", result)

    def test_json_format(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js(output_format="json")
        self.assertIn("type: 'coverage'", result)
        self.assertIn("basic_blocks", result)
        self.assertNotIn("DRCOV VERSION", result)

    def test_custom_target_module(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js(target_module="sample.exe")
        self.assertIn("sample.exe", result)
        self.assertIn('Process.getModuleByName("sample.exe")', result)

    def test_default_module(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js(target_module=None)
        self.assertIn("Process.enumerateModules()[0]", result)

    def test_contains_rpc_exports(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js()
        self.assertIn("rpc.exports", result)
        self.assertIn("dump:", result)
        self.assertIn("count:", result)

    def test_invalid_format_falls_back_to_drcov(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js(output_format="invalid")
        self.assertIn("DRCOV VERSION", result)

    def test_contains_stalker_parse(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js()
        self.assertIn("Stalker.parse", result)

    def test_contains_arkana_banner(self):
        from arkana.mcp._frida_templates import generate_stalker_coverage_js
        result = generate_stalker_coverage_js()
        self.assertIn("[ARKANA]", result)


class TestAntiVmBypassJs(unittest.TestCase):
    """Test generate_anti_vm_bypass_js output."""

    def test_returns_non_empty_string(self):
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_contains_reg_open_key_hooks(self):
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertIn("RegOpenKeyExA", result)
        self.assertIn("RegOpenKeyExW", result)

    def test_contains_interceptor_attach(self):
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertIn("Interceptor.attach", result)

    def test_contains_vm_registry_keys(self):
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertIn("VMware", result)
        self.assertIn("VirtualBox", result)
        self.assertIn("vmRegKeys", result)

    def test_contains_smbios_scrub(self):
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertIn("GetSystemFirmwareTable", result)
        self.assertIn("vmSmbiosStrings", result)

    def test_contains_process_enumeration_filter(self):
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertIn("Process32FirstW", result)
        self.assertIn("Process32NextW", result)
        self.assertIn("vmProcessNames", result)

    def test_contains_mac_address_masking(self):
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertIn("GetAdaptersInfo", result)
        self.assertIn("vmMacPrefixes", result)

    def test_contains_error_file_not_found(self):
        """Registry bypass should return ERROR_FILE_NOT_FOUND (2)."""
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertIn("retval.replace(2)", result)

    def test_contains_use_strict(self):
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertTrue(result.startswith('"use strict"'))

    def test_contains_arkana_banner(self):
        from arkana.mcp._frida_templates import generate_anti_vm_bypass_js
        result = generate_anti_vm_bypass_js()
        self.assertIn("[ARKANA]", result)


class TestInjectionDetectorJs(unittest.TestCase):
    """Test generate_injection_detector_js output."""

    def test_returns_non_empty_string(self):
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_contains_virtual_alloc_ex(self):
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIn("VirtualAllocEx", result)

    def test_contains_write_process_memory(self):
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIn("WriteProcessMemory", result)

    def test_contains_create_remote_thread(self):
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIn("CreateRemoteThread", result)

    def test_contains_nt_map_view_of_section(self):
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIn("NtMapViewOfSection", result)

    def test_contains_injection_sequence_detection(self):
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIn("injection_sequence_detected", result)

    def test_contains_send_alert(self):
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIn("sendAlert", result)
        self.assertIn("send(msg)", result)

    def test_tracks_injection_state(self):
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIn("injectionState", result)

    def test_contains_interceptor_attach(self):
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIn("Interceptor.attach", result)

    def test_data_preview_capture(self):
        """WriteProcessMemory hook should capture data preview."""
        from arkana.mcp._frida_templates import generate_injection_detector_js
        result = generate_injection_detector_js()
        self.assertIn("data_preview_hex", result)
        self.assertIn("readByteArray", result)


class TestApiLoggerJs(unittest.TestCase):
    """Test generate_api_logger_js output."""

    def test_returns_non_empty_string(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA"])
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_empty_apis_returns_placeholder(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=[])
        self.assertIn("No APIs specified", result)

    def test_hooks_specified_api(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA", "WriteFile"])
        self.assertIn("CreateFileA", result)
        self.assertIn("WriteFile", result)

    def test_contains_interceptor_attach(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA"])
        self.assertIn("Interceptor.attach", result)

    def test_contains_call_index(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA"])
        self.assertIn("callIndex", result)
        self.assertIn("call_index", result)

    def test_includes_timestamp(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA"])
        self.assertIn("toISOString()", result)

    def test_with_backtrace_true(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA"], include_backtrace=True)
        self.assertIn("Thread.backtrace", result)
        self.assertIn("Backtracer.ACCURATE", result)

    def test_without_backtrace(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA"], include_backtrace=False)
        self.assertNotIn("Thread.backtrace", result)

    def test_known_api_has_arg_resolution(self):
        """Known APIs (in FRIDA_API_SIGNATURES) should have argument resolution."""
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA"], include_args=True)
        # CreateFileA first arg is lpFileName:str
        self.assertIn("lpFileName", result)

    def test_unknown_api_has_generic_args(self):
        """Unknown APIs should get generic arg capture."""
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["MyCustomFunction"], include_args=True)
        self.assertIn("MyCustomFunction", result)
        self.assertIn("arg0", result)

    def test_multiple_apis(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        apis = ["CreateFileA", "WriteFile", "ReadFile", "DeleteFileA"]
        result = generate_api_logger_js(apis=apis)
        for api in apis:
            self.assertIn(api, result)

    def test_sends_json_entries(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA"])
        self.assertIn("send(entry)", result)

    def test_contains_api_count_banner(self):
        from arkana.mcp._frida_templates import generate_api_logger_js
        result = generate_api_logger_js(apis=["CreateFileA", "WriteFile"])
        self.assertIn("[ARKANA] API logger active", result)
        self.assertIn("2 APIs hooked", result)


class TestFridaApiSignatures(unittest.TestCase):
    """Test the FRIDA_API_SIGNATURES database."""

    def test_signatures_is_dict(self):
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        self.assertIsInstance(FRIDA_API_SIGNATURES, dict)

    def test_signatures_non_empty(self):
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        self.assertGreater(len(FRIDA_API_SIGNATURES), 0)

    def test_key_apis_present(self):
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        expected = [
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "CreateFileA", "CreateFileW", "WriteFile", "ReadFile",
            "RegOpenKeyExA", "IsDebuggerPresent", "CreateProcessA",
            "VirtualAlloc", "VirtualProtect",
        ]
        for api in expected:
            self.assertIn(api, FRIDA_API_SIGNATURES, f"Missing API: {api}")

    def test_signature_structure(self):
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        for name, sig in FRIDA_API_SIGNATURES.items():
            self.assertIn("args", sig, f"{name} missing 'args'")
            self.assertIn("return", sig, f"{name} missing 'return'")
            self.assertIn("category", sig, f"{name} missing 'category'")
            self.assertIsInstance(sig["args"], list, f"{name} args should be list")


class TestAntiDebugBypasses(unittest.TestCase):
    """Test the ANTI_DEBUG_BYPASSES templates."""

    def test_bypasses_is_dict(self):
        from arkana.mcp._frida_templates import ANTI_DEBUG_BYPASSES
        self.assertIsInstance(ANTI_DEBUG_BYPASSES, dict)

    def test_bypasses_contain_key_apis(self):
        from arkana.mcp._frida_templates import ANTI_DEBUG_BYPASSES
        expected = [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "GetTickCount",
        ]
        for api in expected:
            self.assertIn(api, ANTI_DEBUG_BYPASSES, f"Missing bypass: {api}")

    def test_bypass_templates_contain_interceptor(self):
        from arkana.mcp._frida_templates import ANTI_DEBUG_BYPASSES
        for name, template in ANTI_DEBUG_BYPASSES.items():
            self.assertIn("Interceptor.attach", template, f"{name} missing Interceptor.attach")


class TestGenerateFridaStalkerScriptTool(unittest.TestCase):
    """Test the MCP tool generate_frida_stalker_script exists and has compact description."""

    def test_tool_exists(self):
        from arkana.mcp.tools_frida import generate_frida_stalker_script
        self.assertTrue(callable(generate_frida_stalker_script))

    def test_compact_description_in_docstring(self):
        from arkana.mcp.tools_frida import generate_frida_stalker_script
        doc = generate_frida_stalker_script.__doc__ or ""
        self.assertIn("---compact:", doc)

    def test_compact_description_content(self):
        from arkana.mcp.tools_frida import generate_frida_stalker_script
        doc = generate_frida_stalker_script.__doc__ or ""
        # Should mention Stalker and script types
        compact_line = [line for line in doc.splitlines() if "---compact:" in line]
        self.assertEqual(len(compact_line), 1)
        self.assertIn("Stalker", compact_line[0])


class TestGenerateBypassJs(unittest.TestCase):
    """Test the generate_bypass_js combined anti-debug script."""

    def test_returns_string(self):
        from arkana.mcp._frida_templates import generate_bypass_js
        result = generate_bypass_js(["IsDebuggerPresent"])
        self.assertIsInstance(result, str)

    def test_includes_selected_techniques(self):
        from arkana.mcp._frida_templates import generate_bypass_js
        result = generate_bypass_js(["IsDebuggerPresent", "GetTickCount"])
        self.assertIn("IsDebuggerPresent", result)
        self.assertIn("GetTickCount", result)

    def test_skips_unknown_techniques(self):
        from arkana.mcp._frida_templates import generate_bypass_js
        result = generate_bypass_js(["NonexistentBypass"])
        # Should still generate a valid script with the banner
        self.assertIn("[ARKANA]", result)

    def test_empty_techniques(self):
        from arkana.mcp._frida_templates import generate_bypass_js
        result = generate_bypass_js([])
        self.assertIn("[ARKANA]", result)


if __name__ == "__main__":
    unittest.main()
