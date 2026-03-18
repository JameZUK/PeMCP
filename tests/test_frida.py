"""Tests for arkana.mcp.tools_frida and arkana.mcp._frida_templates."""
import pytest


# =====================================================================
#  Template Tests
# =====================================================================

class TestFridaApiSignatures:
    """Tests for the API signature database."""

    def test_signatures_not_empty(self):
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        assert len(FRIDA_API_SIGNATURES) > 40

    def test_all_entries_have_required_fields(self):
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        for api_name, sig in FRIDA_API_SIGNATURES.items():
            assert "args" in sig, f"{api_name} missing 'args'"
            assert "return" in sig, f"{api_name} missing 'return'"
            assert "category" in sig, f"{api_name} missing 'category'"
            assert isinstance(sig["args"], list), f"{api_name} args is not a list"

    def test_known_api_signature(self):
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        sig = FRIDA_API_SIGNATURES["CreateRemoteThread"]
        assert sig["return"] == "HANDLE"
        assert sig["category"] == "process_injection"
        assert len(sig["args"]) == 7

    def test_category_coverage(self):
        """Multiple categories are represented."""
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        categories = {sig["category"] for sig in FRIDA_API_SIGNATURES.values()}
        assert "process_injection" in categories
        assert "networking" in categories
        assert "crypto" in categories
        assert "file_io" in categories
        assert "anti_debug" in categories


class TestAntiDebugBypasses:
    """Tests for anti-debug bypass templates."""

    def test_bypasses_not_empty(self):
        from arkana.mcp._frida_templates import ANTI_DEBUG_BYPASSES
        assert len(ANTI_DEBUG_BYPASSES) >= 8

    def test_known_bypass_exists(self):
        from arkana.mcp._frida_templates import ANTI_DEBUG_BYPASSES
        assert "IsDebuggerPresent" in ANTI_DEBUG_BYPASSES
        assert "NtQueryInformationProcess" in ANTI_DEBUG_BYPASSES

    def test_bypass_templates_are_js(self):
        from arkana.mcp._frida_templates import ANTI_DEBUG_BYPASSES
        for name, js in ANTI_DEBUG_BYPASSES.items():
            assert isinstance(js, str), f"{name} template is not a string"
            assert "Interceptor" in js or "console" in js, f"{name} doesn't look like Frida JS"


class TestAntiDebugApis:
    """Tests for the anti-debug API detection set."""

    def test_api_set_not_empty(self):
        from arkana.mcp._frida_templates import ANTI_DEBUG_APIS
        assert len(ANTI_DEBUG_APIS) > 10

    def test_known_apis_present(self):
        from arkana.mcp._frida_templates import ANTI_DEBUG_APIS
        assert "IsDebuggerPresent" in ANTI_DEBUG_APIS
        assert "GetTickCount" in ANTI_DEBUG_APIS


class TestGenerateHookJs:
    """Tests for the generate_hook_js function."""

    def test_known_api(self):
        from arkana.mcp._frida_templates import generate_hook_js
        js = generate_hook_js("CreateRemoteThread")
        assert "CreateRemoteThread" in js
        assert "Interceptor.attach" in js
        assert "onEnter" in js
        assert "onLeave" in js

    def test_known_api_with_args(self):
        from arkana.mcp._frida_templates import generate_hook_js
        js = generate_hook_js("CreateRemoteThread", include_args=True)
        assert "hProcess" in js
        assert "lpStartAddress" in js

    def test_known_api_without_args(self):
        from arkana.mcp._frida_templates import generate_hook_js
        js = generate_hook_js("CreateRemoteThread", include_args=False)
        assert "hProcess" not in js

    def test_with_module(self):
        from arkana.mcp._frida_templates import generate_hook_js
        js = generate_hook_js("CreateRemoteThread", module="kernel32.dll")
        assert "kernel32.dll" in js

    def test_without_backtrace(self):
        from arkana.mcp._frida_templates import generate_hook_js
        js = generate_hook_js("CreateRemoteThread", include_backtrace=False)
        assert "Backtracer" not in js

    def test_unknown_api(self):
        """Unknown APIs should still produce valid JS with generic logging."""
        from arkana.mcp._frida_templates import generate_hook_js
        js = generate_hook_js("MyCustomFunction")
        assert "MyCustomFunction" in js
        assert "Interceptor.attach" in js


class TestGenerateHookForAddress:
    """Tests for raw address hook generation."""

    def test_basic_address(self):
        from arkana.mcp._frida_templates import generate_hook_for_address
        js = generate_hook_for_address("0x401000")
        assert "0x401000" in js
        assert "Interceptor.attach" in js

    def test_with_backtrace(self):
        from arkana.mcp._frida_templates import generate_hook_for_address
        js = generate_hook_for_address("0x401000", include_backtrace=True)
        assert "Backtracer" in js

    def test_without_backtrace(self):
        from arkana.mcp._frida_templates import generate_hook_for_address
        js = generate_hook_for_address("0x401000", include_backtrace=False)
        assert "Backtracer" not in js


class TestGenerateBypassJs:
    """Tests for the bypass script generator."""

    def test_single_technique(self):
        from arkana.mcp._frida_templates import generate_bypass_js
        js = generate_bypass_js(["IsDebuggerPresent"])
        assert "IsDebuggerPresent" in js
        assert "BYPASS" in js
        assert "use strict" in js

    def test_multiple_techniques(self):
        from arkana.mcp._frida_templates import generate_bypass_js
        js = generate_bypass_js(["IsDebuggerPresent", "NtQueryInformationProcess"])
        assert "IsDebuggerPresent" in js
        assert "NtQueryInformationProcess" in js

    def test_empty_techniques(self):
        from arkana.mcp._frida_templates import generate_bypass_js
        js = generate_bypass_js([])
        assert "Arkana Anti-Debug Bypass" in js

    def test_unknown_technique_skipped(self):
        from arkana.mcp._frida_templates import generate_bypass_js
        js = generate_bypass_js(["NonexistentTechnique"])
        assert "Interceptor" not in js


class TestGenerateTraceJs:
    """Tests for the trace script generator."""

    def test_basic_trace(self):
        from arkana.mcp._frida_templates import generate_trace_js
        apis = [{"name": "CreateRemoteThread", "category": "process_injection"}]
        js = generate_trace_js(apis)
        assert "CreateRemoteThread" in js
        assert "Tracing 1 APIs" in js

    def test_category_filter(self):
        from arkana.mcp._frida_templates import generate_trace_js
        apis = [
            {"name": "CreateRemoteThread", "category": "process_injection"},
            {"name": "send", "category": "networking"},
        ]
        js = generate_trace_js(apis, categories=["networking"])
        assert "send" in js
        assert "Tracing 1 APIs" in js

    def test_empty_apis(self):
        from arkana.mcp._frida_templates import generate_trace_js
        js = generate_trace_js([])
        assert "Tracing 0 APIs" in js


# =====================================================================
#  MCP Tool Tests
# =====================================================================

class TestValidateTargets:
    """Tests for target validation."""

    def test_empty_list(self):
        from arkana.mcp.tools_frida import _validate_targets
        with pytest.raises(ValueError, match="empty"):
            _validate_targets([])

    def test_too_many_targets(self):
        from arkana.mcp.tools_frida import _validate_targets
        with pytest.raises(ValueError, match="Too many"):
            _validate_targets(["api"] * 51)

    def test_long_target_name(self):
        from arkana.mcp.tools_frida import _validate_targets
        with pytest.raises(ValueError, match="too long"):
            _validate_targets(["x" * 257])

    def test_valid_targets(self):
        from arkana.mcp.tools_frida import _validate_targets
        result = _validate_targets(["CreateRemoteThread", "0x401000"])
        assert len(result) == 2

    def test_whitespace_stripped(self):
        from arkana.mcp.tools_frida import _validate_targets
        result = _validate_targets(["  CreateRemoteThread  "])
        assert result == ["CreateRemoteThread"]

    def test_empty_strings_filtered(self):
        from arkana.mcp.tools_frida import _validate_targets
        result = _validate_targets(["CreateRemoteThread", "", "  "])
        assert result == ["CreateRemoteThread"]

    def test_non_string_rejected(self):
        from arkana.mcp.tools_frida import _validate_targets
        with pytest.raises(ValueError, match="Invalid target type"):
            _validate_targets([123])


class TestToolRegistration:
    """Test that all Frida tools are properly decorated."""

    def test_hook_tool(self):
        import asyncio
        from arkana.mcp.tools_frida import generate_frida_hook_script
        assert asyncio.iscoroutinefunction(generate_frida_hook_script)

    def test_bypass_tool(self):
        import asyncio
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        assert asyncio.iscoroutinefunction(generate_frida_bypass_script)

    def test_trace_tool(self):
        import asyncio
        from arkana.mcp.tools_frida import generate_frida_trace_script
        assert asyncio.iscoroutinefunction(generate_frida_trace_script)
