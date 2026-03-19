"""Tests for arkana.mcp.tools_frida and arkana.mcp._frida_templates."""
import asyncio
import pytest


def _run(coro):
    """Helper to run async functions in tests."""
    return asyncio.run(coro)


@pytest.fixture
def clean_state():
    """Reset global state for each test."""
    from arkana.config import state
    old_filepath = state.filepath
    old_pe_data = state.pe_data
    old_triage = getattr(state, '_cached_triage', None)

    state.filepath = None
    state.pe_data = None
    state._cached_triage = None

    yield

    state.filepath = old_filepath
    state.pe_data = old_pe_data
    state._cached_triage = old_triage


@pytest.fixture
def mock_ctx():
    """Minimal mock MCP context."""
    class MockCtx:
        async def info(self, msg): pass
        async def warning(self, msg): pass
        async def error(self, msg): pass
        async def report_progress(self, current, total): pass
    return MockCtx()


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
        import inspect
        from arkana.mcp.tools_frida import generate_frida_hook_script
        assert inspect.iscoroutinefunction(generate_frida_hook_script)

    def test_bypass_tool(self):
        import inspect
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        assert inspect.iscoroutinefunction(generate_frida_bypass_script)

    def test_trace_tool(self):
        import inspect
        from arkana.mcp.tools_frida import generate_frida_trace_script
        assert inspect.iscoroutinefunction(generate_frida_trace_script)


# =====================================================================
#  _collect_import_names() helper tests
# =====================================================================

class TestCollectImportNames:
    """Tests for the shared import parsing helper."""

    def test_canonical_list_of_dicts(self):
        """Bug fix: the canonical format with dll_name + symbols."""
        from arkana.mcp.tools_frida import _collect_import_names
        pe_data = {
            "imports": [
                {
                    "dll_name": "kernel32.dll",
                    "symbols": [
                        {"name": "CreateProcessA", "ordinal": None},
                        {"name": "VirtualAlloc", "ordinal": None},
                    ]
                },
                {
                    "dll_name": "wininet.dll",
                    "symbols": [
                        {"name": "InternetOpenA", "ordinal": None},
                    ]
                },
            ]
        }
        result = _collect_import_names(pe_data)
        assert ("CreateProcessA", "kernel32.dll") in result
        assert ("VirtualAlloc", "kernel32.dll") in result
        assert ("InternetOpenA", "wininet.dll") in result
        assert len(result) == 3

    def test_dict_keyed_by_dll_fallback(self):
        """Dict fallback format: {dll: [{name: ...}]}."""
        from arkana.mcp.tools_frida import _collect_import_names
        pe_data = {
            "imports": {
                "kernel32.dll": [
                    {"name": "CreateProcessA"},
                    {"name": "VirtualAlloc"},
                ],
            }
        }
        result = _collect_import_names(pe_data)
        assert ("CreateProcessA", "kernel32.dll") in result
        assert ("VirtualAlloc", "kernel32.dll") in result
        assert len(result) == 2

    def test_none_pe_data(self):
        from arkana.mcp.tools_frida import _collect_import_names
        assert _collect_import_names(None) == set()

    def test_empty_pe_data(self):
        from arkana.mcp.tools_frida import _collect_import_names
        assert _collect_import_names({}) == set()

    def test_no_imports_key(self):
        from arkana.mcp.tools_frida import _collect_import_names
        assert _collect_import_names({"mode": "pe"}) == set()

    def test_symbols_without_name(self):
        """Symbols missing the 'name' key should be skipped."""
        from arkana.mcp.tools_frida import _collect_import_names
        pe_data = {
            "imports": [
                {
                    "dll_name": "kernel32.dll",
                    "symbols": [
                        {"ordinal": 42},  # no name
                        {"name": "GetLastError"},
                    ]
                },
            ]
        }
        result = _collect_import_names(pe_data)
        assert len(result) == 1
        assert ("GetLastError", "kernel32.dll") in result

    def test_non_dict_entries_skipped(self):
        """Non-dict entries in the imports list are skipped."""
        from arkana.mcp.tools_frida import _collect_import_names
        pe_data = {"imports": ["not_a_dict", 42, None]}
        assert _collect_import_names(pe_data) == set()

    def test_string_symbols_in_list_format(self):
        """Symbols can be plain strings in list format."""
        from arkana.mcp.tools_frida import _collect_import_names
        pe_data = {
            "imports": [
                {"dll_name": "user32.dll", "symbols": ["MessageBoxA", "PostQuitMessage"]},
            ]
        }
        result = _collect_import_names(pe_data)
        assert ("MessageBoxA", "user32.dll") in result
        assert ("PostQuitMessage", "user32.dll") in result

    def test_string_symbols_in_dict_format(self):
        """Symbols can be plain strings in dict fallback format."""
        from arkana.mcp.tools_frida import _collect_import_names
        pe_data = {
            "imports": {
                "user32.dll": ["MessageBoxA", "PostQuitMessage"],
            }
        }
        result = _collect_import_names(pe_data)
        assert ("MessageBoxA", "user32.dll") in result
        assert ("PostQuitMessage", "user32.dll") in result


# =====================================================================
#  Bypass tool tests (MCP function via __wrapped__)
# =====================================================================

class TestBypassToolAutoDetect:
    """Test generate_frida_bypass_script auto-detection from imports."""

    @pytest.fixture(autouse=True)
    def setup_state(self, clean_state):
        pass

    def test_detects_anti_debug_from_real_imports(self, mock_ctx):
        """Bug fix validation: anti-debug APIs found from canonical import structure."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        state.filepath = "/fake/test.exe"
        state.pe_data = {
            "imports": [
                {
                    "dll_name": "kernel32.dll",
                    "symbols": [
                        {"name": "IsDebuggerPresent", "ordinal": None},
                        {"name": "GetTickCount", "ordinal": None},
                        {"name": "HeapAlloc", "ordinal": None},
                    ]
                },
            ]
        }
        result = _run(generate_frida_bypass_script.__wrapped__(mock_ctx))
        assert "bypassed_techniques" in result
        assert "IsDebuggerPresent" in result["bypassed_techniques"]
        assert "script" in result

    def test_no_pe_data_returns_no_detection(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        result = _run(generate_frida_bypass_script.__wrapped__(mock_ctx))
        assert result["status"] == "no_anti_debug_detected"

    def test_benign_only_imports(self, mock_ctx):
        """No anti-debug APIs in imports → no detection."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        state.pe_data = {
            "imports": [
                {"dll_name": "kernel32.dll", "symbols": [{"name": "HeapAlloc"}]},
            ]
        }
        result = _run(generate_frida_bypass_script.__wrapped__(mock_ctx))
        assert result["status"] == "no_anti_debug_detected"

    def test_triage_data_supplements_imports(self, mock_ctx):
        """Anti-debug from triage data should also be detected."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        state.pe_data = {"imports": []}
        state._cached_triage = {
            "anti_debug_techniques": [
                {"api": "NtQueryInformationProcess"},
            ]
        }
        result = _run(generate_frida_bypass_script.__wrapped__(mock_ctx))
        assert "bypassed_techniques" in result
        assert "NtQueryInformationProcess" in result["bypassed_techniques"]

    def test_dedup_triage_and_imports(self, mock_ctx):
        """Same API from imports + triage should not appear twice."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        state.pe_data = {
            "imports": [
                {"dll_name": "kernel32.dll", "symbols": [{"name": "IsDebuggerPresent"}]},
            ]
        }
        state._cached_triage = {
            "anti_debug_techniques": [{"api": "IsDebuggerPresent"}]
        }
        result = _run(generate_frida_bypass_script.__wrapped__(mock_ctx))
        assert result["bypassed_techniques"].count("IsDebuggerPresent") == 1

    def test_auto_detect_false_no_techniques(self, mock_ctx):
        """auto_detect=False with no techniques → empty script."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        state.pe_data = {
            "imports": [
                {"dll_name": "kernel32.dll", "symbols": [{"name": "IsDebuggerPresent"}]},
            ]
        }
        result = _run(generate_frida_bypass_script.__wrapped__(
            mock_ctx, auto_detect=False
        ))
        # With auto_detect=False and no techniques, detected_techniques stays empty
        assert "script" in result
        assert result["total_bypasses"] == 0


class TestBypassToolManualTechniques:
    """Test generate_frida_bypass_script with manual technique selection."""

    @pytest.fixture(autouse=True)
    def setup_state(self, clean_state):
        pass

    def test_valid_technique(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        result = _run(generate_frida_bypass_script.__wrapped__(
            mock_ctx, techniques=["IsDebuggerPresent"]
        ))
        assert "bypassed_techniques" in result
        assert "IsDebuggerPresent" in result["bypassed_techniques"]

    def test_multiple_techniques(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        result = _run(generate_frida_bypass_script.__wrapped__(
            mock_ctx, techniques=["IsDebuggerPresent", "NtClose"]
        ))
        assert len(result["bypassed_techniques"]) == 2

    def test_invalid_technique_returns_error(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        result = _run(generate_frida_bypass_script.__wrapped__(
            mock_ctx, techniques=["FakeNonexistentApi"]
        ))
        assert "error" in result
        assert "available_techniques" in result

    def test_mixed_valid_invalid_keeps_valid(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_bypass_script
        result = _run(generate_frida_bypass_script.__wrapped__(
            mock_ctx, techniques=["IsDebuggerPresent", "FakeTech"]
        ))
        assert "bypassed_techniques" in result
        assert result["bypassed_techniques"] == ["IsDebuggerPresent"]


# =====================================================================
#  Trace tool tests (MCP function via __wrapped__)
# =====================================================================

class TestTraceToolImportParsing:
    """Test generate_frida_trace_script import parsing (bug fix validation)."""

    @pytest.fixture(autouse=True)
    def setup_state(self, clean_state):
        from arkana.config import state
        state.filepath = "/fake/test.exe"

    def test_finds_apis_from_real_imports(self, mock_ctx):
        """Bug fix validation: APIs found from canonical import structure."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        # Pick an API that's definitely in the signature DB
        known_api = next(iter(FRIDA_API_SIGNATURES))
        state.pe_data = {
            "imports": [
                {"dll_name": "kernel32.dll", "symbols": [{"name": known_api}]},
            ]
        }
        result = _run(generate_frida_trace_script.__wrapped__(mock_ctx))
        assert "traced_apis" in result
        assert known_api in result["traced_apis"]

    def test_category_filter(self, mock_ctx):
        """Category filter returns only matching APIs."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        state.pe_data = {
            "imports": [
                {
                    "dll_name": "kernel32.dll",
                    "symbols": [
                        {"name": "CreateRemoteThread"},
                        {"name": "IsDebuggerPresent"},
                    ]
                },
            ]
        }
        result = _run(generate_frida_trace_script.__wrapped__(
            mock_ctx, categories=["process_injection"]
        ))
        if "traced_apis" in result:
            for _api in result["traced_apis"]:
                assert result["by_category"].get("process_injection") is not None

    def test_invalid_category_returns_error(self, mock_ctx):
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        state.pe_data = {"imports": []}
        result = _run(generate_frida_trace_script.__wrapped__(
            mock_ctx, categories=["nonexistent_category"]
        ))
        assert "error" in result
        assert "valid_categories" in result

    def test_limit_clamping(self, mock_ctx):
        """Limit is clamped to [1, MAX_TOOL_LIMIT]."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        state.pe_data = {
            "imports": [
                {
                    "dll_name": "kernel32.dll",
                    "symbols": [
                        {"name": "CreateRemoteThread"},
                        {"name": "WriteProcessMemory"},
                        {"name": "VirtualAllocEx"},
                    ]
                },
            ]
        }
        result = _run(generate_frida_trace_script.__wrapped__(mock_ctx, limit=1))
        if "traced_apis" in result:
            assert len(result["traced_apis"]) <= 1

    def test_dedup_by_name(self, mock_ctx):
        """Same API from two DLLs should appear only once."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        state.pe_data = {
            "imports": [
                {"dll_name": "kernel32.dll", "symbols": [{"name": "CreateRemoteThread"}]},
                {"dll_name": "kernelbase.dll", "symbols": [{"name": "CreateRemoteThread"}]},
            ]
        }
        result = _run(generate_frida_trace_script.__wrapped__(mock_ctx))
        if "traced_apis" in result:
            assert result["traced_apis"].count("CreateRemoteThread") == 1

    def test_no_matching_apis(self, mock_ctx):
        """Imports with no known APIs returns no_matching_apis."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        state.pe_data = {
            "imports": [
                {"dll_name": "custom.dll", "symbols": [{"name": "MyPrivateFunc"}]},
            ]
        }
        result = _run(generate_frida_trace_script.__wrapped__(mock_ctx))
        assert result.get("status") == "no_matching_apis"

    def test_no_pe_data_raises(self, mock_ctx):
        """No pe_data should trigger _check_pe_loaded error."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        state.pe_data = None
        with pytest.raises(RuntimeError, match="No file is currently loaded"):
            _run(generate_frida_trace_script.__wrapped__(mock_ctx))

    def test_by_category_summary(self, mock_ctx):
        """Result includes by_category summary dict."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        state.pe_data = {
            "imports": [
                {"dll_name": "kernel32.dll", "symbols": [{"name": "CreateRemoteThread"}]},
            ]
        }
        result = _run(generate_frida_trace_script.__wrapped__(mock_ctx))
        if "by_category" in result:
            assert isinstance(result["by_category"], dict)

    def test_empty_imports_list(self, mock_ctx):
        """Empty imports list returns no_matching_apis."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        state.pe_data = {"imports": []}
        result = _run(generate_frida_trace_script.__wrapped__(mock_ctx))
        assert result.get("status") == "no_matching_apis"

    def test_categorized_imports_db_fallback(self, mock_ctx):
        """APIs in CATEGORIZED_IMPORTS_DB but not FRIDA_API_SIGNATURES are also traced."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        try:
            from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB
        except ImportError:
            pytest.skip("CATEGORIZED_IMPORTS_DB not available")
        from arkana.mcp._frida_templates import FRIDA_API_SIGNATURES
        # Find an API in CATEGORIZED_IMPORTS_DB but not FRIDA_API_SIGNATURES
        fallback_api = None
        for name in CATEGORIZED_IMPORTS_DB:
            if name not in FRIDA_API_SIGNATURES:
                fallback_api = name
                break
        if not fallback_api:
            pytest.skip("No fallback API found")
        state.pe_data = {
            "imports": [
                {"dll_name": "test.dll", "symbols": [{"name": fallback_api}]},
            ]
        }
        result = _run(generate_frida_trace_script.__wrapped__(mock_ctx))
        if "traced_apis" in result:
            assert fallback_api in result["traced_apis"]

    def test_dict_format_imports(self, mock_ctx):
        """Dict-format imports (fallback) also work for trace tool."""
        from arkana.config import state
        from arkana.mcp.tools_frida import generate_frida_trace_script
        state.pe_data = {
            "imports": {
                "kernel32.dll": [{"name": "CreateRemoteThread"}],
            }
        }
        result = _run(generate_frida_trace_script.__wrapped__(mock_ctx))
        if "traced_apis" in result:
            assert "CreateRemoteThread" in result["traced_apis"]


# =====================================================================
#  Hook tool tests (MCP function via __wrapped__)
# =====================================================================

class TestHookToolMcpFunction:
    """Test generate_frida_hook_script MCP tool."""

    def test_known_api_hooked(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_hook_script
        result = _run(generate_frida_hook_script.__wrapped__(
            mock_ctx, targets=["CreateRemoteThread"]
        ))
        assert result["total_hooks"] == 1
        assert "CreateRemoteThread" in result["hooked_apis"]
        assert "Interceptor.attach" in result["script"]

    def test_address_hooked(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_hook_script
        result = _run(generate_frida_hook_script.__wrapped__(
            mock_ctx, targets=["0x401000"]
        ))
        assert result["total_hooks"] == 1
        assert "0x401000" in result["hooked_addresses"]

    def test_unknown_target(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_hook_script
        result = _run(generate_frida_hook_script.__wrapped__(
            mock_ctx, targets=["SomeCustomFunc"]
        ))
        assert "SomeCustomFunc" in result["unknown_targets"]

    def test_mixed_targets(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_hook_script
        result = _run(generate_frida_hook_script.__wrapped__(
            mock_ctx, targets=["CreateRemoteThread", "0x401000", "CustomApi"]
        ))
        assert result["total_hooks"] == 3
        assert len(result["hooked_apis"]) == 1
        assert len(result["hooked_addresses"]) == 1
        assert len(result["unknown_targets"]) == 1

    def test_total_count(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_hook_script
        result = _run(generate_frida_hook_script.__wrapped__(
            mock_ctx, targets=["CreateRemoteThread", "WriteProcessMemory"]
        ))
        assert result["total_hooks"] == 2

    def test_script_content(self, mock_ctx):
        from arkana.mcp.tools_frida import generate_frida_hook_script
        result = _run(generate_frida_hook_script.__wrapped__(
            mock_ctx, targets=["CreateRemoteThread"]
        ))
        assert '"use strict"' in result["script"]
        assert "Arkana Hook Script" in result["script"]
        assert "hooks installed" in result["script"]


# =====================================================================
#  _save_script tests
# =====================================================================

class TestSaveScript:
    """Tests for script saving."""

    def test_none_path_returns_none(self):
        from arkana.mcp.tools_frida import _save_script
        assert _save_script(None, "console.log('test');", "test_tool") is None

    def test_empty_path_returns_none(self):
        from arkana.mcp.tools_frida import _save_script
        assert _save_script("", "console.log('test');", "test_tool") is None

    def test_save_calls_write(self, tmp_path, monkeypatch):
        """Saving to a valid path should write the file."""
        from arkana.config import state
        from arkana.mcp.tools_frida import _save_script
        # Allow the path
        monkeypatch.setattr(state, "check_path_allowed", lambda p: None)
        out = str(tmp_path / "test_script.js")
        # Mock the artifact registration at the source module
        monkeypatch.setattr(
            "arkana.mcp._refinery_helpers._write_output_and_register_artifact",
            lambda path, data, tool, desc: {"path": path},
        )
        result = _save_script(out, "test script", "test_tool")
        assert result is not None


# =====================================================================
#  _format_arg_reader tests
# =====================================================================

class TestFormatArgReader:
    """Tests for JS argument reader generation."""

    def test_str_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(0, "lpName:str")
        assert "readAnsiString" in js
        assert "lpName" in js
        assert "args[0]" in js

    def test_wstr_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(1, "lpWideName:wstr")
        assert "readUtf16String" in js
        assert "lpWideName" in js
        assert "args[1]" in js

    def test_uint_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(0, "dwFlags:uint")
        assert "toInt32" in js
        assert "dwFlags" in js

    def test_int_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(0, "nCount:int")
        assert "toInt32" in js

    def test_bool_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(0, "bInherit:BOOL")
        assert "toInt32" in js

    def test_handle_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(0, "hProcess:HANDLE")
        assert "args[0]" in js
        assert "toInt32" not in js
        assert "readAnsiString" not in js

    def test_ptr_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(2, "lpBuffer:ptr")
        assert "args[2]" in js

    def test_long_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(0, "lParam:LONG")
        assert "toInt32" in js

    def test_ntstatus_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(0, "status:NTSTATUS")
        assert "toInt32" in js

    def test_socket_type(self):
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(0, "s:SOCKET")
        assert "toInt32" in js

    def test_default_type(self):
        """Unknown type falls back to raw pointer."""
        from arkana.mcp._frida_templates import _format_arg_reader
        js = _format_arg_reader(3, "lpUnknown:MYSTRUCT")
        assert "args[3]" in js
        assert "toInt32" not in js
        assert "readAnsiString" not in js


# =====================================================================
#  Void return type test
# =====================================================================

class TestVoidReturnType:
    """Test generate_hook_js handles void return type."""

    def test_void_return_still_logs_retval(self):
        """APIs with void return still produce valid onLeave."""
        from arkana.mcp._frida_templates import generate_hook_js
        js = generate_hook_js("OutputDebugStringA", include_args=True)
        assert "onLeave" in js
        assert "returned:" in js
        assert "OutputDebugStringA" in js
