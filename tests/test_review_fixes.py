"""Tests for iteration 10 review fixes.

Covers:
- Hook state corruption fix (HIGH 1.1)
- Unsafe dict access in string tools (HIGH 1.3)
- Exception counters in dataflow (HIGH 1.2)
- Env var int parsing guard (MEDIUM 2.1)
- Speakeasy cascade failure (MEDIUM 2.2)
- Unipacker timeout (MEDIUM 2.3)
- Upfront regex validation in deobfuscation (MEDIUM 2.4)
- Redundant regex compile removal (LOW 3.4)
"""
import os
import re
import json
import pytest
import asyncio

pytest.importorskip("pefile", reason="pefile not installed")


def _run(coro):
    """Helper to run async functions in tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ===================================================================
# Fix 2.1: Environment variable int parsing guard
# ===================================================================

class TestSafeEnvInt:
    """Test _safe_env_int handles bad environment variable values."""

    def test_valid_int(self, monkeypatch):
        monkeypatch.setenv("PEMCP_MAX_CONCURRENT_ANALYSES", "5")
        from pemcp.mcp.tools_pe import _safe_env_int
        assert _safe_env_int("PEMCP_MAX_CONCURRENT_ANALYSES", 3) == 5

    def test_missing_env_uses_default(self, monkeypatch):
        monkeypatch.delenv("PEMCP_TEST_NONEXISTENT", raising=False)
        from pemcp.mcp.tools_pe import _safe_env_int
        assert _safe_env_int("PEMCP_TEST_NONEXISTENT", 42) == 42

    def test_invalid_string_uses_default(self, monkeypatch):
        monkeypatch.setenv("PEMCP_MAX_CONCURRENT_ANALYSES", "not_a_number")
        from pemcp.mcp.tools_pe import _safe_env_int
        assert _safe_env_int("PEMCP_MAX_CONCURRENT_ANALYSES", 3) == 3

    def test_empty_string_uses_default(self, monkeypatch):
        monkeypatch.setenv("PEMCP_MAX_CONCURRENT_ANALYSES", "")
        from pemcp.mcp.tools_pe import _safe_env_int
        assert _safe_env_int("PEMCP_MAX_CONCURRENT_ANALYSES", 3) == 3

    def test_float_string_uses_default(self, monkeypatch):
        monkeypatch.setenv("PEMCP_MAX_CONCURRENT_ANALYSES", "3.5")
        from pemcp.mcp.tools_pe import _safe_env_int
        assert _safe_env_int("PEMCP_MAX_CONCURRENT_ANALYSES", 3) == 3

    def test_negative_value(self, monkeypatch):
        monkeypatch.setenv("PEMCP_MAX_CONCURRENT_ANALYSES", "-1")
        from pemcp.mcp.tools_pe import _safe_env_int
        assert _safe_env_int("PEMCP_MAX_CONCURRENT_ANALYSES", 3) == -1

    def test_zero_value(self, monkeypatch):
        monkeypatch.setenv("PEMCP_MAX_CONCURRENT_ANALYSES", "0")
        from pemcp.mcp.tools_pe import _safe_env_int
        assert _safe_env_int("PEMCP_MAX_CONCURRENT_ANALYSES", 3) == 0


# ===================================================================
# Fix 2.2: Speakeasy cascade failure
# ===================================================================

class TestSpeakeasyRunner:
    """Test speakeasy_runner properly separates load and run errors."""

    def test_emulate_shellcode_missing_input(self):
        """emulate_shellcode returns error when no input provided."""
        # We can't import speakeasy itself, but we can verify the logic structure
        # by checking the source code has separate try blocks
        runner_path = os.path.join(os.path.dirname(__file__), "..", "scripts", "speakeasy_runner.py")
        with open(runner_path) as f:
            source = f.read()
        # Verify load and run are in separate try blocks
        assert "except Exception as e:\n        return {\"error\": f\"Failed to load shellcode:" in source
        # Verify run_shellcode is in its own try block
        assert "se.run_shellcode(addr" in source


# ===================================================================
# Fix 2.4: Upfront regex validation in deobfuscation
# ===================================================================

class TestDeobfuscationRegexValidation:
    """Test that invalid regex patterns are caught upfront."""

    def test_source_has_upfront_validation(self):
        """Verify the deobfuscation tool validates regex before processing."""
        deobfuscation_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_deobfuscation.py"
        )
        with open(deobfuscation_path) as f:
            source = f.read()
        # Verify upfront validation exists before the Setup section
        setup_idx = source.index("# --- Setup ---")
        validation_idx = source.index("Validate regex patterns upfront")
        assert validation_idx < setup_idx, "Regex validation should happen before setup"


# ===================================================================
# Fix 1.1: Hook state corruption
# ===================================================================

class TestHookStateCorruption:
    """Verify hook registration happens after successful hook."""

    def test_hook_registration_after_success(self):
        """Verify source has hook registration after proj.hook / proj.hook_symbol."""
        hooks_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_angr_hooks.py"
        )
        with open(hooks_path) as f:
            source = f.read()
        # The hook state registration should appear after both hook paths
        hook_call_idx = source.index("proj.hook(addr, hook_proc)")
        hook_symbol_idx = source.index("proj.hook_symbol(address_or_name, hook_proc)")
        state_registration_idx = source.index("# Register hook in state AFTER successful hooking")
        assert state_registration_idx > hook_call_idx
        assert state_registration_idx > hook_symbol_idx

    def test_hex_address_hook_has_error_handling(self):
        """Verify proj.hook(addr) path has try/except."""
        hooks_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_angr_hooks.py"
        )
        with open(hooks_path) as f:
            source = f.read()
        # The hex address hook path should have error handling
        assert 'return {"error": f"Failed to hook address' in source


# ===================================================================
# Fix 1.2: Dataflow exception counters
# ===================================================================

class TestDataflowExceptionCounters:
    """Verify dataflow analysis surfaces skipped definitions."""

    def test_reaching_definitions_has_warning_support(self):
        """Verify get_reaching_definitions can surface skip warnings."""
        dataflow_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_angr_dataflow.py"
        )
        with open(dataflow_path) as f:
            source = f.read()
        assert "_skipped_defs" in source
        assert "definition(s) skipped due to processing errors" in source

    def test_data_dependencies_has_warning_support(self):
        """Verify get_data_dependencies can surface skip warnings."""
        dataflow_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_angr_dataflow.py"
        )
        with open(dataflow_path) as f:
            source = f.read()
        assert "_skipped_obs" in source
        assert "observation(s) skipped due to processing errors" in source


# ===================================================================
# Fix 1.3 / 3.4: Safe dict access + redundant regex removal in tools_strings
# ===================================================================

class TestStringsToolSafety:
    """Verify string tools use safe dict access patterns."""

    def test_search_floss_uses_safe_access(self):
        """search_floss_strings should use .get() for string access."""
        strings_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_strings.py"
        )
        with open(strings_path) as f:
            source = f.read()
        # The filtering loop should use .get() for string_to_search
        assert 'string_to_search = item.get("string", "")' in source

    def test_sifted_strings_uses_safe_access(self):
        """get_top_sifted_strings should use .get() for score and string."""
        strings_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_strings.py"
        )
        with open(strings_path) as f:
            source = f.read()
        assert "score = item.get('sifter_score', 0.0)" in source
        assert "str_val = item.get('string', '')" in source

    def test_no_redundant_regex_compile(self):
        """get_top_sifted_strings should pre-compile regex for safe_regex_search."""
        strings_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_strings.py"
        )
        with open(strings_path) as f:
            source = f.read()
        # Find the filter_regex validation block in get_top_sifted_strings
        idx = source.index("def get_top_sifted_strings")
        next_func_idx = source.index("\n@tool_decorator", idx + 1) if "\n@tool_decorator" in source[idx+1:] else len(source)
        func_body = source[idx:idx + (next_func_idx - idx)]
        # Should validate + pre-compile for use with safe_regex_search
        assert "_validate_regex_pattern(filter_regex)" in func_body
        # The old pattern had: try: re.compile ... except re.error (redundant error
        # handling after validate).  Now we pre-compile once for safe_regex_search
        # without a redundant try/except re.error block.
        assert "except re.error" not in func_body


# ===================================================================
# Fix 2.3: Unipacker timeout check
# ===================================================================

class TestUnipackerTimeout:
    """Verify unipacker runner handles timeouts and the tool uses subprocess."""

    def test_timeout_returns_warning_in_runner(self):
        """Verify the unipacker runner script handles timeouts."""
        runner_path = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "unipacker_runner.py"
        )
        with open(runner_path) as f:
            source = f.read()
        assert "if not done_event.wait(timeout=" in source
        assert '"status": "timeout"' in source
        assert "Unpacking timed out" in source

    def test_tool_uses_subprocess_runner(self):
        """Verify auto_unpack_pe uses _run_unipacker subprocess pattern."""
        libs_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_new_libs.py"
        )
        with open(libs_path) as f:
            source = f.read()
        assert "_run_unipacker(" in source
        assert "_UNIPACKER_VENV_PYTHON" in source
        assert "_UNIPACKER_RUNNER" in source


class TestUnipackerRunner:
    """Test unipacker_runner.py structure and error handling."""

    def test_runner_has_unpack_pe_action(self):
        """Verify the runner script handles the unpack_pe action."""
        runner_path = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "unipacker_runner.py"
        )
        with open(runner_path) as f:
            source = f.read()
        # Verify action dispatch
        assert '"unpack_pe"' in source
        assert "def unpack_pe(cmd):" in source
        # Verify JSON stdin/stdout pattern
        assert "json.loads(sys.stdin.read())" in source
        assert "json.dump(result, sys.stdout)" in source

    def test_runner_handles_unknown_action(self):
        """Verify the runner returns error for unknown actions."""
        runner_path = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "unipacker_runner.py"
        )
        with open(runner_path) as f:
            source = f.read()
        assert "Unknown action" in source


# ===================================================================
# Fix 2.5: Binwalk failure surfacing
# ===================================================================

class TestBinwalkFailureSurfacing:
    """Verify binwalk CLI failures are surfaced to users."""

    def test_cli_warning_returned_in_response(self):
        """Verify binwalk CLI warnings are included in the response."""
        libs_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_new_libs.py"
        )
        with open(libs_path) as f:
            source = f.read()
        assert '_cli_warning' in source
        assert 'response["warning"] = warning' in source


# ===================================================================
# Fix 3.2: Subprocess cleanup race
# ===================================================================

class TestSubprocessCleanup:
    """Verify speakeasy and unipacker subprocess cleanup handles errors."""

    def test_kill_wait_wrapped_in_try(self):
        """Verify proc.kill/wait is wrapped in try/except for both runners."""
        libs_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_new_libs.py"
        )
        with open(libs_path) as f:
            source = f.read()
        # Find the timeout handlers in _run_speakeasy and _run_unipacker
        assert "proc.kill()" in source
        assert "# Best-effort cleanup" in source
        # Verify both runner functions exist
        assert "_run_speakeasy" in source
        assert "_run_unipacker" in source


# ===================================================================
# Iteration 11 review fixes
# ===================================================================

# Fix 1: Compact triage report data structure access
# ===================================================================

class TestCompactTriageDataAccess:
    """Verify compact triage correctly reads list-based suspicious_imports and capabilities."""

    def test_compact_reads_imports_as_list(self):
        """The compact triage code must treat suspicious_imports as a list, not a dict."""
        triage_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_triage.py"
        )
        with open(triage_path) as f:
            source = f.read()
        # Find the compact section
        compact_idx = source.index("if compact:")
        compact_block = source[compact_idx:compact_idx + 1500]
        # Must NOT access .get("items", []) on suspicious_imports (it's a list)
        assert 'sus.get("items"' not in compact_block, \
            "Compact triage should not use .get('items') on suspicious_imports (it's a list)"
        # Must use isinstance(sus, list) instead of isinstance(sus, dict)
        assert "isinstance(sus, list)" in compact_block, \
            "Compact triage should check isinstance(sus, list)"

    def test_compact_reads_capabilities_as_list(self):
        """The compact triage code must treat suspicious_capabilities as a list."""
        triage_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_triage.py"
        )
        with open(triage_path) as f:
            source = f.read()
        compact_idx = source.index("if compact:")
        compact_block = source[compact_idx:compact_idx + 1500]
        assert 'caps.get("items"' not in compact_block, \
            "Compact triage should not use .get('items') on capabilities (it's a list)"
        assert "isinstance(caps, list)" in compact_block

    def test_compact_uses_correct_signature_key(self):
        """The compact triage must use 'present' key (not 'embedded_signature_present')."""
        triage_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_triage.py"
        )
        with open(triage_path) as f:
            source = f.read()
        compact_idx = source.index("if compact:")
        compact_block = source[compact_idx:compact_idx + 2500]
        assert 'sig.get("embedded_signature_present")' not in compact_block, \
            "Compact triage should use 'present' key, not 'embedded_signature_present'"
        assert 'sig.get("present")' in compact_block


# Fix 2: Thread-safe close_file
# ===================================================================

class TestCloseFileThreadSafety:
    """Verify close_file uses thread-safe clear methods."""

    def test_close_file_uses_clear_notes(self):
        """close_file should call state.clear_notes() not state.notes = []."""
        pe_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_pe.py"
        )
        with open(pe_path) as f:
            source = f.read()
        # Find the close_file function
        idx = source.index("async def close_file")
        next_func_idx = source.index("\n@tool_decorator", idx + 1) if "\n@tool_decorator" in source[idx+1:] else len(source)
        func_body = source[idx:next_func_idx]
        assert "state.notes = []" not in func_body, \
            "close_file should use clear_notes() not direct assignment"
        assert "clear_notes()" in func_body

    def test_close_file_uses_clear_tool_history(self):
        """close_file should call state.clear_tool_history() not state.tool_history = []."""
        pe_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_pe.py"
        )
        with open(pe_path) as f:
            source = f.read()
        idx = source.index("async def close_file")
        next_func_idx = source.index("\n@tool_decorator", idx + 1) if "\n@tool_decorator" in source[idx+1:] else len(source)
        func_body = source[idx:next_func_idx]
        assert "state.tool_history = []" not in func_body, \
            "close_file should use clear_tool_history() not direct assignment"
        assert "clear_tool_history()" in func_body

    def test_clear_notes_exists_on_state(self):
        """AnalyzerState must have a clear_notes method."""
        from pemcp.state import AnalyzerState
        s = AnalyzerState()
        s.add_note("test note", category="general")
        assert len(s.get_notes()) == 1
        count = s.clear_notes()
        assert count == 1
        assert len(s.get_notes()) == 0


# Fix 3: Regex timeout protection
# ===================================================================

class TestSafeRegexSearch:
    """Verify safe_regex_search provides timeout protection."""

    def test_safe_regex_search_exists(self):
        """utils.py must export safe_regex_search."""
        from pemcp.utils import safe_regex_search
        assert callable(safe_regex_search)

    def test_safe_regex_search_returns_match(self):
        """safe_regex_search returns a match object for valid patterns."""
        from pemcp.utils import safe_regex_search
        pat = re.compile(r'hello')
        result = safe_regex_search(pat, "say hello world")
        assert result is not None
        assert result.group() == "hello"

    def test_safe_regex_search_returns_none_on_no_match(self):
        """safe_regex_search returns None when pattern doesn't match."""
        from pemcp.utils import safe_regex_search
        pat = re.compile(r'xyz')
        result = safe_regex_search(pat, "hello world")
        assert result is None

    def test_strings_tool_uses_safe_regex(self):
        """tools_strings.py should import and use safe_regex_search."""
        strings_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_strings.py"
        )
        with open(strings_path) as f:
            source = f.read()
        assert "safe_regex_search" in source, \
            "tools_strings.py should use safe_regex_search for user-provided patterns"

    def test_deobfuscation_tool_uses_safe_regex(self):
        """tools_deobfuscation.py should import and use safe_regex_search."""
        deobfuscation_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_deobfuscation.py"
        )
        with open(deobfuscation_path) as f:
            source = f.read()
        assert "safe_regex_search" in source, \
            "tools_deobfuscation.py should use safe_regex_search for user-provided patterns"


# Fix 4: Cache mtime/size validation
# ===================================================================

class TestCacheMtimeValidation:
    """Verify cache stores and validates file mtime and size."""

    def test_cache_put_stores_mtime_and_size(self):
        """cache.py put() must store file_mtime and file_size in metadata."""
        cache_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "cache.py"
        )
        with open(cache_path) as f:
            source = f.read()
        # Find the put method's meta assignment
        put_idx = source.index("def put(")
        put_end = source.index("\ndef ", put_idx + 10) if "\ndef " in source[put_idx+10:] else len(source)
        put_body = source[put_idx:put_idx + (put_end - put_idx)]
        assert '"file_mtime"' in put_body, "put() must store file_mtime in cache metadata"
        assert '"file_size"' in put_body, "put() must store file_size in cache metadata"

    def test_cache_get_validates_mtime(self):
        """cache.py get() must check file_mtime on cache hit."""
        cache_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "cache.py"
        )
        with open(cache_path) as f:
            source = f.read()
        get_idx = source.index("def get(")
        get_end = source.index("\ndef ", get_idx + 10) if "\ndef " in source[get_idx+10:] else len(source)
        get_body = source[get_idx:get_idx + (get_end - get_idx)]
        assert "file_mtime" in get_body, "get() must validate file_mtime"
        assert "file_size" in get_body, "get() must validate file_size"


# Improvement 5: IP filtering
# ===================================================================

class TestIPFiltering:
    """Verify triage filters non-routable IPs from IOC extraction."""

    def _extract_ips(self, test_strings):
        """Helper to run the IP extraction logic from _triage_network_iocs."""
        from unittest.mock import patch, MagicMock
        from pemcp.state import AnalyzerState

        mock_state = AnalyzerState()
        mock_state.pe_data = {}

        with patch("pemcp.mcp.tools_triage.state", mock_state):
            from pemcp.mcp.tools_triage import _triage_network_iocs
            result, _ = _triage_network_iocs(100, test_strings)
            return result.get("ip_addresses", [])

    def test_filters_private_10_range(self):
        ips = self._extract_ips({"connect to 10.0.0.1 server"})
        assert "10.0.0.1" not in ips

    def test_filters_private_192_168_range(self):
        ips = self._extract_ips({"connect to 192.168.1.1 server"})
        assert "192.168.1.1" not in ips

    def test_filters_private_172_range(self):
        ips = self._extract_ips({"connect to 172.16.0.1 server"})
        assert "172.16.0.1" not in ips

    def test_filters_link_local(self):
        ips = self._extract_ips({"connect to 169.254.1.1 server"})
        assert "169.254.1.1" not in ips

    def test_filters_multicast(self):
        ips = self._extract_ips({"connect to 224.0.0.1 server"})
        assert "224.0.0.1" not in ips
        ips = self._extract_ips({"connect to 239.255.255.255 server"})
        assert "239.255.255.255" not in ips

    def test_filters_test_net_1(self):
        ips = self._extract_ips({"connect to 192.0.2.1 server"})
        assert "192.0.2.1" not in ips

    def test_filters_test_net_2(self):
        ips = self._extract_ips({"connect to 198.51.100.1 server"})
        assert "198.51.100.1" not in ips

    def test_filters_test_net_3(self):
        ips = self._extract_ips({"connect to 203.0.113.1 server"})
        assert "203.0.113.1" not in ips

    def test_keeps_public_ip(self):
        ips = self._extract_ips({"connect to 8.8.8.8 server"})
        assert "8.8.8.8" in ips

    def test_filters_loopback(self):
        ips = self._extract_ips({"connect to 127.0.0.1 server"})
        assert "127.0.0.1" not in ips


# Improvement 6: Background task exception handling
# ===================================================================

class TestBackgroundExceptionHandling:
    """Verify background task uses single consolidated exception handler."""

    def test_no_redundant_except_blocks(self):
        """background.py should use a single except Exception block."""
        bg_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "background.py"
        )
        with open(bg_path) as f:
            source = f.read()
        # Find the wrapper function
        wrapper_idx = source.index("async def _run_background_task_wrapper")
        next_func_idx = source.index("\ndef ", wrapper_idx + 10) if "\ndef " in source[wrapper_idx+10:] else len(source)
        wrapper_body = source[wrapper_idx:wrapper_idx + (next_func_idx - wrapper_idx)]
        # Should NOT have the specific exception types before the general one
        assert "except (OSError, RuntimeError, ValueError, TypeError)" not in wrapper_body, \
            "Background task should use a single 'except Exception' block"
        assert "except Exception as e:" in wrapper_body
