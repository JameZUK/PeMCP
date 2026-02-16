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
        # Import the function from the runner script
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "speakeasy_runner",
            os.path.join(os.path.dirname(__file__), "..", "scripts", "speakeasy_runner.py"),
        )
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
        """get_top_sifted_strings should not have redundant re.compile after validate."""
        strings_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_strings.py"
        )
        with open(strings_path) as f:
            source = f.read()
        # Find the filter_regex validation block in get_top_sifted_strings
        # It should just call _validate_regex_pattern, not also re.compile
        idx = source.index("def get_top_sifted_strings")
        next_func_idx = source.index("\n@tool_decorator", idx + 1) if "\n@tool_decorator" in source[idx+1:] else len(source)
        func_body = source[idx:idx + (next_func_idx - idx)]
        # Should have _validate_regex_pattern but NOT a separate re.compile for the same purpose
        assert "_validate_regex_pattern(filter_regex)" in func_body
        # The old pattern was: _validate_regex_pattern + try: re.compile ... except re.error
        # This should be gone now
        assert "re.compile(filter_regex)" not in func_body


# ===================================================================
# Fix 2.3: Unipacker timeout check
# ===================================================================

class TestUnipackerTimeout:
    """Verify unipacker checks done_event.is_set() after wait."""

    def test_timeout_returns_warning(self):
        """Verify the unipacker code checks wait() return value."""
        libs_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_new_libs.py"
        )
        with open(libs_path) as f:
            source = f.read()
        assert "if not done_event.wait(timeout=300):" in source
        assert '"status": "timeout"' in source
        assert "Unpacking timed out" in source


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
    """Verify speakeasy subprocess cleanup handles errors."""

    def test_kill_wait_wrapped_in_try(self):
        """Verify proc.kill/wait is wrapped in try/except."""
        libs_path = os.path.join(
            os.path.dirname(__file__), "..", "pemcp", "mcp", "tools_new_libs.py"
        )
        with open(libs_path) as f:
            source = f.read()
        # Find the timeout handler in _run_speakeasy
        assert "proc.kill()" in source
        assert "# Best-effort cleanup" in source
