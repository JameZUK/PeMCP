"""Tests for streamlined binary analysis tools.

Covers: get_focused_imports, get_strings_summary, get_triage_report(compact),
get_config environment info, get_function_map (PE-only fallback),
auto_note_function, get_analysis_digest, get_session_summary (analysis_phase),
get_function_complexity_list(compact), _category_maps module.
"""
import os
import asyncio
import pytest
import time

pytest.importorskip("pefile", reason="pefile not installed")


def _run(coro):
    """Helper to run async functions in tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ===================================================================
# Category Maps Module
# ===================================================================

class TestCategoryMaps:
    """Test _category_maps module loads correctly."""

    def test_categorized_imports_db_has_entries(self):
        from pemcp.mcp._category_maps import CATEGORIZED_IMPORTS_DB
        assert len(CATEGORIZED_IMPORTS_DB) > 50
        # Each entry should be (risk, category) tuple
        for api, val in CATEGORIZED_IMPORTS_DB.items():
            assert isinstance(val, tuple) and len(val) == 2
            risk, cat = val
            assert risk in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert isinstance(cat, str)

    def test_risk_order_complete(self):
        from pemcp.mcp._category_maps import RISK_ORDER
        assert "CRITICAL" in RISK_ORDER
        assert "HIGH" in RISK_ORDER
        assert "MEDIUM" in RISK_ORDER

    def test_string_patterns_compile(self):
        from pemcp.mcp._category_maps import STRING_CATEGORY_PATTERNS
        import re
        for name, pattern in STRING_CATEGORY_PATTERNS.items():
            assert isinstance(pattern, re.Pattern), f"{name} is not a compiled regex"

    def test_category_descriptions_present(self):
        from pemcp.mcp._category_maps import CATEGORY_DESCRIPTIONS, CATEGORIZED_IMPORTS_DB
        # Every category in the DB should have a description
        categories_in_db = {cat for _, (_, cat) in CATEGORIZED_IMPORTS_DB.items()}
        for cat in categories_in_db:
            assert cat in CATEGORY_DESCRIPTIONS, f"Missing description for category '{cat}'"


# ===================================================================
# Container Detection
# ===================================================================

class TestContainerDetection:
    """Test container detection logic."""

    def test_detect_container_returns_dict(self):
        from pemcp.mcp.tools_config import _detect_container
        result = _detect_container()
        assert isinstance(result, dict)
        assert "containerized" in result
        assert "container_type" in result

    def test_get_environment_info_returns_dict(self):
        from pemcp.mcp.tools_config import _get_environment_info
        result = _get_environment_info()
        assert isinstance(result, dict)
        assert "containerized" in result
        assert "paths" in result
        assert "writable_paths" in result
        assert "recommended_export_path" in result
        # recommended path should be a non-empty string
        assert isinstance(result["recommended_export_path"], str)
        assert len(result["recommended_export_path"]) > 0

    def test_environment_paths_structure(self):
        from pemcp.mcp.tools_config import _get_environment_info
        result = _get_environment_info()
        for key in ("samples_dir", "cache_dir", "export_dir"):
            assert key in result["paths"], f"Missing path key: {key}"
            path_info = result["paths"][key]
            assert "internal" in path_info
            assert "writable" in path_info
            assert isinstance(path_info["writable"], bool)


# ===================================================================
# Analysis Phase Detection
# ===================================================================

class TestAnalysisPhase:
    """Test analysis phase detection logic."""

    def test_not_started_phase(self, clean_state):
        from pemcp.mcp.tools_session import _detect_analysis_phase
        assert _detect_analysis_phase() == "not_started"

    def test_file_loaded_phase(self, clean_state):
        from pemcp.config import state
        from pemcp.mcp.tools_session import _detect_analysis_phase
        state.filepath = "/fake/file.exe"
        state.pe_data = {"mode": "pe", "file_hashes": {}}
        assert _detect_analysis_phase() == "file_loaded"


# ===================================================================
# Focused Imports
# ===================================================================

class TestFocusedImports:
    """Test get_focused_imports with mocked PE data."""

    @pytest.fixture(autouse=True)
    def setup_state(self, clean_state):
        from pemcp.config import state
        state.filepath = "/fake/test.exe"
        state.pe_data = {
            "mode": "pe",
            "file_hashes": {"sha256": "a" * 64},
            "imports": [
                {
                    "dll_name": "kernel32.dll",
                    "symbols": [
                        {"name": "CreateRemoteThread", "ordinal": None},
                        {"name": "WriteProcessMemory", "ordinal": None},
                        {"name": "GetLastError", "ordinal": None},
                        {"name": "HeapAlloc", "ordinal": None},
                        {"name": "VirtualAllocEx", "ordinal": None},
                    ]
                },
                {
                    "dll_name": "ws2_32.dll",
                    "symbols": [
                        {"name": "WSAStartup", "ordinal": None},
                        {"name": "connect", "ordinal": None},
                        {"name": "send", "ordinal": None},
                    ]
                },
                {
                    "dll_name": "user32.dll",
                    "symbols": [
                        {"name": "MessageBoxA", "ordinal": None},
                        {"name": "GetWindowTextA", "ordinal": None},
                    ]
                },
            ],
        }

    def test_returns_suspicious_only(self, mock_ctx):
        from pemcp.mcp.tools_pe import get_focused_imports
        result = _run(get_focused_imports.__wrapped__(mock_ctx))
        assert "filtered_imports" in result
        assert result["total_suspicious"] > 0
        # Should not include GetLastError or HeapAlloc
        func_names = [i["function"] for i in result["filtered_imports"]]
        assert "GetLastError" not in func_names
        assert "HeapAlloc" not in func_names
        # Should include CreateRemoteThread
        assert "CreateRemoteThread" in func_names

    def test_category_filter(self, mock_ctx):
        from pemcp.mcp.tools_pe import get_focused_imports
        result = _run(get_focused_imports.__wrapped__(mock_ctx, category="networking"))
        func_names = [i["function"] for i in result["filtered_imports"]]
        # Should include networking only
        assert "WSAStartup" in func_names or "connect" in func_names or "send" in func_names
        # Should not include process injection
        assert "CreateRemoteThread" not in func_names

    def test_benign_summary(self, mock_ctx):
        from pemcp.mcp.tools_pe import get_focused_imports
        result = _run(get_focused_imports.__wrapped__(mock_ctx, include_benign_summary=True))
        assert "benign_summary" in result
        assert "Filtered out" in result["benign_summary"]

    def test_by_category_counts(self, mock_ctx):
        from pemcp.mcp.tools_pe import get_focused_imports
        result = _run(get_focused_imports.__wrapped__(mock_ctx))
        assert "by_category" in result
        assert isinstance(result["by_category"], dict)


# ===================================================================
# Strings Summary
# ===================================================================

class TestStringsSummary:
    """Test get_strings_summary with mocked string data."""

    @pytest.fixture(autouse=True)
    def setup_state(self, clean_state):
        from pemcp.config import state
        state.filepath = "/fake/test.exe"
        state.pe_data = {
            "mode": "pe",
            "file_hashes": {"sha256": "b" * 64},
            "basic_ascii_strings": [
                {"string": "http://evil.com/payload.exe", "offset": 0x1000},
                {"string": "192.168.1.100", "offset": 0x1100},
                {"string": "10.0.0.1", "offset": 0x1200},  # private IP
                {"string": "C:\\Windows\\System32\\cmd.exe", "offset": 0x1300},
                {"string": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "offset": 0x1400},
                {"string": "Global\\MyMutex", "offset": 0x1500},
                {"string": "Hello World", "offset": 0x1600},
                {"string": "user@example.com", "offset": 0x1700},
            ],
            "floss_analysis": {
                "strings": {
                    "static_strings": [
                        {"string": "evil.com", "sifter_score": 9.5},
                        {"string": "payload", "sifter_score": 8.0},
                    ]
                }
            },
        }

    def test_returns_categorized_strings(self, mock_ctx):
        from pemcp.mcp.tools_strings import get_strings_summary
        result = _run(get_strings_summary.__wrapped__(mock_ctx))
        assert "total_strings" in result
        assert "categorized" in result
        assert result["total_strings"] > 0

    def test_url_category(self, mock_ctx):
        from pemcp.mcp.tools_strings import get_strings_summary
        result = _run(get_strings_summary.__wrapped__(mock_ctx))
        cats = result["categorized"]
        assert "urls" in cats
        assert cats["urls"]["count"] >= 1

    def test_file_paths_category(self, mock_ctx):
        from pemcp.mcp.tools_strings import get_strings_summary
        result = _run(get_strings_summary.__wrapped__(mock_ctx))
        cats = result["categorized"]
        assert "file_paths" in cats

    def test_mutex_category(self, mock_ctx):
        from pemcp.mcp.tools_strings import get_strings_summary
        result = _run(get_strings_summary.__wrapped__(mock_ctx))
        cats = result["categorized"]
        assert "mutex_names" in cats

    def test_private_ips_filtered(self, mock_ctx):
        from pemcp.mcp.tools_strings import get_strings_summary
        result = _run(get_strings_summary.__wrapped__(mock_ctx))
        cats = result["categorized"]
        # 10.0.0.1 is private and should be filtered
        if "ip_addresses" in cats:
            for ip in cats["ip_addresses"]["examples"]:
                assert not ip.startswith("10.")

    def test_sifter_distribution(self, mock_ctx):
        from pemcp.mcp.tools_strings import get_strings_summary
        result = _run(get_strings_summary.__wrapped__(mock_ctx))
        assert "sifter_score_distribution" in result
        dist = result["sifter_score_distribution"]
        assert "9-10" in dist


# ===================================================================
# Auto Note Function
# ===================================================================

class TestAutoNoteFunction:
    """Test auto_note_function without angr."""

    @pytest.fixture(autouse=True)
    def setup_state(self, clean_state):
        from pemcp.config import state
        state.filepath = "/fake/test.exe"
        state.pe_data = {
            "mode": "pe",
            "file_hashes": {"sha256": "c" * 64},
        }

    def test_custom_summary_creates_note(self, mock_ctx):
        from pemcp.mcp.tools_notes import auto_note_function
        result = _run(auto_note_function.__wrapped__(
            mock_ctx,
            function_address="0x401000",
            custom_summary="Injects code into remote process"
        ))
        assert result["auto_summary"] == "Injects code into remote process"
        assert result["note_id"].startswith("n_")
        assert result["address"] == "0x401000"

    def test_no_angr_fallback(self, mock_ctx):
        from pemcp.mcp.tools_notes import auto_note_function
        result = _run(auto_note_function.__wrapped__(
            mock_ctx,
            function_address="0x401000",
        ))
        assert "auto_summary" in result
        assert "note_id" in result


# ===================================================================
# Analysis Digest
# ===================================================================

class TestAnalysisDigest:
    """Test get_analysis_digest with mocked state."""

    @pytest.fixture(autouse=True)
    def setup_state(self, clean_state):
        from pemcp.config import state
        state.filepath = "/fake/test.exe"
        state.pe_data = {
            "mode": "pe",
            "file_hashes": {"sha256": "d" * 64},
        }

    def test_returns_digest_without_triage(self, mock_ctx):
        from pemcp.mcp.tools_session import get_analysis_digest
        result = _run(get_analysis_digest.__wrapped__(mock_ctx))
        assert "binary_profile" in result
        assert "Triage not yet run" in result["binary_profile"]

    def test_returns_digest_with_cached_triage(self, mock_ctx):
        from pemcp.config import state
        from pemcp.mcp.tools_session import get_analysis_digest
        state._cached_triage = {
            "risk_level": "HIGH",
            "risk_score": 15,
            "packing_assessment": {"likely_packed": True, "packer_name": "UPX"},
            "digital_signature": {"embedded_signature_present": False},
            "network_iocs": {
                "ip_addresses": ["1.2.3.4"],
                "urls": [],
                "domains": ["evil.com"],
                "registry_keys": [],
            },
        }
        result = _run(get_analysis_digest.__wrapped__(mock_ctx))
        assert "HIGH" in result["binary_profile"]
        assert "coverage" in result
        assert result["coverage"]["functions_explored"] == 0

    def test_since_last_digest_updates_timestamp(self, mock_ctx):
        from pemcp.config import state
        from pemcp.mcp.tools_session import get_analysis_digest
        assert state.last_digest_timestamp == 0.0
        _run(get_analysis_digest.__wrapped__(mock_ctx))
        assert state.last_digest_timestamp > 0.0

    def test_function_notes_in_digest(self, mock_ctx):
        from pemcp.config import state
        from pemcp.mcp.tools_session import get_analysis_digest
        state.add_note(content="Does process injection", category="function", address="0x401000")
        result = _run(get_analysis_digest.__wrapped__(mock_ctx))
        assert "functions_explored" in result
        assert len(result["functions_explored"]) == 1
        assert result["functions_explored"][0]["one_liner"] == "Does process injection"


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def clean_state():
    """Reset global state for each test."""
    from pemcp.config import state
    old_filepath = state.filepath
    old_pe_data = state.pe_data
    old_pe_object = state.pe_object
    old_triage = getattr(state, '_cached_triage', None)
    old_scores = getattr(state, '_cached_function_scores', None)
    old_digest_ts = getattr(state, 'last_digest_timestamp', 0.0)

    # Reset
    state.filepath = None
    state.pe_data = None
    state.pe_object = None
    state._cached_triage = None
    state._cached_function_scores = None
    state.last_digest_timestamp = 0.0
    # Clear notes
    state.notes = []

    yield

    # Restore
    state.filepath = old_filepath
    state.pe_data = old_pe_data
    state.pe_object = old_pe_object
    state._cached_triage = old_triage
    state._cached_function_scores = old_scores
    state.last_digest_timestamp = old_digest_ts


@pytest.fixture
def mock_ctx():
    """Minimal mock MCP context."""
    class MockCtx:
        async def info(self, msg): pass
        async def warning(self, msg): pass
        async def error(self, msg): pass
        async def report_progress(self, current, total): pass
    return MockCtx()
