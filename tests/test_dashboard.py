"""Tests for the Arkana Web Dashboard."""
import os
import tempfile
import pytest

from arkana.state import AnalyzerState, _default_state, _session_registry, _registry_lock


# ---------------------------------------------------------------------------
#  Triage status on AnalyzerState
# ---------------------------------------------------------------------------

class TestTriageStatus:
    def setup_method(self):
        self.state = AnalyzerState()

    def test_set_and_get_triage(self):
        self.state.set_triage_status("0x401000", "flagged")
        assert self.state.get_triage_status("0x401000") == "flagged"

    def test_default_unreviewed(self):
        assert self.state.get_triage_status("0xdeadbeef") == "unreviewed"

    def test_get_all_triage(self):
        self.state.set_triage_status("0x1000", "clean")
        self.state.set_triage_status("0x2000", "suspicious")
        result = self.state.get_triage_status()
        assert isinstance(result, dict)
        assert result["0x1000"] == "clean"
        assert result["0x2000"] == "suspicious"

    def test_invalid_status_raises(self):
        with pytest.raises(ValueError):
            self.state.set_triage_status("0x1000", "invalid_status")

    def test_snapshot(self):
        self.state.set_triage_status("0x1000", "flagged")
        snap = self.state.get_all_triage_snapshot()
        assert snap == {"0x1000": "flagged"}
        # Snapshot is a copy
        snap["0x1000"] = "clean"
        assert self.state.get_triage_status("0x1000") == "flagged"

    def test_clear(self):
        self.state.set_triage_status("0x1000", "flagged")
        self.state.set_triage_status("0x2000", "clean")
        count = self.state.clear_triage()
        assert count == 2
        assert self.state.get_triage_status() == {}

    def test_address_normalized_lowercase(self):
        self.state.set_triage_status("0xABCD", "suspicious")
        assert self.state.get_triage_status("0xabcd") == "suspicious"


# ---------------------------------------------------------------------------
#  state_api data extraction
# ---------------------------------------------------------------------------

class TestStateApi:
    def setup_method(self):
        """Clear session registry so _get_state() uses _default_state."""
        with _registry_lock:
            self._saved_registry = dict(_session_registry)
            _session_registry.clear()

    def teardown_method(self):
        with _registry_lock:
            _session_registry.clear()
            _session_registry.update(self._saved_registry)

    def test_overview_no_file(self):
        from arkana.dashboard.state_api import get_overview_data
        # Temporarily clear default state
        old_fp = _default_state.filepath
        old_pd = _default_state.pe_data
        _default_state.filepath = None
        _default_state.pe_data = None
        try:
            data = get_overview_data()
            assert data["file_loaded"] is False
            assert data["filename"] is None
            assert data["phase"] == "not_started"
        finally:
            _default_state.filepath = old_fp
            _default_state.pe_data = old_pd

    def test_overview_with_file(self):
        from arkana.dashboard.state_api import get_overview_data
        old_fp = _default_state.filepath
        old_pd = _default_state.pe_data
        _default_state.filepath = "/tmp/test.exe"
        _default_state.pe_data = {
            "file_hashes": {"sha256": "abc123", "md5": "def456"},
            "mode": "pe",
        }
        try:
            data = get_overview_data()
            assert data["file_loaded"] is True
            assert data["filename"] == "test.exe"
            assert data["sha256"] == "abc123"
        finally:
            _default_state.filepath = old_fp
            _default_state.pe_data = old_pd

    def test_get_state_session_registry_fallback(self):
        """Dashboard should find state from session registry when _default_state is empty."""
        from arkana.dashboard.state_api import _get_state, get_overview_data
        from arkana.state import _session_registry, _registry_lock, AnalyzerState
        # Create a session state with a file loaded
        session_state = AnalyzerState()
        session_state.filepath = "/tmp/session_file.exe"
        session_state.pe_data = {"file_hashes": {"sha256": "sess123"}, "mode": "pe"}
        # Register it
        with _registry_lock:
            _session_registry["test_session"] = session_state
        try:
            # Default state has no file — should fall back to session state
            old_fp = _default_state.filepath
            _default_state.filepath = None
            try:
                resolved = _get_state()
                assert resolved is session_state
                data = get_overview_data()
                assert data["file_loaded"] is True
                assert data["filename"] == "session_file.exe"
            finally:
                _default_state.filepath = old_fp
        finally:
            with _registry_lock:
                _session_registry.pop("test_session", None)

    def test_functions_no_angr(self):
        from arkana.dashboard.state_api import get_functions_data
        data = get_functions_data()
        assert isinstance(data, list)

    def test_callgraph_no_angr(self):
        from arkana.dashboard.state_api import get_callgraph_data
        data = get_callgraph_data()
        assert data["nodes"] == []
        assert data["edges"] == []

    def test_sections_no_data(self):
        from arkana.dashboard.state_api import get_sections_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = None
        try:
            data = get_sections_data()
            assert isinstance(data, dict)
            assert data["sections"] == []
        finally:
            _default_state.pe_data = old_pd

    def test_sections_with_data(self):
        from arkana.dashboard.state_api import get_sections_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "sections": [
                {"name": ".text", "virtual_address": "0x1000", "virtual_size": 4096,
                 "raw_size": 4096, "entropy": 6.5, "characteristics": 0x60000020},
            ]
        }
        try:
            data = get_sections_data()
            assert isinstance(data, dict)
            assert len(data["sections"]) == 1
            assert data["sections"][0]["name"] == ".text"
            assert "R" in data["sections"][0]["permissions"]
        finally:
            _default_state.pe_data = old_pd

    def test_timeline_empty(self):
        from arkana.dashboard.state_api import get_timeline_data
        data = get_timeline_data()
        assert isinstance(data, list)

    def test_notes_empty(self):
        from arkana.dashboard.state_api import get_notes_data
        data = get_notes_data()
        assert isinstance(data, list)

    def test_imports_no_data(self):
        from arkana.dashboard.state_api import get_imports_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = None
        try:
            data = get_imports_data()
            assert isinstance(data, dict)
            assert data["imports"] == []
            assert data["total_import_dlls"] == 0
        finally:
            _default_state.pe_data = old_pd

    def test_imports_with_data(self):
        from arkana.dashboard.state_api import get_imports_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "imports": [
                {
                    "dll": "KERNEL32.dll",
                    "symbols": [
                        {"name": "CreateFileW", "address": "0x1000"},
                        {"name": "ReadFile", "address": "0x1004"},
                    ],
                },
                {
                    "dll": "NTDLL.dll",
                    "symbols": [
                        {"name": "NtCreateProcess", "address": "0x2000"},
                    ],
                },
            ],
            "exports": {"functions": [
                {"name": "DllMain", "address": "0x3000", "ordinal": 1},
            ]},
        }
        try:
            data = get_imports_data()
            assert data["total_import_dlls"] == 2
            assert data["total_import_functions"] == 3
            assert data["total_exports"] == 1
            # Search filter
            data_filtered = get_imports_data(search="KERNEL32")
            assert data_filtered["total_import_dlls"] == 1
            assert data_filtered["imports"][0]["dll"] == "KERNEL32.dll"
        finally:
            _default_state.pe_data = old_pd

    def test_overview_string_counts(self):
        from arkana.dashboard.state_api import get_overview_data
        old_pd = _default_state.pe_data
        old_fp = _default_state.filepath
        _default_state.filepath = "/tmp/test.exe"
        _default_state.pe_data = {
            "file_hashes": {"sha256": "abc123"},
            "basic_ascii_strings": ["str1", "str2", "str3"],
            "floss_analysis": {
                "status": "Complete",
                "strings": {
                    "static_strings": [{"string": "a"}] * 10,
                    "stack_strings": [{"string": "b"}] * 3,
                    "decoded_strings": [{"string": "c"}] * 2,
                },
            },
        }
        try:
            data = get_overview_data()
            bs = data["binary_summary"]
            assert bs["basic_string_count"] == 3
            assert bs["floss_static_count"] == 10
            assert bs["floss_stack_count"] == 3
            assert bs["floss_decoded_count"] == 2
        finally:
            _default_state.pe_data = old_pd
            _default_state.filepath = old_fp

    def test_sections_includes_data_directories(self):
        from arkana.dashboard.state_api import get_sections_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "sections": [],
            "data_directories": [
                {"name": "IMPORT_TABLE", "virtual_address": "0x2000", "size": 512},
            ],
            "resources_summary": [
                {"type": "RT_VERSION", "name": "1", "size": 256, "language": "English"},
            ],
        }
        try:
            data = get_sections_data()
            assert len(data["data_directories"]) == 1
            assert len(data["resources"]) == 1
            assert data["data_directories"][0]["name"] == "IMPORT_TABLE"
        finally:
            _default_state.pe_data = old_pd


# ---------------------------------------------------------------------------
#  Dashboard token management
# ---------------------------------------------------------------------------

class TestTokenManagement:
    def test_ensure_token_creates_file(self):
        from arkana.dashboard.app import _ensure_token, _TOKEN_FILE
        import arkana.dashboard.app as app_module
        # Use a temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            test_token_file = os.path.join(tmpdir, "dashboard_token")
            original = app_module._TOKEN_FILE
            app_module._TOKEN_FILE = type(original)(test_token_file)
            try:
                token = _ensure_token()
                assert len(token) > 20
                # Second call returns same token
                assert _ensure_token() == token
                # File exists
                assert os.path.exists(test_token_file)
            finally:
                app_module._TOKEN_FILE = original

    def test_check_token(self):
        from arkana.dashboard.app import _check_token
        assert _check_token("secret123", "secret123") is True
        assert _check_token("wrong", "secret123") is False


# ---------------------------------------------------------------------------
#  Dashboard auth helpers
# ---------------------------------------------------------------------------

class TestDashboardAuth:
    def test_create_dashboard_app(self):
        from arkana.dashboard.app import create_dashboard_app
        app = create_dashboard_app(token="test-token-123")
        # Should be a Starlette app
        assert app is not None
        assert hasattr(app, "routes")

    def test_dashboard_token_stored_on_state(self):
        from arkana.dashboard.app import create_dashboard_app
        create_dashboard_app(token="my-secret-token")
        assert _default_state.dashboard_token == "my-secret-token"


# ---------------------------------------------------------------------------
#  Section permission parsing
# ---------------------------------------------------------------------------

class TestSectionPermissions:
    def test_rx_permissions(self):
        from arkana.dashboard.state_api import _section_permissions
        # IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        assert "R" in _section_permissions({"characteristics": 0x60000000})
        assert "X" in _section_permissions({"characteristics": 0x60000000})

    def test_rw_permissions(self):
        from arkana.dashboard.state_api import _section_permissions
        # IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
        assert "R" in _section_permissions({"characteristics": 0xC0000000})
        assert "W" in _section_permissions({"characteristics": 0xC0000000})

    def test_string_characteristics(self):
        from arkana.dashboard.state_api import _section_permissions
        assert _section_permissions({"characteristics": "RWX"}) == "RWX"

    def test_no_characteristics(self):
        from arkana.dashboard.state_api import _section_permissions
        assert _section_permissions({}) == "?"


# ---------------------------------------------------------------------------
#  Decompile endpoint (state_api)
# ---------------------------------------------------------------------------

class TestDecompileStateApi:
    def test_get_decompiled_code_no_cache(self):
        from arkana.dashboard.state_api import get_decompiled_code
        result = get_decompiled_code("0x401000")
        assert result["cached"] is False

    def test_get_decompiled_code_invalid_address(self):
        from arkana.dashboard.state_api import get_decompiled_code
        result = get_decompiled_code("not_hex")
        assert result["cached"] is False
        assert "error" in result

    def test_get_decompiled_code_with_cache(self):
        from arkana.dashboard.state_api import get_decompiled_code
        try:
            from arkana.mcp.tools_angr import _decompile_meta
        except ImportError:
            pytest.skip("angr tools not importable")
        # Inject a cached decompilation
        cache_key = (0x401000,)
        _decompile_meta[cache_key] = {
            "function_name": "test_func",
            "address": "0x401000",
            "lines": [
                "void test_func(void) {",
                "    return;",
                "}",
            ],
        }
        try:
            result = get_decompiled_code("0x401000")
            assert result["cached"] is True
            assert result["function_name"] == "test_func"
            assert result["line_count"] == 3
            assert "void test_func" in result["lines"][0]
        finally:
            _decompile_meta.pop(cache_key, None)


# ---------------------------------------------------------------------------
#  FLOSS decoded strings in overview
# ---------------------------------------------------------------------------

class TestFlossDecodedStrings:
    def setup_method(self):
        with _registry_lock:
            self._saved_registry = dict(_session_registry)
            _session_registry.clear()

    def teardown_method(self):
        with _registry_lock:
            _session_registry.clear()
            _session_registry.update(self._saved_registry)

    def test_overview_includes_floss_top_decoded(self):
        from arkana.dashboard.state_api import get_overview_data
        old_fp = _default_state.filepath
        old_pd = _default_state.pe_data
        _default_state.filepath = "/tmp/test.exe"
        _default_state.pe_data = {
            "file_hashes": {"sha256": "abc123"},
            "floss_analysis": {
                "status": "Complete",
                "strings": {
                    "static_strings": [],
                    "stack_strings": [{"string": "stack_secret"}],
                    "decoded_strings": [{"string": "decoded_payload"}],
                },
            },
        }
        try:
            data = get_overview_data()
            bs = data["binary_summary"]
            assert bs["floss_top_decoded"] == [{"string": "decoded_payload"}]
            assert bs["floss_top_stack"] == [{"string": "stack_secret"}]
        finally:
            _default_state.pe_data = old_pd
            _default_state.filepath = old_fp


class TestStringsData:
    def setup_method(self):
        with _registry_lock:
            self._saved_registry = dict(_session_registry)
            _session_registry.clear()

    def teardown_method(self):
        with _registry_lock:
            _session_registry.clear()
            _session_registry.update(self._saved_registry)

    def test_strings_no_data(self):
        from arkana.dashboard.state_api import get_strings_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = None
        try:
            data = get_strings_data()
            assert data["total"] == 0
            assert data["strings"] == []
        finally:
            _default_state.pe_data = old_pd

    def test_strings_with_basic_ascii(self):
        from arkana.dashboard.state_api import get_strings_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "basic_ascii_strings": ["hello", "world", "test"],
        }
        try:
            data = get_strings_data()
            assert data["total_unfiltered"] == 3
            assert data["type_counts"]["ASCII"] == 3
            assert data["strings"][0]["type"] == "ASCII"
        finally:
            _default_state.pe_data = old_pd

    def test_strings_filter_by_type(self):
        from arkana.dashboard.state_api import get_strings_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "basic_ascii_strings": ["hello"],
            "floss_analysis": {
                "strings": {
                    "static_strings": [{"string": "static1", "offset": "0x100"}],
                    "stack_strings": [{"string": "stack1", "function_va": "0x401000"}],
                    "decoded_strings": [],
                    "tight_strings": [],
                },
            },
        }
        try:
            data = get_strings_data(string_type="stack")
            assert data["total"] == 1
            assert data["strings"][0]["type"] == "STACK"
        finally:
            _default_state.pe_data = old_pd

    def test_strings_search(self):
        from arkana.dashboard.state_api import get_strings_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "basic_ascii_strings": ["CreateFileW", "ReadFile", "something"],
        }
        try:
            data = get_strings_data(search="File")
            assert data["total"] == 2
        finally:
            _default_state.pe_data = old_pd

    def test_strings_pagination(self):
        from arkana.dashboard.state_api import get_strings_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "basic_ascii_strings": ["s" + str(i) for i in range(10)],
        }
        try:
            data = get_strings_data(offset=3, limit=4)
            assert len(data["strings"]) == 4
            assert data["total"] == 10
            assert data["offset"] == 3
        finally:
            _default_state.pe_data = old_pd

    def test_strings_skips_error_items(self):
        from arkana.dashboard.state_api import get_strings_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "floss_analysis": {
                "strings": {
                    "static_strings": [{"error": "failed"}],
                    "stack_strings": [{"string": "ok", "function_va": "0x1000"}],
                    "decoded_strings": [],
                    "tight_strings": [],
                },
            },
        }
        try:
            data = get_strings_data()
            assert data["total_unfiltered"] == 1
            assert data["strings"][0]["string"] == "ok"
        finally:
            _default_state.pe_data = old_pd


class TestGlobalSearch:
    def setup_method(self):
        with _registry_lock:
            self._saved_registry = dict(_session_registry)
            _session_registry.clear()

    def teardown_method(self):
        with _registry_lock:
            _session_registry.clear()
            _session_registry.update(self._saved_registry)

    def test_search_empty_query(self):
        from arkana.dashboard.state_api import global_search
        result = global_search("")
        assert result == {"functions": [], "strings": [], "imports": [], "notes": []}

    def test_search_strings(self):
        from arkana.dashboard.state_api import global_search
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "basic_ascii_strings": ["CreateFile", "WriteFile", "other"],
        }
        try:
            result = global_search("File")
            assert len(result["strings"]) == 2
            assert result["strings"][0]["type"] == "ASCII"
        finally:
            _default_state.pe_data = old_pd

    def test_search_imports(self):
        from arkana.dashboard.state_api import global_search
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "imports": [{
                "dll": "KERNEL32.dll",
                "symbols": [
                    {"name": "CreateFileW"},
                    {"name": "ReadFile"},
                    {"name": "CloseHandle"},
                ],
            }],
        }
        try:
            result = global_search("Create")
            assert len(result["imports"]) == 1
            assert result["imports"][0]["function"] == "CreateFileW"
        finally:
            _default_state.pe_data = old_pd

    def test_search_notes(self):
        from arkana.dashboard.state_api import global_search
        old_pd = _default_state.pe_data
        _default_state.pe_data = {}
        _default_state.add_note("Suspicious CreateFile call", category="ioc")
        try:
            result = global_search("Suspicious")
            assert len(result["notes"]) == 1
            assert result["notes"][0]["category"] == "ioc"
        finally:
            _default_state.pe_data = old_pd
            _default_state.notes.clear()

    def test_search_limit(self):
        from arkana.dashboard.state_api import global_search
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "basic_ascii_strings": ["match" + str(i) for i in range(20)],
        }
        try:
            result = global_search("match", limit_per_category=5)
            assert len(result["strings"]) == 5
        finally:
            _default_state.pe_data = old_pd


class TestFunctionAnalysis:
    def setup_method(self):
        with _registry_lock:
            self._saved_registry = dict(_session_registry)
            _session_registry.clear()

    def teardown_method(self):
        with _registry_lock:
            _session_registry.clear()
            _session_registry.update(self._saved_registry)

    def test_analysis_no_angr(self):
        from arkana.dashboard.state_api import get_function_analysis_data
        data = get_function_analysis_data("0x401000")
        assert data["address"] == "0x401000"
        assert data["callers"] == []
        assert data["callees"] == []
        assert data["suspicious_apis"] == []
        assert data["complexity"] == {"blocks": 0, "edges": 0}

    def test_analysis_invalid_address(self):
        from arkana.dashboard.state_api import get_function_analysis_data
        data = get_function_analysis_data("not_hex")
        assert data["callers"] == []
        assert data["callees"] == []

    def test_analysis_includes_strings(self):
        from arkana.dashboard.state_api import get_function_analysis_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "floss_analysis": {
                "strings": {
                    "static_strings": [],
                    "stack_strings": [
                        {"string": "secret", "function_va": "0x401000", "string_va": "0x500"},
                    ],
                    "decoded_strings": [],
                    "tight_strings": [],
                },
            },
        }
        try:
            data = get_function_analysis_data("0x401000")
            assert len(data["strings"]) == 1
            assert data["strings"][0]["string"] == "secret"
        finally:
            _default_state.pe_data = old_pd

    def test_analysis_strings_limited_to_20(self):
        from arkana.dashboard.state_api import get_function_analysis_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "floss_analysis": {
                "strings": {
                    "static_strings": [],
                    "stack_strings": [
                        {"string": "s" + str(i), "function_va": "0x401000", "string_va": hex(0x500 + i)}
                        for i in range(30)
                    ],
                    "decoded_strings": [],
                    "tight_strings": [],
                },
            },
        }
        try:
            data = get_function_analysis_data("0x401000")
            assert len(data["strings"]) == 20
        finally:
            _default_state.pe_data = old_pd


class TestFunctionXrefs:
    def setup_method(self):
        with _registry_lock:
            self._saved_registry = dict(_session_registry)
            _session_registry.clear()

    def teardown_method(self):
        with _registry_lock:
            _session_registry.clear()
            _session_registry.update(self._saved_registry)

    def test_xrefs_no_angr(self):
        from arkana.dashboard.state_api import get_function_xrefs_data
        data = get_function_xrefs_data("0x401000")
        assert data["callers"] == []
        assert data["callees"] == []

    def test_xrefs_invalid_address(self):
        from arkana.dashboard.state_api import get_function_xrefs_data
        data = get_function_xrefs_data("not_hex")
        # Without angr loaded, returns empty lists (error only on parse failure with angr)
        assert data["callers"] == []
        assert data["callees"] == []

    def test_function_strings_no_data(self):
        from arkana.dashboard.state_api import get_function_strings_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = None
        try:
            data = get_function_strings_data("0x401000")
            assert data["strings"] == []
        finally:
            _default_state.pe_data = old_pd

    def test_function_strings_match(self):
        from arkana.dashboard.state_api import get_function_strings_data
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "floss_analysis": {
                "strings": {
                    "static_strings": [],
                    "stack_strings": [
                        {"string": "found", "function_va": "0x401000", "string_va": "0x500"},
                        {"string": "other", "function_va": "0x402000", "string_va": "0x600"},
                    ],
                    "decoded_strings": [],
                    "tight_strings": [],
                },
            },
        }
        try:
            data = get_function_strings_data("0x401000")
            assert len(data["strings"]) == 1
            assert data["strings"][0]["string"] == "found"
        finally:
            _default_state.pe_data = old_pd


# ---------------------------------------------------------------------------
#  FLOSS Summary (for strings page detail panel)
# ---------------------------------------------------------------------------

class TestFlossSummary:
    def setup_method(self):
        with _registry_lock:
            self._saved_registry = dict(_session_registry)
            _session_registry.clear()

    def teardown_method(self):
        with _registry_lock:
            _session_registry.clear()
            _session_registry.update(self._saved_registry)

    def test_no_data(self):
        from arkana.dashboard.state_api import get_floss_summary
        old_pd = _default_state.pe_data
        _default_state.pe_data = None
        try:
            data = get_floss_summary()
            assert data["available"] is False
        finally:
            _default_state.pe_data = old_pd

    def test_no_floss_analysis(self):
        from arkana.dashboard.state_api import get_floss_summary
        old_pd = _default_state.pe_data
        _default_state.pe_data = {"basic_ascii_strings": ["hello"]}
        try:
            data = get_floss_summary()
            assert data["available"] is False
        finally:
            _default_state.pe_data = old_pd

    def test_static_only(self):
        from arkana.dashboard.state_api import get_floss_summary
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "floss_analysis": {
                "status": "Complete",
                "strings": {
                    "static_strings": [
                        {"string": "static1", "offset": "0x100"},
                        {"string": "static2", "offset": "0x200"},
                    ],
                    "stack_strings": [],
                    "decoded_strings": [],
                    "tight_strings": [],
                },
            },
        }
        try:
            data = get_floss_summary()
            assert data["available"] is True
            assert data["status"] == "Complete"
            assert data["type_counts"]["STATIC"] == 2
            assert data["type_counts"]["STACK"] == 0
            assert data["total_floss_strings"] == 2
            assert data["top_decoded"] == []
        finally:
            _default_state.pe_data = old_pd

    def test_complete_analysis(self):
        from arkana.dashboard.state_api import get_floss_summary
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "floss_analysis": {
                "status": "Complete",
                "metadata": {"version": "2.3.0"},
                "analysis_config": {"min_length": 4, "timeout": 60},
                "strings": {
                    "static_strings": [{"string": "s" + str(i)} for i in range(5)],
                    "stack_strings": [{"string": "stack_" + str(i), "function_va": "0x1000"} for i in range(3)],
                    "decoded_strings": [{"string": "decoded_" + str(i)} for i in range(7)],
                    "tight_strings": [{"string": "tight_" + str(i)} for i in range(2)],
                },
            },
        }
        try:
            data = get_floss_summary()
            assert data["available"] is True
            assert data["type_counts"]["STATIC"] == 5
            assert data["type_counts"]["STACK"] == 3
            assert data["type_counts"]["DECODED"] == 7
            assert data["type_counts"]["TIGHT"] == 2
            assert data["total_floss_strings"] == 17
            assert len(data["top_decoded"]) == 7
            assert len(data["top_stack"]) == 3
            assert data["top_decoded"][0] == "decoded_0"
            assert data["floss_version"] == "2.3.0"
            assert data["analysis_config"]["min_length"] == 4
        finally:
            _default_state.pe_data = old_pd

    def test_error_entries_skipped(self):
        from arkana.dashboard.state_api import get_floss_summary
        old_pd = _default_state.pe_data
        _default_state.pe_data = {
            "floss_analysis": {
                "status": "Complete",
                "strings": {
                    "static_strings": [{"error": "failed"}, {"string": "ok"}],
                    "stack_strings": [],
                    "decoded_strings": [],
                    "tight_strings": [],
                },
            },
        }
        try:
            data = get_floss_summary()
            assert data["type_counts"]["STATIC"] == 1
            assert data["total_floss_strings"] == 1
        finally:
            _default_state.pe_data = old_pd


# ---------------------------------------------------------------------------
#  Global Status Partial
# ---------------------------------------------------------------------------

class TestGlobalStatusPartial:
    def setup_method(self):
        with _registry_lock:
            self._saved_registry = dict(_session_registry)
            _session_registry.clear()

    def teardown_method(self):
        with _registry_lock:
            _session_registry.clear()
            _session_registry.update(self._saved_registry)

    def test_empty_when_idle(self):
        """Global status partial returns empty content when nothing is running."""
        from arkana.dashboard.state_api import get_overview_data
        old_fp = _default_state.filepath
        old_pd = _default_state.pe_data
        _default_state.filepath = None
        _default_state.pe_data = None
        try:
            data = get_overview_data()
            # No active tool and no background tasks = nothing to show
            assert data["active_tool"] is None
            assert data["background_tasks"] == []
        finally:
            _default_state.filepath = old_fp
            _default_state.pe_data = old_pd


# ---------------------------------------------------------------------------
#  FLOSS progress reporting
# ---------------------------------------------------------------------------

class TestFlossVivisectProgress:
    """Tests for split Vivisect load/analyze with progress polling."""

    def test_load_workspace_calls_progress_callback(self):
        """Verify _load_floss_vivisect_workspace fires progress_callback during analysis."""
        from unittest.mock import patch, MagicMock
        from arkana.parsers.floss import _load_floss_vivisect_workspace

        calls = []

        def _record(pct, msg):
            calls.append((pct, msg))

        mock_vw = MagicMock()
        # getFunctions returns increasing counts across calls
        func_counts = [[], [1, 2, 3], [1, 2, 3, 4, 5]]
        mock_vw.getFunctions.side_effect = func_counts

        # analyze() completes quickly so polling loop fires once before done
        def fast_analyze():
            import time
            time.sleep(0.1)

        mock_vw.analyze.side_effect = fast_analyze

        from pathlib import Path
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".exe") as tmp:
            tmp.write(b"\x00" * 1024)
            tmp.flush()
            sample = Path(tmp.name)

            with patch("arkana.parsers.floss.viv_utils", create=True) as mock_vu, \
                 patch("arkana.parsers.floss.FLOSS_ANALYSIS_OK", True), \
                 patch("arkana.parsers.floss.VIVISECT_POLL_INTERVAL", 0.05):
                mock_vu.getWorkspace.return_value = mock_vw
                result = _load_floss_vivisect_workspace(sample, "pe", progress_callback=_record)

        assert result is mock_vw
        # Should have at least the initial "Loading" and final "Vivisect complete" callbacks
        assert any(pct == 10 for pct, _ in calls), f"Expected 10% callback, got: {calls}"
        assert any("Vivisect complete" in msg for _, msg in calls), f"Expected completion message, got: {calls}"
        # Final callback should be at 40%
        assert any(pct == 40 for pct, _ in calls)

    def test_load_workspace_shellcode_no_split(self):
        """Shellcode format uses one-shot path, still fires progress callback."""
        from unittest.mock import patch, MagicMock
        from arkana.parsers.floss import _load_floss_vivisect_workspace

        calls = []
        mock_vw = MagicMock()

        from pathlib import Path
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".sc32") as tmp:
            tmp.write(b"\x90" * 64)
            tmp.flush()
            sample = Path(tmp.name)

            with patch("arkana.parsers.floss.viv_utils", create=True) as mock_vu, \
                 patch("arkana.parsers.floss.FLOSS_ANALYSIS_OK", True):
                mock_vu.getShellcodeWorkspaceFromFile.return_value = mock_vw
                result = _load_floss_vivisect_workspace(
                    sample, "sc32", progress_callback=lambda p, m: calls.append((p, m)),
                )

        assert result is mock_vw
        assert any(pct == 10 for pct, _ in calls)
        # No polling loop for shellcode — no "Vivisect complete" at 40%
        assert not any(pct == 40 for pct, _ in calls)

    def test_analysis_exception_propagates(self):
        """If vw.analyze() raises, the exception is caught and returns None."""
        from unittest.mock import patch, MagicMock
        from arkana.parsers.floss import _load_floss_vivisect_workspace

        mock_vw = MagicMock()
        mock_vw.analyze.side_effect = RuntimeError("vivisect boom")
        mock_vw.getFunctions.return_value = []

        from pathlib import Path
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".exe") as tmp:
            tmp.write(b"\x00" * 512)
            tmp.flush()
            sample = Path(tmp.name)

            with patch("arkana.parsers.floss.viv_utils", create=True) as mock_vu, \
                 patch("arkana.parsers.floss.FLOSS_ANALYSIS_OK", True), \
                 patch("arkana.parsers.floss.VIVISECT_POLL_INTERVAL", 0.05):
                mock_vu.getWorkspace.return_value = mock_vw
                # The exception from analyze() is caught by the outer try/except
                result = _load_floss_vivisect_workspace(sample, "pe")

        assert result is None  # error is caught and returns None


class TestFlossParseProgressCallback:
    """Tests that _parse_floss_analysis fires progress_callback at expected stages."""

    def _floss_patches(self, mock_vw):
        """Return a stack of patches for a full FLOSS analysis with mocked deps."""
        from unittest.mock import patch
        import contextlib
        return contextlib.ExitStack(), [
            patch("arkana.parsers.floss.FLOSS_AVAILABLE", True),
            patch("arkana.parsers.floss.FLOSS_ANALYSIS_OK", True),
            patch("arkana.parsers.floss._setup_floss_logging"),
            patch("arkana.parsers.floss._load_floss_vivisect_workspace", return_value=mock_vw),
            patch("arkana.parsers.floss.get_imagebase", create=True, return_value=0x400000),
            patch("arkana.parsers.floss.get_static_strings", create=True, return_value=[]),
            patch("arkana.parsers.floss.find_decoding_function_features", create=True, return_value=({}, {})),
            patch("arkana.parsers.floss.extract_stackstrings", create=True, return_value=[]),
            patch("arkana.parsers.floss.get_functions_with_tightloops", create=True, return_value={}),
            patch("arkana.parsers.floss.extract_tightstrings", create=True, return_value=[]),
            patch("arkana.parsers.floss.get_top_functions", create=True, return_value={}),
            patch("arkana.parsers.floss.get_function_fvas", create=True, return_value=set()),
            patch("arkana.parsers.floss.decode_strings", create=True, return_value=[]),
            patch("arkana.parsers.floss.FlossAnalysis", create=True),
        ]

    def test_progress_stages_full_analysis(self):
        """Verify progress callback fires at all expected stages during a complete analysis."""
        from unittest.mock import patch, MagicMock
        from arkana.parsers.floss import _parse_floss_analysis

        calls = []

        def _record(pct, msg):
            calls.append((pct, msg))

        mock_vw = MagicMock()
        mock_vw.getFunctions.return_value = [0x401000, 0x402000]
        mock_vw.getXrefsTo.return_value = []

        import tempfile
        _, patches = self._floss_patches(mock_vw)
        with tempfile.NamedTemporaryFile(suffix=".exe") as tmp:
            tmp.write(b"\x00" * 1024)
            tmp.flush()

            import contextlib
            with contextlib.ExitStack() as stack:
                for p in patches:
                    stack.enter_context(p)

                _parse_floss_analysis(
                    tmp.name, 4, 0, 0, "pe",
                    [], [], [], True,
                    progress_callback=_record,
                )

        # Verify stage progression
        pcts = [pct for pct, _ in calls]
        msgs = [msg for _, msg in calls]

        # Feature identification at 55%
        assert 55 in pcts, f"Expected 55% for feature identification, got {pcts}"
        # Stack strings at 60%
        assert 60 in pcts, f"Expected 60% for stack strings, got {pcts}"
        # Decoded strings at 80%
        assert 80 in pcts, f"Expected 80% for decoded strings, got {pcts}"
        # Finalization at 90%
        assert 90 in pcts, f"Expected 90% for finalization, got {pcts}"

        # Verify messages are descriptive
        assert any("function features" in m for m in msgs)
        assert any("stack strings" in m.lower() for m in msgs)
        assert any("decoded strings" in m.lower() for m in msgs)
        assert any("Finalizing" in m for m in msgs)

    def test_no_callback_does_not_error(self):
        """Verify analysis works fine without a progress_callback."""
        from unittest.mock import MagicMock
        from arkana.parsers.floss import _parse_floss_analysis

        mock_vw = MagicMock()
        mock_vw.getFunctions.return_value = []
        mock_vw.getXrefsTo.return_value = []

        import tempfile, contextlib
        _, patches = self._floss_patches(mock_vw)
        with tempfile.NamedTemporaryFile(suffix=".exe") as tmp:
            tmp.write(b"\x00" * 1024)
            tmp.flush()

            with contextlib.ExitStack() as stack:
                for p in patches:
                    stack.enter_context(p)

                _parse_floss_analysis(
                    tmp.name, 4, 0, 0, "pe",
                    [], [], [], True,
                    # No progress_callback — just verify no exception
                )
