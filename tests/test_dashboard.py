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
            from arkana.mcp.tools_angr import _decompile_cache, _decompile_meta
        except ImportError:
            pytest.skip("angr tools not importable")
        # Inject a cached decompilation
        cache_key = (0x401000,)
        _decompile_cache.set("decompile_function_with_angr", cache_key, [
            "void test_func(void) {",
            "    return;",
            "}",
        ])
        _decompile_meta[cache_key] = {
            "function_name": "test_func",
            "address": "0x401000",
        }
        try:
            result = get_decompiled_code("0x401000")
            assert result["cached"] is True
            assert result["function_name"] == "test_func"
            assert result["line_count"] == 3
            assert "void test_func" in result["lines"][0]
        finally:
            bucket = _decompile_cache._store.get("decompile_function_with_angr")
            if bucket:
                bucket.pop(cache_key, None)
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
            assert bs["floss_top_decoded"] == ["decoded_payload"]
            assert bs["floss_top_stack"] == ["stack_secret"]
        finally:
            _default_state.pe_data = old_pd
            _default_state.filepath = old_fp
