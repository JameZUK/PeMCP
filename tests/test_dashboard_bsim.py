"""Tests for BSim dashboard data functions in state_api.py."""
import os
import sqlite3
import tempfile
import pytest

from arkana.state import _default_state, _session_registry, _registry_lock


class TestBsimDashboard:
    """Tests for BSim signature database dashboard functions."""

    def setup_method(self):
        with _registry_lock:
            self._saved_registry = dict(_session_registry)
            _session_registry.clear()
        from arkana.dashboard.state_api import _bsim_triage_cache
        self._saved_triage_cache = dict(_bsim_triage_cache)
        _bsim_triage_cache.clear()

    def teardown_method(self):
        with _registry_lock:
            _session_registry.clear()
            _session_registry.update(self._saved_registry)
        from arkana.dashboard.state_api import _bsim_triage_cache
        _bsim_triage_cache.clear()
        _bsim_triage_cache.update(self._saved_triage_cache)

    # --- SHA256 validation ---
    def test_validate_sha256_valid(self):
        from arkana.dashboard.state_api import _validate_sha256
        assert _validate_sha256("a" * 64) is True
        assert _validate_sha256("0123456789abcdef" * 4) is True
        assert _validate_sha256("ABCDEF0123456789" * 4) is True

    def test_validate_sha256_invalid(self):
        from arkana.dashboard.state_api import _validate_sha256
        assert _validate_sha256("") is False
        assert _validate_sha256("a" * 63) is False
        assert _validate_sha256("a" * 65) is False
        assert _validate_sha256("g" * 64) is False
        assert _validate_sha256("a" * 32) is False

    # --- DB stats ---
    def test_get_bsim_db_stats_no_db(self, tmp_path, monkeypatch):
        from arkana.dashboard.state_api import get_bsim_db_stats
        # Point to nonexistent DB
        monkeypatch.setattr(
            "arkana.dashboard.state_api.get_bsim_db_stats.__module__",
            "arkana.dashboard.state_api",
        )
        # Use monkeypatch on the imported function's internal
        import arkana.mcp._bsim_features as bsim
        orig = bsim.get_db_path
        bsim.get_db_path = lambda: tmp_path / "nonexistent.db"
        try:
            result = get_bsim_db_stats()
            assert result["available"] is True
            assert result["total_binaries"] == 0
            assert result["total_functions"] == 0
        finally:
            bsim.get_db_path = orig

    def test_get_bsim_db_stats_with_data(self, tmp_path):
        from arkana.dashboard.state_api import get_bsim_db_stats
        import arkana.mcp._bsim_features as bsim

        # Create a test DB
        db_path = tmp_path / "test_sigs.db"
        bsim.init_db(db_path)
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO binaries (sha256, filename, architecture, function_count, "
            "indexed_at, file_size, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("a" * 64, "test.exe", "AMD64", 10, "2026-01-01T00:00:00", 1024, "user"),
        )
        conn.commit()
        conn.close()

        orig = bsim.get_db_path
        bsim.get_db_path = lambda: db_path
        try:
            result = get_bsim_db_stats()
            assert result["available"] is True
            assert result["total_binaries"] == 1
            assert result["user_entries"] == 1
            assert result["library_entries"] == 0
        finally:
            bsim.get_db_path = orig

    # --- Indexed binaries ---
    def test_get_bsim_indexed_binaries_empty(self, tmp_path):
        from arkana.dashboard.state_api import get_bsim_indexed_binaries
        import arkana.mcp._bsim_features as bsim

        db_path = tmp_path / "empty.db"
        bsim.init_db(db_path)

        orig = bsim.get_db_path
        bsim.get_db_path = lambda: db_path
        try:
            result = get_bsim_indexed_binaries()
            assert result["binaries"] == []
            assert result["total"] == 0
        finally:
            bsim.get_db_path = orig

    def test_get_bsim_indexed_binaries_with_data(self, tmp_path):
        from arkana.dashboard.state_api import get_bsim_indexed_binaries
        import arkana.mcp._bsim_features as bsim

        db_path = tmp_path / "test.db"
        bsim.init_db(db_path)
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO binaries (sha256, filename, architecture, function_count, "
            "indexed_at, file_size, source, library_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("b" * 64, "mal.exe", "X86", 5, "2026-01-01T00:00:00", 2048, "user", None),
        )
        conn.commit()
        conn.close()

        orig = bsim.get_db_path
        bsim.get_db_path = lambda: db_path
        try:
            result = get_bsim_indexed_binaries()
            assert result["total"] == 1
            assert result["binaries"][0]["filename"] == "mal.exe"
            assert result["binaries"][0]["architecture"] == "X86"
        finally:
            bsim.get_db_path = orig

    # --- Delete binary ---
    def test_delete_bsim_binary_invalid_sha(self):
        from arkana.dashboard.state_api import delete_bsim_binary
        result = delete_bsim_binary("not-a-sha256")
        assert "error" in result

    def test_delete_bsim_binary_success(self, tmp_path):
        from arkana.dashboard.state_api import delete_bsim_binary
        import arkana.mcp._bsim_features as bsim

        db_path = tmp_path / "del_test.db"
        bsim.init_db(db_path)
        sha = "c" * 64
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO binaries (sha256, filename, architecture, function_count, "
            "indexed_at, file_size, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sha, "victim.exe", "AMD64", 3, "2026-01-01T00:00:00", 512, "user"),
        )
        conn.commit()
        conn.close()

        orig = bsim.get_db_path
        bsim.get_db_path = lambda: db_path
        try:
            result = delete_bsim_binary(sha)
            assert result["status"] == "success"

            # Verify actually deleted
            conn2 = sqlite3.connect(str(db_path))
            row = conn2.execute("SELECT COUNT(*) FROM binaries").fetchone()
            assert row[0] == 0
            conn2.close()
        finally:
            bsim.get_db_path = orig

    def test_delete_bsim_binary_not_found(self, tmp_path):
        from arkana.dashboard.state_api import delete_bsim_binary
        import arkana.mcp._bsim_features as bsim

        db_path = tmp_path / "del_nf.db"
        bsim.init_db(db_path)

        orig = bsim.get_db_path
        bsim.get_db_path = lambda: db_path
        try:
            result = delete_bsim_binary("d" * 64)
            assert "error" in result
        finally:
            bsim.get_db_path = orig

    # --- Clear DB ---
    def test_clear_bsim_db(self, tmp_path):
        from arkana.dashboard.state_api import clear_bsim_db
        import arkana.mcp._bsim_features as bsim

        db_path = tmp_path / "clear_test.db"
        bsim.init_db(db_path)
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO binaries (sha256, filename, architecture, function_count, "
            "indexed_at, file_size, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("e" * 64, "clearme.exe", "AMD64", 2, "2026-01-01T00:00:00", 256, "user"),
        )
        conn.commit()
        conn.close()

        orig = bsim.get_db_path
        bsim.get_db_path = lambda: db_path
        try:
            result = clear_bsim_db()
            assert result["status"] == "success"

            conn2 = sqlite3.connect(str(db_path))
            row = conn2.execute("SELECT COUNT(*) FROM binaries").fetchone()
            assert row[0] == 0
            conn2.close()
        finally:
            bsim.get_db_path = orig

    # --- Triage data (no angr) ---
    def test_get_bsim_triage_data_no_angr(self):
        from arkana.dashboard.state_api import get_bsim_triage_data
        # Default state has no angr loaded
        old_proj = _default_state.angr_project
        old_cfg = _default_state.angr_cfg
        _default_state.angr_project = None
        _default_state.angr_cfg = None
        try:
            result = get_bsim_triage_data()
            assert result["available"] is False
        finally:
            _default_state.angr_project = old_proj
            _default_state.angr_cfg = old_cfg

    # --- Triage function matches ---
    def test_get_bsim_triage_function_matches_invalid_sha(self):
        from arkana.dashboard.state_api import get_bsim_triage_function_matches
        result = get_bsim_triage_function_matches("invalid")
        assert "error" in result

    def test_get_bsim_triage_function_matches_no_cache(self):
        from arkana.dashboard.state_api import get_bsim_triage_function_matches
        result = get_bsim_triage_function_matches("f" * 64)
        assert result["available"] is False

    def test_get_bsim_triage_function_matches_from_cache(self):
        import time
        from arkana.dashboard.state_api import (
            get_bsim_triage_function_matches,
            _bsim_triage_cache,
            _cache_lock,
        )
        sha_target = "a" * 64
        sha_match = "b" * 64
        fake_result = {
            "available": True,
            "results": [{
                "binary_sha256": sha_match,
                "binary_filename": "other.exe",
                "shared_function_count": 3,
                "avg_similarity": 0.85,
                "top_matches": [
                    {"source_address": "0x1000", "source_name": "func_a",
                     "match_name": "func_b", "similarity": 0.9, "confidence": 5.0},
                ],
            }],
        }
        with _cache_lock:
            _bsim_triage_cache[sha_target] = (time.time() + 300, fake_result)

        result = get_bsim_triage_function_matches(sha_match)
        assert result["available"] is True
        assert result["binary_filename"] == "other.exe"
        assert len(result["matches"]) == 1

    # --- DB health (empty) ---
    def test_get_bsim_db_health_no_db(self, tmp_path):
        from arkana.dashboard.state_api import get_bsim_db_health
        import arkana.mcp._bsim_features as bsim

        orig = bsim.get_db_path
        bsim.get_db_path = lambda: tmp_path / "nonexistent.db"
        try:
            result = get_bsim_db_health()
            assert result["status"] == "empty"
        finally:
            bsim.get_db_path = orig

    # --- Index current binary (no angr) ---
    def test_index_current_binary_no_angr(self):
        from arkana.dashboard.state_api import index_current_binary
        old_proj = _default_state.angr_project
        old_cfg = _default_state.angr_cfg
        _default_state.angr_project = None
        _default_state.angr_cfg = None
        try:
            result = index_current_binary()
            assert "error" in result
        finally:
            _default_state.angr_project = old_proj
            _default_state.angr_cfg = old_cfg
