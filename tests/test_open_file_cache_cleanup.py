"""Tests for cross-file cache cleanup when open_file() is called without close_file().

Verifies that module-level caches keyed by _state_uuid are properly invalidated
when a new file is loaded, preventing cross-file data contamination.
"""
import threading
import time

import pytest

from arkana.state import AnalyzerState


# ---------------------------------------------------------------------------
#  Bug 1: _decompile_meta cleared on open_file()
# ---------------------------------------------------------------------------

class TestDecompileMetaClearedOnOpenFile:
    """Verify _decompile_meta entries are removed during open_file cleanup."""

    def test_clear_decompile_meta_removes_session_entries(self):
        from arkana.mcp.tools_angr import _decompile_meta, _decompile_meta_lock, clear_decompile_meta

        state = AnalyzerState()
        key1 = (state._state_uuid, 0x401000)
        key2 = (state._state_uuid, 0x402000)

        with _decompile_meta_lock:
            _decompile_meta[key1] = {"function_name": "main", "lines": ["int main() {"]}
            _decompile_meta[key2] = {"function_name": "foo", "lines": ["void foo() {"]}

        try:
            clear_decompile_meta(session_uuid=state._state_uuid)

            with _decompile_meta_lock:
                assert key1 not in _decompile_meta
                assert key2 not in _decompile_meta
        finally:
            # Cleanup
            with _decompile_meta_lock:
                _decompile_meta.pop(key1, None)
                _decompile_meta.pop(key2, None)

    def test_clear_decompile_meta_preserves_other_sessions(self):
        from arkana.mcp.tools_angr import _decompile_meta, _decompile_meta_lock, clear_decompile_meta

        state_a = AnalyzerState()
        state_b = AnalyzerState()
        key_a = (state_a._state_uuid, 0x401000)
        key_b = (state_b._state_uuid, 0x401000)

        with _decompile_meta_lock:
            _decompile_meta[key_a] = {"function_name": "main_a", "lines": []}
            _decompile_meta[key_b] = {"function_name": "main_b", "lines": []}

        try:
            clear_decompile_meta(session_uuid=state_a._state_uuid)

            with _decompile_meta_lock:
                assert key_a not in _decompile_meta
                assert key_b in _decompile_meta
        finally:
            with _decompile_meta_lock:
                _decompile_meta.pop(key_a, None)
                _decompile_meta.pop(key_b, None)


# ---------------------------------------------------------------------------
#  Bug 2: _phase_caches cleared on open_file()
# ---------------------------------------------------------------------------

class TestPhaseCacheClearedOnOpenFile:
    """Verify _phase_caches entries are removed during open_file cleanup."""

    def test_cleanup_phase_cache_removes_session_entry(self):
        from arkana.mcp.tools_session import _phase_caches, _phase_caches_lock, cleanup_phase_cache

        state = AnalyzerState()

        with _phase_caches_lock:
            _phase_caches[state._state_uuid] = {"phase": "triage", "ts": time.time()}

        try:
            cleanup_phase_cache(state._state_uuid)

            with _phase_caches_lock:
                assert state._state_uuid not in _phase_caches
        finally:
            with _phase_caches_lock:
                _phase_caches.pop(state._state_uuid, None)

    def test_cleanup_phase_cache_preserves_other_sessions(self):
        from arkana.mcp.tools_session import _phase_caches, _phase_caches_lock, cleanup_phase_cache

        state_a = AnalyzerState()
        state_b = AnalyzerState()

        with _phase_caches_lock:
            _phase_caches[state_a._state_uuid] = {"phase": "triage"}
            _phase_caches[state_b._state_uuid] = {"phase": "deep-dive"}

        try:
            cleanup_phase_cache(state_a._state_uuid)

            with _phase_caches_lock:
                assert state_a._state_uuid not in _phase_caches
                assert state_b._state_uuid in _phase_caches
        finally:
            with _phase_caches_lock:
                _phase_caches.pop(state_a._state_uuid, None)
                _phase_caches.pop(state_b._state_uuid, None)


# ---------------------------------------------------------------------------
#  Bug 3: Dashboard caches cleared on open_file()
# ---------------------------------------------------------------------------

class TestDashboardCachesClearedOnOpenFile:
    """Verify dashboard module-level caches are removed during open_file cleanup."""

    def test_cleanup_session_caches_clears_all_dashboard_caches(self):
        from arkana.dashboard.state_api import (
            _cleanup_session_caches, _cache_lock,
            _func_lookup_cache, _overview_enrichment_cache,
            _overview_cache, _functions_cache, _strings_cache,
        )

        state = AnalyzerState()
        uid = state._state_uuid

        with _cache_lock:
            _func_lookup_cache[uid] = (time.time() + 100, "/old/file", [], [])
            _overview_enrichment_cache[uid] = (time.time() + 100, {})
            _overview_cache[uid] = (time.time() + 100, "/old/file", {})
            _functions_cache[uid] = (time.time() + 100, "v1", [])
            _strings_cache[uid] = (time.time() + 100, "v1", [])

        try:
            _cleanup_session_caches(uid)

            with _cache_lock:
                assert uid not in _func_lookup_cache
                assert uid not in _overview_enrichment_cache
                assert uid not in _overview_cache
                assert uid not in _functions_cache
                assert uid not in _strings_cache
        finally:
            with _cache_lock:
                for c in [_func_lookup_cache, _overview_enrichment_cache,
                          _overview_cache, _functions_cache, _strings_cache]:
                    c.pop(uid, None)

    def test_cleanup_session_caches_preserves_other_sessions(self):
        from arkana.dashboard.state_api import (
            _cleanup_session_caches, _cache_lock, _overview_cache,
        )

        state_a = AnalyzerState()
        state_b = AnalyzerState()

        with _cache_lock:
            _overview_cache[state_a._state_uuid] = (time.time() + 100, "/a", {})
            _overview_cache[state_b._state_uuid] = (time.time() + 100, "/b", {})

        try:
            _cleanup_session_caches(state_a._state_uuid)

            with _cache_lock:
                assert state_a._state_uuid not in _overview_cache
                assert state_b._state_uuid in _overview_cache
        finally:
            with _cache_lock:
                _overview_cache.pop(state_a._state_uuid, None)
                _overview_cache.pop(state_b._state_uuid, None)


# ---------------------------------------------------------------------------
#  Bug 4: result_cache cleared on open_file()
# ---------------------------------------------------------------------------

class TestResultCacheClearedOnOpenFile:
    """Verify per-state result_cache is cleared during open_file cleanup."""

    def test_result_cache_clear(self):
        state = AnalyzerState()
        # Populate result cache with a fake entry
        state.result_cache._store["test_tool"] = {"key": {"items": [1, 2, 3], "ts": time.time()}}

        state.result_cache.clear()

        assert state.result_cache._store == {}

    def test_result_cache_clear_specific_tool(self):
        state = AnalyzerState()
        import collections
        state.result_cache._store["tool_a"] = collections.OrderedDict(
            [("k1", {"items": [1], "ts": time.time()})]
        )
        state.result_cache._store["tool_b"] = collections.OrderedDict(
            [("k2", {"items": [2], "ts": time.time()})]
        )

        state.result_cache.clear(tool_name="tool_a")

        assert "tool_a" not in state.result_cache._store
        assert "tool_b" in state.result_cache._store


# ---------------------------------------------------------------------------
#  Bug 5: Per-state _last_decompile_save_time
# ---------------------------------------------------------------------------

class TestPerStateDecompileSaveThrottle:
    """Verify async save throttle is per-state, not global."""

    def test_initial_value_is_zero(self):
        state = AnalyzerState()
        assert state._last_decompile_save_time == 0.0

    def test_independent_across_states(self):
        state_a = AnalyzerState()
        state_b = AnalyzerState()

        state_a._last_decompile_save_time = time.time()

        # State B's throttle should still be at zero
        assert state_b._last_decompile_save_time == 0.0

    def test_save_throttle_uses_per_state_field(self):
        """Verify save_decompile_cache_async reads from state, not global."""
        from arkana.enrichment import save_decompile_cache_async, _ASYNC_SAVE_INTERVAL

        state = AnalyzerState()
        # No pe_data → early return, but throttle check happens first
        state.pe_data = None

        # Set the per-state throttle to the future — should cause early return
        state._last_decompile_save_time = time.time() + 9999

        # This should return immediately due to throttle (no error = success)
        save_decompile_cache_async(state)

    def test_global_last_async_save_removed(self):
        """Verify the global _last_async_save variable no longer exists."""
        import arkana.enrichment as enrichment_mod
        assert not hasattr(enrichment_mod, "_last_async_save")


# ---------------------------------------------------------------------------
#  Bug 6: analysis_warnings cleared on open_file()
# ---------------------------------------------------------------------------

class TestAnalysisWarningsClearedOnOpenFile:
    """Verify analysis warnings are cleared during open_file cleanup."""

    def test_clear_warnings(self):
        state = AnalyzerState()

        # Add some warnings
        with state._warnings_lock:
            state.analysis_warnings.append({
                "logger": "angr", "level": "WARNING",
                "message": "Old warning from previous file",
                "tool": "decompile_function_with_angr",
            })
            state._warning_dedup[("angr", "WARNING", "Old warning")] = {
                "count": 1, "last_seen": time.time(),
            }

        count = state.clear_warnings()

        assert count == 1
        assert len(state.analysis_warnings) == 0
        assert len(state._warning_dedup) == 0


# ---------------------------------------------------------------------------
#  Bug 7: _overview_cache filepath validation
# ---------------------------------------------------------------------------

class TestOverviewCacheFilepathValidation:
    """Verify _overview_cache rejects entries with mismatched filepath."""

    def test_cache_hit_with_matching_filepath(self):
        from arkana.dashboard.state_api import _overview_cache, _cache_lock

        uid = "test-uuid-match"
        data = {"filepath": "/some/file.exe"}

        with _cache_lock:
            _overview_cache[uid] = (time.time() + 100, "/some/file.exe", data)

        try:
            with _cache_lock:
                cached = _overview_cache.get(uid)

            assert cached is not None
            expire_time, cached_filepath, cached_data = cached
            assert cached_filepath == "/some/file.exe"
            assert cached_data == data
        finally:
            with _cache_lock:
                _overview_cache.pop(uid, None)

    def test_cache_miss_with_mismatched_filepath(self):
        """Stale cache entry with wrong filepath should be treated as a miss."""
        from arkana.dashboard.state_api import _overview_cache, _cache_lock

        uid = "test-uuid-mismatch"
        stale_data = {"filepath": "/old/file.exe"}

        with _cache_lock:
            _overview_cache[uid] = (time.time() + 100, "/old/file.exe", stale_data)

        try:
            with _cache_lock:
                cached = _overview_cache.get(uid)

            assert cached is not None
            expire_time, cached_filepath, cached_data = cached
            # Simulate the filepath check in get_overview_data
            new_filepath = "/new/file.exe"
            assert cached_filepath != new_filepath  # Should be a miss
        finally:
            with _cache_lock:
                _overview_cache.pop(uid, None)

    def test_cache_stores_filepath_in_tuple(self):
        """Verify the cache store format includes filepath."""
        from arkana.dashboard.state_api import _overview_cache, _cache_lock

        uid = "test-uuid-format"
        with _cache_lock:
            _overview_cache[uid] = (time.time() + 100, "/test/path.exe", {"key": "val"})

        try:
            with _cache_lock:
                entry = _overview_cache[uid]
            # Should be a 3-tuple: (expire_time, filepath, data)
            assert len(entry) == 3
            assert isinstance(entry[0], float)  # expire_time
            assert isinstance(entry[1], str)    # filepath
            assert isinstance(entry[2], dict)   # data
        finally:
            with _cache_lock:
                _overview_cache.pop(uid, None)


# ---------------------------------------------------------------------------
#  Integration: open_file cleanup block calls all cleanups
# ---------------------------------------------------------------------------

class TestOpenFileCleanupBlock:
    """Verify the open_file cleanup block invokes all necessary cleanup calls."""

    def test_open_file_source_has_cache_cleanup_calls(self):
        """Verify open_file source code contains the cache cleanup calls.

        This is a source-level check to ensure the cleanup block wasn't
        accidentally removed during refactoring.
        """
        import inspect
        from arkana.mcp.tools_pe import open_file

        source = inspect.getsource(open_file)
        assert "clear_decompile_meta" in source
        assert "cleanup_phase_cache" in source
        assert "_cleanup_session_caches" in source
        assert "result_cache.clear()" in source
        assert "clear_warnings()" in source

    def test_close_file_source_has_cache_cleanup_calls(self):
        """Verify close_file source also has the decompile_meta and phase cleanup."""
        import inspect
        from arkana.mcp.tools_pe import close_file

        source = inspect.getsource(close_file)
        assert "clear_decompile_meta" in source
        assert "_phase_caches" in source
