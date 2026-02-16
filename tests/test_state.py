"""Unit tests for pemcp/state.py — AnalyzerState and session management."""
import os
import time
import threading
import pytest

from pemcp.state import (
    AnalyzerState,
    StateProxy,
    get_current_state,
    set_current_state,
    get_or_create_session_state,
    activate_session_state,
    get_all_session_states,
    get_session_key_from_context,
    MAX_COMPLETED_TASKS,
    SESSION_TTL_SECONDS,
    _default_state,
    _current_state_var,
)


# ---------------------------------------------------------------------------
# AnalyzerState basics
# ---------------------------------------------------------------------------

class TestAnalyzerState:
    def test_initial_state(self):
        s = AnalyzerState()
        assert s.filepath is None
        assert s.pe_data is None
        assert s.pe_object is None
        assert s.pefile_version is None
        assert s.loaded_from_cache is False
        assert s.allowed_paths is None
        assert s.samples_path is None
        assert s.angr_project is None
        assert s.angr_cfg is None
        assert s.angr_hooks == {}
        assert s.background_tasks == {}

    def test_touch_updates_last_active(self):
        s = AnalyzerState()
        t1 = s.last_active
        time.sleep(0.01)
        s.touch()
        assert s.last_active > t1


# ---------------------------------------------------------------------------
# Background task management
# ---------------------------------------------------------------------------

class TestBackgroundTasks:
    def test_set_and_get_task(self):
        s = AnalyzerState()
        s.set_task("t1", {"status": "running", "data": 42})
        task = s.get_task("t1")
        assert task["status"] == "running"
        assert task["data"] == 42

    def test_get_nonexistent_task(self):
        s = AnalyzerState()
        assert s.get_task("nonexistent") is None

    def test_get_task_returns_copy(self):
        s = AnalyzerState()
        s.set_task("t1", {"status": "running"})
        task = s.get_task("t1")
        task["status"] = "modified"
        # Original should be unchanged
        assert s.get_task("t1")["status"] == "running"

    def test_update_task(self):
        s = AnalyzerState()
        s.set_task("t1", {"status": "running", "progress": 0})
        s.update_task("t1", progress=50, status="running")
        task = s.get_task("t1")
        assert task["progress"] == 50

    def test_update_nonexistent_task(self):
        s = AnalyzerState()
        # Should not raise
        s.update_task("nonexistent", status="running")

    def test_get_all_task_ids(self):
        s = AnalyzerState()
        s.set_task("a", {"status": "running"})
        s.set_task("b", {"status": "completed"})
        ids = s.get_all_task_ids()
        assert set(ids) == {"a", "b"}

    def test_evict_old_tasks(self):
        s = AnalyzerState()
        # Add more than MAX_COMPLETED_TASKS completed tasks
        for i in range(MAX_COMPLETED_TASKS + 10):
            s.set_task(f"task-{i}", {
                "status": "completed",
                "created_at_epoch": float(i),
            })
        # Should have evicted the oldest ones
        assert len([
            t for t in s.background_tasks.values()
            if t["status"] == "completed"
        ]) <= MAX_COMPLETED_TASKS

    def test_running_tasks_not_evicted(self):
        s = AnalyzerState()
        s.set_task("running-1", {"status": "running", "created_at_epoch": 0.0})
        for i in range(MAX_COMPLETED_TASKS + 5):
            s.set_task(f"done-{i}", {
                "status": "completed",
                "created_at_epoch": float(i + 1),
            })
        # Running task should still be there
        assert s.get_task("running-1") is not None


# ---------------------------------------------------------------------------
# Path sandboxing
# ---------------------------------------------------------------------------

class TestPathSandboxing:
    def test_no_restriction(self):
        s = AnalyzerState()
        s.allowed_paths = None
        # Should not raise
        s.check_path_allowed("/any/path")

    def test_allowed_path(self, tmp_path):
        s = AnalyzerState()
        s.allowed_paths = [str(tmp_path)]
        test_file = tmp_path / "test.bin"
        test_file.touch()
        # Should not raise
        s.check_path_allowed(str(test_file))

    def test_disallowed_path(self, tmp_path):
        s = AnalyzerState()
        s.allowed_paths = [str(tmp_path / "allowed")]
        with pytest.raises(RuntimeError, match="Access denied"):
            s.check_path_allowed("/etc/passwd")

    def test_exact_path_match(self, tmp_path):
        test_file = tmp_path / "exact.bin"
        test_file.touch()
        s = AnalyzerState()
        s.allowed_paths = [str(test_file)]
        # Exact path should be allowed
        s.check_path_allowed(str(test_file))

    def test_relative_traversal_blocked(self, tmp_path):
        """Relative path traversal (../../) should be resolved and blocked."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        s = AnalyzerState()
        s.allowed_paths = [str(allowed)]
        # Construct a path that traverses out of the allowed directory
        traversal_path = str(allowed / ".." / ".." / "etc" / "passwd")
        with pytest.raises(RuntimeError, match="Access denied"):
            s.check_path_allowed(traversal_path)

    def test_symlink_resolved_and_blocked(self, tmp_path):
        """Symlinks pointing outside allowed dirs should be blocked."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_text("sensitive")
        # Create a symlink inside allowed that points outside
        link = allowed / "sneaky_link"
        link.symlink_to(secret)
        s = AnalyzerState()
        s.allowed_paths = [str(allowed)]
        with pytest.raises(RuntimeError, match="Access denied"):
            s.check_path_allowed(str(link))

    def test_symlink_within_allowed_ok(self, tmp_path):
        """Symlinks that resolve within allowed dirs should pass."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        real_file = allowed / "real.bin"
        real_file.write_bytes(b"\x00")
        link = allowed / "link.bin"
        link.symlink_to(real_file)
        s = AnalyzerState()
        s.allowed_paths = [str(allowed)]
        # Should not raise — symlink target is inside allowed
        s.check_path_allowed(str(link))

    def test_similar_prefix_dir_blocked(self, tmp_path):
        """A dir whose name starts with the allowed dir name should be blocked."""
        allowed = tmp_path / "data"
        allowed.mkdir()
        evil = tmp_path / "data_evil"
        evil.mkdir()
        evil_file = evil / "payload.bin"
        evil_file.write_bytes(b"\x00")
        s = AnalyzerState()
        s.allowed_paths = [str(allowed)]
        with pytest.raises(RuntimeError, match="Access denied"):
            s.check_path_allowed(str(evil_file))

    def test_nested_allowed_path(self, tmp_path):
        """Files in subdirectories of allowed paths should pass."""
        allowed = tmp_path / "samples"
        allowed.mkdir()
        nested = allowed / "subdir" / "deep"
        nested.mkdir(parents=True)
        test_file = nested / "file.bin"
        test_file.write_bytes(b"\x00")
        s = AnalyzerState()
        s.allowed_paths = [str(allowed)]
        # Should not raise
        s.check_path_allowed(str(test_file))

    def test_multiple_allowed_paths(self, tmp_path):
        """Check that any of the allowed paths is accepted."""
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        file_b = dir_b / "file.bin"
        file_b.write_bytes(b"\x00")
        s = AnalyzerState()
        s.allowed_paths = [str(dir_a), str(dir_b)]
        # File is in dir_b which is allowed
        s.check_path_allowed(str(file_b))


# ---------------------------------------------------------------------------
# Angr state management
# ---------------------------------------------------------------------------

class TestAngrState:
    def test_set_and_get_angr_results(self):
        s = AnalyzerState()
        s.set_angr_results("proj", "cfg", {"loops": []}, {"config": True})
        proj, cfg = s.get_angr_snapshot()
        assert proj == "proj"
        assert cfg == "cfg"
        assert s.angr_loop_cache == {"loops": []}

    def test_reset_angr(self):
        s = AnalyzerState()
        s.set_angr_results("proj", "cfg", {}, {})
        s.angr_hooks = {"0x1000": {"nop": True}}
        s.reset_angr()
        proj, cfg = s.get_angr_snapshot()
        assert proj is None
        assert cfg is None
        assert s.angr_hooks == {}


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

class TestSessionManagement:
    def test_default_session_returns_default_state(self):
        result = get_or_create_session_state("default")
        assert result is _default_state

    def test_new_session_creates_state(self):
        s = get_or_create_session_state("test-session-unique-1")
        assert isinstance(s, AnalyzerState)
        assert s is not _default_state

    def test_same_session_returns_same_state(self):
        s1 = get_or_create_session_state("test-session-unique-2")
        s2 = get_or_create_session_state("test-session-unique-2")
        assert s1 is s2

    def test_activate_session_state(self):
        s = activate_session_state("test-session-unique-3")
        assert get_current_state() is s

    def test_get_all_session_states_includes_default(self):
        states = get_all_session_states()
        assert _default_state in states

    def test_session_key_from_context_default(self):
        # Non-context object should return "default"
        key = get_session_key_from_context(object())
        assert key == "default"

    def test_session_key_from_none(self):
        key = get_session_key_from_context(None)
        assert key == "default"


# ---------------------------------------------------------------------------
# StateProxy
# ---------------------------------------------------------------------------

class TestStateProxy:
    def test_proxy_delegates_to_current_state(self):
        proxy = StateProxy()
        # By default, delegates to _default_state
        s = AnalyzerState()
        s.filepath = "/test/path"
        set_current_state(s)
        assert proxy.filepath == "/test/path"
        # Clean up
        set_current_state(None)

    def test_proxy_setattr(self):
        proxy = StateProxy()
        s = AnalyzerState()
        set_current_state(s)
        proxy.filepath = "/new/path"
        assert s.filepath == "/new/path"
        # Clean up
        set_current_state(None)

    def test_proxy_repr(self):
        proxy = StateProxy()
        r = repr(proxy)
        assert "StateProxy" in r
