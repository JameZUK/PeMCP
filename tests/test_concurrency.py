"""Concurrency tests for pemcp/state.py — session isolation under concurrent load."""
import threading
import time
import pytest

from pemcp.state import (
    AnalyzerState,
    StateProxy,
    get_current_state,
    set_current_state,
    get_or_create_session_state,
    activate_session_state,
    _default_state,
    _current_state_var,
)


# ---------------------------------------------------------------------------
# Concurrent session isolation
# ---------------------------------------------------------------------------

class TestConcurrentSessionIsolation:
    """Verify that per-session state does not leak between threads."""

    def test_threads_get_isolated_states(self):
        """Multiple threads activating different sessions see their own state."""
        results = {}
        errors = []

        def worker(session_key, filepath, barrier):
            try:
                s = activate_session_state(session_key)
                s.filepath = filepath
                barrier.wait()  # Sync all threads before reading
                time.sleep(0.01)  # Give time for potential cross-contamination
                actual = get_current_state().filepath
                results[session_key] = actual
            except Exception as e:
                errors.append(e)

        barrier = threading.Barrier(4)
        threads = []
        for i in range(4):
            key = f"concurrent-test-{i}"
            path = f"/test/file_{i}.exe"
            t = threading.Thread(target=worker, args=(key, path, barrier))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Threads raised exceptions: {errors}"
        for i in range(4):
            key = f"concurrent-test-{i}"
            assert results[key] == f"/test/file_{i}.exe", (
                f"Session {key} saw filepath={results[key]}, expected /test/file_{i}.exe"
            )

    def test_concurrent_task_updates_no_corruption(self):
        """Multiple threads updating tasks on the same state don't corrupt data."""
        s = AnalyzerState()
        errors = []

        def worker(task_prefix, count):
            try:
                for i in range(count):
                    tid = f"{task_prefix}-{i}"
                    s.set_task(tid, {
                        "status": "running",
                        "progress": 0,
                        "created_at_epoch": time.time(),
                    })
                    s.update_task(tid, progress=50)
                    s.update_task(tid, progress=100, status="completed")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(f"w{i}", 50))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Threads raised exceptions: {errors}"
        # All tasks should be present or evicted (but not corrupted)
        all_ids = s.get_all_task_ids()
        for tid in all_ids:
            task = s.get_task(tid)
            assert task is not None
            assert "status" in task

    def test_concurrent_angr_state_set_get(self):
        """Concurrent set/get of angr results doesn't corrupt state."""
        s = AnalyzerState()
        errors = []

        def writer():
            try:
                for i in range(100):
                    s.set_angr_results(f"proj-{i}", f"cfg-{i}", {}, {})
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(100):
                    proj, cfg = s.get_angr_snapshot()
                    # Both should be consistent (same index or None)
                    if proj is not None and cfg is not None:
                        # Extract index from both and verify consistency
                        proj_idx = proj.split("-")[1] if "-" in str(proj) else None
                        cfg_idx = cfg.split("-")[1] if "-" in str(cfg) else None
                        assert proj_idx == cfg_idx, (
                            f"Inconsistent angr state: proj={proj}, cfg={cfg}"
                        )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(2)]
        threads += [threading.Thread(target=reader) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Threads raised exceptions: {errors}"


class TestConcurrentPathSandboxing:
    """Verify path sandbox checks are thread-safe."""

    def test_concurrent_path_checks(self, tmp_path):
        s = AnalyzerState()
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        s.allowed_paths = [str(allowed_dir)]

        errors = []
        results = {"allowed": 0, "denied": 0}
        lock = threading.Lock()

        def check_allowed():
            try:
                s.check_path_allowed(str(allowed_dir / "test.bin"))
                with lock:
                    results["allowed"] += 1
            except Exception as e:
                errors.append(e)

        def check_denied():
            try:
                s.check_path_allowed("/etc/passwd")
                errors.append(AssertionError("Should have been denied"))
            except RuntimeError:
                with lock:
                    results["denied"] += 1
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(10):
            threads.append(threading.Thread(target=check_allowed))
            threads.append(threading.Thread(target=check_denied))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        unexpected_errors = [e for e in errors if not isinstance(e, AssertionError)]
        assert not unexpected_errors, f"Unexpected errors: {unexpected_errors}"
        assert results["allowed"] == 10
        assert results["denied"] == 10


class TestStateProxyConcurrency:
    """Verify StateProxy correctly delegates per-thread."""

    def test_proxy_per_thread_isolation(self):
        """Each thread sees its own state through the proxy."""
        proxy = StateProxy()
        results = {}
        errors = []

        def worker(thread_id):
            try:
                s = AnalyzerState()
                s.filepath = f"/thread/{thread_id}/file.exe"
                set_current_state(s)
                time.sleep(0.01)
                results[thread_id] = proxy.filepath
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Threads raised exceptions: {errors}"
        for i in range(8):
            assert results[i] == f"/thread/{i}/file.exe", (
                f"Thread {i} saw {results[i]}"
            )
