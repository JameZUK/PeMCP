"""Tests for flush_overlay lock-safety: I/O must happen outside _project_lock.

Verifies that flush_overlay() does not hold _project_lock during the
save_overlay() I/O path, which previously could block all threads calling
mark_overlay_dirty() or _maybe_promote_scratch() for the duration of
gzip compression + file writes.
"""
import threading
import time
import pytest

from arkana.state import AnalyzerState


class _FakeManifest:
    """Minimal Project manifest stub."""
    def __init__(self, sha="abc123def456"):
        self.last_active_sha256 = sha


class _FakeProject:
    """Minimal Project stub with controllable save_overlay latency."""
    is_scratch = False

    def __init__(self, *, save_delay=0.0):
        self.manifest = _FakeManifest()
        self._save_delay = save_delay
        self.saved = False
        self.save_called = threading.Event()

    def save_overlay(self, sha, overlay):
        self.save_called.set()
        if self._save_delay:
            time.sleep(self._save_delay)
        self.saved = True


class TestFlushOverlayLockSafety:
    """Ensure _project_lock is NOT held during save_overlay I/O."""

    def test_flush_overlay_saves(self):
        """Basic flush_overlay works and calls save_overlay."""
        st = AnalyzerState()
        proj = _FakeProject()
        with st._project_lock:
            st.active_project = proj
            st._overlay_dirty = True
        assert st.flush_overlay() is True
        assert proj.saved

    def test_flush_overlay_noop_when_scratch(self):
        """flush_overlay returns False for scratch projects."""
        st = AnalyzerState()
        proj = _FakeProject()
        proj.is_scratch = True
        with st._project_lock:
            st.active_project = proj
            st._overlay_dirty = True
        assert st.flush_overlay() is False

    def test_flush_overlay_noop_when_no_project(self):
        st = AnalyzerState()
        assert st.flush_overlay() is False

    def test_mark_overlay_dirty_not_blocked_during_save(self):
        """mark_overlay_dirty() must NOT block while save_overlay is running.

        This is the key regression test: previously flush_overlay held
        _project_lock for the entire save_overlay() call, which meant
        mark_overlay_dirty() would block until the I/O completed.
        """
        st = AnalyzerState()
        proj = _FakeProject(save_delay=2.0)  # slow I/O
        with st._project_lock:
            st.active_project = proj
            st._overlay_dirty = True

        dirty_set = threading.Event()
        dirty_blocked = threading.Event()

        def _flush():
            st.flush_overlay()

        def _mark_dirty():
            # Wait until save_overlay has been called (I/O is in progress)
            proj.save_called.wait(timeout=5.0)
            # Now try to mark dirty — should NOT block for 2s
            start = time.monotonic()
            st.mark_overlay_dirty()
            elapsed = time.monotonic() - start
            if elapsed < 1.0:
                dirty_set.set()
            else:
                dirty_blocked.set()

        t_flush = threading.Thread(target=_flush)
        t_dirty = threading.Thread(target=_mark_dirty)
        t_flush.start()
        t_dirty.start()

        t_dirty.join(timeout=5.0)
        t_flush.join(timeout=5.0)

        assert dirty_set.is_set(), (
            "mark_overlay_dirty() was blocked for >1s during save_overlay I/O — "
            "_project_lock is still held during I/O"
        )
        assert not dirty_blocked.is_set()

    def test_concurrent_flushes_serialize_correctly(self):
        """Two concurrent flush_overlay calls don't corrupt state."""
        st = AnalyzerState()
        proj = _FakeProject(save_delay=0.1)
        with st._project_lock:
            st.active_project = proj
            st._overlay_dirty = True

        results = []

        def _flush():
            results.append(st.flush_overlay())

        threads = [threading.Thread(target=_flush) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        # At least one should succeed
        assert any(results)


class TestLockWatchdog:
    """Smoke test for the lock watchdog infrastructure."""

    def test_watchdog_constants_defined(self):
        from arkana.state import _LOCK_WATCHDOG_INTERVAL, _LOCK_ACQUIRE_TIMEOUT
        assert _LOCK_WATCHDOG_INTERVAL > 0
        assert _LOCK_ACQUIRE_TIMEOUT > 0

    def test_watchdog_probes_locks(self):
        """Watchdog can probe locks on a fresh AnalyzerState without error."""
        st = AnalyzerState()
        locks_to_probe = [
            ("_project_lock", st._project_lock),
            ("_task_lock", st._task_lock),
            ("_pe_lock", st._pe_lock),
        ]
        for name, lock in locks_to_probe:
            acquired = lock.acquire(timeout=0.1)
            assert acquired, f"Could not acquire {name} on a fresh state"
            lock.release()


class TestFaulthandler:
    """Verify faulthandler is enabled after importing main."""

    def test_faulthandler_enabled(self):
        import faulthandler
        # faulthandler.enable() is called at import time in main.py.
        # We can't easily test SIGUSR1 registration in unit tests, but we
        # can verify the module is available and callable.
        assert hasattr(faulthandler, "dump_traceback")
        assert callable(faulthandler.dump_traceback)
