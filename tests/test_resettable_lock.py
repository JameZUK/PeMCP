"""Tests for the ResettableLock class and its integration with cancel_all_background_tasks."""
import threading
import time

import pytest

from arkana.state import ResettableLock, AnalyzerState


# ---------------------------------------------------------------------------
#  Basic ResettableLock functionality
# ---------------------------------------------------------------------------

class TestResettableLockBasic:
    def setup_method(self):
        self.lock = ResettableLock()

    def test_acquire_and_release(self):
        """Normal acquire/release cycle works."""
        assert self.lock.acquire(timeout=1) is True
        self.lock.release()

    def test_acquire_blocking(self):
        """Blocking acquire works (default)."""
        assert self.lock.acquire() is True
        self.lock.release()

    def test_acquire_nonblocking_free(self):
        """Non-blocking acquire succeeds on free lock."""
        assert self.lock.acquire(blocking=False) is True
        self.lock.release()

    def test_acquire_nonblocking_held(self):
        """Non-blocking acquire fails on held lock."""
        assert self.lock.acquire(blocking=False) is True
        # Same thread can't acquire again (not reentrant)
        result = [None]
        def try_acquire():
            result[0] = self.lock.acquire(blocking=False)
        t = threading.Thread(target=try_acquire)
        t.start()
        t.join(timeout=2)
        assert result[0] is False
        self.lock.release()

    def test_acquire_timeout(self):
        """Acquire with timeout returns False when lock is held."""
        assert self.lock.acquire() is True
        result = [None]
        def try_acquire():
            result[0] = self.lock.acquire(timeout=0.1)
        t = threading.Thread(target=try_acquire)
        t.start()
        t.join(timeout=2)
        assert result[0] is False
        self.lock.release()

    def test_mutual_exclusion(self):
        """Lock provides mutual exclusion between threads."""
        order = []
        t1_acquired = threading.Event()

        def worker(name, delay, event=None):
            self.lock.acquire()
            try:
                if event:
                    event.set()
                order.append(f"{name}_start")
                time.sleep(delay)
                order.append(f"{name}_end")
            finally:
                self.lock.release()

        t1 = threading.Thread(target=worker, args=("t1", 0.1, t1_acquired))
        t1.start()
        t1_acquired.wait(timeout=2)
        t2 = threading.Thread(target=worker, args=("t2", 0.05))
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)
        assert order.index("t1_end") < order.index("t2_start")

    def test_repr(self):
        """__repr__ includes generation and holder count."""
        r = repr(self.lock)
        assert "ResettableLock" in r
        assert "gen=0" in r


# ---------------------------------------------------------------------------
#  force_reset() behavior
# ---------------------------------------------------------------------------

class TestResettableLockForceReset:
    def setup_method(self):
        self.lock = ResettableLock()

    def test_force_reset_when_not_held(self):
        """force_reset() on a free lock doesn't crash."""
        self.lock.force_reset()
        assert self.lock._generation == 1

    def test_force_reset_increments_generation(self):
        """Each force_reset() increments the generation counter."""
        assert self.lock._generation == 0
        self.lock.force_reset()
        assert self.lock._generation == 1
        self.lock.force_reset()
        assert self.lock._generation == 2

    def test_force_reset_releases_held_lock(self):
        """force_reset() releases a lock held by another thread."""
        holder_ready = threading.Event()
        holder_release = threading.Event()

        def holder():
            self.lock.acquire()
            holder_ready.set()
            holder_release.wait(timeout=5)
            self.lock.release()  # Should be no-op after force_reset

        t = threading.Thread(target=holder, daemon=True)
        t.start()
        holder_ready.wait(timeout=2)

        # Lock is held by the holder thread
        assert self.lock.acquire(blocking=False) is False

        # Force-reset releases it
        self.lock.force_reset()

        # Now we can acquire it
        assert self.lock.acquire(timeout=1) is True
        self.lock.release()

        holder_release.set()
        t.join(timeout=2)

    def test_stale_release_is_noop(self):
        """Old holder's release() is a no-op after force_reset()."""
        holder_ready = threading.Event()
        holder_done = threading.Event()
        release_results = []

        def holder():
            self.lock.acquire()
            holder_ready.set()
            # Wait for force_reset to happen
            holder_done.wait(timeout=5)
            # This release should be a no-op (generation mismatch)
            self.lock.release()
            release_results.append("released")

        t = threading.Thread(target=holder, daemon=True)
        t.start()
        holder_ready.wait(timeout=2)

        self.lock.force_reset()

        # New holder acquires
        assert self.lock.acquire(timeout=1) is True

        # Let old holder try to release — should NOT release our lock
        holder_done.set()
        t.join(timeout=2)
        assert "released" in release_results

        # Our lock should still be held
        result = [None]
        def try_acquire():
            result[0] = self.lock.acquire(blocking=False)
        t2 = threading.Thread(target=try_acquire)
        t2.start()
        t2.join(timeout=2)
        assert result[0] is False  # Still held by us

        self.lock.release()

    def test_new_holder_after_reset(self):
        """New thread can acquire, use, and release after force_reset."""
        self.lock.acquire()
        self.lock.force_reset()

        result = [None]
        def new_holder():
            acquired = self.lock.acquire(timeout=1)
            if acquired:
                result[0] = "acquired"
                self.lock.release()
                result[0] = "released"

        t = threading.Thread(target=new_holder)
        t.start()
        t.join(timeout=2)
        assert result[0] == "released"

    def test_multiple_force_resets(self):
        """Multiple sequential force_resets work correctly."""
        for i in range(5):
            self.lock.acquire()
            self.lock.force_reset()
            assert self.lock._generation == i + 1
        # Lock should be acquirable
        assert self.lock.acquire(timeout=1) is True
        self.lock.release()

    def test_force_reset_sets_timestamp(self):
        """force_reset() records _last_force_reset timestamp."""
        assert self.lock._last_force_reset == 0.0
        before = time.time()
        self.lock.force_reset()
        after = time.time()
        assert before <= self.lock._last_force_reset <= after

    def test_force_reset_clears_holder_gen(self):
        """force_reset() clears the holder generation map."""
        self.lock.acquire()
        assert len(self.lock._holder_gen) == 1
        self.lock.force_reset()
        assert len(self.lock._holder_gen) == 0


# ---------------------------------------------------------------------------
#  Concurrent scenarios
# ---------------------------------------------------------------------------

class TestResettableLockConcurrent:
    def setup_method(self):
        self.lock = ResettableLock()

    def test_concurrent_acquire_after_reset(self):
        """Multiple threads compete for the lock after force_reset."""
        holder_ready = threading.Event()
        holder_continue = threading.Event()

        def old_holder():
            self.lock.acquire()
            holder_ready.set()
            holder_continue.wait(timeout=5)  # Wait for signal instead of sleep
            self.lock.release()

        old = threading.Thread(target=old_holder, daemon=True)
        old.start()
        holder_ready.wait(timeout=2)

        self.lock.force_reset()

        # Launch 3 threads that each try to acquire
        results = []
        results_lock = threading.Lock()
        all_done = threading.Event()
        done_count = [0]

        def competitor(name):
            if self.lock.acquire(timeout=5):
                with results_lock:
                    results.append(name)
                self.lock.release()
            with results_lock:
                done_count[0] += 1
                if done_count[0] == 3:
                    all_done.set()

        threads = [threading.Thread(target=competitor, args=(f"t{i}",)) for i in range(3)]
        for t in threads:
            t.start()

        # Wait for all competitors to finish (event-based, not timeout-based)
        all_done.wait(timeout=10)
        holder_continue.set()  # Release old holder
        for t in threads:
            t.join(timeout=2)
        old.join(timeout=2)

        # All 3 should have acquired the lock
        assert len(results) == 3


# ---------------------------------------------------------------------------
#  Integration with cancel_all_background_tasks
# ---------------------------------------------------------------------------

class TestCancelAllBackgroundTasksLockReset:
    def setup_method(self):
        self.state = AnalyzerState()

    def test_cancel_resets_decompile_lock(self):
        """cancel_all_background_tasks() calls force_reset on the decompile lock."""
        gen_before = self.state._decompile_lock._generation
        self.state.cancel_all_background_tasks()
        assert self.state._decompile_lock._generation == gen_before + 1

    def test_cancel_resets_on_demand_count(self):
        """cancel_all_background_tasks() resets _decompile_on_demand_count."""
        self.state._decompile_on_demand_count = 3
        self.state.cancel_all_background_tasks()
        assert self.state._decompile_on_demand_count == 0

    def test_cancel_releases_held_lock(self):
        """cancel_all_background_tasks() releases a lock held by another thread."""
        holder_ready = threading.Event()
        holder_done = threading.Event()

        def holder():
            self.state._decompile_lock.acquire()
            holder_ready.set()
            holder_done.wait(timeout=5)
            self.state._decompile_lock.release()

        t = threading.Thread(target=holder, daemon=True)
        t.start()
        holder_ready.wait(timeout=2)

        # Lock is held
        assert self.state._decompile_lock.acquire(blocking=False) is False

        # cancel_all_background_tasks force-resets it
        self.state.cancel_all_background_tasks()

        # Now acquirable
        assert self.state._decompile_lock.acquire(timeout=1) is True
        self.state._decompile_lock.release()

        holder_done.set()
        t.join(timeout=2)

    def test_cancel_sets_force_reset_timestamp(self):
        """cancel_all_background_tasks() sets _last_force_reset for alert system."""
        assert self.state._decompile_lock._last_force_reset == 0.0
        self.state.cancel_all_background_tasks()
        assert self.state._decompile_lock._last_force_reset > 0
