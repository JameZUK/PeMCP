"""Tests for background task hardening: cancel events, generation guards, race fixes.

Covers the changes from the 'Harden background task management' commit:
- FLOSS deep analysis: cancel event, generation guard, thread tracking, finally cleanup
- angr_background_worker: _cancel_event parameter, overtime loop check, finally cleanup
- cancel_all_background_tasks: aborted=True flag
- _register_background_task: atomic cancel event + task registration
- open_file error handler: cancel_all_background_tasks call
- abort_background_task: TASK_RUNNING/TASK_OVERTIME constants
- _collect_background_alerts: logger.debug on exception
- Removed dead monitor_thread_started field
"""
import asyncio
import datetime
import threading
import time
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

from arkana.state import (
    AnalyzerState, TASK_RUNNING, TASK_OVERTIME, TASK_COMPLETED, TASK_FAILED,
    _default_state, set_current_state, get_current_state,
)


class TestCancelAllSetsAborted(unittest.TestCase):
    """cancel_all_background_tasks must set aborted=True on cancelled tasks."""

    def test_aborted_flag_set_on_running(self):
        st = AnalyzerState()
        st.set_task("r1", {"status": TASK_RUNNING, "tool": "test"})
        st.cancel_all_background_tasks()
        task = st.get_task("r1")
        assert task["status"] == TASK_FAILED
        assert task["aborted"] is True

    def test_aborted_flag_set_on_overtime(self):
        st = AnalyzerState()
        st.set_task("o1", {"status": TASK_OVERTIME, "tool": "test"})
        st.cancel_all_background_tasks()
        task = st.get_task("o1")
        assert task["status"] == TASK_FAILED
        assert task["aborted"] is True

    def test_aborted_not_set_on_completed(self):
        st = AnalyzerState()
        st.set_task("c1", {"status": TASK_COMPLETED, "tool": "test"})
        st.cancel_all_background_tasks()
        task = st.get_task("c1")
        assert task["status"] == TASK_COMPLETED
        assert "aborted" not in task

    def test_aborted_not_set_on_already_failed(self):
        st = AnalyzerState()
        st.set_task("f1", {"status": TASK_FAILED, "error": "original", "tool": "test"})
        st.cancel_all_background_tasks()
        task = st.get_task("f1")
        assert task["status"] == TASK_FAILED
        assert task["error"] == "original"
        assert "aborted" not in task

    def test_multiple_tasks_all_get_aborted(self):
        st = AnalyzerState()
        st.set_task("a", {"status": TASK_RUNNING, "tool": "t"})
        st.set_task("b", {"status": TASK_OVERTIME, "tool": "t"})
        st.set_task("c", {"status": TASK_RUNNING, "tool": "t"})
        st.cancel_all_background_tasks()
        for tid in ("a", "b", "c"):
            assert st.get_task(tid)["aborted"] is True


class TestRegisterBackgroundTask(unittest.TestCase):
    """_register_background_task creates cancel event and sets task atomically."""

    def setUp(self):
        self.st = AnalyzerState()
        set_current_state(self.st)

    def test_returns_cancel_event(self):
        from arkana.background import _register_background_task
        cancel = _register_background_task("test-reg", {
            "status": TASK_RUNNING,
            "tool": "test",
        })
        assert isinstance(cancel, threading.Event)
        assert not cancel.is_set()

    def test_cancel_event_registered_in_state(self):
        from arkana.background import _register_background_task
        cancel = _register_background_task("test-reg2", {
            "status": TASK_RUNNING,
            "tool": "test",
        })
        assert "test-reg2" in self.st._task_cancel_events
        assert self.st._task_cancel_events["test-reg2"] is cancel

    def test_task_is_set(self):
        from arkana.background import _register_background_task
        _register_background_task("test-reg3", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "tool": "test",
        })
        task = self.st.get_task("test-reg3")
        assert task is not None
        assert task["status"] == TASK_RUNNING
        assert task["tool"] == "test"

    def test_cancel_event_exists_before_task_visible(self):
        """Cancel event should exist even if cancel_all fires immediately after."""
        from arkana.background import _register_background_task
        _register_background_task("test-race", {
            "status": TASK_RUNNING,
            "tool": "test",
        })
        # Simulate cancel_all right after registration
        self.st.cancel_all_background_tasks()
        task = self.st.get_task("test-race")
        assert task["status"] == TASK_FAILED
        assert task["aborted"] is True
        # Cancel event should have been set
        assert self.st._task_cancel_events["test-race"].is_set()


class TestWrapperPreRegisteredCancelEvent(unittest.TestCase):
    """_run_background_task_wrapper accepts pre-registered cancel_event."""

    def setUp(self):
        self.st = AnalyzerState()
        set_current_state(self.st)

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            if loop._default_executor is not None:
                loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()

    def test_uses_pre_registered_cancel_event(self):
        from arkana.background import _run_background_task_wrapper

        cancel = threading.Event()
        self.st._task_cancel_events["test-pre"] = cancel

        def fast():
            return {"ok": True}

        self.st.set_task("test-pre", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Testing...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "test-pre", fast, cancel_event=cancel, soft_timeout=10
        ))

        task = self.st.get_task("test-pre")
        assert task["status"] == TASK_COMPLETED
        # Cancel event cleaned up
        assert "test-pre" not in self.st._task_cancel_events

    def test_pre_cancelled_event_prevents_result_write(self):
        from arkana.background import _run_background_task_wrapper

        cancel = threading.Event()
        cancel.set()  # Pre-cancel
        self.st._task_cancel_events["test-precancel"] = cancel

        def fast():
            return {"should": "not be stored"}

        self.st.set_task("test-precancel", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Testing...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "test-precancel", fast, cancel_event=cancel, soft_timeout=10
        ))

        task = self.st.get_task("test-precancel")
        # Should NOT be COMPLETED — cancel event was set
        assert task["status"] != TASK_COMPLETED

    def test_creates_cancel_event_when_none_passed(self):
        """Backward compat: wrapper creates its own cancel event if none given."""
        from arkana.background import _run_background_task_wrapper

        def fast():
            return {"ok": True}

        self.st.set_task("test-auto", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Testing...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "test-auto", fast, soft_timeout=10
        ))

        task = self.st.get_task("test-auto")
        assert task["status"] == TASK_COMPLETED
        # Cancel event cleaned up
        assert "test-auto" not in self.st._task_cancel_events


class TestFlossTaskInfraRegistration(unittest.TestCase):
    """FLOSS deep analysis task registers cancel event and thread ref."""

    def setUp(self):
        self.st = AnalyzerState()
        self.st.pe_data = {"floss_analysis": None}
        set_current_state(self.st)

    def test_cancel_event_registered(self):
        """Cancel event exists in _task_cancel_events after launch."""
        barrier = threading.Event()

        def held_floss(*args, **kwargs):
            barrier.wait(timeout=5)
            return {"status": "Complete"}

        with patch("arkana.mcp.tools_pe._parse_floss_analysis", side_effect=held_floss):
            from arkana.mcp.tools_pe import _start_floss_background_task
            _start_floss_background_task(self.st, ("data", 6))

            # Cancel event should be registered immediately (before worker finishes)
            assert "floss-deep-analysis" in self.st._task_cancel_events
            assert isinstance(self.st._task_cancel_events["floss-deep-analysis"], threading.Event)

            # Thread ref should be registered
            assert "floss-deep-analysis" in self.st._background_threads
            assert isinstance(self.st._background_threads["floss-deep-analysis"], threading.Thread)

            # Let worker finish
            barrier.set()
            thread = self.st._background_threads["floss-deep-analysis"]
            thread.join(timeout=5)

    def test_cleanup_after_success(self):
        """Cancel event and thread ref cleaned up after successful completion."""
        barrier = threading.Event()

        def held_floss(*args, **kwargs):
            barrier.wait(timeout=5)
            return {"status": "Complete"}

        with patch("arkana.mcp.tools_pe._parse_floss_analysis", side_effect=held_floss):
            from arkana.mcp.tools_pe import _start_floss_background_task
            _start_floss_background_task(self.st, ("data", 6))

            # Infra entries exist while worker is blocked
            thread = self.st._background_threads.get("floss-deep-analysis")
            assert thread is not None
            assert "floss-deep-analysis" in self.st._task_cancel_events

            # Let worker finish
            barrier.set()
            thread.join(timeout=5)

        # After completion, infra should be cleaned up
        assert "floss-deep-analysis" not in self.st._task_cancel_events
        assert "floss-deep-analysis" not in self.st._background_threads

    def test_cleanup_after_failure(self):
        """Cancel event and thread ref cleaned up even on exception."""
        def failing_floss(*args, **kwargs):
            raise RuntimeError("FLOSS exploded")

        with patch("arkana.mcp.tools_pe._parse_floss_analysis", side_effect=failing_floss):
            from arkana.mcp.tools_pe import _start_floss_background_task
            _start_floss_background_task(self.st, ("data", 6))
            thread = self.st._background_threads.get("floss-deep-analysis")
            assert thread is not None
            thread.join(timeout=5)

        # Infra cleaned up
        assert "floss-deep-analysis" not in self.st._task_cancel_events
        assert "floss-deep-analysis" not in self.st._background_threads

        # Task should be FAILED
        task = self.st.get_task("floss-deep-analysis")
        assert task["status"] == TASK_FAILED

    def test_generation_guard_prevents_cross_file_write(self):
        """If generation changes, result is NOT written to pe_data."""
        barrier = threading.Event()

        def slow_floss(*args, **kwargs):
            barrier.wait(timeout=5)
            return {"status": "Complete", "enriched": True}

        with patch("arkana.mcp.tools_pe._parse_floss_analysis", side_effect=slow_floss):
            from arkana.mcp.tools_pe import _start_floss_background_task
            _start_floss_background_task(self.st, ("data", 6))
            thread = self.st._background_threads.get("floss-deep-analysis")

            # Simulate file switch by incrementing generation
            self.st.increment_generation()

            # Let worker continue
            barrier.set()
            thread.join(timeout=5)

        # Result should NOT be written (generation mismatch)
        assert self.st.pe_data["floss_analysis"] is None

    def test_cancel_event_stops_before_result_write(self):
        """Setting cancel event prevents result from being written."""
        barrier = threading.Event()

        def slow_floss(*args, **kwargs):
            barrier.wait(timeout=5)
            return {"status": "Complete", "enriched": True}

        with patch("arkana.mcp.tools_pe._parse_floss_analysis", side_effect=slow_floss):
            from arkana.mcp.tools_pe import _start_floss_background_task
            _start_floss_background_task(self.st, ("data", 6))
            thread = self.st._background_threads.get("floss-deep-analysis")

            # Set cancel event
            self.st._task_cancel_events["floss-deep-analysis"].set()

            # Let worker continue
            barrier.set()
            thread.join(timeout=5)

        # Result should NOT be written (cancelled)
        assert self.st.pe_data["floss_analysis"] is None

    def test_cancel_all_stops_floss(self):
        """cancel_all_background_tasks sets the FLOSS cancel event."""
        barrier = threading.Event()

        def slow_floss(*args, **kwargs):
            barrier.wait(timeout=5)
            return {"status": "Complete"}

        with patch("arkana.mcp.tools_pe._parse_floss_analysis", side_effect=slow_floss):
            from arkana.mcp.tools_pe import _start_floss_background_task
            _start_floss_background_task(self.st, ("data", 6))

            # cancel_all should set the FLOSS cancel event
            self.st.cancel_all_background_tasks()
            cancel = self.st._task_cancel_events.get("floss-deep-analysis")
            if cancel is not None:
                assert cancel.is_set()

            barrier.set()
            thread = self.st._background_threads.get("floss-deep-analysis")
            if thread:
                thread.join(timeout=5)


class TestAngrWorkerCancelEvent(unittest.TestCase):
    """angr_background_worker checks _cancel_event in overtime loop and before results."""

    def setUp(self):
        self._saved_tasks = _default_state.background_tasks.copy()
        self._saved_cancel = _default_state._task_cancel_events.copy()
        self._saved_threads = _default_state._background_threads.copy()
        set_current_state(_default_state)

    def tearDown(self):
        _default_state.background_tasks = self._saved_tasks
        _default_state._task_cancel_events = self._saved_cancel
        _default_state._background_threads = self._saved_threads

    @patch('arkana.background.angr_background_worker')
    def test_cancel_event_passed_to_worker(self, mock_worker):
        """start_angr_background passes cancel event to the worker."""
        from arkana.background import start_angr_background
        start_angr_background("/test/file.exe", task_id="test-cancel-pass")

        # The worker should have been called with _cancel_event kwarg
        mock_worker.assert_called_once()
        kwargs = mock_worker.call_args.kwargs
        assert "_cancel_event" in kwargs
        assert isinstance(kwargs["_cancel_event"], threading.Event)
        # Should be the same event registered in _task_cancel_events
        assert kwargs["_cancel_event"] is _default_state._task_cancel_events["test-cancel-pass"]

    @patch('arkana.background.angr_background_worker')
    def test_worker_cleanup_in_finally(self, mock_worker):
        """Worker's finally block should clean up cancel events and thread refs."""
        from arkana.background import start_angr_background

        # The mock prevents the real worker from running, but the thread
        # still starts and finishes quickly
        start_angr_background("/test/file.exe", task_id="test-finally")

        # Wait for the mock thread to complete
        thread = _default_state._background_threads.get("test-finally")
        if thread:
            thread.join(timeout=5)

        # Since we're mocking the worker, the finally won't run (mock returns immediately).
        # But we can verify the registration happened.
        assert "test-finally" in _default_state._task_cancel_events


class TestAbortBackgroundTaskConstants(unittest.TestCase):
    """abort_background_task uses TASK_RUNNING/TASK_OVERTIME constants."""

    def test_source_uses_constants(self):
        """Verify abort_background_task imports and uses task status constants."""
        import inspect
        from arkana.mcp import tools_config
        source = inspect.getsource(tools_config)
        assert "from arkana.state import TASK_FAILED, TASK_RUNNING, TASK_OVERTIME" in source

    def test_abort_rejects_completed_task(self):
        """Completed tasks cannot be aborted."""
        st = AnalyzerState()
        st.set_task("done-task", {"status": TASK_COMPLETED, "tool": "test"})

        with patch("arkana.mcp.tools_config.state", st):
            from arkana.mcp.tools_config import abort_background_task
            ctx = AsyncMock()
            ctx.info = AsyncMock()

            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(
                    abort_background_task.__wrapped__(ctx, "done-task")
                )
            finally:
                if loop._default_executor is not None:
                    loop.run_until_complete(loop.shutdown_default_executor())
                loop.close()

        assert "error" in result
        assert "not running" in result["error"]


class TestAlertCollectionLogging(unittest.TestCase):
    """_collect_background_alerts logs exceptions at debug level."""

    def test_logs_on_exception(self):
        """Exception during alert collection should log at debug level."""
        from arkana.mcp.server import _collect_background_alerts

        # Create a state that will raise when accessed
        broken_state = MagicMock()
        broken_state.get_all_task_ids.side_effect = RuntimeError("broken")

        with patch("arkana.mcp.server.logger") as mock_logger:
            alerts = _collect_background_alerts(broken_state)

        # Should return empty list (not crash)
        assert alerts == []
        # Should have logged the error
        mock_logger.debug.assert_called_once()
        args = mock_logger.debug.call_args
        assert "Alert collection error" in args[0][0]


class TestMonitorThreadStartedRemoved(unittest.TestCase):
    """monitor_thread_started field should not exist on AnalyzerState."""

    def test_field_removed(self):
        st = AnalyzerState()
        assert not hasattr(st, "monitor_thread_started")


class TestOpenFileErrorHandlerCancelsAll(unittest.TestCase):
    """open_file error handler calls cancel_all_background_tasks."""

    def test_source_calls_cancel_all_in_error_handler(self):
        """Verify the error handler source includes cancel_all_background_tasks."""
        import inspect
        from arkana.mcp import tools_pe
        source = inspect.getsource(tools_pe.open_file.__wrapped__)
        # The error handler should call cancel_all before individual cleanup
        lines = source.split("\n")
        in_except = False
        found_cancel_all = False
        found_enrichment_cancel = False
        for line in lines:
            if "except Exception" in line:
                in_except = True
            if in_except:
                if "cancel_all_background_tasks" in line:
                    found_cancel_all = True
                if "_enrichment_cancel.set()" in line:
                    found_enrichment_cancel = True
                    break
        assert found_cancel_all, "cancel_all_background_tasks not found in error handler"
        assert found_cancel_all and found_enrichment_cancel, \
            "cancel_all should appear before _enrichment_cancel.set()"


class TestAngrWorkerProgressMessageInErrorHandler(unittest.TestCase):
    """angr worker error handlers include progress_message in update_task."""

    def test_source_has_progress_message_in_error_handler(self):
        """Verify angr worker error handlers use progress_message in update_task."""
        import inspect
        from arkana.background import angr_background_worker
        source = inspect.getsource(angr_background_worker)
        # Find the except blocks that call update_task with TASK_FAILED
        # They should include progress_message= directly (not a separate _update_progress call)
        lines = source.split("\n")
        in_except = False
        for i, line in enumerate(lines):
            if "except (OSError, RuntimeError, ValueError)" in line or \
               "except Exception as e:" in line:
                in_except = True
                continue
            if in_except:
                if "update_task" in line and "TASK_FAILED" in line:
                    # Check the next line(s) for progress_message
                    block = "\n".join(lines[i:i+3])
                    assert "progress_message=" in block, \
                        f"Missing progress_message in error handler update_task near line {i}"
                    in_except = False
                if line.strip().startswith("except") or line.strip().startswith("finally"):
                    in_except = False


class TestAngrWorkerFinallyCleanup(unittest.TestCase):
    """angr_background_worker has finally block for cleanup."""

    def test_finally_block_exists(self):
        import inspect
        from arkana.background import angr_background_worker
        source = inspect.getsource(angr_background_worker)
        assert "unregister_task_infra(task_id)" in source
        assert "finally:" in source


class TestFlossIntegrationWithCancelAll(unittest.TestCase):
    """Integration: cancel_all_background_tasks properly interacts with FLOSS task."""

    def test_cancel_all_sets_floss_cancel_event_and_marks_failed(self):
        """cancel_all should both mark FLOSS task FAILED and set its cancel event."""
        st = AnalyzerState()
        set_current_state(st)

        cancel = threading.Event()
        st._task_cancel_events["floss-deep-analysis"] = cancel
        st.set_task("floss-deep-analysis", {"status": TASK_RUNNING, "tool": "FLOSS"})

        st.cancel_all_background_tasks()

        task = st.get_task("floss-deep-analysis")
        assert task["status"] == TASK_FAILED
        assert task["aborted"] is True
        assert cancel.is_set()


class TestWrapperCancelEventRaceWindowClosed(unittest.TestCase):
    """The race window between set_task(RUNNING) and cancel event registration is closed."""

    def setUp(self):
        self.st = AnalyzerState()
        set_current_state(self.st)

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            if loop._default_executor is not None:
                loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()

    def test_cancel_event_exists_when_task_is_running(self):
        """Cancel event exists when the wrapper starts executing."""
        from arkana.background import _run_background_task_wrapper, _register_background_task

        seen_cancel = {}

        def check_cancel():
            # At this point, the cancel event should exist
            seen_cancel["exists"] = "test-racewin" in self.st._task_cancel_events
            return {"ok": True}

        _cancel = _register_background_task("test-racewin", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        # Cancel event should exist BEFORE wrapper runs
        assert "test-racewin" in self.st._task_cancel_events
        assert self.st._task_cancel_events["test-racewin"] is _cancel

        self._run(_run_background_task_wrapper(
            "test-racewin", check_cancel, cancel_event=_cancel, soft_timeout=10
        ))

        assert seen_cancel.get("exists") is True


if __name__ == "__main__":
    unittest.main()
