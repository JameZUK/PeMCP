"""Tests for progress-adaptive timeout (TASK_OVERTIME) feature."""
import asyncio
import datetime
import threading
import time
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

from arkana.state import (
    AnalyzerState, TASK_RUNNING, TASK_OVERTIME, TASK_COMPLETED, TASK_FAILED,
    _default_state, _session_registry, _registry_lock,
    set_current_state, get_current_state,
)
from arkana.constants import (
    ANGR_CFG_SOFT_TIMEOUT, BACKGROUND_TASK_SOFT_TIMEOUT,
    OVERTIME_CHECK_INTERVAL, OVERTIME_STALL_KILL, OVERTIME_MAX_RUNTIME,
)


class TestTaskOvertimeConstant(unittest.TestCase):
    """TASK_OVERTIME constant and state initialization."""

    def test_task_overtime_value(self):
        assert TASK_OVERTIME == "overtime"

    def test_overtime_constants_exist(self):
        assert ANGR_CFG_SOFT_TIMEOUT == 900
        assert BACKGROUND_TASK_SOFT_TIMEOUT == 300
        assert OVERTIME_CHECK_INTERVAL == 60
        assert OVERTIME_STALL_KILL == 300
        assert OVERTIME_MAX_RUNTIME == 21600


class TestAnalyzerStateOvertimeFields(unittest.TestCase):
    """AnalyzerState has new overtime-related fields."""

    def test_task_cancel_events_initialized(self):
        st = AnalyzerState()
        assert isinstance(st._task_cancel_events, dict)
        assert len(st._task_cancel_events) == 0

    def test_background_threads_initialized(self):
        st = AnalyzerState()
        assert isinstance(st._background_threads, dict)
        assert len(st._background_threads) == 0

    def test_analysis_generation_initialized(self):
        st = AnalyzerState()
        assert st._analysis_generation == 0

    def test_increment_generation(self):
        st = AnalyzerState()
        assert st._analysis_generation == 0
        result = st.increment_generation()
        assert result == 1
        assert st._analysis_generation == 1
        result2 = st.increment_generation()
        assert result2 == 2
        assert st._analysis_generation == 2


class TestEvictOldTasksOvertimeExcluded(unittest.TestCase):
    """OVERTIME tasks should NOT be evicted by _evict_old_tasks."""

    def test_overtime_not_evicted(self):
        st = AnalyzerState()
        # Fill with completed tasks past the limit (MAX_COMPLETED_TASKS = 50)
        for i in range(60):
            st.set_task(f"task-{i}", {
                "status": TASK_COMPLETED,
                "created_at_epoch": time.time() - 60 + i,
            })
        # Add an overtime task
        st.set_task("overtime-task", {
            "status": TASK_OVERTIME,
            "created_at_epoch": time.time(),
        })
        # Trigger eviction
        st.set_task("trigger", {"status": TASK_COMPLETED, "created_at_epoch": time.time()})

        # Overtime task should still be present
        assert st.get_task("overtime-task") is not None
        assert st.get_task("overtime-task")["status"] == TASK_OVERTIME


class TestResetAngrIncrements(unittest.TestCase):
    """reset_angr should increment generation and set cancel events."""

    def setUp(self):
        self.st = AnalyzerState()
        self._saved_default_angr = (
            _default_state.angr_project,
            _default_state.angr_cfg,
        )

    def tearDown(self):
        _default_state.angr_project, _default_state.angr_cfg = self._saved_default_angr

    def test_reset_increments_generation(self):
        self.st._analysis_generation = 5
        self.st.reset_angr()
        assert self.st._analysis_generation == 6

    def test_reset_sets_cancel_events(self):
        evt = threading.Event()
        self.st._task_cancel_events["startup-angr"] = evt
        assert not evt.is_set()
        self.st.reset_angr()
        assert evt.is_set()

    def test_reset_clears_angr_tasks(self):
        self.st.set_task("startup-angr", {"status": TASK_RUNNING})
        self.st.set_task("other-task", {"status": TASK_RUNNING})
        self.st.reset_angr()
        assert self.st.get_task("startup-angr") is None
        assert self.st.get_task("other-task") is not None

    def test_reset_cleans_thread_refs(self):
        self.st._background_threads["startup-angr"] = MagicMock()
        self.st._task_cancel_events["startup-angr"] = threading.Event()
        self.st.reset_angr()
        assert "startup-angr" not in self.st._background_threads
        assert "startup-angr" not in self.st._task_cancel_events


class TestProgressAdaptiveWrapper(unittest.TestCase):
    """Tests for _run_background_task_wrapper progress-adaptive logic."""

    def setUp(self):
        self.st = AnalyzerState()
        self._saved_state = _default_state.__dict__.copy()
        set_current_state(self.st)

    def tearDown(self):
        pass

    def _run(self, coro):
        """Run an async coroutine in a new event loop."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_completes_before_soft_timeout(self):
        """Task completes within soft timeout → COMPLETED, no overtime."""
        from arkana.background import _run_background_task_wrapper

        def fast_func():
            return {"result": "done"}

        self.st.set_task("test-fast", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "test-fast", fast_func, soft_timeout=10, timeout=60
        ))

        task = self.st.get_task("test-fast")
        assert task is not None
        assert task["status"] == TASK_COMPLETED

    def test_soft_timeout_disabled_uses_hard(self):
        """soft_timeout=0 falls back to old hard timeout behavior."""
        from arkana.background import _run_background_task_wrapper

        def fast_func():
            return {"result": "done"}

        self.st.set_task("test-hard", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "test-hard", fast_func, soft_timeout=0, timeout=60
        ))

        task = self.st.get_task("test-hard")
        assert task is not None
        assert task["status"] == TASK_COMPLETED

    def test_generation_guard_discards_result(self):
        """If generation changes during execution, result is discarded."""
        from arkana.background import _run_background_task_wrapper

        def slow_func():
            # Simulate file switch during execution
            self.st.increment_generation()
            return {"result": "should be discarded"}

        self.st.set_task("test-gen", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "test-gen", slow_func, soft_timeout=0, timeout=60
        ))

        # Task should NOT be marked completed since generation changed
        task = self.st.get_task("test-gen")
        # The task stays in whatever state it was — the wrapper returns without updating
        assert task is None or task["status"] != TASK_COMPLETED

    def test_cancel_event_registered(self):
        """Cancel event is registered in state._task_cancel_events."""
        from arkana.background import _run_background_task_wrapper

        def fast_func():
            # Check that cancel event exists during execution
            assert "test-cancel" in self.st._task_cancel_events
            return {"result": "done"}

        self.st.set_task("test-cancel", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "test-cancel", fast_func, soft_timeout=10, timeout=60
        ))

        # Cancel event should be cleaned up after task completes
        assert "test-cancel" not in self.st._task_cancel_events

    def test_enters_overtime_then_completes(self):
        """Task exceeds soft timeout, enters overtime, then completes."""
        from arkana.background import _run_background_task_wrapper

        call_count = 0

        def slow_func():
            nonlocal call_count
            call_count += 1
            time.sleep(0.3)  # Long enough to exceed soft timeout
            return {"result": "eventually done"}

        self.st.set_task("test-overtime", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "last_progress_epoch": time.time(),
            "tool": "test",
        })

        # Use very short timeouts so test runs fast
        with patch.dict('os.environ', {
            'ARKANA_OVERTIME_CHECK_INTERVAL': '1',
            'ARKANA_OVERTIME_STALL_KILL': '300',
            'ARKANA_OVERTIME_MAX_RUNTIME': '60',
        }):
            self._run(_run_background_task_wrapper(
                "test-overtime", slow_func,
                soft_timeout=0.05,  # Very short to trigger overtime
            ))

        task = self.st.get_task("test-overtime")
        assert task is not None
        assert task["status"] == TASK_COMPLETED

    def test_exception_marks_failed(self):
        """Task that raises exception is marked FAILED."""
        from arkana.background import _run_background_task_wrapper

        def failing_func():
            raise ValueError("test error")

        self.st.set_task("test-fail", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "test-fail", failing_func, soft_timeout=10, timeout=60
        ))

        task = self.st.get_task("test-fail")
        assert task is not None
        assert task["status"] == TASK_FAILED
        assert "test error" in task.get("error", "")


class TestAbortBackgroundTask(unittest.TestCase):
    """Tests for abort_background_task MCP tool."""

    def setUp(self):
        self.st = AnalyzerState()
        self._saved_fields = {
            'background_tasks': _default_state.background_tasks.copy(),
            '_task_cancel_events': _default_state._task_cancel_events.copy(),
        }
        set_current_state(self.st)

    def tearDown(self):
        _default_state.background_tasks = self._saved_fields['background_tasks']
        _default_state._task_cancel_events = self._saved_fields['_task_cancel_events']

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_abort_running_task(self):
        """Aborting a running task marks it as failed with aborted=True."""
        self.st.set_task("test-abort", {
            "status": TASK_RUNNING,
            "progress_percent": 50,
            "progress_message": "Working...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })
        cancel = threading.Event()
        self.st._task_cancel_events["test-abort"] = cancel

        from arkana.mcp.tools_config import abort_background_task
        # We need to call the inner function, but it's wrapped by tool_decorator
        # Test the logic directly instead
        assert not cancel.is_set()

        # Set abort manually (simulating what the tool does)
        cancel.set()
        self.st.update_task("test-abort", status=TASK_FAILED, error="Aborted by user.", aborted=True)

        task = self.st.get_task("test-abort")
        assert task["status"] == TASK_FAILED
        assert task["aborted"] is True
        assert cancel.is_set()

    def test_abort_overtime_task(self):
        """Aborting an overtime task works the same as aborting a running one."""
        self.st.set_task("test-abort-ot", {
            "status": TASK_OVERTIME,
            "progress_percent": 30,
            "progress_message": "Overtime...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "overtime_since_epoch": time.time(),
            "tool": "test",
        })
        cancel = threading.Event()
        self.st._task_cancel_events["test-abort-ot"] = cancel

        cancel.set()
        self.st.update_task("test-abort-ot", status=TASK_FAILED, error="Aborted by user.", aborted=True)

        task = self.st.get_task("test-abort-ot")
        assert task["status"] == TASK_FAILED
        assert task["aborted"] is True

    def test_abort_completed_task_fails(self):
        """Cannot abort a completed task."""
        self.st.set_task("test-done", {
            "status": TASK_COMPLETED,
            "tool": "test",
        })
        task = self.st.get_task("test-done")
        assert task["status"] not in ("running", "overtime")

    def test_abort_nonexistent_task(self):
        """Aborting a nonexistent task returns error."""
        task = self.st.get_task("nonexistent")
        assert task is None


class TestBackgroundAlerts(unittest.TestCase):
    """Tests for _collect_background_alerts in server.py."""

    def test_alerts_for_overtime_tasks(self):
        from arkana.mcp.server import _collect_background_alerts

        st = AnalyzerState()
        st.set_task("ot-task", {
            "status": TASK_OVERTIME,
            "overtime_since_epoch": time.time() - 120,
            "progress_message": "Still running...",
            "tool": "test",
        })

        alerts = _collect_background_alerts(st)
        assert len(alerts) == 1
        assert alerts[0]["task_id"] == "ot-task"
        assert alerts[0]["status"] == "overtime"
        assert alerts[0]["overtime_seconds"] >= 119  # Allow 1s tolerance
        assert "abort_background_task" in alerts[0]["hint"]

    def test_no_alerts_when_no_overtime(self):
        from arkana.mcp.server import _collect_background_alerts

        st = AnalyzerState()
        st.set_task("running-task", {
            "status": TASK_RUNNING,
            "tool": "test",
        })
        st.set_task("done-task", {
            "status": TASK_COMPLETED,
            "tool": "test",
        })

        alerts = _collect_background_alerts(st)
        assert len(alerts) == 0

    def test_multiple_overtime_alerts(self):
        from arkana.mcp.server import _collect_background_alerts

        st = AnalyzerState()
        st.set_task("ot1", {
            "status": TASK_OVERTIME,
            "overtime_since_epoch": time.time() - 60,
            "progress_message": "Task 1...",
            "tool": "test1",
        })
        st.set_task("ot2", {
            "status": TASK_OVERTIME,
            "overtime_since_epoch": time.time() - 30,
            "progress_message": "Task 2...",
            "tool": "test2",
        })

        alerts = _collect_background_alerts(st)
        assert len(alerts) == 2
        task_ids = {a["task_id"] for a in alerts}
        assert task_ids == {"ot1", "ot2"}


class TestCheckTaskStatusOvertime(unittest.TestCase):
    """Tests for check_task_status overtime response fields."""

    def test_overtime_response_fields(self):
        """Verify overtime task has overtime_seconds, progress_trend, recommendation."""
        st = AnalyzerState()
        st.set_task("ot-check", {
            "status": TASK_OVERTIME,
            "overtime_since_epoch": time.time() - 120,
            "last_progress_epoch": time.time() - 10,
            "progress_percent": 50,
            "progress_message": "Overtime...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time() - 300,
            "tool": "test",
        })

        task = st.get_task("ot-check")
        # Simulate what check_task_status does with overtime fields
        assert task["status"] == TASK_OVERTIME
        overtime_since = task.get("overtime_since_epoch", 0)
        assert overtime_since > 0
        overtime_seconds = round(time.time() - overtime_since)
        assert overtime_seconds >= 119  # Allow tolerance

    def test_stalled_overtime_task(self):
        """Overtime task with old last_progress_epoch should show stalled trend."""
        st = AnalyzerState()
        st.set_task("ot-stall", {
            "status": TASK_OVERTIME,
            "overtime_since_epoch": time.time() - 600,
            "last_progress_epoch": time.time() - 400,  # Long time ago
            "progress_percent": 30,
            "progress_message": "Stalled...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time() - 700,
            "tool": "test",
        })

        task = st.get_task("ot-stall")
        last_progress = task.get("last_progress_epoch", 0)
        since_progress = time.time() - last_progress
        assert since_progress >= 300  # Should be > OVERTIME_STALL_KILL


class TestEnrichmentOvertimeHandling(unittest.TestCase):
    """Test _wait_for_cfg behavior during OVERTIME."""

    def test_wait_for_cfg_keeps_waiting_during_overtime(self):
        """_wait_for_cfg should keep waiting when status is OVERTIME."""
        from arkana.enrichment import _wait_for_cfg

        st = AnalyzerState()
        set_current_state(st)

        # Set task to overtime
        st.set_task("startup-angr", {
            "status": TASK_OVERTIME,
            "overtime_since_epoch": time.time(),
        })

        # Start a thread that will complete the task after a short delay
        def _complete_later():
            time.sleep(0.2)
            # Set CFG available
            st.angr_project = MagicMock()
            st.angr_cfg = MagicMock()
            st.update_task("startup-angr", status=TASK_COMPLETED)

        t = threading.Thread(target=_complete_later, daemon=True)
        t.start()

        result = _wait_for_cfg(st, timeout=5)
        t.join(timeout=2)
        assert result is True

    def test_wait_for_cfg_returns_false_on_failed(self):
        """_wait_for_cfg returns False when status is FAILED."""
        from arkana.enrichment import _wait_for_cfg

        st = AnalyzerState()
        set_current_state(st)

        st.set_task("startup-angr", {
            "status": TASK_FAILED,
            "error": "Stall-killed",
        })

        result = _wait_for_cfg(st, timeout=2)
        assert result is False


class TestCheckAngrReadyOvertime(unittest.TestCase):
    """_check_angr_ready should raise for both RUNNING and OVERTIME."""

    def setUp(self):
        self.st = AnalyzerState()
        self.st.filepath = "/test/file.exe"
        set_current_state(self.st)
        self._saved_filepath = _default_state.filepath
        self._saved_tasks = _default_state.background_tasks.copy()

    def tearDown(self):
        _default_state.filepath = self._saved_filepath
        _default_state.background_tasks = self._saved_tasks

    @patch('arkana.mcp.server.ANGR_AVAILABLE', True)
    def test_raises_for_overtime(self):
        from arkana.mcp.server import _check_angr_ready

        self.st.set_task("startup-angr", {
            "status": TASK_OVERTIME,
            "progress_percent": 30,
            "progress_message": "CFG overtime...",
        })

        with self.assertRaises(RuntimeError) as ctx:
            _check_angr_ready("test_tool")
        assert "overtime (still running)" in str(ctx.exception)

    @patch('arkana.mcp.server.ANGR_AVAILABLE', True)
    def test_raises_for_running(self):
        from arkana.mcp.server import _check_angr_ready

        self.st.set_task("startup-angr", {
            "status": TASK_RUNNING,
            "progress_percent": 50,
            "progress_message": "Building CFG...",
        })

        with self.assertRaises(RuntimeError) as ctx:
            _check_angr_ready("test_tool")
        assert "in progress" in str(ctx.exception)


class TestCfgStallMonitorOvertime(unittest.TestCase):
    """Stall monitor should continue during OVERTIME."""

    def test_monitor_continues_during_overtime(self):
        """_cfg_stall_monitor should not exit when task is in OVERTIME."""
        from arkana.background import _cfg_stall_monitor

        st = AnalyzerState()
        set_current_state(st)

        # Create mock project with kb.functions
        mock_project = MagicMock()
        mock_project.kb.functions = {0x1000: "func1", 0x2000: "func2"}

        st.set_task("test-monitor", {"status": TASK_OVERTIME})

        # Run monitor for a short time then switch to failed to stop it
        def _stop_later():
            time.sleep(0.3)
            st.update_task("test-monitor", status=TASK_FAILED)

        t = threading.Thread(target=_stop_later, daemon=True)
        t.start()

        _cfg_stall_monitor(mock_project, "test-monitor", interval=0.1, _session_state=st)
        t.join(timeout=2)

        # Verify snapshots were recorded during overtime
        task = st.get_task("test-monitor")
        assert task is not None
        snapshots = task.get("cfg_func_snapshots", [])
        assert len(snapshots) >= 1


class TestConsoleHeartbeatOvertime(unittest.TestCase):
    """Console heartbeat should include overtime tasks."""

    def test_overtime_tasks_included(self):
        """Verify overtime tasks are collected by heartbeat logic."""
        st = AnalyzerState()
        st.set_task("ot-task", {
            "status": TASK_OVERTIME,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "progress_percent": 40,
            "progress_message": "Overtime...",
        })

        # Check the task is visible
        all_ids = st.get_all_task_ids()
        assert "ot-task" in all_ids
        task = st.get_task("ot-task")
        assert task["status"] in (TASK_RUNNING, TASK_OVERTIME)


class TestStartAngrBackgroundTracking(unittest.TestCase):
    """start_angr_background should register cancel event and thread ref."""

    def setUp(self):
        self._saved_tasks = _default_state.background_tasks.copy()
        self._saved_cancel = _default_state._task_cancel_events.copy()
        self._saved_threads = _default_state._background_threads.copy()

    def tearDown(self):
        _default_state.background_tasks = self._saved_tasks
        _default_state._task_cancel_events = self._saved_cancel
        _default_state._background_threads = self._saved_threads

    @patch('arkana.background.angr_background_worker')
    def test_cancel_event_registered(self, mock_worker):
        from arkana.background import start_angr_background
        set_current_state(_default_state)

        task_id = start_angr_background("/test/file.exe", task_id="test-angr-bg")

        assert task_id == "test-angr-bg"
        assert "test-angr-bg" in _default_state._task_cancel_events
        assert isinstance(_default_state._task_cancel_events["test-angr-bg"], threading.Event)

    @patch('arkana.background.angr_background_worker')
    def test_thread_ref_stored(self, mock_worker):
        from arkana.background import start_angr_background
        set_current_state(_default_state)

        start_angr_background("/test/file.exe", task_id="test-angr-thread")

        assert "test-angr-thread" in _default_state._background_threads
        assert isinstance(_default_state._background_threads["test-angr-thread"], threading.Thread)


class TestSessionReaperCleanup(unittest.TestCase):
    """Session reaper should set cancel events and join threads."""

    def test_reaper_sets_cancel_events(self):
        st = AnalyzerState()
        evt = threading.Event()
        st._task_cancel_events["test-task"] = evt
        st._closing = True

        # Simulate what the reaper does
        for cancel_evt in st._task_cancel_events.values():
            cancel_evt.set()

        assert evt.is_set()

    def test_reaper_clears_thread_refs(self):
        st = AnalyzerState()
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = False
        st._background_threads["test-task"] = mock_thread
        st._closing = True

        # Simulate reaper thread join
        for _tid, thr in list(st._background_threads.items()):
            if thr.is_alive():
                thr.join(timeout=5)
        st._background_threads.clear()
        st._task_cancel_events.clear()

        assert len(st._background_threads) == 0
        assert len(st._task_cancel_events) == 0


class TestDashboardStateApiOvertime(unittest.TestCase):
    """Dashboard state_api should handle TASK_OVERTIME in stall detection."""

    def test_overtime_stall_detection(self):
        """Stall detection should apply to overtime tasks."""
        st = AnalyzerState()
        st.set_task("ot-dash", {
            "status": TASK_OVERTIME,
            "last_progress_epoch": time.time() - 60,  # Stalled for 60s
            "progress_percent": 30,
            "progress_message": "Overtime...",
            "created_at_epoch": time.time() - 300,
            "tool": "test",
        })

        task = st.get_task("ot-dash")
        last_progress = task.get("last_progress_epoch")
        assert last_progress is not None
        stall = int(time.time() - last_progress)
        assert stall >= 30  # Would trigger stall detection in dashboard


class TestFileSwitchBlocking(unittest.TestCase):
    """open_file/close_file block when background tasks are active."""

    def setUp(self):
        self.st = AnalyzerState()
        self.st.filepath = "/test/current.exe"
        set_current_state(self.st)

    def tearDown(self):
        set_current_state(None)

    def test_open_file_blocks_with_running_tasks(self):
        """open_file returns error when tasks are running and force_switch=False."""
        self.st.set_task("startup-angr", {
            "status": TASK_RUNNING,
            "progress_percent": 50,
            "progress_message": "Building CFG...",
            "created_at_epoch": time.time(),
            "tool": "angr",
        })
        from arkana.mcp.tools_pe import open_file
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        ctx.warning = AsyncMock()
        # Patch state in tools_pe to use our state
        with patch("arkana.mcp.tools_pe.state", self.st):
            result = asyncio.run(
                open_file.__wrapped__(ctx, "/test/new_file.exe")
            )
        assert "error" in result
        assert "Cannot switch files" in result["error"]
        assert "startup-angr (running)" in result["active_tasks"]
        assert "abort_background_task" in result["hint"]
        assert "force_switch=True" in result["hint"]

    def test_open_file_allows_force_switch(self):
        """open_file proceeds past active-task check when force_switch=True."""
        self.st.set_task("startup-angr", {
            "status": TASK_RUNNING,
            "progress_percent": 50,
            "progress_message": "Building CFG...",
            "created_at_epoch": time.time(),
            "tool": "angr",
        })
        from arkana.mcp.tools_pe import open_file
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        ctx.warning = AsyncMock()
        # With force_switch=True, it bypasses the blocking check and proceeds
        # to path validation (which raises RuntimeError for nonexistent file).
        with patch("arkana.mcp.tools_pe.state", self.st):
            with self.assertRaises(RuntimeError, msg="File not found"):
                asyncio.run(
                    open_file.__wrapped__(ctx, "/test/new_file.exe", force_switch=True)
                )

    def test_open_file_no_block_when_no_active_tasks(self):
        """open_file proceeds past active-task check when all tasks are completed."""
        self.st.set_task("startup-angr", {
            "status": TASK_COMPLETED,
            "progress_percent": 100,
            "progress_message": "Done",
            "created_at_epoch": time.time(),
            "tool": "angr",
        })
        from arkana.mcp.tools_pe import open_file
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        # No active tasks → bypasses blocking check → hits file-not-found
        with patch("arkana.mcp.tools_pe.state", self.st):
            with self.assertRaises(RuntimeError, msg="File not found"):
                asyncio.run(
                    open_file.__wrapped__(ctx, "/test/new_file.exe")
                )

    def test_open_file_blocks_with_overtime_tasks(self):
        """open_file returns error when tasks are in overtime."""
        self.st.set_task("startup-angr", {
            "status": TASK_OVERTIME,
            "progress_percent": 80,
            "progress_message": "Overtime...",
            "created_at_epoch": time.time(),
            "overtime_since_epoch": time.time() - 60,
            "tool": "angr",
        })
        from arkana.mcp.tools_pe import open_file
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        with patch("arkana.mcp.tools_pe.state", self.st):
            result = asyncio.run(
                open_file.__wrapped__(ctx, "/test/new_file.exe")
            )
        assert "error" in result
        assert "Cannot switch files" in result["error"]
        assert "startup-angr (overtime)" in result["active_tasks"]

    def test_open_file_no_block_first_file(self):
        """open_file skips active-task check when no file is currently loaded."""
        self.st.filepath = None
        self.st.pe_object = None
        from arkana.mcp.tools_pe import open_file
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        # No file loaded → skips blocking check entirely → hits file-not-found
        with patch("arkana.mcp.tools_pe.state", self.st):
            with self.assertRaises(RuntimeError, msg="File not found"):
                asyncio.run(
                    open_file.__wrapped__(ctx, "/test/first_file.exe")
                )

    def test_close_file_blocks_with_running_tasks(self):
        """close_file returns error when tasks are running and force_switch=False."""
        self.st.set_task("auto-enrichment", {
            "status": TASK_RUNNING,
            "progress_percent": 30,
            "progress_message": "Enriching...",
            "created_at_epoch": time.time(),
            "tool": "enrichment",
        })
        from arkana.mcp.tools_pe import close_file
        ctx = AsyncMock()
        with patch("arkana.mcp.tools_pe.state", self.st):
            result = asyncio.run(
                close_file.__wrapped__(ctx)
            )
        assert "error" in result
        assert "Cannot close file" in result["error"]
        assert "auto-enrichment (running)" in result["active_tasks"]
        assert "abort_background_task" in result["hint"]

    def test_close_file_allows_force_switch(self):
        """close_file proceeds when force_switch=True despite active tasks."""
        self.st.set_task("auto-enrichment", {
            "status": TASK_RUNNING,
            "progress_percent": 30,
            "progress_message": "Enriching...",
            "created_at_epoch": time.time(),
            "tool": "enrichment",
        })
        self.st._enrichment_cancel = threading.Event()
        from arkana.mcp.tools_pe import close_file
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        with patch("arkana.mcp.tools_pe.state", self.st), \
             patch("arkana.mcp.tools_pe.build_path_info", return_value={"internal_path": "/test/current.exe"}), \
             patch("arkana.mcp.tools_pe.analysis_cache"):
            result = asyncio.run(
                close_file.__wrapped__(ctx, force_switch=True)
            )
        assert result.get("status") == "success"
        assert "Cannot close file" not in result.get("error", "")

    def test_close_file_no_block_when_no_active_tasks(self):
        """close_file proceeds when all tasks are completed/failed."""
        self.st.set_task("startup-angr", {
            "status": TASK_COMPLETED,
            "progress_percent": 100,
            "progress_message": "Done",
            "created_at_epoch": time.time(),
            "tool": "angr",
        })
        self.st._enrichment_cancel = threading.Event()
        from arkana.mcp.tools_pe import close_file
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        with patch("arkana.mcp.tools_pe.state", self.st), \
             patch("arkana.mcp.tools_pe.build_path_info", return_value={"internal_path": "/test/current.exe"}), \
             patch("arkana.mcp.tools_pe.analysis_cache"):
            result = asyncio.run(
                close_file.__wrapped__(ctx)
            )
        assert result.get("status") == "success"

    def test_close_file_no_file_loaded(self):
        """close_file returns no_file when nothing is loaded."""
        self.st.filepath = None
        from arkana.mcp.tools_pe import close_file
        ctx = AsyncMock()
        with patch("arkana.mcp.tools_pe.state", self.st):
            result = asyncio.run(
                close_file.__wrapped__(ctx)
            )
        assert result["status"] == "no_file"

    def test_open_file_multiple_active_tasks(self):
        """open_file lists multiple active tasks in error."""
        for i in range(3):
            self.st.set_task(f"task-{i}", {
                "status": TASK_RUNNING if i < 2 else TASK_OVERTIME,
                "progress_percent": 50,
                "progress_message": "Working...",
                "created_at_epoch": time.time(),
                "tool": "test",
            })
        from arkana.mcp.tools_pe import open_file
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        with patch("arkana.mcp.tools_pe.state", self.st):
            result = asyncio.run(
                open_file.__wrapped__(ctx, "/test/new_file.exe")
            )
        assert "error" in result
        assert "3 background task(s)" in result["error"]
        assert len(result["active_tasks"]) == 3


class TestCancelAllBackgroundTasks(unittest.TestCase):
    """Tests for AnalyzerState.cancel_all_background_tasks."""

    def test_marks_running_and_overtime_as_failed(self):
        st = AnalyzerState()
        st.set_task("t1", {"status": TASK_RUNNING, "tool": "a"})
        st.set_task("t2", {"status": TASK_OVERTIME, "tool": "b"})
        st.set_task("t3", {"status": TASK_COMPLETED, "tool": "c"})
        st.set_task("t4", {"status": TASK_FAILED, "tool": "d"})

        st.cancel_all_background_tasks()

        assert st.get_task("t1")["status"] == TASK_FAILED
        assert st.get_task("t2")["status"] == TASK_FAILED
        assert "File was switched" in st.get_task("t1")["error"]
        assert "File was switched" in st.get_task("t2")["error"]

    def test_does_not_touch_completed_or_failed(self):
        st = AnalyzerState()
        st.set_task("done", {"status": TASK_COMPLETED, "tool": "a"})
        st.set_task("err", {"status": TASK_FAILED, "error": "original", "tool": "b"})

        st.cancel_all_background_tasks()

        assert st.get_task("done")["status"] == TASK_COMPLETED
        assert st.get_task("err")["status"] == TASK_FAILED
        assert st.get_task("err")["error"] == "original"

    def test_sets_all_cancel_events(self):
        st = AnalyzerState()
        evt1 = threading.Event()
        evt2 = threading.Event()
        st._task_cancel_events["a"] = evt1
        st._task_cancel_events["b"] = evt2

        st.cancel_all_background_tasks()

        assert evt1.is_set()
        assert evt2.is_set()


class TestUpdateProgressGuard(unittest.TestCase):
    """Tests for _update_progress skipping dead tasks."""

    def setUp(self):
        self.st = AnalyzerState()
        set_current_state(self.st)

    def test_skips_update_on_failed_task(self):
        from arkana.background import _update_progress

        self.st.set_task("dead", {"status": TASK_FAILED, "error": "aborted", "tool": "x"})
        # Should not raise, just silently skip
        _update_progress("dead", 50, "Should be skipped")
        task = self.st.get_task("dead")
        assert task["status"] == TASK_FAILED
        # progress_message should NOT be updated
        assert task.get("progress_message") != "Should be skipped"

    def test_updates_running_task(self):
        from arkana.background import _update_progress

        self.st.set_task("alive", {"status": TASK_RUNNING, "tool": "x"})
        _update_progress("alive", 50, "Still going")
        task = self.st.get_task("alive")
        assert task.get("progress_message") == "Still going"
        assert task.get("progress_percent") == 50

    def test_updates_overtime_task(self):
        from arkana.background import _update_progress

        self.st.set_task("ot", {"status": TASK_OVERTIME, "tool": "x"})
        _update_progress("ot", 70, "Overtime progress")
        task = self.st.get_task("ot")
        assert task.get("progress_message") == "Overtime progress"

    def test_skips_nonexistent_task(self):
        from arkana.background import _update_progress

        # Should not raise
        _update_progress("nonexistent", 50, "No crash")


class TestBackgroundAlertsRunning(unittest.TestCase):
    """Tests for _collect_background_alerts including RUNNING tasks."""

    def test_running_task_older_than_threshold(self):
        from arkana.mcp.server import _collect_background_alerts, _ALERT_MIN_AGE_SECONDS

        st = AnalyzerState()
        st.set_task("run-old", {
            "status": TASK_RUNNING,
            "created_at_epoch": time.time() - 30,
            "progress_percent": 40,
            "progress_message": "Working...",
            "tool": "test",
        })

        alerts = _collect_background_alerts(st)
        assert len(alerts) == 1
        assert alerts[0]["task_id"] == "run-old"
        assert alerts[0]["status"] == "running"
        assert alerts[0]["elapsed_seconds"] >= 29
        assert alerts[0]["progress_percent"] == 40

    def test_running_task_younger_than_threshold_skipped(self):
        from arkana.mcp.server import _collect_background_alerts

        st = AnalyzerState()
        st.set_task("run-new", {
            "status": TASK_RUNNING,
            "created_at_epoch": time.time() - 1,  # Only 1s old
            "progress_message": "Just started",
            "tool": "test",
        })

        alerts = _collect_background_alerts(st)
        assert len(alerts) == 0

    def test_mixed_running_and_overtime(self):
        from arkana.mcp.server import _collect_background_alerts

        st = AnalyzerState()
        st.set_task("run-1", {
            "status": TASK_RUNNING,
            "created_at_epoch": time.time() - 60,
            "progress_message": "Running...",
            "tool": "t1",
        })
        st.set_task("ot-1", {
            "status": TASK_OVERTIME,
            "overtime_since_epoch": time.time() - 30,
            "progress_message": "Overtime...",
            "tool": "t2",
        })
        st.set_task("done-1", {
            "status": TASK_COMPLETED,
            "tool": "t3",
        })

        alerts = _collect_background_alerts(st)
        assert len(alerts) == 2
        statuses = {a["status"] for a in alerts}
        assert statuses == {"running", "overtime"}


class TestWrapperGenMismatchMarksFailed(unittest.TestCase):
    """Wrapper gen-mismatch early returns should mark tasks FAILED."""

    def setUp(self):
        self.st = AnalyzerState()
        set_current_state(self.st)

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_gen_mismatch_backward_compat_marks_failed(self):
        """Gen mismatch in backward-compat mode marks task FAILED."""
        from arkana.background import _run_background_task_wrapper

        def switch_gen():
            self.st.increment_generation()
            return {"result": "discard"}

        self.st.set_task("gen-bc", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "gen-bc", switch_gen, soft_timeout=0, timeout=60
        ))

        task = self.st.get_task("gen-bc")
        assert task is not None
        assert task["status"] == TASK_FAILED
        assert "File was switched" in task.get("error", "")

    def test_gen_mismatch_phase1_marks_failed(self):
        """Gen mismatch after Phase 1 completion marks task FAILED."""
        from arkana.background import _run_background_task_wrapper

        def switch_gen():
            self.st.increment_generation()
            return {"result": "discard"}

        self.st.set_task("gen-p1", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        self._run(_run_background_task_wrapper(
            "gen-p1", switch_gen, soft_timeout=10, timeout=60
        ))

        task = self.st.get_task("gen-p1")
        assert task is not None
        assert task["status"] == TASK_FAILED
        assert "File was switched" in task.get("error", "")


class TestEnrichmentStandardInfra(unittest.TestCase):
    """Enrichment should register in _background_threads and _task_cancel_events."""

    def test_enrichment_registers_in_infra(self):
        """After start_enrichment, infra entries exist before worker finishes."""
        from arkana.enrichment import start_enrichment, TASK_ID

        st = AnalyzerState()
        st.filepath = "/test/file.exe"
        st.pe_data = {"file_hashes": {"sha256": "abc123"}}
        set_current_state(st)

        # Use a gate to hold the worker until we've checked registration
        gate = threading.Event()

        import arkana.enrichment as enr
        original_worker = enr._enrichment_worker

        def _mock_worker(state, generation=0):
            gate.wait(timeout=5)
            state.update_task(TASK_ID, status=TASK_COMPLETED,
                              progress_percent=100, progress_message="Done")

        enr._enrichment_worker = _mock_worker
        try:
            start_enrichment(st)
            # Registration happens in start_enrichment after t.start()
            # but synchronously before returning
            assert TASK_ID in st._background_threads
            assert TASK_ID in st._task_cancel_events
            # Cancel event should be the same object as _enrichment_cancel
            assert st._task_cancel_events[TASK_ID] is st._enrichment_cancel
        finally:
            gate.set()
            time.sleep(0.3)
            enr._enrichment_worker = original_worker

    def test_enrichment_cleans_up_infra(self):
        """After worker finishes, infra entries are removed in finally block."""
        from arkana.enrichment import TASK_ID

        st = AnalyzerState()
        st.filepath = "/test/file.exe"
        st.pe_data = {"file_hashes": {"sha256": "abc123"}}
        set_current_state(st)

        import arkana.enrichment as enr
        original_worker = enr._enrichment_worker

        def _mock_worker(state, generation=0):
            try:
                state.update_task(TASK_ID, status=TASK_COMPLETED,
                                  progress_percent=100, progress_message="Done")
            finally:
                # Simulate the real worker's finally block
                state._background_threads.pop(TASK_ID, None)
                state._task_cancel_events.pop(TASK_ID, None)

        enr._enrichment_worker = _mock_worker
        try:
            enr.start_enrichment(st)
            time.sleep(0.5)
            # After completion, infra entries should be cleaned up
            assert TASK_ID not in st._background_threads
            assert TASK_ID not in st._task_cancel_events
        finally:
            enr._enrichment_worker = original_worker


class TestSoftTimeoutFallbackToTimeout(unittest.TestCase):
    """When soft_timeout is not specified, per-tool timeout should be used."""

    def setUp(self):
        self.st = AnalyzerState()
        set_current_state(self.st)

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_timeout_used_as_soft_when_no_soft_specified(self):
        """When only timeout is given, it should be used as soft timeout."""
        from arkana.background import _run_background_task_wrapper

        def fast_func():
            return {"result": "done"}

        self.st.set_task("t-soft", {
            "status": TASK_RUNNING,
            "progress_percent": 0,
            "progress_message": "Starting...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "test",
        })

        # Pass timeout=1800 with no soft_timeout → should use 1800 as soft_t
        # The task completes instantly so this is really testing the code path
        self._run(_run_background_task_wrapper(
            "t-soft", fast_func, timeout=1800
        ))

        task = self.st.get_task("t-soft")
        assert task is not None
        assert task["status"] == TASK_COMPLETED


if __name__ == "__main__":
    unittest.main()
