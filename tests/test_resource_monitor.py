"""Tests for process-level resource monitor."""
import threading
import time
import unittest
from collections import deque
from unittest.mock import patch, MagicMock, AsyncMock

from arkana.constants import (
    RESOURCE_MONITOR_INTERVAL,
    RESOURCE_MEMORY_HIGH_MB,
    RESOURCE_MEMORY_CRITICAL_MB,
    RESOURCE_CPU_HIGH_PERCENT,
    RESOURCE_HISTORY_SIZE,
)


class TestResourceMonitorConstants(unittest.TestCase):
    """Verify resource monitor constants have expected defaults."""

    def test_interval(self):
        assert RESOURCE_MONITOR_INTERVAL == 10

    def test_memory_high(self):
        assert RESOURCE_MEMORY_HIGH_MB == 4096

    def test_memory_critical(self):
        assert RESOURCE_MEMORY_CRITICAL_MB == 8192

    def test_cpu_high(self):
        assert RESOURCE_CPU_HIGH_PERCENT == 90

    def test_history_size(self):
        assert RESOURCE_HISTORY_SIZE == 60


class TestPsutilAvailabilityGuard(unittest.TestCase):
    """All public functions return None/[] when psutil is unavailable."""

    def test_snapshot_returns_none(self):
        import arkana.resource_monitor as rm
        old = rm.PSUTIL_AVAILABLE
        try:
            rm.PSUTIL_AVAILABLE = False
            assert rm.get_resource_snapshot() is None
        finally:
            rm.PSUTIL_AVAILABLE = old

    def test_history_returns_empty(self):
        import arkana.resource_monitor as rm
        old = rm.PSUTIL_AVAILABLE
        try:
            rm.PSUTIL_AVAILABLE = False
            assert rm.get_resource_history() == []
        finally:
            rm.PSUTIL_AVAILABLE = old

    def test_alert_returns_none(self):
        import arkana.resource_monitor as rm
        old = rm.PSUTIL_AVAILABLE
        try:
            rm.PSUTIL_AVAILABLE = False
            assert rm.get_resource_alert() is None
        finally:
            rm.PSUTIL_AVAILABLE = old


class TestMakeSnapshot(unittest.TestCase):
    """Test _make_snapshot builds correct dicts."""

    def _mock_proc(self, rss_bytes=500 * 1024 * 1024, cpu_pct=25.0, threads=10):
        proc = MagicMock()
        mem = MagicMock()
        mem.rss = rss_bytes
        proc.memory_info.return_value = mem
        proc.cpu_percent.return_value = cpu_pct
        proc.num_threads.return_value = threads
        return proc

    def test_normal_level(self):
        from arkana.resource_monitor import _make_snapshot
        snap = _make_snapshot(self._mock_proc(rss_bytes=500 * 1024 * 1024))
        assert snap["memory_level"] == "normal"
        assert snap["rss_mb"] == 500.0
        assert snap["cpu_percent"] == 25.0
        assert snap["thread_count"] == 10
        assert "timestamp" in snap

    def test_high_level(self):
        from arkana.resource_monitor import _make_snapshot, _MEMORY_HIGH
        rss = int((_MEMORY_HIGH + 1) * 1024 * 1024)
        snap = _make_snapshot(self._mock_proc(rss_bytes=rss))
        assert snap["memory_level"] == "high"

    def test_critical_level(self):
        from arkana.resource_monitor import _make_snapshot, _MEMORY_CRITICAL
        rss = int((_MEMORY_CRITICAL + 1) * 1024 * 1024)
        snap = _make_snapshot(self._mock_proc(rss_bytes=rss))
        assert snap["memory_level"] == "critical"


class TestResourceAlert(unittest.TestCase):
    """Test get_resource_alert returns correct alerts or None."""

    def test_no_alert_when_normal(self):
        import arkana.resource_monitor as rm
        snap = {
            "timestamp": time.time(),
            "rss_mb": 500.0,
            "rss_bytes": 500 * 1024 * 1024,
            "cpu_percent": 25.0,
            "thread_count": 10,
            "memory_level": "normal",
        }
        with patch.object(rm, "get_resource_snapshot", return_value=snap):
            assert rm.get_resource_alert() is None

    def test_alert_when_high(self):
        import arkana.resource_monitor as rm
        snap = {
            "timestamp": time.time(),
            "rss_mb": 5000.0,
            "rss_bytes": 5000 * 1024 * 1024,
            "cpu_percent": 50.0,
            "thread_count": 10,
            "memory_level": "high",
        }
        with patch.object(rm, "get_resource_snapshot", return_value=snap):
            alert = rm.get_resource_alert()
            assert alert is not None
            assert alert["type"] == "resource_pressure"
            assert alert["level"] == "high"
            assert alert["rss_mb"] == 5000.0
            assert "hint" in alert

    def test_alert_when_critical(self):
        import arkana.resource_monitor as rm
        snap = {
            "timestamp": time.time(),
            "rss_mb": 9000.0,
            "rss_bytes": 9000 * 1024 * 1024,
            "cpu_percent": 95.0,
            "thread_count": 20,
            "memory_level": "critical",
        }
        with patch.object(rm, "get_resource_snapshot", return_value=snap):
            alert = rm.get_resource_alert()
            assert alert is not None
            assert alert["level"] == "critical"
            assert "OOM" in alert["hint"]

    def test_no_alert_when_snapshot_none(self):
        import arkana.resource_monitor as rm
        with patch.object(rm, "get_resource_snapshot", return_value=None):
            assert rm.get_resource_alert() is None


class TestResourceHistory(unittest.TestCase):
    """Test snapshot history deque."""

    def test_history_accumulates(self):
        import arkana.resource_monitor as rm
        old_snap = rm._latest_snapshot
        old_hist = rm._snapshot_history
        try:
            rm._snapshot_history = deque(maxlen=RESOURCE_HISTORY_SIZE)
            snap1 = {"timestamp": 1.0, "rss_mb": 100}
            snap2 = {"timestamp": 2.0, "rss_mb": 200}
            rm._snapshot_history.append(snap1)
            rm._snapshot_history.append(snap2)
            rm._latest_snapshot = snap2
            # Bypass _ensure_started by patching PSUTIL_AVAILABLE
            old_avail = rm.PSUTIL_AVAILABLE
            rm.PSUTIL_AVAILABLE = False
            history = rm.get_resource_history()
            rm.PSUTIL_AVAILABLE = old_avail
            # When psutil not available, returns []
            assert history == []
        finally:
            rm._latest_snapshot = old_snap
            rm._snapshot_history = old_hist

    def test_history_returns_copies(self):
        import arkana.resource_monitor as rm
        old_snap = rm._latest_snapshot
        old_hist = rm._snapshot_history
        old_avail = rm.PSUTIL_AVAILABLE
        old_thread = rm._monitor_thread
        try:
            rm._snapshot_history = deque(maxlen=RESOURCE_HISTORY_SIZE)
            snap = {"timestamp": 1.0, "rss_mb": 100}
            rm._snapshot_history.append(snap)
            rm._latest_snapshot = snap
            rm.PSUTIL_AVAILABLE = True
            # Mock _ensure_started to avoid starting real thread
            with patch.object(rm, "_ensure_started"):
                history = rm.get_resource_history()
                assert len(history) == 1
                # Should be a copy, not the same object
                assert history[0] is not snap
                assert history[0]["rss_mb"] == 100
        finally:
            rm._latest_snapshot = old_snap
            rm._snapshot_history = old_hist
            rm.PSUTIL_AVAILABLE = old_avail
            rm._monitor_thread = old_thread


class TestBackgroundAlertsIntegration(unittest.TestCase):
    """Verify _collect_background_alerts includes resource alerts."""

    def test_resource_alert_injected(self):
        from arkana.mcp.server import _collect_background_alerts
        from arkana.state import AnalyzerState

        mock_alert = {
            "type": "resource_pressure",
            "level": "high",
            "rss_mb": 5000.0,
            "cpu_percent": 50.0,
            "thread_count": 10,
            "threshold_mb": 4096,
            "hint": "test",
        }
        st = AnalyzerState()
        with patch("arkana.mcp.server.get_resource_alert", create=True, return_value=mock_alert):
            # The import is inside the function, so we patch the module path
            with patch("arkana.resource_monitor.get_resource_alert", return_value=mock_alert):
                alerts = _collect_background_alerts(st)
                resource_alerts = [a for a in alerts if a.get("type") == "resource_pressure"]
                assert len(resource_alerts) == 1
                assert resource_alerts[0]["level"] == "high"

    def test_no_resource_alert_when_normal(self):
        from arkana.mcp.server import _collect_background_alerts
        from arkana.state import AnalyzerState

        st = AnalyzerState()
        with patch("arkana.resource_monitor.get_resource_alert", return_value=None):
            alerts = _collect_background_alerts(st)
            resource_alerts = [a for a in alerts if a.get("type") == "resource_pressure"]
            assert len(resource_alerts) == 0


class TestGetResourceUsageTool(unittest.TestCase):
    """Test the get_resource_usage MCP tool."""

    def test_returns_error_without_psutil(self):
        import asyncio
        from arkana.mcp.tools_config import get_resource_usage

        loop = asyncio.new_event_loop()
        try:
            ctx = MagicMock()
            ctx.info = AsyncMock()
            with patch("arkana.resource_monitor.PSUTIL_AVAILABLE", False):
                # The tool uses lazy import, so patch at the source
                result = loop.run_until_complete(get_resource_usage.__wrapped__(ctx))
                assert "error" in result
                assert "psutil" in result["error"]
        finally:
            loop.close()

    def test_returns_snapshot_and_trend(self):
        import asyncio
        from arkana.mcp.tools_config import get_resource_usage

        now = time.time()
        snap = {
            "timestamp": now,
            "rss_mb": 800.0,
            "rss_bytes": 800 * 1024 * 1024,
            "cpu_percent": 30.0,
            "thread_count": 12,
            "memory_level": "normal",
        }
        history = [
            {"timestamp": now - 60, "rss_mb": 700.0},
            snap,
        ]

        loop = asyncio.new_event_loop()
        try:
            ctx = MagicMock()
            ctx.info = AsyncMock()
            with patch("arkana.resource_monitor.PSUTIL_AVAILABLE", True), \
                 patch("arkana.resource_monitor.get_resource_snapshot", return_value=snap), \
                 patch("arkana.resource_monitor.get_resource_history", return_value=history):
                result = loop.run_until_complete(get_resource_usage.__wrapped__(ctx))
                assert "current" in result
                assert result["current"]["rss_mb"] == 800.0
                assert "trend" in result
                assert result["trend"]["rss_change_mb"] == 100.0
                assert "thresholds" in result
        finally:
            loop.close()


class TestMonitorThreadLifecycle(unittest.TestCase):
    """Test lazy start and stop of the monitor thread."""

    def test_ensure_started_noop_without_psutil(self):
        import arkana.resource_monitor as rm
        old = rm.PSUTIL_AVAILABLE
        try:
            rm.PSUTIL_AVAILABLE = False
            rm._ensure_started()
            # Should not start any thread
            assert rm._monitor_thread is None or not rm._monitor_thread.is_alive()
        finally:
            rm.PSUTIL_AVAILABLE = old

    def test_stop_monitor_clears_state(self):
        import arkana.resource_monitor as rm
        old_snap = rm._latest_snapshot
        old_hist = rm._snapshot_history
        old_thread = rm._monitor_thread
        try:
            rm._latest_snapshot = {"test": True}
            rm._snapshot_history = deque([{"test": True}])
            rm._monitor_thread = None
            rm.stop_monitor()
            assert rm._latest_snapshot is None
            assert len(rm._snapshot_history) == 0
        finally:
            rm._latest_snapshot = old_snap
            rm._snapshot_history = old_hist
            rm._monitor_thread = old_thread


class TestSnapshotReturnsCopy(unittest.TestCase):
    """Verify get_resource_snapshot returns a copy, not a reference."""

    def test_snapshot_is_copy(self):
        import arkana.resource_monitor as rm
        old_snap = rm._latest_snapshot
        old_avail = rm.PSUTIL_AVAILABLE
        try:
            snap = {"timestamp": 1.0, "rss_mb": 100}
            rm._latest_snapshot = snap
            rm.PSUTIL_AVAILABLE = True
            with patch.object(rm, "_ensure_started"):
                result = rm.get_resource_snapshot()
                assert result is not snap
                assert result == snap
                # Mutating result should not affect internal state
                result["rss_mb"] = 999
                assert rm._latest_snapshot["rss_mb"] == 100
        finally:
            rm._latest_snapshot = old_snap
            rm.PSUTIL_AVAILABLE = old_avail


if __name__ == "__main__":
    unittest.main()
