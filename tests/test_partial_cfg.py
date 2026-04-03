"""Tests for partial CFG acceptance and error-rate-based degradation detection."""
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from arkana.state import AnalyzerState


class TestCfgQualityField(unittest.TestCase):
    """_cfg_quality field on AnalyzerState."""

    def test_default_none(self):
        st = AnalyzerState()
        assert st._cfg_quality is None

    def test_reset_angr_clears_quality(self):
        st = AnalyzerState()
        st._cfg_quality = {"status": "partial", "functions_discovered": 500}
        st.reset_angr()
        assert st._cfg_quality is None

    def test_quality_dict_structure(self):
        st = AnalyzerState()
        quality = {
            "status": "full",
            "functions_discovered": 1234,
            "errors_during_build": 5,
            "timestamp": time.time(),
        }
        st._cfg_quality = quality
        assert st._cfg_quality["status"] == "full"
        assert st._cfg_quality["functions_discovered"] == 1234


class TestPartialCFG(unittest.TestCase):
    """_PartialCFG wrapper class."""

    def test_partial_cfg_creation(self):
        from arkana.background import _PartialCFG

        # Mock an angr project with kb.functions
        project = MagicMock()
        project.kb.functions = {"0x1000": MagicMock(), "0x2000": MagicMock()}
        project.kb.cfgs.get_most_accurate.return_value = MagicMock()

        partial = _PartialCFG(project)
        assert partial._partial is True
        assert partial.functions is project.kb.functions
        assert partial.model is not None

    def test_partial_cfg_no_model(self):
        from arkana.background import _PartialCFG

        project = MagicMock()
        project.kb.functions = {}
        project.kb.cfgs.get_most_accurate.side_effect = Exception("no model")

        partial = _PartialCFG(project)
        assert partial._partial is True
        assert partial.model is None

    def test_partial_cfg_live_reference(self):
        """PartialCFG.functions is a live reference to project.kb.functions."""
        from arkana.background import _PartialCFG

        funcs = {}
        project = MagicMock()
        project.kb.functions = funcs
        project.kb.cfgs.get_most_accurate.return_value = None

        partial = _PartialCFG(project)
        assert len(partial.functions) == 0

        # Simulate CFGFast discovering a new function
        funcs["0x3000"] = MagicMock()
        assert len(partial.functions) == 1  # Live reference

    def test_partial_cfg_repr(self):
        from arkana.background import _PartialCFG

        project = MagicMock()
        project.kb.functions = {"a": 1, "b": 2}
        project.kb.cfgs.get_most_accurate.return_value = None

        partial = _PartialCFG(project)
        r = repr(partial)
        assert "PartialCFG" in r
        assert "functions=2" in r
        assert "model=no" in r


class TestAcceptPartialCfg(unittest.TestCase):
    """_accept_partial_cfg helper function."""

    def setUp(self):
        self.state = AnalyzerState()
        # Patch the module-level state in background.py
        self._patcher = patch("arkana.background.state", self.state)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()

    def test_accept_stores_partial_cfg(self):
        from arkana.background import _accept_partial_cfg, _PartialCFG

        project = MagicMock()
        project.kb.functions = {i: MagicMock() for i in range(200)}
        project.kb.cfgs.get_most_accurate.return_value = MagicMock()

        # Register task first
        self.state.set_task("test-task", {"status": "running"})

        _accept_partial_cfg("test-task", project, "test reason", 200, 10)

        # Check state
        _, cfg = self.state.get_angr_snapshot()
        assert cfg is not None
        assert isinstance(cfg, _PartialCFG)
        assert cfg._partial is True

    def test_accept_sets_quality(self):
        from arkana.background import _accept_partial_cfg

        project = MagicMock()
        project.kb.functions = {}
        project.kb.cfgs.get_most_accurate.return_value = None

        self.state.set_task("test-task", {"status": "running"})
        _accept_partial_cfg("test-task", project, "stalled for 300s", 500, 42)

        quality = self.state._cfg_quality
        assert quality is not None
        assert quality["status"] == "partial"
        assert quality["reason"] == "stalled for 300s"
        assert quality["functions_discovered"] == 500
        assert quality["errors_during_build"] == 42

    def test_accept_marks_task_completed(self):
        from arkana.background import _accept_partial_cfg

        project = MagicMock()
        project.kb.functions = {}
        project.kb.cfgs.get_most_accurate.return_value = None

        self.state.set_task("test-task", {"status": "running"})
        _accept_partial_cfg("test-task", project, "test", 100, 5)

        task = self.state.get_task("test-task")
        assert task["status"] == "completed"
        assert "partial" in task["progress_message"].lower()


class TestCfgQualityAlert(unittest.TestCase):
    """Partial CFG alert in _collect_background_alerts."""

    def test_partial_cfg_alert_shown(self):
        from arkana.mcp.server import _collect_background_alerts

        st = AnalyzerState()
        st._cfg_quality = {
            "status": "partial",
            "functions_discovered": 500,
            "errors_during_build": 30,
            "reason": "stalled for 300s",
        }

        alerts = _collect_background_alerts(st)
        cfg_alerts = [a for a in alerts if a.get("type") == "cfg_partial"]
        assert len(cfg_alerts) == 1
        assert cfg_alerts[0]["functions_discovered"] == 500
        assert "partial" in cfg_alerts[0]["message"].lower()

    def test_full_cfg_no_alert(self):
        from arkana.mcp.server import _collect_background_alerts

        st = AnalyzerState()
        st._cfg_quality = {
            "status": "full",
            "functions_discovered": 1000,
            "errors_during_build": 0,
        }

        alerts = _collect_background_alerts(st)
        cfg_alerts = [a for a in alerts if a.get("type") == "cfg_partial"]
        assert len(cfg_alerts) == 0

    def test_no_quality_no_alert(self):
        from arkana.mcp.server import _collect_background_alerts

        st = AnalyzerState()
        assert st._cfg_quality is None

        alerts = _collect_background_alerts(st)
        cfg_alerts = [a for a in alerts if a.get("type") == "cfg_partial"]
        assert len(cfg_alerts) == 0


class TestStallMonitorErrorTracking(unittest.TestCase):
    """Enhanced _cfg_stall_monitor tracks error count."""

    def test_monitor_records_error_count(self):
        """Stall monitor writes cfg_error_count to task metadata."""
        st = AnalyzerState()

        # Add some warnings to the state before monitoring starts
        st.add_warning("angr.analyses", "ERROR", "SimValueError at 0x1234")
        st.add_warning("angr.analyses", "ERROR", "Type error at 0x5678")

        # Set up task
        st.set_task("test-cfg", {"status": "running"})

        # Mock project with kb.functions
        project = MagicMock()
        project.kb.functions = {i: MagicMock() for i in range(50)}

        # Run one iteration of the monitor (patch sleep to exit immediately)
        with patch("arkana.background.state", st), \
             patch("arkana.background.set_current_state"):
            from arkana.background import _cfg_stall_monitor

            # After first iteration, task status changes to "completed" so monitor stops
            original_get_task = st.get_task
            call_count = [0]

            def mock_get_task(tid):
                call_count[0] += 1
                if call_count[0] > 1:
                    return {"status": "completed"}
                return original_get_task(tid)

            with patch.object(st, "get_task", side_effect=mock_get_task), \
                 patch("arkana.background.time.sleep"):
                _cfg_stall_monitor(project, "test-cfg", interval=0, _session_state=st)

        task = original_get_task("test-cfg")
        # The monitor should have recorded some snapshots
        snapshots = task.get("cfg_func_snapshots", [])
        assert len(snapshots) >= 1
        # Snapshots now have 3 elements: (timestamp, func_count, error_count)
        assert len(snapshots[0]) == 3


class TestConstants(unittest.TestCase):
    """CFG degradation constants exist."""

    def test_constants_importable(self):
        from arkana.constants import CFG_ERROR_RATE_THRESHOLD, CFG_PARTIAL_MIN_FUNCS
        assert CFG_ERROR_RATE_THRESHOLD == 50
        assert CFG_PARTIAL_MIN_FUNCS == 100
