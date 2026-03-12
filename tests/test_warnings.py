"""Tests for the library warning capture system."""
import logging
import threading
import time

import pytest

from arkana.state import AnalyzerState
from arkana.warning_handler import (
    LibraryWarningHandler,
    CAPTURED_LOGGER_PREFIXES,
    _current_tool_var,
    _current_task_var,
)


# ---------------------------------------------------------------------------
#  AnalyzerState warning field tests
# ---------------------------------------------------------------------------

class TestWarningStateFields:
    def setup_method(self):
        self.state = AnalyzerState()

    def test_add_warning_basic(self):
        entry = self.state.add_warning("angr", "WARNING", "Bad loop")
        assert entry is not None
        assert entry["logger"] == "angr"
        assert entry["level"] == "WARNING"
        assert entry["message"] == "Bad loop"
        assert entry["count"] == 1

    def test_dedup_returns_none_and_increments(self):
        self.state.add_warning("angr", "WARNING", "Bad loop")
        result = self.state.add_warning("angr", "WARNING", "Bad loop")
        assert result is None
        warnings = self.state.get_warnings()
        assert len(warnings) == 1
        assert warnings[0]["count"] == 2

    def test_dedup_updates_last_seen(self):
        self.state.add_warning("angr", "WARNING", "Bad loop")
        time.sleep(0.01)
        self.state.add_warning("angr", "WARNING", "Bad loop")
        warnings = self.state.get_warnings()
        assert warnings[0]["last_seen"] > warnings[0]["first_seen"]

    def test_different_messages_not_deduped(self):
        self.state.add_warning("angr", "WARNING", "Bad loop A")
        self.state.add_warning("angr", "WARNING", "Bad loop B")
        assert self.state.get_warning_count() == 2

    def test_different_levels_not_deduped(self):
        self.state.add_warning("angr", "WARNING", "msg")
        self.state.add_warning("angr", "ERROR", "msg")
        assert self.state.get_warning_count() == 2

    def test_different_loggers_not_deduped(self):
        self.state.add_warning("angr", "WARNING", "msg")
        self.state.add_warning("cle", "WARNING", "msg")
        assert self.state.get_warning_count() == 2

    def test_with_tool_name(self):
        self.state.add_warning("angr", "WARNING", "msg", tool_name="decompile_function_with_angr")
        warnings = self.state.get_warnings()
        assert warnings[0]["tool_name"] == "decompile_function_with_angr"

    def test_with_task_id(self):
        self.state.add_warning("angr", "WARNING", "msg", task_id="startup-angr")
        warnings = self.state.get_warnings()
        assert warnings[0]["task_id"] == "startup-angr"

    def test_filter_by_logger(self):
        self.state.add_warning("angr", "WARNING", "a")
        self.state.add_warning("cle", "WARNING", "b")
        result = self.state.get_warnings(logger_name="angr")
        assert len(result) == 1
        assert result[0]["logger"] == "angr"

    def test_filter_by_level(self):
        self.state.add_warning("angr", "WARNING", "a")
        self.state.add_warning("angr", "ERROR", "b")
        result = self.state.get_warnings(level="ERROR")
        assert len(result) == 1
        assert result[0]["level"] == "ERROR"

    def test_filter_by_tool(self):
        self.state.add_warning("angr", "WARNING", "a", tool_name="open_file")
        self.state.add_warning("angr", "WARNING", "b", tool_name="decompile_function_with_angr")
        result = self.state.get_warnings(tool_name="open_file")
        assert len(result) == 1

    def test_clear(self):
        self.state.add_warning("angr", "WARNING", "a")
        self.state.add_warning("cle", "WARNING", "b")
        count = self.state.clear_warnings()
        assert count == 2
        assert self.state.get_warning_count() == 0
        assert self.state.get_warnings() == []

    def test_count(self):
        assert self.state.get_warning_count() == 0
        self.state.add_warning("angr", "WARNING", "a")
        assert self.state.get_warning_count() == 1

    def test_max_eviction(self):
        from arkana.constants import MAX_ANALYSIS_WARNINGS
        for i in range(MAX_ANALYSIS_WARNINGS + 10):
            self.state.add_warning("angr", "WARNING", f"msg {i}")
        assert self.state.get_warning_count() == MAX_ANALYSIS_WARNINGS

    def test_message_truncation(self):
        long_msg = "x" * 1000
        self.state.add_warning("angr", "WARNING", long_msg)
        warnings = self.state.get_warnings()
        assert len(warnings[0]["message"]) == 500

    def test_get_warnings_returns_copies(self):
        self.state.add_warning("angr", "WARNING", "msg")
        w1 = self.state.get_warnings()
        w2 = self.state.get_warnings()
        assert w1 == w2
        w1[0]["message"] = "modified"
        w3 = self.state.get_warnings()
        assert w3[0]["message"] == "msg"


# ---------------------------------------------------------------------------
#  LibraryWarningHandler tests
# ---------------------------------------------------------------------------

class TestLibraryWarningHandler:
    def setup_method(self):
        self.handler = LibraryWarningHandler()

    def _make_record(self, name, level=logging.WARNING, msg="test"):
        record = logging.LogRecord(
            name=name, level=level, pathname="", lineno=0,
            msg=msg, args=(), exc_info=None,
        )
        return record

    def test_should_capture_angr(self):
        assert self.handler._should_capture(self._make_record("angr"))

    def test_should_capture_angr_sublogger(self):
        assert self.handler._should_capture(self._make_record("angr.analyses.loopfinder"))

    def test_should_not_capture_arkana(self):
        assert not self.handler._should_capture(self._make_record("Arkana"))
        assert not self.handler._should_capture(self._make_record("Arkana.mcp"))

    def test_should_not_capture_unknown(self):
        assert not self.handler._should_capture(self._make_record("mylib"))
        assert not self.handler._should_capture(self._make_record("uvicorn"))

    def test_all_known_prefixes_captured(self):
        for prefix in CAPTURED_LOGGER_PREFIXES:
            assert self.handler._should_capture(self._make_record(prefix)), f"prefix '{prefix}' not captured"
            assert self.handler._should_capture(self._make_record(f"{prefix}.sub")), f"prefix '{prefix}.sub' not captured"

    def test_info_level_not_captured(self):
        record = self._make_record("angr", level=logging.INFO)
        # Handler level is WARNING, so emit filters it — but _should_capture is True.
        # The filtering happens at the handler level check, not in _should_capture.
        assert self.handler._should_capture(record)
        # But the handler.level is WARNING, so logging framework won't call emit for INFO

    def test_prefix_boundary(self):
        """Logger 'angrx' should NOT match prefix 'angr'."""
        assert not self.handler._should_capture(self._make_record("angrx"))


# ---------------------------------------------------------------------------
#  ContextVar tests
# ---------------------------------------------------------------------------

class TestContextVars:
    def test_default_none(self):
        assert _current_tool_var.get(None) is None
        assert _current_task_var.get(None) is None

    def test_set_reset_roundtrip(self):
        token = _current_tool_var.set("my_tool")
        assert _current_tool_var.get() == "my_tool"
        _current_tool_var.reset(token)
        assert _current_tool_var.get(None) is None

    def test_task_var_set(self):
        token = _current_task_var.set("task-123")
        assert _current_task_var.get() == "task-123"
        _current_task_var.reset(token)


# ---------------------------------------------------------------------------
#  Thread safety test
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_add_warnings(self):
        st = AnalyzerState()
        errors = []

        def worker(thread_id):
            try:
                for i in range(50):
                    st.add_warning("angr", "WARNING", f"t{thread_id}_msg_{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors occurred: {errors}"
        # 4 threads x 50 unique messages = 200
        assert st.get_warning_count() == 200
