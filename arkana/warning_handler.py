"""Capture WARNING+ messages from library loggers and store them on AnalyzerState.

Provides context variables for tracking which MCP tool or background task
triggered each warning, and a logging.Handler that filters by logger prefix.
"""
import contextvars
import logging
from typing import Optional, FrozenSet

from arkana.state import get_current_state

# Context variables — set by tool_decorator and background task wrappers
_current_tool_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    '_current_tool', default=None,
)
_current_task_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    '_current_task', default=None,
)

# Logger name prefixes whose WARNING+ messages we capture.
CAPTURED_LOGGER_PREFIXES: FrozenSet[str] = frozenset({
    "angr", "cle", "claripy", "pyvex",
    "capa", "floss", "vivisect", "viv_utils", "envi", "vtrace",
    "capstone", "pefile", "lief", "yara", "keystone",
    "unicorn", "qiling", "speakeasy", "unipacker",
})


class LibraryWarningHandler(logging.Handler):
    """Logging handler that captures WARNING+ from known library loggers.

    Attached to the root logger. Only processes records whose logger name
    starts with one of ``CAPTURED_LOGGER_PREFIXES``. Never raises — all
    errors are silently swallowed to avoid disrupting the application.
    """

    def __init__(self, level: int = logging.WARNING):
        super().__init__(level)

    def _should_capture(self, record: logging.LogRecord) -> bool:
        """Return True if this record comes from a library we track."""
        name = record.name
        # Skip Arkana's own loggers
        if name.startswith("Arkana"):
            return False
        # Check prefix match
        for prefix in CAPTURED_LOGGER_PREFIXES:
            if name == prefix or name.startswith(prefix + "."):
                return True
        return False

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if not self._should_capture(record):
                return
            state = get_current_state()
            if state is None:
                return
            message = self.format(record)
            level = record.levelname
            tool_name = _current_tool_var.get(None)
            task_id = _current_task_var.get(None)
            state.add_warning(
                logger_name=record.name,
                level=level,
                message=message,
                tool_name=tool_name,
                task_id=task_id,
            )
        except Exception:
            pass  # Never crash the application


def install_warning_handler() -> None:
    """Attach the LibraryWarningHandler to the root logger."""
    handler = LibraryWarningHandler()
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    logging.getLogger().addHandler(handler)
