"""Shared fixtures for Arkana tests."""
import faulthandler
import os
import sys

import pytest
from arkana.state import AnalyzerState, set_current_state

# CI diagnostic: dump all thread stacks and exit if tests hang for >120s.
# The full suite normally finishes in <30s.
if os.environ.get("CI"):
    faulthandler.dump_traceback_later(120, file=sys.stderr, exit=True)


class MockContext:
    """Minimal mock for MCP Context used by tool tests."""
    def __init__(self):
        self.warnings = []
        self.errors = []
        self.infos = []

    async def warning(self, msg):
        self.warnings.append(msg)

    async def error(self, msg):
        self.errors.append(msg)

    async def info(self, msg):
        self.infos.append(msg)


@pytest.fixture
def mock_ctx():
    """Provide a MockContext for async tool tests."""
    return MockContext()


@pytest.fixture
def clean_state():
    """Ensure a clean AnalyzerState for each test, then tear down."""
    s = AnalyzerState()
    set_current_state(s)
    yield s
    set_current_state(None)
