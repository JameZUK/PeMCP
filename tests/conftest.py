"""Shared fixtures for Arkana tests."""
import pytest
from arkana.state import AnalyzerState, set_current_state


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

    async def report_progress(self, current, total):
        pass


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
