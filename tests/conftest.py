"""Shared fixtures for PeMCP tests."""
import pytest
from pemcp.state import AnalyzerState, set_current_state


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
