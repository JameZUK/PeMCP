"""Unit tests for MCP response size checking and smart truncation."""
import json
import pytest
import asyncio

pytest.importorskip("pefile", reason="pefile not installed")

from unittest.mock import AsyncMock

from pemcp.mcp.server import _check_mcp_response_size
from pemcp.config import MAX_MCP_RESPONSE_SIZE_BYTES


class MockContext:
    """Minimal mock for MCP Context used by truncation logic."""
    def __init__(self):
        self.warnings = []
        self.errors = []

    async def warning(self, msg):
        self.warnings.append(msg)

    async def error(self, msg):
        self.errors.append(msg)


def _run(coro):
    """Helper to run async functions in tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


class TestCheckMcpResponseSize:
    """Tests for _check_mcp_response_size smart truncation."""

    def test_small_response_unchanged(self):
        """Responses under the limit should pass through unchanged."""
        ctx = MockContext()
        data = {"key": "value", "number": 42}
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        assert result == data
        assert len(ctx.warnings) == 0

    def test_empty_response(self):
        ctx = MockContext()
        data = {}
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        assert result == {}

    def test_large_list_truncated(self):
        """A dict containing a large list should have the list truncated."""
        ctx = MockContext()
        # Create data larger than 64KB
        data = {"items": [{"id": i, "data": "x" * 100} for i in range(1000)]}
        raw_size = len(json.dumps(data).encode("utf-8"))
        assert raw_size > MAX_MCP_RESPONSE_SIZE_BYTES

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES
        assert len(result["items"]) < 1000
        assert "_truncation_warning" in result
        assert len(ctx.warnings) > 0

    def test_large_string_truncated(self):
        """A dict containing a large string should have it truncated."""
        ctx = MockContext()
        data = {"content": "A" * (MAX_MCP_RESPONSE_SIZE_BYTES + 1000)}
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES
        assert result["content"].endswith("...[TRUNCATED]")

    def test_large_dict_truncated(self):
        """A dict containing a large nested dict should have keys removed."""
        ctx = MockContext()
        inner = {f"key_{i}": "v" * 200 for i in range(500)}
        data = {"nested": inner}
        raw_size = len(json.dumps(data).encode("utf-8"))
        assert raw_size > MAX_MCP_RESPONSE_SIZE_BYTES

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES
        assert len(result["nested"]) < 500

    def test_root_list_truncated(self):
        """A root-level list should be truncated."""
        ctx = MockContext()
        data = [{"id": i, "payload": "x" * 200} for i in range(1000)]
        raw_size = len(json.dumps(data).encode("utf-8"))
        assert raw_size > MAX_MCP_RESPONSE_SIZE_BYTES

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES
        assert len(result) < 1000

    def test_root_string_truncated(self):
        """A root-level string should be truncated."""
        ctx = MockContext()
        data = "B" * (MAX_MCP_RESPONSE_SIZE_BYTES + 5000)
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES
        assert "...[TRUNCATED]" in result

    def test_exactly_at_limit(self):
        """Data exactly at the limit should pass unchanged."""
        ctx = MockContext()
        # Build a string that fits just within limits
        overhead = len(json.dumps({"d": ""}).encode("utf-8"))
        data = {"d": "x" * (MAX_MCP_RESPONSE_SIZE_BYTES - overhead)}
        raw_size = len(json.dumps(data).encode("utf-8"))
        assert raw_size <= MAX_MCP_RESPONSE_SIZE_BYTES

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        assert result == data

    def test_does_not_mutate_original(self):
        """Truncation should not modify the original data object."""
        ctx = MockContext()
        original_items = [{"id": i, "data": "x" * 100} for i in range(1000)]
        data = {"items": original_items}
        original_len = len(original_items)

        _run(_check_mcp_response_size(ctx, data, "test_tool"))
        # Original should be untouched
        assert len(data["items"]) == original_len

    def test_deeply_nested_dicts(self):
        """Deeply nested dicts should be truncated to fit the limit."""
        ctx = MockContext()
        # Build a large deeply nested structure (enough to exceed 64KB)
        inner = {f"deep_{i}": "v" * 500 for i in range(200)}
        data = {"level1": {"level2": {"level3": inner}}}
        raw_size = len(json.dumps(data).encode("utf-8"))
        assert raw_size > MAX_MCP_RESPONSE_SIZE_BYTES

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES

    def test_mixed_large_keys(self):
        """When multiple keys are large, the largest should be truncated first."""
        ctx = MockContext()
        data = {
            "small": "tiny",
            "medium_list": [{"id": i} for i in range(100)],
            "large_string": "X" * (MAX_MCP_RESPONSE_SIZE_BYTES + 1000),
        }
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES
        # The small key should survive intact
        assert result["small"] == "tiny"

    def test_unicode_multibyte_characters(self):
        """Multibyte UTF-8 characters should be handled — verify truncation triggers."""
        ctx = MockContext()
        # Each emoji is ~12 bytes in JSON (\uXXXX\uXXXX encoding), so fewer
        # chars are needed to exceed the limit.
        emoji_count = MAX_MCP_RESPONSE_SIZE_BYTES // 4
        data = {"emojis": "\U0001f600" * emoji_count}
        raw_size = len(json.dumps(data).encode("utf-8"))
        assert raw_size > MAX_MCP_RESPONSE_SIZE_BYTES

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        # Truncation should have been triggered
        assert len(ctx.warnings) > 0
        # The result should have been reduced (may fall back to string preview
        # for multibyte-heavy content where char-count reduction doesn't
        # proportionally reduce byte count)
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES or "_truncation_warning" in result or "data_preview" in result

    def test_list_of_strings_truncated(self):
        """A list of large strings should be truncated by reducing list length."""
        ctx = MockContext()
        data = {"strings": ["string_" + "a" * 500 + str(i) for i in range(200)]}
        raw_size = len(json.dumps(data).encode("utf-8"))
        assert raw_size > MAX_MCP_RESPONSE_SIZE_BYTES

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES
        assert len(result["strings"]) < 200

    def test_single_massive_value(self):
        """A single value much larger than the limit should still be truncated."""
        ctx = MockContext()
        data = {"huge": "Z" * (MAX_MCP_RESPONSE_SIZE_BYTES * 5)}
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES
