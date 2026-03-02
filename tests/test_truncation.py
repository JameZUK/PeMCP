"""Unit tests for MCP response size checking and smart truncation."""
import json
import pytest
import asyncio

pytest.importorskip("pefile", reason="pefile not installed")

from unittest.mock import AsyncMock

from arkana.mcp.server import _check_mcp_response_size, _SOFT_LIMIT
from arkana.config import MAX_MCP_RESPONSE_SIZE_BYTES, MCP_SOFT_RESPONSE_LIMIT_CHARS


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
    return asyncio.run(coro)


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

    def test_under_soft_limit_passes_through(self):
        """Responses under the soft char limit should pass through unchanged."""
        ctx = MockContext()
        # Build data just under the soft limit in chars
        overhead = len(json.dumps({"d": ""}))
        data = {"d": "x" * (_SOFT_LIMIT - overhead - 10)}
        raw_chars = len(json.dumps(data))
        assert raw_chars <= _SOFT_LIMIT

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        assert result == data
        assert len(ctx.warnings) == 0

    def test_over_soft_limit_truncated(self):
        """Data exceeding the soft char limit should be truncated."""
        ctx = MockContext()
        # Create data above soft limit but below 64KB byte limit
        data = {"content": "A" * (_SOFT_LIMIT + 5000)}
        raw_chars = len(json.dumps(data))
        assert raw_chars > _SOFT_LIMIT

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT
        assert len(ctx.warnings) > 0

    def test_large_list_truncated(self):
        """A dict containing a large list should have the list truncated."""
        ctx = MockContext()
        # Create data larger than soft limit
        data = {"items": [{"id": i, "data": "x" * 100} for i in range(1000)]}
        raw_chars = len(json.dumps(data))
        assert raw_chars > _SOFT_LIMIT

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT
        assert len(result["items"]) < 1000
        assert "_truncation_warning" in result
        assert len(ctx.warnings) > 0

    def test_large_string_truncated(self):
        """A dict containing a large string should have it truncated."""
        ctx = MockContext()
        data = {"content": "A" * (_SOFT_LIMIT * 2)}
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT
        assert result["content"].endswith("...[TRUNCATED]")

    def test_large_dict_truncated(self):
        """A dict containing a large nested dict should have keys removed."""
        ctx = MockContext()
        inner = {f"key_{i}": "v" * 200 for i in range(500)}
        data = {"nested": inner}
        raw_chars = len(json.dumps(data))
        assert raw_chars > _SOFT_LIMIT

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT
        assert len(result["nested"]) < 500

    def test_root_list_truncated(self):
        """A root-level list should be truncated."""
        ctx = MockContext()
        data = [{"id": i, "payload": "x" * 200} for i in range(1000)]
        raw_chars = len(json.dumps(data))
        assert raw_chars > _SOFT_LIMIT

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT
        assert len(result) < 1000

    def test_root_string_truncated(self):
        """A root-level string should be truncated."""
        ctx = MockContext()
        data = "B" * (_SOFT_LIMIT * 2)
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT
        assert "...[TRUNCATED]" in result

    def test_exactly_at_soft_limit(self):
        """Data exactly at the soft char limit should pass unchanged."""
        ctx = MockContext()
        # Build a string that fits just within the soft limit
        overhead = len(json.dumps({"d": ""}))
        data = {"d": "x" * (_SOFT_LIMIT - overhead)}
        raw_chars = len(json.dumps(data))
        assert raw_chars <= _SOFT_LIMIT

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
        inner = {f"deep_{i}": "v" * 500 for i in range(200)}
        data = {"level1": {"level2": {"level3": inner}}}
        raw_chars = len(json.dumps(data))
        assert raw_chars > _SOFT_LIMIT

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT

    def test_mixed_large_keys(self):
        """When multiple keys are large, the largest should be truncated first."""
        ctx = MockContext()
        data = {
            "small": "tiny",
            "medium_list": [{"id": i} for i in range(100)],
            "large_string": "X" * (_SOFT_LIMIT * 2),
        }
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT
        # The small key should survive intact
        assert result["small"] == "tiny"

    def test_unicode_multibyte_characters(self):
        """Multibyte UTF-8 characters should be handled -- verify truncation triggers."""
        ctx = MockContext()
        # With ensure_ascii=False, each emoji is 1 char in the JSON string but
        # 4 bytes in UTF-8.  Use enough emojis to exceed the soft char limit.
        emoji_count = _SOFT_LIMIT + 500
        data = {"emojis": "\U0001f600" * emoji_count}
        raw_chars = len(json.dumps(data, ensure_ascii=False))
        assert raw_chars > _SOFT_LIMIT

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        # Truncation should have been triggered
        assert len(ctx.warnings) > 0
        result_chars = len(json.dumps(result, ensure_ascii=False))
        assert result_chars <= _SOFT_LIMIT or "_truncation_warning" in result or "data_preview" in result

    def test_list_of_strings_truncated(self):
        """A list of large strings should be truncated by reducing list length."""
        ctx = MockContext()
        data = {"strings": ["string_" + "a" * 500 + str(i) for i in range(200)]}
        raw_chars = len(json.dumps(data))
        assert raw_chars > _SOFT_LIMIT

        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT
        assert len(result["strings"]) < 200

    def test_single_massive_value(self):
        """A single value much larger than the limit should still be truncated."""
        ctx = MockContext()
        data = {"huge": "Z" * (_SOFT_LIMIT * 5)}
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_chars = len(json.dumps(result))
        assert result_chars <= _SOFT_LIMIT

    def test_byte_backstop_still_enforced(self):
        """The 64KB byte backstop should still be enforced for very large data."""
        ctx = MockContext()
        # Create data that's massive in both chars and bytes
        data = {"huge": "Z" * (MAX_MCP_RESPONSE_SIZE_BYTES * 2)}
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        result_size = len(json.dumps(result).encode("utf-8"))
        assert result_size <= MAX_MCP_RESPONSE_SIZE_BYTES

    def test_truncation_warning_mentions_char_limit(self):
        """Truncation warning should reference the char limit."""
        ctx = MockContext()
        data = {"items": [{"id": i, "data": "x" * 100} for i in range(200)]}
        result = _run(_check_mcp_response_size(ctx, data, "test_tool"))
        assert "_truncation_warning" in result
        assert str(_SOFT_LIMIT) in result["_truncation_warning"]

    def test_truncation_warning_with_limit_param_info(self):
        """When limit_param_info is provided, it should appear in the warning."""
        ctx = MockContext()
        data = {"items": [{"id": i, "data": "x" * 100} for i in range(200)]}
        result = _run(_check_mcp_response_size(ctx, data, "test_tool", "the 'limit' parameter"))
        assert "_truncation_warning" in result
        assert "limit" in result["_truncation_warning"]
