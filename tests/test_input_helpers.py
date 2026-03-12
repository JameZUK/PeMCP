"""Tests for arkana.mcp._input_helpers — parsing, caching, and pagination."""
import pytest

from arkana.mcp._input_helpers import (
    _parse_int_param,
    _ToolResultCache,
    _make_cache_key,
    _paginated_response,
    _cached_paginated_response,
    _paginate_field,
)


class TestParseIntParam:
    """Test hex/int parameter parsing."""

    def test_plain_int(self):
        assert _parse_int_param(42) == 42

    def test_decimal_string(self):
        assert _parse_int_param("1778392") == 1778392

    def test_hex_string(self):
        assert _parse_int_param("0x1b22d8") == 0x1b22d8

    def test_binary_string(self):
        assert _parse_int_param("0b1010") == 10

    def test_octal_string(self):
        assert _parse_int_param("0o777") == 0o777

    def test_zero(self):
        assert _parse_int_param(0) == 0
        assert _parse_int_param("0") == 0

    def test_negative_int(self):
        assert _parse_int_param(-1) == -1

    def test_hex_uppercase(self):
        assert _parse_int_param("0x1B22D8") == 0x1b22d8

    def test_whitespace_stripped(self):
        assert _parse_int_param("  0x10  ") == 16

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            _parse_int_param("not_a_number")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            _parse_int_param("")

    def test_float_string_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            _parse_int_param("3.14")

    def test_custom_name_in_error(self):
        with pytest.raises(ValueError, match="Invalid address"):
            _parse_int_param("xyz", name="address")


class TestToolResultCache:
    """Test LRU result cache."""

    def test_get_miss(self):
        cache = _ToolResultCache()
        assert cache.get("tool", ("key",)) is None

    def test_set_and_get(self):
        cache = _ToolResultCache()
        cache.set("tool", ("k1",), [1, 2, 3])
        assert cache.get("tool", ("k1",)) == [1, 2, 3]

    def test_different_keys(self):
        cache = _ToolResultCache()
        cache.set("tool", ("k1",), [1])
        cache.set("tool", ("k2",), [2])
        assert cache.get("tool", ("k1",)) == [1]
        assert cache.get("tool", ("k2",)) == [2]

    def test_different_tools(self):
        cache = _ToolResultCache()
        cache.set("tool_a", ("k",), [1])
        cache.set("tool_b", ("k",), [2])
        assert cache.get("tool_a", ("k",)) == [1]
        assert cache.get("tool_b", ("k",)) == [2]

    def test_lru_eviction(self):
        cache = _ToolResultCache()
        # Fill beyond the 5-slot limit
        for i in range(7):
            cache.set("tool", (f"k{i}",), [i])
        # First two should be evicted
        assert cache.get("tool", ("k0",)) is None
        assert cache.get("tool", ("k1",)) is None
        # Recent entries still present
        assert cache.get("tool", ("k6",)) == [6]

    def test_clear_specific_tool(self):
        cache = _ToolResultCache()
        cache.set("tool_a", ("k",), [1])
        cache.set("tool_b", ("k",), [2])
        cache.clear("tool_a")
        assert cache.get("tool_a", ("k",)) is None
        assert cache.get("tool_b", ("k",)) == [2]

    def test_clear_all(self):
        cache = _ToolResultCache()
        cache.set("tool_a", ("k",), [1])
        cache.set("tool_b", ("k",), [2])
        cache.clear()
        assert cache.get("tool_a", ("k",)) is None
        assert cache.get("tool_b", ("k",)) is None


class TestMakeCacheKey:
    """Test cache key generation."""

    def test_basic_key(self):
        key = _make_cache_key(a=1, b="hello")
        assert key == (("a", 1), ("b", "hello"))

    def test_skips_pagination_params(self):
        key = _make_cache_key(a=1, offset=0, limit=10, compact=True, ctx=None)
        assert key == (("a", 1),)

    def test_skips_new_pagination_params(self):
        """All pagination params added for _paginate_field are skipped."""
        key = _make_cache_key(
            a=1,
            notes_offset=0, notes_limit=50, history_limit=30,
            findings_offset=0, findings_limit=15,
            functions_offset=0, functions_limit=30,
            ioc_offset=0, ioc_limit=10,
            unexplored_offset=0, unexplored_limit=10,
            indicator_offset=0, indicator_limit=50,
            method_limit=20, max_suggestions=5,
        )
        assert key == (("a", 1),)

    def test_list_converted_to_tuple(self):
        key = _make_cache_key(tags=[1, 2, 3])
        assert key == (("tags", (1, 2, 3)),)

    def test_dict_converted_to_sorted_tuple(self):
        key = _make_cache_key(meta={"b": 2, "a": 1})
        assert key == (("meta", (("a", 1), ("b", 2))),)

    def test_sorted_keys(self):
        key = _make_cache_key(z=1, a=2)
        assert key == (("a", 2), ("z", 1))


class TestPaginatedResponse:
    """Test pagination response building."""

    def test_basic_pagination(self):
        items = list(range(20))
        result = _paginated_response(items, offset=0, limit=5)
        assert result["count"] == 5
        assert result["results"] == [0, 1, 2, 3, 4]
        assert result["_pagination"]["total"] == 20
        assert result["_pagination"]["has_more"] is True

    def test_last_page(self):
        items = list(range(10))
        result = _paginated_response(items, offset=8, limit=5)
        assert result["results"] == [8, 9]
        assert result["count"] == 2
        assert result["_pagination"]["has_more"] is False

    def test_offset_beyond_total(self):
        items = list(range(5))
        result = _paginated_response(items, offset=10, limit=5)
        assert result["results"] == []
        assert result["count"] == 0

    def test_empty_items(self):
        result = _paginated_response([], offset=0, limit=10)
        assert result["count"] == 0
        assert result["_pagination"]["total"] == 0

    def test_extra_keys_merged(self):
        items = [1, 2, 3]
        result = _paginated_response(items, offset=0, limit=10, extra={"meta": "test"})
        assert result["meta"] == "test"


class TestCachedPaginatedResponse:
    """Test cached pagination flow."""

    def test_compute_on_miss(self):
        cache = _ToolResultCache()
        called = [0]

        def compute():
            called[0] += 1
            return list(range(50))

        result = _cached_paginated_response(
            cache, "tool", ("key",), compute, offset=0, limit=10
        )
        assert called[0] == 1
        assert result["count"] == 10
        assert result["results"] == list(range(10))

    def test_cache_hit(self):
        cache = _ToolResultCache()
        called = [0]

        def compute():
            called[0] += 1
            return list(range(50))

        _cached_paginated_response(cache, "tool", ("key",), compute, offset=0, limit=10)
        result = _cached_paginated_response(cache, "tool", ("key",), compute, offset=10, limit=5)
        assert called[0] == 1  # compute called only once
        assert result["results"] == list(range(10, 15))

    def test_internal_max(self):
        cache = _ToolResultCache()

        def compute():
            return list(range(10000))

        result = _cached_paginated_response(
            cache, "tool", ("key",), compute, offset=0, limit=10, internal_max=100
        )
        assert result["_pagination"]["total"] == 100


class TestPaginateField:
    """Test _paginate_field helper for inline list pagination."""

    def test_basic_slice(self):
        items = list(range(100))
        page, pag = _paginate_field(items, offset=0, limit=10)
        assert page == list(range(10))
        assert pag["total"] == 100
        assert pag["offset"] == 0
        assert pag["limit"] == 10
        assert pag["returned"] == 10
        assert pag["has_more"] is True

    def test_middle_page(self):
        items = list(range(50))
        page, pag = _paginate_field(items, offset=20, limit=10)
        assert page == list(range(20, 30))
        assert pag["total"] == 50
        assert pag["offset"] == 20
        assert pag["returned"] == 10
        assert pag["has_more"] is True

    def test_last_page(self):
        items = list(range(25))
        page, pag = _paginate_field(items, offset=20, limit=10)
        assert page == list(range(20, 25))
        assert pag["total"] == 25
        assert pag["offset"] == 20
        assert pag["returned"] == 5
        assert pag["has_more"] is False

    def test_exact_boundary(self):
        items = list(range(10))
        page, pag = _paginate_field(items, offset=0, limit=10)
        assert page == list(range(10))
        assert pag["has_more"] is False
        assert pag["returned"] == 10

    def test_offset_beyond(self):
        items = list(range(5))
        page, pag = _paginate_field(items, offset=10, limit=5)
        assert page == []
        assert pag["total"] == 5
        assert pag["offset"] == 5  # clamped to total
        assert pag["returned"] == 0
        assert pag["has_more"] is False

    def test_empty_list(self):
        page, pag = _paginate_field([], offset=0, limit=10)
        assert page == []
        assert pag["total"] == 0
        assert pag["returned"] == 0
        assert pag["has_more"] is False

    def test_non_list_input(self):
        """Sets and generators are converted to lists."""
        page, pag = _paginate_field({1, 2, 3}, offset=0, limit=10)
        assert len(page) == 3
        assert pag["total"] == 3
        assert pag["has_more"] is False

    def test_none_input(self):
        page, pag = _paginate_field(None, offset=0, limit=10)
        assert page == []
        assert pag["total"] == 0

    def test_default_params(self):
        items = list(range(100))
        page, pag = _paginate_field(items)
        assert pag["offset"] == 0
        assert pag["limit"] == 50
        assert pag["returned"] == 50
        assert pag["has_more"] is True

    def test_negative_offset_clamped(self):
        items = list(range(10))
        page, pag = _paginate_field(items, offset=-5, limit=3)
        assert pag["offset"] == 0
        assert page == [0, 1, 2]
