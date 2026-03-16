"""Unit tests for result caching in MCP tools.

Tests that _get_cached_flat_strings() and other result caches work correctly:
cache hits, cache misses, different variants, and TTL behaviour.
"""
import time
import pytest
from unittest import mock

from arkana.mcp._input_helpers import _ToolResultCache, _make_cache_key


# ---------------------------------------------------------------------------
#  _ToolResultCache basics
# ---------------------------------------------------------------------------

class TestToolResultCache:
    def test_get_miss(self):
        cache = _ToolResultCache()
        assert cache.get("tool", "key") is None

    def test_set_and_get(self):
        cache = _ToolResultCache()
        items = [{"a": 1}, {"b": 2}]
        cache.set("tool", "key", items)
        assert cache.get("tool", "key") == items

    def test_different_keys(self):
        cache = _ToolResultCache()
        cache.set("tool", "k1", [1])
        cache.set("tool", "k2", [2])
        assert cache.get("tool", "k1") == [1]
        assert cache.get("tool", "k2") == [2]

    def test_different_tools(self):
        cache = _ToolResultCache()
        cache.set("t1", "key", [1])
        cache.set("t2", "key", [2])
        assert cache.get("t1", "key") == [1]
        assert cache.get("t2", "key") == [2]

    def test_ttl_expiry(self):
        cache = _ToolResultCache()
        cache.set("tool", "key", [1])
        # Manually expire the entry
        bucket = cache._store["tool"]
        bucket["key"]["ts"] = time.time() - 4000  # older than 3600s TTL
        assert cache.get("tool", "key") is None

    def test_lru_eviction(self):
        cache = _ToolResultCache()
        # Fill 5 slots (the LRU limit)
        for i in range(5):
            cache.set("tool", f"k{i}", [i])
        # Adding a 6th should evict the oldest (k0)
        cache.set("tool", "k5", [5])
        assert cache.get("tool", "k0") is None
        assert cache.get("tool", "k5") == [5]

    def test_clear_specific_tool(self):
        cache = _ToolResultCache()
        cache.set("t1", "k", [1])
        cache.set("t2", "k", [2])
        cache.clear("t1")
        assert cache.get("t1", "k") is None
        assert cache.get("t2", "k") == [2]

    def test_clear_all(self):
        cache = _ToolResultCache()
        cache.set("t1", "k", [1])
        cache.set("t2", "k", [2])
        cache.clear()
        assert cache.get("t1", "k") is None
        assert cache.get("t2", "k") is None


# ---------------------------------------------------------------------------
#  _make_cache_key
# ---------------------------------------------------------------------------

class TestMakeCacheKey:
    def test_skips_pagination_params(self):
        k1 = _make_cache_key(filter_name="foo", offset=0, limit=20)
        k2 = _make_cache_key(filter_name="foo", offset=10, limit=50)
        assert k1 == k2

    def test_skips_compact(self):
        k1 = _make_cache_key(sort="name", compact=True)
        k2 = _make_cache_key(sort="name", compact=False)
        assert k1 == k2

    def test_different_filters_differ(self):
        k1 = _make_cache_key(category="all", min_risk="HIGH")
        k2 = _make_cache_key(category="crypto", min_risk="HIGH")
        assert k1 != k2

    def test_skips_ctx(self):
        k1 = _make_cache_key(name="x", ctx="session1")
        k2 = _make_cache_key(name="x", ctx="session2")
        assert k1 == k2

    def test_empty_params(self):
        k = _make_cache_key()
        assert k == ()


# ---------------------------------------------------------------------------
#  _get_cached_flat_strings
# ---------------------------------------------------------------------------

class TestCachedFlatStrings:
    """Tests for the shared string list cache helper."""

    def _setup_state(self, monkeypatch, floss_strings=None, basic_ascii=None):
        """Set up mock state with pe_data and result_cache."""
        cache = _ToolResultCache()
        pe_data = {}
        if floss_strings is not None:
            pe_data['floss_analysis'] = {'strings': floss_strings}
        if basic_ascii is not None:
            pe_data['basic_ascii_strings'] = basic_ascii

        mock_state = mock.MagicMock()
        mock_state.pe_data = pe_data
        mock_state.result_cache = cache

        monkeypatch.setattr("arkana.mcp.tools_strings.state", mock_state)
        return mock_state, cache

    def test_floss_only_no_dedup(self, monkeypatch):
        from arkana.mcp.tools_strings import _get_cached_flat_strings

        floss = {
            'static_strings': [
                {'string': 'hello', 'sifter_score': 5.0},
                {'string': 'world', 'sifter_score': 3.0},
            ],
            'decoded_strings': [
                {'string': 'hello', 'sifter_score': 7.0},  # duplicate value
            ],
        }
        self._setup_state(monkeypatch, floss_strings=floss)

        result = _get_cached_flat_strings(include_basic_ascii=False, deduplicate=False)
        # No dedup, so 'hello' appears twice
        assert len(result) == 3
        values = [s['string'] for s in result]
        assert values.count('hello') == 2

    def test_deduped_all(self, monkeypatch):
        from arkana.mcp.tools_strings import _get_cached_flat_strings

        floss = {
            'static_strings': [
                {'string': 'hello', 'sifter_score': 5.0},
                {'string': 'world', 'sifter_score': 3.0},
            ],
        }
        basic = [
            {'string': 'hello', 'sifter_score': 4.0},  # dup with FLOSS
            {'string': 'unique', 'sifter_score': 8.0},
        ]
        self._setup_state(monkeypatch, floss_strings=floss, basic_ascii=basic)

        result = _get_cached_flat_strings(include_basic_ascii=True, deduplicate=True)
        values = [s['string'] for s in result]
        assert len(values) == 3  # hello, world, unique
        assert 'hello' in values
        assert 'world' in values
        assert 'unique' in values

    def test_cache_hit(self, monkeypatch):
        from arkana.mcp.tools_strings import _get_cached_flat_strings

        floss = {
            'static_strings': [
                {'string': 'foo', 'sifter_score': 1.0},
            ],
        }
        mock_state, cache = self._setup_state(monkeypatch, floss_strings=floss)

        # First call — cache miss, builds list
        result1 = _get_cached_flat_strings(include_basic_ascii=True, deduplicate=True)
        assert len(result1) == 1

        # Same data — cache hit returns same list (get returns same ref)
        result2 = _get_cached_flat_strings(include_basic_ascii=True, deduplicate=True)
        assert result2 == result1
        assert len(result2) == 1

        # Modify underlying data — cache key includes content version,
        # so the cache correctly invalidates and returns fresh data
        mock_state.pe_data['floss_analysis']['strings']['static_strings'].append(
            {'string': 'bar', 'sifter_score': 2.0}
        )

        result3 = _get_cached_flat_strings(include_basic_ascii=True, deduplicate=True)
        assert result3 is not result1
        assert len(result3) == 2

    def test_source_type_added(self, monkeypatch):
        from arkana.mcp.tools_strings import _get_cached_flat_strings

        floss = {
            'decoded_strings': [
                {'string': 'secret', 'sifter_score': 9.0},
            ],
        }
        self._setup_state(monkeypatch, floss_strings=floss)

        result = _get_cached_flat_strings(include_basic_ascii=False, deduplicate=False)
        assert result[0]['source_type'] == 'decoded'

    def test_empty_state(self, monkeypatch):
        from arkana.mcp.tools_strings import _get_cached_flat_strings
        self._setup_state(monkeypatch)
        result = _get_cached_flat_strings(include_basic_ascii=True, deduplicate=True)
        assert result == []

    def test_string_items_included(self, monkeypatch):
        """Plain string items (not dicts) in FLOSS data should be wrapped."""
        from arkana.mcp.tools_strings import _get_cached_flat_strings
        floss = {
            'static_strings': ['plain_string'],
        }
        self._setup_state(monkeypatch, floss_strings=floss)
        result = _get_cached_flat_strings(include_basic_ascii=False, deduplicate=False)
        assert len(result) == 1
        assert result[0]['string'] == 'plain_string'
        assert 'source_type' in result[0]


# ---------------------------------------------------------------------------
#  Focused imports cache
# ---------------------------------------------------------------------------

class TestFocusedImportsCache:
    def test_cache_key_varies_by_category_and_risk(self):
        k1 = _make_cache_key(category="all", min_risk="MEDIUM")
        k2 = _make_cache_key(category="all", min_risk="HIGH")
        k3 = _make_cache_key(category="crypto", min_risk="MEDIUM")
        assert k1 != k2
        assert k1 != k3


# ---------------------------------------------------------------------------
#  Capa filter cache
# ---------------------------------------------------------------------------

class TestCapaFilterCache:
    def test_cache_key_varies_by_filter(self):
        k1 = _make_cache_key(filter_rule_name="inject")
        k2 = _make_cache_key(filter_rule_name="persist")
        assert k1 != k2

    def test_cache_key_ignores_offset_limit(self):
        k1 = _make_cache_key(filter_rule_name="inject", offset=0, limit=20)
        k2 = _make_cache_key(filter_rule_name="inject", offset=5, limit=50)
        assert k1 == k2


# ---------------------------------------------------------------------------
#  Timeline cache
# ---------------------------------------------------------------------------

class TestTimelineCache:
    def test_event_count_as_version_key(self):
        """Different event counts produce different cache keys."""
        k1 = ("_timeline", 10)
        k2 = ("_timeline", 11)
        assert k1 != k2
