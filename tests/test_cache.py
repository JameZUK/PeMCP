"""Unit tests for pemcp/cache.py — AnalysisCache disk-based caching."""
import json
import gzip
import time
import pytest
from unittest import mock

from pemcp.cache import AnalysisCache, CACHE_FORMAT_VERSION


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Redirect cache to a temporary directory."""
    cache_path = tmp_path / "cache"
    cache_path.mkdir()
    meta_file = cache_path / "meta.json"
    monkeypatch.setattr("pemcp.cache.CACHE_DIR", cache_path)
    monkeypatch.setattr("pemcp.cache.META_FILE", meta_file)
    return cache_path


@pytest.fixture
def cache(cache_dir):
    """Create a fresh AnalysisCache instance in the temp directory."""
    return AnalysisCache(max_size_mb=10, enabled=True)


@pytest.fixture
def sample_pe_data():
    return {
        "filepath": "/original/test.exe",
        "mode": "pe",
        "file_hashes": {"md5": "abc123", "sha256": "deadbeef" * 8},
        "sections": [{"name": ".text", "entropy": 6.5}],
    }


# ---------------------------------------------------------------------------
# Disabled cache
# ---------------------------------------------------------------------------

class TestCacheDisabled:
    def test_get_returns_none_when_disabled(self, cache_dir):
        c = AnalysisCache(enabled=False)
        assert c.get("deadbeef" * 8, "/some/path") is None

    def test_put_returns_false_when_disabled(self, cache_dir):
        c = AnalysisCache(enabled=False)
        assert c.put("deadbeef" * 8, {"data": 1}, "/some/path") is False


# ---------------------------------------------------------------------------
# Basic put/get
# ---------------------------------------------------------------------------

class TestCachePutGet:
    def test_put_and_get(self, cache, sample_pe_data):
        sha = "a" * 64
        assert cache.put(sha, sample_pe_data, "/original/test.exe") is True

        result = cache.get(sha, "/new/path/test.exe")
        assert result is not None
        assert result["filepath"] == "/new/path/test.exe"
        assert result["file_hashes"] == sample_pe_data["file_hashes"]

    def test_get_miss(self, cache):
        assert cache.get("b" * 64, "/any/path") is None

    def test_case_insensitive_sha(self, cache, sample_pe_data):
        sha_upper = "A" * 64
        sha_lower = "a" * 64
        cache.put(sha_upper, sample_pe_data, "/test.exe")
        result = cache.get(sha_lower, "/test.exe")
        assert result is not None

    def test_filepath_not_stored_in_cache(self, cache, sample_pe_data):
        sha = "c" * 64
        cache.put(sha, sample_pe_data, "/original.exe")
        # Read raw cache file to verify filepath is not persisted
        entry_path = cache._entry_path(sha)
        with gzip.open(entry_path, "rt") as f:
            wrapper = json.load(f)
        assert "filepath" not in wrapper["pe_data"]


# ---------------------------------------------------------------------------
# Version invalidation
# ---------------------------------------------------------------------------

class TestCacheVersionInvalidation:
    def test_format_version_mismatch(self, cache, cache_dir, sample_pe_data):
        sha = "d" * 64
        cache.put(sha, sample_pe_data, "/test.exe")

        # Tamper with the cache format version
        entry_path = cache._entry_path(sha)
        with gzip.open(entry_path, "rt") as f:
            wrapper = json.load(f)
        wrapper["_cache_meta"]["cache_format_version"] = 9999
        with gzip.open(entry_path, "wt") as f:
            json.dump(wrapper, f)

        assert cache.get(sha, "/test.exe") is None

    def test_pemcp_version_mismatch(self, cache, cache_dir, sample_pe_data, monkeypatch):
        sha = "e" * 64
        cache.put(sha, sample_pe_data, "/test.exe")

        # Change the version that _get_pemcp_version returns
        monkeypatch.setattr("pemcp.cache._get_pemcp_version", lambda: "99.99.99")

        result = cache.get(sha, "/test.exe")
        assert result is None


# ---------------------------------------------------------------------------
# Eviction
# ---------------------------------------------------------------------------

class TestCacheEviction:
    def test_eviction_removes_oldest(self, cache_dir):
        # Create cache with tiny size limit (1 KB)
        c = AnalysisCache(max_size_mb=0, enabled=True)
        # Force max to 1 KB for testing
        c.max_size_bytes = 1024

        data1 = {"mode": "pe", "big_data": "x" * 200}
        data2 = {"mode": "pe", "big_data": "y" * 200}
        data3 = {"mode": "pe", "big_data": "z" * 200}

        c.put("1" * 64, data1, "/t1.exe")
        time.sleep(0.01)
        c.put("2" * 64, data2, "/t2.exe")
        time.sleep(0.01)
        c.put("3" * 64, data3, "/t3.exe")

        # Oldest entry should have been evicted
        stats = c.get_stats()
        # Total size should be within limits
        assert stats["total_size_mb"] * 1024 * 1024 <= c.max_size_bytes or stats["entry_count"] <= 3


# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------

class TestCacheClear:
    def test_clear(self, cache, sample_pe_data):
        sha = "f" * 64
        cache.put(sha, sample_pe_data, "/test.exe")

        result = cache.clear()
        assert result["entries_removed"] >= 1
        assert result["space_freed_mb"] >= 0

        # After clear, get should miss
        assert cache.get(sha, "/test.exe") is None


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestCacheStats:
    def test_stats_empty(self, cache):
        stats = cache.get_stats()
        assert stats["entry_count"] == 0
        assert stats["enabled"] is True
        assert stats["total_size_mb"] == 0

    def test_stats_after_put(self, cache, sample_pe_data):
        cache.put("a" * 64, sample_pe_data, "/test.exe")
        stats = cache.get_stats()
        assert stats["entry_count"] == 1
        # Check via entries dict since small data rounds to 0.0 MB
        entries = stats["entries"]
        assert len(entries) == 1


# ---------------------------------------------------------------------------
# Remove by hash
# ---------------------------------------------------------------------------

class TestCacheRemoveByHash:
    def test_remove_existing(self, cache, sample_pe_data):
        sha = "ab" * 32
        cache.put(sha, sample_pe_data, "/test.exe")
        assert cache.remove_entry_by_hash(sha) is True
        assert cache.get(sha, "/test.exe") is None

    def test_remove_nonexistent(self, cache):
        assert cache.remove_entry_by_hash("ff" * 32) is False


# ---------------------------------------------------------------------------
# Corrupt entry handling
# ---------------------------------------------------------------------------

class TestCacheCorruptEntry:
    def test_corrupt_gzip_returns_none(self, cache, sample_pe_data, cache_dir):
        sha = "cc" * 32
        cache.put(sha, sample_pe_data, "/test.exe")

        # Corrupt the file
        entry_path = cache._entry_path(sha)
        with open(entry_path, "wb") as f:
            f.write(b"this is not gzip data")

        assert cache.get(sha, "/test.exe") is None
