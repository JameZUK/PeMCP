"""Unit tests for arkana/cache.py — AnalysisCache disk-based caching."""
import json
import gzip
import time
import pytest
from unittest import mock

from arkana.cache import AnalysisCache, CACHE_FORMAT_VERSION, _validate_sha256


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Redirect cache to a temporary directory."""
    cache_path = tmp_path / "cache"
    cache_path.mkdir()
    meta_file = cache_path / "meta.json"
    monkeypatch.setattr("arkana.cache.CACHE_DIR", cache_path)
    monkeypatch.setattr("arkana.cache.META_FILE", meta_file)
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

    def test_arkana_version_mismatch(self, cache, cache_dir, sample_pe_data, monkeypatch):
        sha = "e" * 64
        cache.put(sha, sample_pe_data, "/test.exe")

        # Change the version that _get_arkana_version returns
        monkeypatch.setattr("arkana.cache._get_arkana_version", lambda: "99.99.99")

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

        # Each entry needs unique chars to defeat gzip compression (~500+ bytes each)
        import random
        rng = random.Random(42)
        data1 = {"mode": "pe", "big_data": "".join(rng.choices("abcdefghij", k=2000))}
        data2 = {"mode": "pe", "big_data": "".join(rng.choices("klmnopqrst", k=2000))}
        data3 = {"mode": "pe", "big_data": "".join(rng.choices("uvwxyz0123", k=2000))}

        c.put("1" * 64, data1, "/t1.exe")
        time.sleep(0.01)
        c.put("2" * 64, data2, "/t2.exe")
        time.sleep(0.01)
        c.put("3" * 64, data3, "/t3.exe")

        # Oldest entry should have been evicted (cache size is 1KB, each entry ~200+ bytes)
        stats = c.get_stats()
        # At least one entry should have been evicted to stay within limits
        assert stats["entry_count"] < 3, f"Expected eviction but all 3 entries remain: {stats}"
        # Total size should be within limits
        assert stats["total_size_mb"] * 1024 * 1024 <= c.max_size_bytes
        # The oldest entry specifically should be gone
        assert c.get("1" * 64, "/t1.exe") is None, "Oldest entry should have been evicted"


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


# ---------------------------------------------------------------------------
# Meta file handling
# ---------------------------------------------------------------------------

class TestCacheMetaHandling:
    def test_corrupt_meta_json(self, cache_dir):
        """Cache should handle corrupt meta.json gracefully."""
        meta_file = cache_dir / "meta.json"
        meta_file.write_text("{{invalid json}}")
        c = AnalysisCache(max_size_mb=10, enabled=True)
        # Should not crash — _load_meta returns {}
        data = {"mode": "pe", "test": True}
        assert c.put("dd" * 32, data, "/test.exe") is True

    def test_meta_save_error(self, cache, cache_dir, monkeypatch):
        """Cache survives when meta file cannot be written."""
        monkeypatch.setattr("arkana.cache.META_FILE",
                            cache_dir / "nonexistent_subdir" / "meta.json")
        # put should still succeed (data written, meta save fails gracefully)
        data = {"mode": "pe", "test": True}
        sha = "ee" * 32
        # This exercises the OSError path in _save_meta
        result = cache.put(sha, data, "/test.exe")
        assert result is True, "put() should succeed even when meta save fails"
        # Verify the data was actually written and is retrievable
        # Restore META_FILE only (undo() would also revert CACHE_DIR from cache_dir fixture)
        monkeypatch.setattr("arkana.cache.META_FILE", cache_dir / "meta.json")
        retrieved = cache.get(sha, "/test.exe")
        assert retrieved is not None, "Data should be retrievable after meta save failure"
        assert retrieved.get("test") is True


# ---------------------------------------------------------------------------
# SHA256 validation
# ---------------------------------------------------------------------------

class TestSha256Validation:
    def test_valid_sha256(self):
        assert _validate_sha256("a" * 64) == "a" * 64

    def test_uppercase_normalized(self):
        assert _validate_sha256("A" * 64) == "a" * 64

    def test_whitespace_stripped(self):
        assert _validate_sha256("  " + "b" * 64 + "  ") == "b" * 64

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError, match="Invalid SHA256"):
            _validate_sha256("../../etc/passwd")

    def test_short_hash_rejected(self):
        with pytest.raises(ValueError, match="Invalid SHA256"):
            _validate_sha256("abcdef")

    def test_non_hex_rejected(self):
        with pytest.raises(ValueError, match="Invalid SHA256"):
            _validate_sha256("g" * 64)

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError, match="Invalid SHA256"):
            _validate_sha256("")

    def test_cache_get_rejects_invalid_sha(self, cache):
        with pytest.raises(ValueError):
            cache.get("../../../etc/passwd", "/test.exe")

    def test_cache_put_rejects_invalid_sha(self, cache):
        with pytest.raises(ValueError):
            cache.put("invalid", {"data": 1}, "/test.exe")

    def test_cache_update_session_rejects_invalid_sha(self, cache):
        with pytest.raises(ValueError):
            cache.update_session_data("bad-hash", notes=[])

    def test_cache_remove_rejects_invalid_sha(self, cache):
        with pytest.raises(ValueError):
            cache.remove_entry_by_hash("not-a-sha256")


# ---------------------------------------------------------------------------
# Session data update (outside-lock I/O)
# ---------------------------------------------------------------------------

class TestCacheUpdateSessionData:
    """Cache wrapper v2: user-mutable state lives in project overlays, not the
    cache. ``update_session_data`` no-ops on v2 wrappers (returns True silently),
    and ``get_session_metadata`` returns empty fields. Legacy v1 wrappers are
    only encountered during the migration path in ProjectManager._migrate_*."""

    def test_update_v2_wrapper_is_noop(self, cache, sample_pe_data):
        sha = "a" * 64
        cache.put(sha, sample_pe_data, "/test.exe")
        # Returns True (silently no-ops) for v2 wrappers
        assert cache.update_session_data(sha, notes=[{"id": "n1", "text": "test"}]) is True
        # And the wrapper carries no user-state fields
        meta = cache.get_session_metadata(sha)
        assert meta is not None
        assert meta["notes"] == []
        assert meta["_cache_format_version"] == 2

    def test_update_nonexistent_entry(self, cache):
        assert cache.update_session_data("b" * 64, notes=[]) is False

    def test_update_disabled_cache(self, cache_dir):
        c = AnalysisCache(enabled=False)
        assert c.update_session_data("a" * 64, notes=[]) is False

    def test_get_session_metadata_disabled(self, cache_dir):
        c = AnalysisCache(enabled=False)
        assert c.get_session_metadata("a" * 64) is None
