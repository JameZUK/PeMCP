"""
Disk-based cache for file analysis results.

Stores compressed JSON in ~/.pemcp/cache/, keyed by SHA256 hash of the
analysed file.  Uses gzip compression (typically 5-15x on JSON data)
and LRU eviction when total cache size exceeds a configurable limit.

Cache entries are invalidated automatically when:
  - PeMCP version changes (parser logic may have changed)
  - Cache format version changes (wrapper structure changed)
  - Data is corrupt (bad gzip / JSON)
"""
import gzip
import json
import os
import time
import logging
import threading

from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger("PeMCP")

# Lazy-loaded to avoid circular imports (config.py instantiates this class)
_PEMCP_VERSION: Optional[str] = None


def _get_pemcp_version() -> str:
    global _PEMCP_VERSION
    if _PEMCP_VERSION is None:
        from pemcp import __version__
        _PEMCP_VERSION = __version__
    return _PEMCP_VERSION


# --- Constants ---
CACHE_DIR = Path.home() / ".pemcp" / "cache"
META_FILE = CACHE_DIR / "meta.json"
DEFAULT_MAX_CACHE_SIZE_MB = 500
CACHE_FORMAT_VERSION = 1


class AnalysisCache:
    """
    Thread-safe, gzip-compressed, LRU-evicting disk cache for pe_data dicts.

    Directory layout (git-style two-char prefix to avoid flat-dir issues)::

        ~/.pemcp/cache/
            meta.json          # index: sha256 -> {filename, times, size}
            ab/
                abcdef....json.gz
            cd/
                cdef78....json.gz
    """

    def __init__(self, max_size_mb: int = DEFAULT_MAX_CACHE_SIZE_MB, enabled: bool = True):
        self._lock = threading.Lock()
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.enabled = enabled
        self._ensure_cache_dir()

    # ------------------------------------------------------------------
    #  Directory helpers
    # ------------------------------------------------------------------

    def _ensure_cache_dir(self) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _entry_dir(self, sha256: str) -> Path:
        return CACHE_DIR / sha256[:2]

    def _entry_path(self, sha256: str) -> Path:
        return self._entry_dir(sha256) / f"{sha256}.json.gz"

    # ------------------------------------------------------------------
    #  Metadata index
    # ------------------------------------------------------------------

    def _load_meta(self) -> Dict[str, Any]:
        if not META_FILE.exists():
            return {}
        try:
            with open(META_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Cache meta read error: %s", e)
            return {}

    def _save_meta(self, meta: Dict[str, Any]) -> None:
        tmp = META_FILE.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
            # Path.replace() is atomic on POSIX (rename(2) syscall).
            # On Windows this is NOT atomic and can fail if the target
            # is locked by another process.  Since PeMCP primarily targets
            # Linux/Docker deployments this is acceptable; Windows users
            # may see rare cache metadata corruption under high concurrency.
            tmp.replace(META_FILE)
        except OSError as e:
            logger.error("Cache meta write error: %s", e)

    # ------------------------------------------------------------------
    #  Core operations
    # ------------------------------------------------------------------

    def get(self, sha256: str, current_filepath: str) -> Optional[Dict[str, Any]]:
        """
        Look up cached analysis by SHA256.

        Returns the ``pe_data`` dict (with *filepath* patched to the
        caller's current path) or ``None`` on miss / invalid entry.

        The gzip decompression (potentially slow for large analyses) runs
        outside the lock to avoid blocking concurrent ``put()`` / ``get()``
        callers.  The lock is only held for metadata updates.
        """
        if not self.enabled:
            return None

        sha256 = sha256.lower()
        entry_path = self._entry_path(sha256)

        if not entry_path.exists():
            return None

        # --- Read and decompress OUTSIDE the lock (this can be slow) ---
        try:
            with gzip.open(entry_path, "rt", encoding="utf-8") as f:
                wrapper = json.load(f)
        except (gzip.BadGzipFile, json.JSONDecodeError, OSError, KeyError) as e:
            logger.warning("Cache read error for %s...: %s", sha256[:12], e)
            with self._lock:
                self._remove_entry_and_meta(sha256)
            return None

        # --- Validate cache metadata (no lock needed, local data) ---
        cmeta = wrapper.get("_cache_meta", {})

        if cmeta.get("cache_format_version") != CACHE_FORMAT_VERSION:
            logger.info("Cache format mismatch for %s..., ignoring.", sha256[:12])
            return None

        if cmeta.get("pemcp_version") != _get_pemcp_version():
            logger.info(
                "Cache version mismatch for %s... (cached=%s, current=%s). Invalidating.",
                sha256[:12], cmeta.get('pemcp_version'), _get_pemcp_version()
            )
            with self._lock:
                self._remove_entry_and_meta(sha256)
            return None

        pe_data = wrapper.get("pe_data")
        if pe_data is None:
            return None

        # --- Validate file hasn't changed on disk AND touch LRU ---
        # single lock acquisition for both metadata validation and LRU update
        # to reduce lock contention on the hot path.
        try:
            file_exists = os.path.exists(current_filepath)
            current_mtime = os.path.getmtime(current_filepath) if file_exists else None
            current_size = os.path.getsize(current_filepath) if file_exists else None
        except OSError:
            file_exists = False
            current_mtime = None
            current_size = None

        try:
            with self._lock:
                meta = self._load_meta()
                if file_exists and current_mtime is not None:
                    cached_meta = meta.get(sha256, {})
                    cached_mtime = cached_meta.get("file_mtime")
                    cached_size = cached_meta.get("file_size")
                    if cached_mtime is not None and abs(current_mtime - cached_mtime) > 0.01:
                        logger.info("Cache mtime mismatch for %s..., invalidating.", sha256[:12])
                        self._remove_entry_and_meta(sha256)
                        return None
                    if cached_size is not None and current_size != cached_size:
                        logger.info("Cache file size mismatch for %s..., invalidating.", sha256[:12])
                        self._remove_entry_and_meta(sha256)
                        return None
                # Touch LRU timestamp (throttled to once per 60s)
                if sha256 in meta:
                    last = meta[sha256].get("last_accessed", 0)
                    now = time.time()
                    if now - last > 60:
                        meta[sha256]["last_accessed"] = now
                        self._save_meta(meta)
        except OSError:
            pass  # Stale LRU timestamp is acceptable

        # Patch session-specific field
        pe_data["filepath"] = current_filepath

        logger.info("Cache HIT for %s...", sha256[:12])
        return pe_data

    def put(self, sha256: str, pe_data: Dict[str, Any], original_filepath: str,
            notes: Optional[list] = None, tool_history: Optional[list] = None) -> bool:
        """
        Store a ``pe_data`` dict in the cache.  Returns True on success.

        Optionally includes session notes and tool history alongside the
        analysis data.
        """
        if not self.enabled:
            return False

        sha256 = sha256.lower()

        wrapper = {
            "_cache_meta": {
                "cache_format_version": CACHE_FORMAT_VERSION,
                "pemcp_version": _get_pemcp_version(),
                "sha256": sha256,
                "original_filename": os.path.basename(original_filepath),
                "original_file_size": (
                    os.path.getsize(original_filepath)
                    if os.path.exists(original_filepath) else None
                ),
                "cached_at": time.time(),
                "cached_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "mode": pe_data.get("mode", "unknown"),
                "analyses_present": [
                    k for k in pe_data
                    if k not in ("filepath", "pefile_version", "mode", "note")
                ],
            },
            "pe_data": {k: v for k, v in pe_data.items() if k != "filepath"},
            "notes": notes or [],
            "tool_history": tool_history or [],
        }

        with self._lock:
            try:
                entry_dir = self._entry_dir(sha256)
                entry_dir.mkdir(parents=True, exist_ok=True)
                entry_path = self._entry_path(sha256)

                tmp = entry_path.with_suffix(".tmp")
                with gzip.open(tmp, "wt", encoding="utf-8") as f:
                    json.dump(wrapper, f)
                tmp.replace(entry_path)  # atomic on POSIX only (see _save_meta)

                file_size = entry_path.stat().st_size
                meta = self._load_meta()
                meta[sha256] = {
                    "original_filename": os.path.basename(original_filepath),
                    "cached_at": time.time(),
                    "last_accessed": time.time(),
                    "size_bytes": file_size,
                    "mode": pe_data.get("mode", "unknown"),
                    "file_mtime": (
                        os.path.getmtime(original_filepath)
                        if os.path.exists(original_filepath) else None
                    ),
                    "file_size": (
                        os.path.getsize(original_filepath)
                        if os.path.exists(original_filepath) else None
                    ),
                }
                self._save_meta(meta)

                logger.info(
                    "Cache STORE %s... (%.1f KB compressed)",
                    sha256[:12], file_size / 1024
                )

                self._evict_if_needed(meta)
                return True

            except (OSError, TypeError, ValueError) as e:
                logger.error("Cache write error for %s...: %s", sha256[:12], e)
                return False

    # ------------------------------------------------------------------
    #  Eviction
    # ------------------------------------------------------------------

    def _evict_if_needed(self, meta: Optional[Dict[str, Any]] = None) -> None:
        if meta is None:
            meta = self._load_meta()

        total_size = sum(e.get("size_bytes", 0) for e in meta.values())
        if total_size <= self.max_size_bytes:
            return

        sorted_entries = sorted(
            meta.items(),
            key=lambda item: item[1].get("last_accessed", 0),
        )

        evicted = 0
        for sha, _ in sorted_entries:
            if total_size <= self.max_size_bytes:
                break
            size = meta[sha].get("size_bytes", 0)
            try:
                self._remove_entry(sha)
            except Exception as e:
                # If filesystem removal fails, skip this entry to keep
                # metadata consistent with what's actually on disk.
                logger.warning("Cache eviction skipped %s: %s", sha[:12], e)
                continue
            total_size -= size
            del meta[sha]
            evicted += 1

        if evicted:
            self._save_meta(meta)
            logger.info("Cache eviction: removed %d entries.", evicted)

    def _remove_entry(self, sha256: str) -> None:
        entry_path = self._entry_path(sha256)
        try:
            entry_path.unlink(missing_ok=True)
            parent = entry_path.parent
            if parent != CACHE_DIR and parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
        except OSError as e:
            logger.warning("Cache removal error for %s...: %s", sha256[:12], e)

    def _remove_entry_and_meta(self, sha256: str) -> None:
        """Remove both the on-disk entry and its metadata index record."""
        self._remove_entry(sha256)
        meta = self._load_meta()
        meta.pop(sha256, None)
        self._save_meta(meta)

    # ------------------------------------------------------------------
    #  Session data helpers (notes + tool history)
    # ------------------------------------------------------------------

    def get_session_metadata(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Read notes and tool_history from a cache entry without loading pe_data.

        Returns ``{"notes": [...], "tool_history": [...]}`` or ``None`` on
        miss / error.
        """
        if not self.enabled:
            return None

        sha256 = sha256.lower()
        entry_path = self._entry_path(sha256)

        if not entry_path.exists():
            return None

        try:
            with gzip.open(entry_path, "rt", encoding="utf-8") as f:
                wrapper = json.load(f)
        except (gzip.BadGzipFile, json.JSONDecodeError, OSError) as e:
            logger.warning("Cache session metadata read error for %s...: %s", sha256[:12], e)
            return None

        return {
            "notes": wrapper.get("notes", []),
            "tool_history": wrapper.get("tool_history", []),
        }

    def update_session_data(self, sha256: str,
                            notes: Optional[list] = None,
                            tool_history: Optional[list] = None) -> bool:
        """Update notes and/or tool_history for an existing cache entry.

        Reads the gzip wrapper, replaces the specified keys, and writes
        it back atomically.  Returns True on success.
        """
        if not self.enabled:
            return False

        sha256 = sha256.lower()

        with self._lock:
            entry_path = self._entry_path(sha256)
            if not entry_path.exists():
                return False
            try:
                with gzip.open(entry_path, "rt", encoding="utf-8") as f:
                    wrapper = json.load(f)
                if notes is not None:
                    wrapper["notes"] = notes
                if tool_history is not None:
                    wrapper["tool_history"] = tool_history
                tmp = entry_path.with_suffix(".tmp")
                with gzip.open(tmp, "wt", encoding="utf-8") as f:
                    json.dump(wrapper, f)
                tmp.replace(entry_path)
                return True
            except Exception as e:
                logger.error("Failed to update session data for %s...: %s", sha256[:12], e)
                return False

    # ------------------------------------------------------------------
    #  Management helpers (exposed via MCP tools)
    # ------------------------------------------------------------------

    def clear(self) -> Dict[str, Any]:
        """Remove all cache entries.  Returns summary dict."""
        with self._lock:
            meta = self._load_meta()
            count = len(meta)
            total = sum(e.get("size_bytes", 0) for e in meta.values())

            for sha in list(meta.keys()):
                self._remove_entry(sha)

            try:
                META_FILE.unlink(missing_ok=True)
            except OSError:
                pass

            if CACHE_DIR.exists():
                for subdir in CACHE_DIR.iterdir():
                    if subdir.is_dir():
                        try:
                            subdir.rmdir()
                        except OSError:
                            pass

            return {
                "entries_removed": count,
                "space_freed_mb": round(total / (1024 * 1024), 2),
            }

    def get_stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            meta = self._load_meta()
            total_size = sum(e.get("size_bytes", 0) for e in meta.values())
            return {
                "cache_dir": str(CACHE_DIR),
                "enabled": self.enabled,
                "entry_count": len(meta),
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "max_size_mb": self.max_size_bytes // (1024 * 1024),
                "utilization_percent": round(
                    (total_size / self.max_size_bytes) * 100, 1
                ) if self.max_size_bytes > 0 else 0,
                "entries": {
                    sha[:12] + "...": {
                        "filename": e.get("original_filename"),
                        "cached_at_iso": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(e.get("cached_at", 0)),
                        ),
                        "size_kb": round(e.get("size_bytes", 0) / 1024, 1),
                    }
                    for sha, e in meta.items()
                },
            }

    def remove_entry_by_hash(self, sha256: str) -> bool:
        """Remove a single entry by hash.  Returns True if it existed."""
        sha256 = sha256.lower()
        with self._lock:
            meta = self._load_meta()
            if sha256 not in meta:
                return False
            self._remove_entry(sha256)
            del meta[sha256]
            self._save_meta(meta)
            return True
