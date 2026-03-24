"""
Disk-based cache for file analysis results.

Stores compressed JSON in ~/.arkana/cache/, keyed by SHA256 hash of the
analysed file.  Uses gzip compression (typically 5-15x on JSON data)
and LRU eviction when total cache size exceeds a configurable limit.

Cache entries are invalidated automatically when:
  - Arkana version changes (parser logic may have changed)
  - Cache format version changes (wrapper structure changed)
  - Data is corrupt (bad gzip / JSON)
"""
import gzip
import json
import os
import re
import tempfile
import time
import logging
import threading

from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger("Arkana")

# Lazy-loaded to avoid circular imports (config.py instantiates this class)
_ARKANA_VERSION: Optional[str] = None


def _get_arkana_version() -> str:
    global _ARKANA_VERSION
    if _ARKANA_VERSION is None:
        from arkana import __version__
        _ARKANA_VERSION = __version__
    return _ARKANA_VERSION


# --- Constants ---
try:
    CACHE_DIR = Path.home() / ".arkana" / "cache"
except RuntimeError:
    CACHE_DIR = Path("/tmp") / ".arkana" / "cache"
META_FILE = CACHE_DIR / "meta.json"
DEFAULT_MAX_CACHE_SIZE_MB = 500
CACHE_FORMAT_VERSION = 1


_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')


def _validate_sha256(sha256: str) -> str:
    """Validate and normalize a SHA256 hash string. Prevents path traversal."""
    sha256 = sha256.lower().strip()
    if not _SHA256_RE.match(sha256):
        raise ValueError(f"Invalid SHA256 hash: {sha256[:20]}...")
    return sha256


class AnalysisCache:
    """
    Thread-safe, gzip-compressed, LRU-evicting disk cache for pe_data dicts.

    Directory layout (git-style two-char prefix to avoid flat-dir issues)::

        ~/.arkana/cache/
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
        # M-E1: In-memory metadata cache to avoid re-reading meta.json on every operation
        self._meta_cache: Optional[Dict[str, Any]] = None
        self._meta_mtime: float = 0.0
        self._meta_size: int = 0
        self._ensure_cache_dir()

    # ------------------------------------------------------------------
    #  Directory helpers
    # ------------------------------------------------------------------

    def _ensure_cache_dir(self) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Enforce permissions even if the directory already existed
        os.chmod(str(CACHE_DIR), 0o700)
        # Clean up orphaned .tmp files from previous interrupted writes
        self._cleanup_orphaned_tmp_files()

    def _cleanup_orphaned_tmp_files(self) -> None:
        """Remove .tmp files left behind by interrupted put() or _save_meta() calls."""
        try:
            for tmp_file in CACHE_DIR.rglob("*.tmp"):
                try:
                    tmp_file.unlink(missing_ok=True)
                    logger.debug("Cleaned up orphaned tmp file: %s", tmp_file)
                except OSError:
                    pass
        except OSError:
            pass  # Cache dir may not be fully accessible yet

    def _entry_dir(self, sha256: str) -> Path:
        return CACHE_DIR / sha256[:2]

    def _entry_path(self, sha256: str) -> Path:
        return self._entry_dir(sha256) / f"{sha256}.json.gz"

    # ------------------------------------------------------------------
    #  Metadata index
    # ------------------------------------------------------------------

    def _load_meta(self) -> Dict[str, Any]:
        # M-E1: Return in-memory cache if the file hasn't changed on disk
        if not META_FILE.exists():
            self._meta_cache = {}
            self._meta_mtime = 0.0
            self._meta_size: int = 0
            return {}
        try:
            st = META_FILE.stat()
            disk_mtime = st.st_mtime
            disk_size = st.st_size
            # Check both mtime and size to detect writes that land within
            # the same filesystem timestamp granularity (e.g. 1s on ext3,
            # HFS+).  Two distinct writes that produce the same mtime will
            # almost always differ in size.
            if (self._meta_cache is not None
                    and disk_mtime == self._meta_mtime
                    and disk_size == self._meta_size):
                return dict(self._meta_cache)
            with open(META_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._meta_cache = data
            self._meta_mtime = disk_mtime
            self._meta_size = disk_size
            return dict(data)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Cache meta read error: %s", e)
            self._meta_cache = None
            self._meta_mtime = 0.0
            self._meta_size = 0
            return {}

    def _save_meta(self, meta: Dict[str, Any]) -> None:
        # M3-v14: Use NamedTemporaryFile to avoid fixed temp path collisions
        import tempfile
        try:
            fd = tempfile.NamedTemporaryFile(
                mode="w", suffix=".tmp", dir=str(META_FILE.parent),
                delete=False, encoding="utf-8",
            )
            tmp = Path(fd.name)
            try:
                json.dump(meta, fd, indent=2)
            except BaseException:
                # M4-v14: Clean up temp file on failure
                tmp.unlink(missing_ok=True)
                raise
            finally:
                fd.close()
            # Path.replace() is atomic on POSIX (rename(2) syscall).
            try:
                tmp.replace(META_FILE)
                self._meta_cache = meta
                st = META_FILE.stat()
                self._meta_mtime = st.st_mtime
                self._meta_size = st.st_size
            except OSError:
                tmp.unlink(missing_ok=True)
                raise
        except (OSError, TypeError, ValueError) as e:
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

        sha256 = _validate_sha256(sha256)
        entry_path = self._entry_path(sha256)

        if not entry_path.exists():
            return None

        # --- Read and decompress OUTSIDE the lock (this can be slow) ---
        try:
            with gzip.open(entry_path, "rt", encoding="utf-8") as f:
                wrapper = json.load(f)
        except FileNotFoundError:
            # File disappeared between exists() check and open — just return None.
            return None
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

        cached_version = cmeta.get("arkana_version") or cmeta.get("pemcp_version")
        if cached_version != _get_arkana_version():
            logger.info(
                "Cache version mismatch for %s... (cached=%s, current=%s). Invalidating.",
                sha256[:12], cached_version, _get_arkana_version()
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

        with self._lock:
            # single lock acquisition for validation + LRU update
            meta = self._load_meta()
            if file_exists and current_mtime is not None:
                cached_meta = meta.get(sha256, {})
                cached_mtime = cached_meta.get("file_mtime")
                cached_size = cached_meta.get("file_size")
                if cached_mtime is not None and abs(current_mtime - cached_mtime) > 0.01:
                    logger.info("Cache mtime mismatch for %s..., invalidating.", sha256[:12])
                    # Inline removal using already-loaded meta to avoid
                    # redundant _load_meta + _save_meta round-trip.
                    self._remove_entry(sha256)
                    meta.pop(sha256, None)
                    self._save_meta(meta)
                    return None
                if cached_size is not None and current_size != cached_size:
                    logger.info("Cache file size mismatch for %s..., invalidating.", sha256[:12])
                    self._remove_entry(sha256)
                    meta.pop(sha256, None)
                    self._save_meta(meta)
                    return None

            # Touch LRU timestamp (throttled to once per minute)
            try:
                if sha256 in meta:
                    last = meta[sha256].get("last_accessed", 0)
                    now = time.time()
                    if now - last > 60:
                        meta[sha256]["last_accessed"] = now
                        self._save_meta(meta)
            except (OSError, TypeError, ValueError) as exc:
                logger.debug("Failed to update LRU timestamp for %s: %s", sha256[:12], exc)

        # Patch session-specific field
        pe_data["filepath"] = current_filepath

        logger.info("Cache HIT for %s...", sha256[:12])
        return pe_data

    def put(self, sha256: str, pe_data: Dict[str, Any], original_filepath: str,
            notes: Optional[list] = None, tool_history: Optional[list] = None,
            artifacts: Optional[list] = None,
            renames: Optional[dict] = None,
            custom_types: Optional[dict] = None,
            triage_status: Optional[dict] = None) -> bool:
        """
        Store a ``pe_data`` dict in the cache.  Returns True on success.

        Optionally includes session notes, tool history, and artifacts
        alongside the analysis data.  The gzip compression runs outside
        the lock to avoid blocking concurrent callers during the
        (potentially slow) compression step.
        """
        if not self.enabled:
            return False

        sha256 = _validate_sha256(sha256)

        wrapper = {
            "_cache_meta": {
                "cache_format_version": CACHE_FORMAT_VERSION,
                "arkana_version": _get_arkana_version(),
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
            "artifacts": artifacts or [],
            "renames": renames or {"functions": {}, "variables": {}, "labels": {}},
            "custom_types": custom_types or {"structs": {}, "enums": {}},
            "triage_status": triage_status or {},
        }

        # Write compressed JSON OUTSIDE the lock — this can be slow for
        # large analyses and would otherwise block concurrent get()/put()
        # callers.  Streaming via gzip.open avoids materialising the full
        # JSON + compressed bytes in memory simultaneously.
        try:
            entry_dir = self._entry_dir(sha256)
            entry_dir.mkdir(parents=True, exist_ok=True)
            entry_path = self._entry_path(sha256)

            # Record mtime before write so we can detect concurrent
            # update_session_data() modifications inside the lock.
            pre_write_mtime = None
            try:
                pre_write_mtime = entry_path.stat().st_mtime if entry_path.exists() else None
            except OSError:
                pass

            # M-10: Use NamedTemporaryFile to avoid .tmp collisions between
            # concurrent put() calls for different SHA256 values that share
            # the same entry_dir.
            fd = tempfile.NamedTemporaryFile(
                dir=str(entry_dir), suffix='.tmp', delete=False,
            )
            tmp = Path(fd.name)
            try:
                fd.close()  # close the raw fd; gzip.open re-opens by path
                with gzip.open(tmp, "wt", encoding="utf-8") as gz:
                    json.dump(wrapper, gz)
                # tmp.replace moved into lock block below to prevent
                # clobbering concurrent update_session_data() writes.
            except Exception:
                tmp.unlink(missing_ok=True)
                raise
        except (TypeError, ValueError, OSError) as e:
            logger.error("Cache serialization error for %s...: %s", sha256[:12], e)
            return False

        _SESSION_FIELDS = ("notes", "tool_history", "artifacts", "renames", "custom_types", "triage_status")

        with self._lock:
            try:
                # Check if session data was updated during our write
                try:
                    current_mtime = entry_path.stat().st_mtime if entry_path.exists() else None
                except OSError:
                    current_mtime = None

                if current_mtime is not None and current_mtime != pre_write_mtime:
                    # Session data was updated during our write — merge it
                    try:
                        with gzip.open(entry_path, "rt", encoding="utf-8") as f:
                            on_disk = json.load(f)
                        with gzip.open(tmp, "rt", encoding="utf-8") as f:
                            our_data = json.load(f)
                        for field in _SESSION_FIELDS:
                            if field in on_disk:
                                our_data[field] = on_disk[field]
                        # Write merged data to a NEW temp file (not tmp itself)
                        # to avoid corrupting tmp if the write fails mid-way.
                        merge_fd = tempfile.NamedTemporaryFile(
                            dir=str(entry_dir), suffix='.tmp', delete=False,
                        )
                        merge_tmp = Path(merge_fd.name)
                        try:
                            merge_fd.close()
                            with gzip.open(merge_tmp, "wt", encoding="utf-8") as gz:
                                json.dump(our_data, gz)
                            # Replace the original tmp with the merged version
                            merge_tmp.replace(tmp)
                        except Exception:
                            merge_tmp.unlink(missing_ok=True)
                            raise
                    except Exception as e:
                        # Merge failed — keep the on-disk version (which has session data)
                        # rather than clobbering it with our unmerged analysis-only data.
                        logger.warning(
                            "Failed to merge session data during cache put: %s. "
                            "Keeping existing on-disk entry to preserve session data.", e
                        )
                        tmp.unlink(missing_ok=True)
                        tmp = None  # signal to skip replace

                if tmp is None:
                    # Merge failed — on-disk entry preserved with session data.
                    # Skip metadata update since we didn't write a new entry.
                    return True

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

            except OSError as e:
                logger.error("Cache write error for %s...: %s", sha256[:12], e)
                if tmp is not None:
                    tmp.unlink(missing_ok=True)
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

        to_evict = []
        for sha, _ in sorted_entries:
            if total_size <= self.max_size_bytes:
                break
            size = meta[sha].get("size_bytes", 0)
            try:
                self._remove_entry(sha)
            except Exception as e:
                logger.warning("Cache eviction skipped %s: %s", sha[:12], e)
                continue
            total_size -= size
            to_evict.append(sha)

        for sha in to_evict:
            del meta[sha]

        if to_evict:
            self._save_meta(meta)
            logger.info("Cache eviction: removed %d entries.", len(to_evict))

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

        sha256 = _validate_sha256(sha256)
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
            "artifacts": wrapper.get("artifacts", []),
            "renames": wrapper.get("renames", {"functions": {}, "variables": {}, "labels": {}}),
            "custom_types": wrapper.get("custom_types", {"structs": {}, "enums": {}}),
            "triage_status": wrapper.get("triage_status", {}),
        }

    def update_session_data(self, sha256: str,
                            notes: Optional[list] = None,
                            tool_history: Optional[list] = None,
                            artifacts: Optional[list] = None,
                            renames: Optional[dict] = None,
                            custom_types: Optional[dict] = None,
                            triage_status: Optional[dict] = None) -> bool:
        """Update notes, tool_history, artifacts, renames, custom_types, and/or triage_status for an existing cache entry.

        Reads the gzip wrapper, replaces the specified keys, and writes
        it back atomically.  Returns True on success.
        """
        if not self.enabled:
            return False

        sha256 = _validate_sha256(sha256)
        entry_path = self._entry_path(sha256)

        # Hold lock through the full read-modify-write cycle to prevent
        # concurrent updates from clobbering each other (e.g. add_note +
        # rename_function racing).  Session data updates are infrequent
        # so the slightly longer lock hold is acceptable.
        with self._lock:
            if not entry_path.exists():
                return False

            try:
                with gzip.open(entry_path, "rt", encoding="utf-8") as f:
                    wrapper = json.load(f)
            except (gzip.BadGzipFile, json.JSONDecodeError, OSError) as e:
                logger.error("Failed to read session data for %s...: %s", sha256[:12], e)
                return False

            # Modify wrapper in memory
            if notes is not None:
                wrapper["notes"] = notes
            if tool_history is not None:
                wrapper["tool_history"] = tool_history
            if artifacts is not None:
                wrapper["artifacts"] = artifacts
            if renames is not None:
                wrapper["renames"] = renames
            if custom_types is not None:
                wrapper["custom_types"] = custom_types
            if triage_status is not None:
                wrapper["triage_status"] = triage_status

            # Write atomically using streaming gzip
            # M-10: Use NamedTemporaryFile to avoid .tmp collisions
            fd = tempfile.NamedTemporaryFile(
                dir=str(entry_path.parent), suffix='.tmp', delete=False,
            )
            tmp = Path(fd.name)
            fd.close()
            try:
                with gzip.open(tmp, "wt", encoding="utf-8") as gz:
                    json.dump(wrapper, gz)
                tmp.replace(entry_path)
                return True
            except (TypeError, ValueError, OSError) as e:
                logger.error("Failed to write session data for %s...: %s", sha256[:12], e)
                tmp.unlink(missing_ok=True)
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
            self._meta_cache = None
            self._meta_mtime = 0.0
            self._meta_size = 0

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

    def insert_raw_entry(self, sha256: str, meta_entry: Dict[str, Any]) -> None:
        """Insert or update cache metadata for a pre-written entry.

        Used by ``import_project`` to register an entry whose ``.json.gz``
        file has already been written to the cache directory.  Acquires
        ``_lock``, loads meta, updates the entry, and saves.
        """
        sha256 = _validate_sha256(sha256)
        with self._lock:
            meta = self._load_meta()
            meta[sha256] = meta_entry
            self._save_meta(meta)
            self._evict_if_needed(meta)

    def remove_entry_by_hash(self, sha256: str) -> bool:
        """Remove a single entry by hash.  Returns True if it existed."""
        sha256 = _validate_sha256(sha256)
        with self._lock:
            meta = self._load_meta()
            if sha256 not in meta:
                return False
            self._remove_entry(sha256)
            del meta[sha256]
            self._save_meta(meta)
            return True
