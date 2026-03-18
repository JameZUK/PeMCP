"""Shared input parsing and pagination helpers for MCP tools.

Centralises hex/int parameter parsing and the full-cache pagination
system so every tool can accept ``0x`` prefixed offsets and return
paginated results with a consistent format.
"""
import collections
import threading
import time
import weakref
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
#  Hex / int parameter parsing
# ---------------------------------------------------------------------------

def _parse_int_param(value: Union[int, str], name: str = "offset") -> int:
    """Parse an integer parameter that may be given as hex string.

    Accepts plain ``int``, ``"0x1b22d8"``, ``"1778392"``, ``"0b1010"``,
    or ``"0o777"``.  Uses ``int(str, 0)`` for auto-base detection.

    Raises ``ValueError`` with a user-friendly message on failure.
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        try:
            return int(value, 0)
        except (ValueError, TypeError):
            pass
    raise ValueError(
        f"Invalid {name}: {value!r}. "
        f"Provide a decimal integer (e.g. 1778392) or hex string (e.g. '0x1b22d8')."
    )


# ---------------------------------------------------------------------------
#  LRU Result Cache (per-tool, 5 slots)
# ---------------------------------------------------------------------------

_LRU_SLOTS_PER_TOOL = 5
_CACHE_TTL_SECONDS = 3600  # 1 hour


class _ToolResultCache:
    """Thread-safe LRU cache for paginated tool results.

    Keyed by ``(tool_name, params_key)`` where *params_key* is a hashable
    representation of the non-pagination parameters.  Each tool gets up to
    ``_LRU_SLOTS_PER_TOOL`` cached results; the least-recently-used entry
    is evicted when the limit is exceeded.  Entries older than
    ``_CACHE_TTL_SECONDS`` are treated as cache misses.

    A class-level registry tracks all instances and enforces a global entry
    cap of ``_GLOBAL_MAX_ENTRIES`` to bound total memory usage.
    """

    # H1-v8: Use WeakSet so reaped AnalyzerState sessions (and their caches)
    # can be garbage collected.  Strong refs in a plain list prevented GC.
    _all_instances: weakref.WeakSet = weakref.WeakSet()
    _global_lock = threading.Lock()
    _global_entry_count = 0
    _GLOBAL_MAX_ENTRIES = 200

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # tool_name -> OrderedDict[(params_key) -> {"items": list, "ts": float}]
        self._store: Dict[str, collections.OrderedDict] = {}
        with _ToolResultCache._global_lock:
            _ToolResultCache._all_instances.add(self)

    def _entry_count(self) -> int:
        """Return total entries across all tool buckets (caller must hold self._lock)."""
        return sum(len(b) for b in self._store.values())

    def get(self, tool_name: str, params_key) -> Optional[List]:
        """Return cached items list or ``None`` on miss (including TTL expiry)."""
        # H3-v8: Release self._lock BEFORE acquiring _global_lock to prevent
        # ABBA deadlock with set() -> _cleanup_expired() which acquires
        # _global_lock then inst._lock.
        need_global_decrement = False
        with self._lock:
            bucket = self._store.get(tool_name)
            if bucket is None or params_key not in bucket:
                return None
            entry = bucket[params_key]
            # TTL check — evict stale entries
            if time.time() - entry["ts"] > _CACHE_TTL_SECONDS:
                del bucket[params_key]
                need_global_decrement = True
            else:
                bucket.move_to_end(params_key)
                return entry["items"]
        # Decrement global counter outside self._lock (consistent lock ordering)
        if need_global_decrement:
            with _ToolResultCache._global_lock:
                _ToolResultCache._global_entry_count = max(0, _ToolResultCache._global_entry_count - 1)
        return None

    def set(self, tool_name: str, params_key, items: List) -> None:
        """Store *items* in the cache, evicting LRU if needed."""
        with self._lock:
            bucket = self._store.setdefault(tool_name, collections.OrderedDict())
            is_new = params_key not in bucket
            bucket[params_key] = {"items": list(items), "ts": time.time()}
            bucket.move_to_end(params_key)
            evicted = 0
            while len(bucket) > _LRU_SLOTS_PER_TOOL:
                bucket.popitem(last=False)
                evicted += 1
        with _ToolResultCache._global_lock:
            if is_new:
                _ToolResultCache._global_entry_count += 1
            _ToolResultCache._global_entry_count -= evicted
            _ToolResultCache._global_entry_count = max(0, _ToolResultCache._global_entry_count)
            if _ToolResultCache._global_entry_count > _ToolResultCache._GLOBAL_MAX_ENTRIES:
                _ToolResultCache._cleanup_expired()

    def keys(self, tool_name: str) -> List:
        """Return a snapshot of cached param keys for *tool_name*."""
        with self._lock:
            bucket = self._store.get(tool_name)
            return list(bucket.keys()) if bucket else []

    def clear(self, tool_name: Optional[str] = None) -> None:
        """Clear cache for a specific tool, or all tools if *tool_name* is ``None``."""
        with self._lock:
            if tool_name is None:
                removed = sum(len(b) for b in self._store.values())
                self._store.clear()
            else:
                bucket = self._store.pop(tool_name, None)
                removed = len(bucket) if bucket else 0
        with _ToolResultCache._global_lock:
            _ToolResultCache._global_entry_count = max(0, _ToolResultCache._global_entry_count - removed)

    @classmethod
    def _cleanup_expired(cls) -> None:
        """Remove expired entries across all instances (caller must hold _global_lock).

        H3-v8: WeakSet iteration is safe — dead refs are automatically skipped.
        Lock ordering: _global_lock (held by caller) -> inst._lock (acquired here).
        """
        now = time.time()
        # M8-v14: Compute recount inside per-instance locks to avoid race
        total = 0
        for inst in list(cls._all_instances):  # snapshot to avoid WeakSet mutation during iteration
            with inst._lock:
                for _tool_name, bucket in list(inst._store.items()):
                    expired_keys = [k for k, v in bucket.items() if now - v["ts"] > _CACHE_TTL_SECONDS]
                    for k in expired_keys:
                        del bucket[k]
                total += sum(len(b) for b in inst._store.values())
        cls._global_entry_count = total


# ---------------------------------------------------------------------------
#  Pagination helper
# ---------------------------------------------------------------------------

_MAKE_HASHABLE_MAX_DEPTH = 20


def _make_hashable(v, _depth=0):
    """Recursively convert mutable values to hashable types for cache keys."""
    if _depth > _MAKE_HASHABLE_MAX_DEPTH:
        return str(v)[:200]
    if isinstance(v, bytearray):
        return bytes(v)
    if isinstance(v, dict):
        return tuple(sorted((k, _make_hashable(val, _depth + 1)) for k, val in v.items()))
    if isinstance(v, (list, tuple, set)):
        return tuple(_make_hashable(item, _depth + 1) for item in v)
    return v


_SKIP = frozenset({"offset", "limit", "compact", "ctx", "line_offset", "line_limit",
                    "search", "context_lines", "case_sensitive",
                    "notes_offset", "notes_limit", "history_limit",
                    "findings_offset", "findings_limit",
                    "functions_offset", "functions_limit",
                    "ioc_limit", "ioc_offset",
                    "unexplored_offset", "unexplored_limit",
                    "indicator_offset", "indicator_limit",
                    "method_limit", "max_suggestions"})


def _make_cache_key(**params) -> tuple:
    """Build a hashable cache key from keyword arguments.

    Excludes ``offset``, ``limit``, ``compact``, and ``ctx`` so that
    different pages of the same query hit the same cache entry.
    """
    parts = []
    for k in sorted(params):
        if k in _SKIP:
            continue
        v = _make_hashable(params[k])
        parts.append((k, v))
    return tuple(parts)


def _paginated_response(
    items: List,
    offset: int,
    limit: int,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a standardised paginated response dict.

    Args:
        items: The full (or page-sliced) list of result items.
        offset: Current page offset.
        limit: Page size.
        extra: Additional keys to merge into the response.

    Returns:
        ``{"results": [...], "count": N, "_pagination": {...}, ...extra}``
    """
    total = len(items) if isinstance(items, list) else 0
    offset = max(0, min(offset, total))
    page = items[offset:offset + limit] if isinstance(items, list) else []
    result: Dict[str, Any] = {
        "results": page,
        "count": len(page),
        "_pagination": {
            "total": total,
            "offset": offset,
            "limit": limit,
            "returned": len(page),
            "has_more": (offset + limit) < total,
        },
    }
    if extra:
        result.update(extra)
    return result


def _paginate_field(items, offset=0, limit=50):
    """Slice a list and return ``(page, pagination_dict)``.

    Lightweight helper for adding pagination metadata to individual
    fields within a larger response dict — unlike ``_paginated_response``
    which builds the entire response wrapper.
    """
    if not isinstance(items, list):
        items = list(items) if items else []
    total = len(items)
    offset = max(0, min(offset, total))
    page = items[offset:offset + limit]
    return page, {
        "total": total,
        "offset": offset,
        "limit": limit,
        "returned": len(page),
        "has_more": (offset + limit) < total,
    }


def _cached_paginated_response(
    cache: "_ToolResultCache",
    tool_name: str,
    params_key,
    compute_fn: Callable[[], List],
    offset: int,
    limit: int,
    internal_max: int = 5000,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Check cache, compute on miss, cache, slice, return with pagination metadata.

    Args:
        cache: The ``_ToolResultCache`` instance (from ``AnalyzerState``).
        tool_name: Name of the calling tool.
        params_key: Hashable cache key (from ``_make_cache_key``).
        compute_fn: Zero-arg callable that returns the full result list.
        offset: Page offset.
        limit: Page size.
        internal_max: Maximum items to cache (per-tool tunable).
        extra: Additional keys to merge into the response.

    Returns:
        Standardised paginated response dict.
    """
    cached = cache.get(tool_name, params_key)
    if cached is None:
        all_items = compute_fn()
        if isinstance(all_items, list):
            all_items = all_items[:internal_max]
        else:
            all_items = list(all_items)[:internal_max]
        cache.set(tool_name, params_key, all_items)
    else:
        all_items = cached
    return _paginated_response(all_items, offset, limit, extra=extra)
