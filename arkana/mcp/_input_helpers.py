"""Shared input parsing and pagination helpers for MCP tools.

Centralises hex/int parameter parsing and the full-cache pagination
system so every tool can accept ``0x`` prefixed offsets and return
paginated results with a consistent format.
"""
import collections
import threading
import time
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
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # tool_name -> OrderedDict[(params_key) -> {"items": list, "ts": float}]
        self._store: Dict[str, collections.OrderedDict] = {}

    def get(self, tool_name: str, params_key) -> Optional[List]:
        """Return cached items list or ``None`` on miss (including TTL expiry)."""
        with self._lock:
            bucket = self._store.get(tool_name)
            if bucket is None or params_key not in bucket:
                return None
            entry = bucket[params_key]
            # TTL check — evict stale entries
            if time.time() - entry["ts"] > _CACHE_TTL_SECONDS:
                del bucket[params_key]
                return None
            bucket.move_to_end(params_key)
            return entry["items"]

    def set(self, tool_name: str, params_key, items: List) -> None:
        """Store *items* in the cache, evicting LRU if needed."""
        with self._lock:
            bucket = self._store.setdefault(tool_name, collections.OrderedDict())
            bucket[params_key] = {"items": items, "ts": time.time()}
            bucket.move_to_end(params_key)
            while len(bucket) > _LRU_SLOTS_PER_TOOL:
                bucket.popitem(last=False)

    def keys(self, tool_name: str) -> List:
        """Return a snapshot of cached param keys for *tool_name*."""
        with self._lock:
            bucket = self._store.get(tool_name)
            return list(bucket.keys()) if bucket else []

    def clear(self, tool_name: Optional[str] = None) -> None:
        """Clear cache for a specific tool, or all tools if *tool_name* is ``None``."""
        with self._lock:
            if tool_name is None:
                self._store.clear()
            else:
                self._store.pop(tool_name, None)


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
    if isinstance(v, (list, set)):
        return tuple(_make_hashable(item, _depth + 1) for item in v)
    return v


def _make_cache_key(**params) -> tuple:
    """Build a hashable cache key from keyword arguments.

    Excludes ``offset``, ``limit``, ``compact``, and ``ctx`` so that
    different pages of the same query hit the same cache entry.
    """
    _SKIP = frozenset({"offset", "limit", "compact", "ctx"})
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
