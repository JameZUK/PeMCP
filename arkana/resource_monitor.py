"""Process-level resource monitor using psutil.

Runs a lightweight daemon thread that polls RSS memory and CPU percentage
on a configurable interval.  All public functions return ``None`` when
psutil is not installed — callers never need to check availability.
"""
import logging
import os
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

from arkana.constants import (
    RESOURCE_MONITOR_INTERVAL,
    RESOURCE_MEMORY_HIGH_MB,
    RESOURCE_MEMORY_CRITICAL_MB,
    RESOURCE_CPU_HIGH_PERCENT,
    RESOURCE_HISTORY_SIZE,
)
from arkana.imports import PSUTIL_AVAILABLE
from arkana.utils import _safe_env_int

logger = logging.getLogger("Arkana")

# Runtime-configurable thresholds (env vars override constants)
_INTERVAL = _safe_env_int("ARKANA_RESOURCE_MONITOR_INTERVAL", RESOURCE_MONITOR_INTERVAL)
_MEMORY_HIGH = _safe_env_int("ARKANA_RESOURCE_MEMORY_HIGH_MB", RESOURCE_MEMORY_HIGH_MB)
_MEMORY_CRITICAL = _safe_env_int("ARKANA_RESOURCE_MEMORY_CRITICAL_MB", RESOURCE_MEMORY_CRITICAL_MB)
_CPU_HIGH = _safe_env_int("ARKANA_RESOURCE_CPU_HIGH_PERCENT", RESOURCE_CPU_HIGH_PERCENT)

# Module-level state
_latest_snapshot: Optional[Dict[str, Any]] = None
_snapshot_history: deque = deque(maxlen=RESOURCE_HISTORY_SIZE)
_monitor_lock = threading.Lock()
_monitor_thread: Optional[threading.Thread] = None
_monitor_stop = threading.Event()


def _make_snapshot(proc) -> Dict[str, Any]:
    """Build a snapshot dict from a psutil.Process."""
    mem = proc.memory_info()
    rss_bytes = mem.rss
    rss_mb = round(rss_bytes / (1024 * 1024), 1)
    cpu_pct = proc.cpu_percent(interval=None)

    if rss_mb >= _MEMORY_CRITICAL:
        level = "critical"
    elif rss_mb >= _MEMORY_HIGH:
        level = "high"
    else:
        level = "normal"

    return {
        "timestamp": time.time(),
        "rss_mb": rss_mb,
        "rss_bytes": rss_bytes,
        "cpu_percent": round(cpu_pct, 1),
        "thread_count": proc.num_threads(),
        "memory_level": level,
    }


def _monitor_loop() -> None:
    """Daemon thread loop — polls psutil at _INTERVAL seconds."""
    import psutil  # guarded by caller

    global _latest_snapshot
    proc = psutil.Process(os.getpid())

    # Prime cpu_percent baseline (first call always returns 0.0)
    proc.cpu_percent(interval=None)

    while not _monitor_stop.wait(timeout=max(1, _INTERVAL)):
        try:
            snap = _make_snapshot(proc)
            with _monitor_lock:
                _latest_snapshot = snap
                _snapshot_history.append(snap)
        except Exception:
            logger.debug("Resource monitor poll error", exc_info=True)


def _ensure_started() -> None:
    """Lazily start the monitor thread if not already running."""
    global _monitor_thread
    if not PSUTIL_AVAILABLE:
        return
    if _monitor_thread is not None and _monitor_thread.is_alive():
        return
    with _monitor_lock:
        if _monitor_thread is not None and _monitor_thread.is_alive():
            return
        _monitor_stop.clear()
        t = threading.Thread(target=_monitor_loop, name="resource-monitor", daemon=True)
        t.start()
        _monitor_thread = t
        logger.debug("Resource monitor thread started (interval=%ds)", _INTERVAL)


def get_resource_snapshot() -> Optional[Dict[str, Any]]:
    """Return the latest resource snapshot, or None if unavailable."""
    if not PSUTIL_AVAILABLE:
        return None
    _ensure_started()
    with _monitor_lock:
        if _latest_snapshot is None:
            return None
        return dict(_latest_snapshot)


def get_resource_history() -> List[Dict[str, Any]]:
    """Return recent snapshots for trend analysis."""
    if not PSUTIL_AVAILABLE:
        return []
    _ensure_started()
    with _monitor_lock:
        return [dict(s) for s in _snapshot_history]


def get_resource_alert() -> Optional[Dict[str, Any]]:
    """Return an alert dict if memory or CPU is above thresholds, else None.

    Injected into ``_collect_background_alerts()`` so the AI sees resource
    pressure in every MCP tool response.
    """
    snap = get_resource_snapshot()
    if snap is None:
        return None

    level = snap["memory_level"]
    if level == "normal":
        return None

    if level == "critical":
        hint = (
            f"Memory usage is critical ({snap['rss_mb']} MB, threshold {_MEMORY_CRITICAL} MB). "
            "Abort background tasks or reduce analysis scope to avoid OOM."
        )
    else:
        hint = (
            f"Memory usage is high ({snap['rss_mb']} MB, threshold {_MEMORY_HIGH} MB). "
            "Consider aborting background tasks to free memory."
        )

    return {
        "type": "resource_pressure",
        "level": level,
        "rss_mb": snap["rss_mb"],
        "cpu_percent": snap["cpu_percent"],
        "thread_count": snap["thread_count"],
        "threshold_mb": _MEMORY_CRITICAL if level == "critical" else _MEMORY_HIGH,
        "hint": hint,
    }


def stop_monitor() -> None:
    """Stop the monitor thread (used in tests)."""
    global _monitor_thread, _latest_snapshot
    _monitor_stop.set()
    if _monitor_thread is not None:
        _monitor_thread.join(timeout=5)
        _monitor_thread = None
    with _monitor_lock:
        _latest_snapshot = None
        _snapshot_history.clear()
