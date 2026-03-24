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


# ---------------------------------------------------------------------------
#  Dynamic memory detection
# ---------------------------------------------------------------------------

def _detect_available_memory_mb() -> tuple:
    """Detect available memory from cgroups or system total.

    Returns (available_mb, source_str) where source is one of:
    'cgroup_v2', 'cgroup_v1', 'psutil', or 'default'.
    Returns (None, 'default') if detection fails.
    """
    # 1. cgroup v2 (Docker, Podman, K8s on modern kernels)
    try:
        with open("/sys/fs/cgroup/memory.max", "r") as f:
            val = f.read().strip()
        if val != "max":
            mb = int(val) // (1024 * 1024)
            if mb > 0:
                return mb, "cgroup_v2"
    except (OSError, ValueError):
        pass

    # 2. cgroup v1 (older Docker)
    try:
        with open("/sys/fs/cgroup/memory/memory.limit_in_bytes", "r") as f:
            val = int(f.read().strip())
        # cgroup v1 reports a very large number (~2^63) when unlimited
        if 0 < val < (1 << 62):
            mb = val // (1024 * 1024)
            if mb > 0:
                return mb, "cgroup_v1"
    except (OSError, ValueError):
        pass

    # 3. System total via psutil
    if PSUTIL_AVAILABLE:
        try:
            import psutil
            total = psutil.virtual_memory().total
            mb = total // (1024 * 1024)
            if mb > 0:
                return mb, "psutil"
        except Exception:
            pass

    return None, "default"


def _compute_thresholds(available_mb):
    """Compute HIGH/CRITICAL thresholds from available memory.

    HIGH  = 60% of available (leave 40% headroom)
    CRITICAL = 80% of available (imminent OOM risk)

    Floor: HIGH >= 512 MB, CRITICAL >= 1024 MB
    Ceiling: HIGH <= 32768 MB, CRITICAL <= 65536 MB
    """
    if available_mb is None:
        return RESOURCE_MEMORY_HIGH_MB, RESOURCE_MEMORY_CRITICAL_MB
    high = max(512, min(int(available_mb * 0.6), 32768))
    critical = max(1024, min(int(available_mb * 0.8), 65536))
    return high, critical


# Detect available memory once at module load
_detected_available_mb, _detected_source = _detect_available_memory_mb()
_dynamic_high, _dynamic_critical = _compute_thresholds(_detected_available_mb)

# Runtime-configurable thresholds — env vars override dynamic defaults
_INTERVAL = _safe_env_int("ARKANA_RESOURCE_MONITOR_INTERVAL", RESOURCE_MONITOR_INTERVAL, min_val=1, max_val=3600)
_MEMORY_HIGH = _safe_env_int("ARKANA_RESOURCE_MEMORY_HIGH_MB", _dynamic_high, min_val=100)
_MEMORY_CRITICAL = _safe_env_int("ARKANA_RESOURCE_MEMORY_CRITICAL_MB", _dynamic_critical, min_val=100)
_CPU_HIGH = _safe_env_int("ARKANA_RESOURCE_CPU_HIGH_PERCENT", RESOURCE_CPU_HIGH_PERCENT, min_val=1, max_val=100)

# Track whether env vars overrode the auto-detected defaults
_env_override_high = os.environ.get("ARKANA_RESOURCE_MEMORY_HIGH_MB") is not None
_env_override_critical = os.environ.get("ARKANA_RESOURCE_MEMORY_CRITICAL_MB") is not None

logger.info(
    "Memory monitor: available=%s MB (source=%s), thresholds: high=%d MB, critical=%d MB%s",
    _detected_available_mb or "unknown", _detected_source,
    _MEMORY_HIGH, _MEMORY_CRITICAL,
    " (env override)" if (_env_override_high or _env_override_critical) else " (auto-detected)"
)

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

    mem_level = snap["memory_level"]
    cpu_high = snap["cpu_percent"] >= _CPU_HIGH

    if mem_level == "normal" and not cpu_high:
        return None

    # Build hint from active pressure sources
    hints = []
    if mem_level == "critical":
        hints.append(
            f"Memory usage is critical ({snap['rss_mb']} MB, threshold {_MEMORY_CRITICAL} MB). "
            "Abort background tasks or reduce analysis scope to avoid OOM."
        )
    elif mem_level == "high":
        hints.append(
            f"Memory usage is high ({snap['rss_mb']} MB, threshold {_MEMORY_HIGH} MB). "
            "Consider aborting background tasks to free memory."
        )
    if cpu_high:
        hints.append(f"CPU usage is high ({snap['cpu_percent']}%, threshold {_CPU_HIGH}%).")

    level = mem_level if mem_level != "normal" else "high"  # CPU-only pressure is "high"

    return {
        "type": "resource_pressure",
        "level": level,
        "rss_mb": snap["rss_mb"],
        "cpu_percent": snap["cpu_percent"],
        "thread_count": snap["thread_count"],
        "threshold_mb": _MEMORY_CRITICAL if mem_level == "critical" else _MEMORY_HIGH,
        "cpu_threshold": _CPU_HIGH,
        "hint": " ".join(hints),
    }


def stop_monitor() -> None:
    """Stop the monitor thread (used in tests)."""
    global _monitor_thread, _latest_snapshot
    _monitor_stop.set()
    if _monitor_thread is not None:
        _monitor_thread.join(timeout=5)
    with _monitor_lock:
        _monitor_thread = None
        _latest_snapshot = None
        _snapshot_history.clear()
