"""MCP tools for configuration, task status, and utility functions."""
import datetime
import os
import threading
import time
from typing import Dict, Any, List, Optional
from arkana.config import (
    state, Context,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    YARA_AVAILABLE, STRINGSIFTER_AVAILABLE, REQUESTS_AVAILABLE,
)
from arkana.user_config import get_config_value, set_config_value, get_masked_config
from arkana.state import TASK_FAILED, TASK_RUNNING, TASK_OVERTIME
from arkana.mcp.server import tool_decorator, _check_mcp_response_size


def _env_with_fallback(new_key: str, old_key: str, default: str = "") -> str:
    """Read an env var with ARKANA_* preferred, PEMCP_* as fallback."""
    return os.environ.get(new_key) or os.environ.get(old_key) or default


def _resolve_export_dir() -> Optional[str]:
    """Resolve the internal export directory from environment with fallback chain.

    Checks ARKANA_EXPORT_DIR / PEMCP_EXPORT_DIR first, then /output, then /tmp.
    Returns None if no usable directory is found.
    """
    export_dir = _env_with_fallback("ARKANA_EXPORT_DIR", "PEMCP_EXPORT_DIR", "/output")
    if os.path.isdir(export_dir):
        return export_dir
    if os.path.isdir("/output"):
        return "/output"
    if os.path.isdir("/tmp"):
        return "/tmp"
    return None


def _build_mount_mappings() -> List[Dict[str, str]]:
    """Build a list of known container-to-host path mappings from environment variables.

    Each mapping is a dict with 'internal' (container path) and 'external' (host path).
    Mappings are sourced from ARKANA_PATH_MAP (semicolon-separated internal=external pairs)
    and the legacy ARKANA_HOST_SAMPLES / ARKANA_HOST_EXPORT variables.

    Returns a list sorted by internal path length (longest first) so that
    more-specific mounts match before less-specific ones.
    """
    mappings: List[Dict[str, str]] = []

    # Primary: ARKANA_PATH_MAP supports arbitrary mount pairs
    # Format: "/container/path1=/host/path1;/container/path2=/host/path2"
    path_map = _env_with_fallback("ARKANA_PATH_MAP", "PEMCP_PATH_MAP")
    if path_map:
        for pair in path_map.split(";"):
            pair = pair.strip()
            if "=" in pair:
                internal, external = pair.split("=", 1)
                internal = internal.strip()
                external = external.strip()
                if internal and external:
                    mappings.append({"internal": internal, "external": external})

    # ARKANA_HOST_SAMPLES maps to the configured samples path
    samples_host = _env_with_fallback("ARKANA_HOST_SAMPLES", "PEMCP_HOST_SAMPLES")
    samples_internal = state.samples_path
    if samples_host and samples_internal:
        if not any(m["internal"] == samples_internal for m in mappings):
            mappings.append({"internal": samples_internal, "external": samples_host})

    # ARKANA_HOST_EXPORT maps to the export directory
    export_host = _env_with_fallback("ARKANA_HOST_EXPORT", "PEMCP_HOST_EXPORT")
    export_dir = _resolve_export_dir()
    if export_host and export_dir:
        if not any(m["internal"] == export_dir for m in mappings):
            mappings.append({"internal": export_dir, "external": export_host})

    # Sort longest internal path first for correct prefix matching
    mappings.sort(key=lambda m: len(m["internal"]), reverse=True)
    return mappings


_mount_mappings_cache: Optional[List[Dict[str, str]]] = None  # L1-v9: cache mount mappings
_mount_cache_lock = threading.Lock()


def _get_mount_mappings() -> List[Dict[str, str]]:
    """Return cached mount mappings, building on first call."""
    global _mount_mappings_cache
    with _mount_cache_lock:
        if _mount_mappings_cache is None:
            _mount_mappings_cache = _build_mount_mappings()
        return _mount_mappings_cache


def translate_to_host_path(container_path: str) -> Optional[str]:
    """Translate a container-internal path to the corresponding host path.

    Uses mount mappings from environment variables to convert a path like
    ``/samples/malware.exe`` to ``/home/user/malware-zoo/malware.exe``.

    Returns ``None`` if no mapping covers the given path (e.g. when running
    outside a container, or for paths that are not under a known mount).
    """
    if not container_path:
        return None

    mappings = _get_mount_mappings()
    if not mappings:
        return None

    for m in mappings:
        internal = m["internal"].rstrip("/")
        external = m["external"].rstrip("/")
        # Exact match or prefix match with path separator
        if container_path == internal or container_path.startswith(internal + "/"):
            suffix = container_path[len(internal):]
            return external + suffix

    return None


def build_path_info(container_path: str) -> Dict[str, Any]:
    """Build a path info dict with internal/external paths for MCP client consumption.

    Returns a dict like::

        {
            "internal_path": "/samples/malware.exe",
            "external_path": "/home/user/zoo/malware.exe",  # or None
            "path_note": "..."  # human-readable explanation
        }
    """
    host_path = translate_to_host_path(container_path)
    info: Dict[str, Any] = {
        "internal_path": container_path,
        "external_path": host_path,
    }
    if host_path:
        info["path_note"] = (
            f"Container path '{container_path}' corresponds to "
            f"host path '{host_path}' outside the container."
        )
    else:
        container_info = _detect_container()
        if container_info["containerized"]:
            info["path_note"] = (
                f"Running inside a container but no host mapping found for '{container_path}'. "
                "Set ARKANA_PATH_MAP or ARKANA_HOST_SAMPLES/ARKANA_HOST_EXPORT to enable path translation."
            )
        else:
            info["path_note"] = "Not running inside a container; internal and host paths are the same."
            info["external_path"] = container_path
    return info


def _detect_container() -> Dict[str, Any]:
    """Detect if running inside a container and return runtime info."""
    containerized = False
    container_type = None

    # Docker detection
    if os.path.exists("/.dockerenv"):
        containerized = True
        container_type = "docker"
    # Podman detection
    elif os.path.exists("/run/.containerenv"):
        containerized = True
        container_type = "podman"
    else:
        # Fallback: check cgroup for docker/containerd
        try:
            with open("/proc/1/cgroup", "r") as f:
                cgroup = f.read(8192)
                if "docker" in cgroup or "containerd" in cgroup:
                    containerized = True
                    container_type = "docker"
                elif "libpod" in cgroup:
                    containerized = True
                    container_type = "podman"
        except (OSError, IOError):
            pass

    return {"containerized": containerized, "container_type": container_type}


def _get_environment_info() -> Dict[str, Any]:
    """Build environment/path information for AI clients."""
    container_info = _detect_container()

    # Known paths to check for writability
    candidate_paths = [
        "/tmp",
        "/app/home/.arkana",
        "/output",
        os.path.expanduser("~/.arkana"),
    ]
    if state.samples_path:
        candidate_paths.append(state.samples_path)

    writable_paths: List[str] = []
    for p in candidate_paths:
        if os.path.isdir(p) and os.access(p, os.W_OK):
            if p not in writable_paths:
                writable_paths.append(p)

    # Build mount mappings once — used for both path translation and host lookups
    mount_mappings = _get_mount_mappings()

    # Samples dir info — derive host path from mount mappings
    samples_internal = state.samples_path
    samples_host = next(
        (m["external"] for m in mount_mappings if m["internal"] == samples_internal),
        None,
    )
    samples_writable = (
        samples_internal is not None
        and os.path.isdir(samples_internal)
        and os.access(samples_internal, os.W_OK)
    )

    # Export dir info — use shared helper, derive host path from mount mappings
    export_dir = _resolve_export_dir()
    export_host = next(
        (m["external"] for m in mount_mappings if m["internal"] == export_dir),
        None,
    ) if export_dir else None
    export_writable = export_dir is not None and os.path.isdir(export_dir) and os.access(export_dir, os.W_OK)

    # Cache dir
    cache_dir = os.path.expanduser("~/.arkana/cache")
    cache_writable = os.path.isdir(cache_dir) and os.access(cache_dir, os.W_OK)

    # Recommended export path
    if export_writable:
        recommended = export_dir
    elif "/tmp" in writable_paths:
        recommended = "/tmp"
    else:
        recommended = writable_paths[0] if writable_paths else "/tmp"

    paths: Dict[str, Any] = {
        "samples_dir": {
            "internal": samples_internal,
            "host": samples_host,
            "writable": samples_writable,
        },
        "cache_dir": {
            "internal": cache_dir,
            "writable": cache_writable,
        },
        "export_dir": {
            "internal": export_dir,
            "host": export_host,
            "writable": export_writable,
        },
    }

    # Build warnings for common configuration issues
    warnings: List[str] = []
    if export_dir and not export_writable:
        warnings.append(
            f"Export directory '{export_dir}' exists but is not writable. "
            "Files cannot be saved there. Set ARKANA_EXPORT_DIR to a writable path."
        )
    if not export_dir:
        warnings.append(
            "No export directory found. Set ARKANA_EXPORT_DIR or mount /output "
            "to enable file exports."
        )
    if container_info["containerized"] and not mount_mappings:
        warnings.append(
            "Running inside a container but no path mappings configured. "
            "File paths in tool outputs will be container-internal paths. "
            "Set ARKANA_PATH_MAP, ARKANA_HOST_SAMPLES, or ARKANA_HOST_EXPORT "
            "to enable host path translation."
        )

    result: Dict[str, Any] = {
        "containerized": container_info["containerized"],
        "container_type": container_info["container_type"],
        "paths": paths,
        "mount_mappings": mount_mappings,
        "writable_paths": writable_paths,
        "recommended_export_path": recommended,
    }
    if warnings:
        result["warnings"] = warnings
    return result


@tool_decorator
async def get_current_datetime(ctx: Context) -> Dict[str,str]:
    """
    [Phase: utility] Retrieves the current date and time in UTC and the server's
    local timezone. Does not require a file to be loaded.

    ---compact: current UTC and local datetime for PE timestamp comparison

    When to use: When analyzing PE timestamps to check if compilation dates are
    in the future or suspiciously old.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing:
        - "utc_datetime": (str) Current UTC date and time in ISO 8601 format.
        - "local_datetime": (str) Current local date and time in ISO 8601 format (includes timezone offset).
        - "local_timezone_name": (str) Name of the server's local timezone.
    """
    await ctx.info("Request for current datetime.")
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_local = datetime.datetime.now().astimezone()
    return {
        "utc_datetime": now_utc.isoformat(),
        "local_datetime": now_local.isoformat(),
        "local_timezone_name": str(now_local.tzinfo),
    }

@tool_decorator
async def check_task_status(ctx: Context, task_id: str) -> Dict[str, Any]:
    """
    [Phase: utility] Checks the status and progress of a background analysis task.

    ---compact: poll background task status, progress, stall detection

    When to use: After launching a background task (e.g. get_reaching_definitions,
    diff_binaries) to check if it has completed. Also shows overtime status with
    progress trend and recommendation.

    Args:
        task_id: The ID returned by a tool running in background mode.
    """
    task = state.get_task(task_id)
    if not task:
        return {"error": f"Task ID '{task_id}' not found.", "available_task_ids": state.get_all_task_ids()}

    response = {
        "task_id": task_id,
        "status": task["status"],
        "progress_percent": task.get("progress_percent", 0),
        "progress_message": task.get("progress_message", "Initializing..."),
        "created_at": task.get("created_at", "unknown"),
        "tool": task.get("tool", "unknown")
    }

    # --- Elapsed time (always shown) ---
    created_epoch = task.get("created_at_epoch")
    if created_epoch is None:
        try:
            created_epoch = datetime.datetime.fromisoformat(task["created_at"]).timestamp()
        except Exception:
            created_epoch = None
    if created_epoch:
        elapsed = time.time() - created_epoch
        response["elapsed_seconds"] = round(elapsed)
        response["elapsed_human"] = str(datetime.timedelta(seconds=int(elapsed)))

    # Angr CFG stall detection — report function discovery progress
    if task_id.startswith("startup-angr"):
        func_count = task.get("cfg_functions_discovered", 0)
        snapshots = task.get("cfg_func_snapshots", [])
        if func_count > 0:
            response["functions_discovered_so_far"] = func_count

        if task["status"] in ("running", "overtime") and len(snapshots) >= 2:
            latest_time, latest_count = snapshots[-1][0], snapshots[-1][1]
            stall_start = latest_time
            for snap in reversed(snapshots):
                if snap[1] != latest_count:
                    break
                stall_start = snap[0]
            seconds_stalled = latest_time - stall_start
            is_stalled = seconds_stalled >= 30

            response["stall_detection"] = {
                "is_stalled": is_stalled,
                "seconds_since_last_change": round(seconds_stalled),
                "functions_discovered": latest_count,
            }

            # Compute discovery rate from last 5 snapshots
            if len(snapshots) >= 2:
                recent = snapshots[-min(5, len(snapshots)):]
                time_span = recent[-1][0] - recent[0][0]
                func_delta = recent[-1][1] - recent[0][1]
                if time_span > 0:
                    response["discovery_rate_per_min"] = round(func_delta / (time_span / 60), 1)

            if is_stalled:
                response["stall_detection"]["verdict"] = (
                    f"CFG analysis appears STALLED — no new functions discovered "
                    f"in {round(seconds_stalled)}s. Binary is likely packed/obfuscated. "
                    "Recommended: unpack first (auto_unpack_pe → try_all_unpackers → "
                    "qiling_dump_unpacked_binary), or use get_angr_partial_functions() "
                    "to see what was discovered, or decompile_function_with_angr() "
                    "on a discovered function (it will build a local CFG)."
                )
                response["hint"] = response["stall_detection"]["verdict"]
            else:
                response["stall_detection"]["verdict"] = (
                    f"CFG analysis is progressing ({latest_count} functions found). "
                    "Wait and retry shortly."
                )

    # --- Generic stall detection (for running/overtime tasks) ---
    if task["status"] in ("running", "overtime") and "stall_detection" not in response:
        last_progress = task.get("last_progress_epoch")
        if last_progress is not None:
            since_update = time.time() - last_progress
            is_stalled = since_update >= 60
            response["stall_detection"] = {
                "is_stalled": is_stalled,
                "seconds_since_last_progress": round(since_update),
                "last_progress_percent": task.get("progress_percent", 0),
            }
            if is_stalled:
                tool = task.get("tool", "unknown")
                response["stall_detection"]["verdict"] = (
                    f"Task '{tool}' appears STALLED - no progress in {round(since_update)}s "
                    f"(last at {task.get('progress_percent', 0)}%). "
                    "Use abort_background_task('" + task_id + "') to stop, or wait for auto stall-kill."
                )
                response["hint"] = response["stall_detection"]["verdict"]

    # --- Overtime-specific fields ---
    if task["status"] == "overtime":
        overtime_since = task.get("overtime_since_epoch", 0)
        if overtime_since:
            response["overtime_seconds"] = round(time.time() - overtime_since)

        # Determine progress trend
        last_progress = task.get("last_progress_epoch", 0)
        from arkana.constants import OVERTIME_STALL_KILL
        stall_threshold = OVERTIME_STALL_KILL
        since_progress = time.time() - last_progress if last_progress else 9999
        is_progressing = since_progress < stall_threshold
        response["progress_trend"] = "progressing" if is_progressing else "stalled"
        response["stall_seconds"] = round(since_progress) if not is_progressing else 0

        if is_progressing:
            response["recommendation"] = (
                "Task is in overtime but still making progress. Worth waiting. "
                "Use abort_background_task('" + task_id + "') to stop if needed."
            )
        else:
            response["recommendation"] = (
                f"Task is in overtime and stalled ({round(since_progress)}s no progress). "
                "Will be auto-killed soon. Use abort_background_task('" + task_id + "') to stop now."
            )
        response["hint"] = response["recommendation"]

    if task["status"] == "completed":
        result_data = task.get("result")
        full_response = {**response, "result": result_data}
        return await _check_mcp_response_size(ctx, full_response, f"check_task_status_{task_id}")

    elif task["status"] == "failed":
        response["error"] = task.get("error", "Unknown error")
        # Timeout + partial results
        if task.get("timed_out"):
            response["timed_out"] = True
            partial = task.get("partial_result")
            if partial:
                response["partial_result"] = partial
                response["hint"] = ("Task timed out but partial results are available. "
                                    "Review the partial_result field.")
        if task.get("aborted"):
            response["aborted"] = True

    elif task["status"] == "running":
        if "hint" not in response:
            response["hint"] = "Task is still processing. Poll again shortly with check_task_status."

    return response


@tool_decorator
async def abort_background_task(ctx: Context, task_id: str) -> Dict[str, Any]:
    """
    [Phase: utility] Aborts a running or overtime background task.

    ---compact: abort running/overtime background task by ID

    The task thread cannot be force-killed (Python limitation), but its result
    will be silently discarded when it eventually completes. The task is immediately
    marked as failed/aborted.

    When to use: When a background task (e.g. CFG build, symbolic execution) is
    taking too long or is stuck and you want to proceed with other analysis.

    Args:
        task_id: The ID of the background task to abort.
    """
    task = state.get_task(task_id)
    if not task:
        return {"error": f"Task ID '{task_id}' not found.", "available_task_ids": state.get_all_task_ids()}

    if task["status"] not in (TASK_RUNNING, TASK_OVERTIME):
        return {
            "error": f"Task '{task_id}' is not running (status: {task['status']}). Cannot abort.",
            "task_id": task_id,
            "status": task["status"],
        }

    # Set cancel event so the worker thread can exit gracefully
    from arkana.state import get_current_state
    current_state = get_current_state()
    cancel = current_state.get_cancel_event(task_id)
    if cancel is not None:
        cancel.set()

    # Collect partial info before marking failed
    func_count = task.get("cfg_functions_discovered", 0)
    partial = task.get("partial_result")

    state.update_task(task_id, status=TASK_FAILED,
                      error="Aborted by user.",
                      aborted=True,
                      progress_message="Aborted by user")

    await ctx.info(f"Task '{task_id}' has been aborted.")

    response = {
        "task_id": task_id,
        "status": "aborted",
        "message": "Task marked as aborted. The worker thread will be discarded when it completes.",
    }
    if func_count > 0:
        response["functions_discovered"] = func_count
    if partial:
        response["partial_result"] = partial
    return response


@tool_decorator
async def release_angr_memory(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: utility] Release angr project and CFG from memory without closing
    the loaded file.

    ---compact: free angr memory (200MB-10GB) | preserves notes/renames/PE data | needs: file

    PE data, notes, renames, tool history, and all session
    state are preserved. Use this when angr analysis is complete and you need
    to free memory (typically 200MB-10GB).

    After release, any angr-dependent tool will automatically rebuild the
    project and CFG from disk when called.

    When to use: After angr CFG build consumed excessive memory (check via
    get_resource_usage), or when switching to non-angr analysis tools.

    This tool does not work while background angr tasks are running —
    abort them first with abort_background_task().
    """
    import gc
    from arkana.state import get_current_state
    current_state = get_current_state()

    # Block if angr tasks are active
    _angr_task_ids = {"startup-angr", "angr-cfg", "angr-analysis"}
    active = []
    for tid in _angr_task_ids:
        task = current_state.get_task(tid)
        if task and task.get("status") in (TASK_RUNNING, TASK_OVERTIME):
            active.append(tid)
    if active:
        return {
            "error": "Cannot release angr memory while background tasks are active.",
            "active_tasks": active,
            "hint": "Call abort_background_task() on each active task first.",
        }

    # Capture RSS before
    rss_before = None
    try:
        from arkana.resource_monitor import get_resource_snapshot
        snap = get_resource_snapshot()
        if snap:
            rss_before = snap.get("rss_mb")
    except Exception:
        pass

    had_angr = current_state.angr_project is not None

    # Release angr
    current_state.reset_angr()

    # Clear decompile caches
    from arkana.mcp.tools_angr import clear_decompile_meta
    clear_decompile_meta(session_uuid=current_state._state_uuid)

    # Clear result cache
    if hasattr(current_state, 'result_cache') and current_state.result_cache is not None:
        current_state.result_cache.clear()

    # Force garbage collection
    gc.collect()

    # Linux: return freed heap to OS via malloc_trim
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_trim(0)
    except Exception:
        pass  # Not Linux/glibc, or not available

    # Capture RSS after
    rss_after = None
    try:
        from arkana.resource_monitor import get_resource_snapshot as _snap
        snap = _snap()
        if snap:
            rss_after = snap.get("rss_mb")
    except Exception:
        pass

    response = {
        "status": "released" if had_angr else "no_angr_loaded",
        "preserved": ["filepath", "pe_data", "notes", "renames", "custom_types",
                       "tool_history", "artifacts", "triage_status"],
        "cleared": ["angr_project", "angr_cfg", "decompile_cache", "result_cache",
                     "loop_cache", "angr_hooks"],
    }
    if rss_before is not None and rss_after is not None:
        response["rss_before_mb"] = round(rss_before, 1)
        response["rss_after_mb"] = round(rss_after, 1)
        response["rss_freed_mb"] = round(rss_before - rss_after, 1)
    if had_angr:
        response["hint"] = "angr tools will rebuild project and CFG from disk when next called."
    return response


@tool_decorator
async def get_resource_usage(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: utility] Returns current process resource usage: RSS memory,
    CPU percentage, thread count, and recent trend data.

    ---compact: process RSS, CPU, thread count, trend data

    When to use: When you notice resource pressure alerts in tool responses,
    or to check server health before launching expensive operations like
    symbolic execution or CFG recovery.

    This tool does not require a file to be loaded.
    """
    from arkana.resource_monitor import (
        get_resource_snapshot, get_resource_history,
        _MEMORY_HIGH, _MEMORY_CRITICAL, _CPU_HIGH,
        _detected_available_mb, _detected_source,
        _env_override_high, _env_override_critical,
        PSUTIL_AVAILABLE,
    )
    if not PSUTIL_AVAILABLE:
        return {
            "error": "psutil is not installed. Install with: pip install psutil",
            "hint": "Resource monitoring requires the psutil library.",
        }

    snapshot = get_resource_snapshot()
    if not snapshot:
        # Brief wait for first snapshot on fresh startup
        import time as _time
        for _ in range(6):
            _time.sleep(0.5)
            snapshot = get_resource_snapshot()
            if snapshot:
                break
        if not snapshot:
            return {"error": "Resource monitor has not collected data yet after 3s. Try again shortly."}

    history = get_resource_history()
    trend: Dict[str, Any] = {}
    if len(history) >= 2:
        oldest = history[0]
        trend["rss_change_mb"] = round(snapshot["rss_mb"] - oldest["rss_mb"], 1)
        trend["period_seconds"] = round(snapshot["timestamp"] - oldest["timestamp"])
        trend["samples"] = len(history)

    return {
        "current": snapshot,
        "trend": trend,
        "thresholds": {
            "memory_high_mb": _MEMORY_HIGH,
            "memory_critical_mb": _MEMORY_CRITICAL,
            "cpu_high_percent": _CPU_HIGH,
        },
        "system": {
            "available_memory_mb": _detected_available_mb,
            "detection_source": _detected_source,
            "thresholds_auto_detected": not (_env_override_high or _env_override_critical),
        },
    }


@tool_decorator
async def set_api_key(ctx: Context, key_name: str, key_value: str) -> Dict[str, str]:
    """
    [Phase: utility] Stores an API key in the user's persistent configuration
    (~/.arkana/config.json). Saved securely (owner-only permissions) and
    recalled automatically in future sessions.

    ---compact: store API key persistently | e.g. vt_api_key for VirusTotal

    When to use: When setting up VirusTotal integration or other API-dependent tools.

    Supported key names:
    - 'vt_api_key': VirusTotal API key (used by get_virustotal_report_for_loaded_file)

    Note: Environment variables (e.g. VT_API_KEY) always take priority over stored keys.

    Args:
        ctx: The MCP Context object.
        key_name: (str) The configuration key name (e.g. 'vt_api_key').
        key_value: (str) The API key value to store.

    Returns:
        A dictionary confirming the key was saved.
    """
    allowed_keys = {"vt_api_key"}
    if key_name not in allowed_keys:
        raise ValueError(
            f"[set_api_key] Unknown key '{key_name}'. "
            f"Supported keys: {', '.join(sorted(allowed_keys))}"
        )

    if not key_value or not key_value.strip():
        raise ValueError("[set_api_key] key_value must not be empty.")

    # Warn about cleartext transmission in HTTP mode without TLS
    if not state.api_key:
        await ctx.warning(
            "API key is being transmitted over an unencrypted MCP connection. "
            "Use a TLS-terminating reverse proxy in production deployments."
        )

    set_config_value(key_name, key_value.strip())
    await ctx.info(f"API key '{key_name}' saved to persistent configuration.")

    return {
        "status": "success",
        "message": f"Key '{key_name}' saved successfully. It will be used automatically in future sessions.",
        "note": "Environment variables always take priority over stored keys. "
                "Use environment variables instead of this tool for sensitive keys in production.",
    }


@tool_decorator
async def get_config(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: utility] Retrieves Arkana configuration: stored API keys (masked),
    environment overrides, container detection, writable paths, host mount
    mappings, and recommended export path.

    ---compact: server config, paths, library availability, container detection

    When to use: At session start to understand the server environment, available
    capabilities, and where files can be safely written.

    This tool does not depend on a file being loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing the current configuration with sensitive values masked,
        server capabilities, and environment/path information.
    """
    await ctx.info("Retrieving current configuration.")
    config = get_masked_config()

    # Add server capability info
    config["_server_info"] = {
        "angr_available": ANGR_AVAILABLE,
        "capa_available": CAPA_AVAILABLE,
        "floss_available": FLOSS_AVAILABLE,
        "yara_available": YARA_AVAILABLE,
        "stringsifter_available": STRINGSIFTER_AVAILABLE,
        "requests_available": REQUESTS_AVAILABLE,
        "file_loaded": state.filepath is not None,
        "loaded_filepath": state.filepath,
        "samples_path": state.samples_path,
        "state_id": getattr(state, '_state_uuid', 'unknown'),
        "pid": os.getpid(),
    }

    # Add environment/path information
    config["_environment"] = _get_environment_info()

    # Add dashboard info if available
    # Token is stored on _default_state (set at dashboard startup), but the
    # StateProxy may resolve to a per-session state, so check both.
    dashboard_token = getattr(state, "dashboard_token", None)
    if not dashboard_token:
        from arkana.state import _default_state
        dashboard_token = getattr(_default_state, "dashboard_token", None)
    if dashboard_token:
        dashboard_port = os.environ.get("ARKANA_DASHBOARD_PORT", "8082")
        masked_token = dashboard_token[:4] + "..." if len(dashboard_token) > 4 else "***"
        config["_dashboard"] = {
            "dashboard_url": f"http://127.0.0.1:{dashboard_port}/dashboard/",
            "dashboard_token": masked_token,
            "dashboard_login_url": f"http://127.0.0.1:{dashboard_port}/dashboard/?token={dashboard_token}",
        }

    return config
