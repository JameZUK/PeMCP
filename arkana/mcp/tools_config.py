"""MCP tools for configuration, task status, and utility functions."""
import datetime
import os
import time
from typing import Dict, Any, List, Optional
from arkana.config import (
    state, Context,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    YARA_AVAILABLE, STRINGSIFTER_AVAILABLE, REQUESTS_AVAILABLE,
)
from arkana.user_config import get_config_value, set_config_value, get_masked_config
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


def translate_to_host_path(container_path: str) -> Optional[str]:
    """Translate a container-internal path to the corresponding host path.

    Uses mount mappings from environment variables to convert a path like
    ``/samples/malware.exe`` to ``/home/user/malware-zoo/malware.exe``.

    Returns ``None`` if no mapping covers the given path (e.g. when running
    outside a container, or for paths that are not under a known mount).
    """
    if not container_path:
        return None

    mappings = _build_mount_mappings()
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
                cgroup = f.read()
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
    mount_mappings = _build_mount_mappings()

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

    When to use: After launching a background task (e.g. get_reaching_definitions,
    diff_binaries) to check if it has completed.

    Args:
        task_id: The ID returned by a tool running in background mode.
    """
    # await ctx.info(f"Checking status for task: {task_id}") # Optional: Comment out to reduce noise

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

        if task["status"] == "running" and len(snapshots) >= 2:
            latest_time, latest_count = snapshots[-1]
            stall_start = latest_time
            for ts, count in reversed(snapshots):
                if count != latest_count:
                    break
                stall_start = ts
            seconds_stalled = latest_time - stall_start
            is_stalled = seconds_stalled >= 30

            response["stall_detection"] = {
                "is_stalled": is_stalled,
                "seconds_since_last_change": round(seconds_stalled),
                "functions_discovered": latest_count,
            }
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

    # --- Generic stall detection (for non-CFG running tasks) ---
    if task["status"] == "running" and "stall_detection" not in response:
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
                    "The task will time out automatically. You can wait or start a new analysis."
                )
                response["hint"] = response["stall_detection"]["verdict"]

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

    elif task["status"] == "running":
        if "hint" not in response:
            response["hint"] = "Task is still processing. Poll again shortly with check_task_status."

    return response


@tool_decorator
async def set_api_key(ctx: Context, key_name: str, key_value: str) -> Dict[str, str]:
    """
    [Phase: utility] Stores an API key in the user's persistent configuration
    (~/.arkana/config.json). Saved securely (owner-only permissions) and
    recalled automatically in future sessions.

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
        "state_id": id(state),
        "pid": os.getpid(),
    }

    # Add environment/path information
    config["_environment"] = _get_environment_info()

    # Add dashboard info if available
    dashboard_token = getattr(state, "dashboard_token", None)
    if dashboard_token:
        dashboard_port = os.environ.get("ARKANA_DASHBOARD_PORT", "8082")
        config["_dashboard"] = {
            "dashboard_url": f"http://127.0.0.1:{dashboard_port}/dashboard/",
            "dashboard_token": dashboard_token,
            "dashboard_login_url": f"http://127.0.0.1:{dashboard_port}/dashboard/?token={dashboard_token}",
        }

    return config
