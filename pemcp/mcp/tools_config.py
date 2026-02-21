"""MCP tools for configuration, task status, and utility functions."""
import datetime
import os
from typing import Dict, Any, List
from pemcp.config import (
    state, Context,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    YARA_AVAILABLE, STRINGSIFTER_AVAILABLE, REQUESTS_AVAILABLE,
)
from pemcp.user_config import get_config_value, set_config_value, get_masked_config
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size


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
        "/app/home/.pemcp",
        "/output",
        os.path.expanduser("~/.pemcp"),
    ]
    if state.samples_path:
        candidate_paths.append(state.samples_path)

    writable_paths: List[str] = []
    for p in candidate_paths:
        if os.path.isdir(p) and os.access(p, os.W_OK):
            if p not in writable_paths:
                writable_paths.append(p)

    # Samples dir info
    samples_internal = state.samples_path
    samples_host = os.environ.get("PEMCP_HOST_SAMPLES")
    samples_writable = (
        samples_internal is not None
        and os.path.isdir(samples_internal)
        and os.access(samples_internal, os.W_OK)
    )

    # Export dir info
    export_dir = os.environ.get("PEMCP_EXPORT_DIR", "/output")
    if not os.path.isdir(export_dir):
        # Fallback chain: /output -> /tmp
        export_dir = "/output" if os.path.isdir("/output") else "/tmp"
    export_host = os.environ.get("PEMCP_HOST_EXPORT")
    export_writable = os.path.isdir(export_dir) and os.access(export_dir, os.W_OK)

    # Cache dir
    cache_dir = os.path.expanduser("~/.pemcp/cache")
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

    return {
        "containerized": container_info["containerized"],
        "container_type": container_info["container_type"],
        "paths": paths,
        "writable_paths": writable_paths,
        "recommended_export_path": recommended,
    }


@tool_decorator
async def get_current_datetime(ctx: Context) -> Dict[str,str]:
    """
    Retrieves the current date and time in UTC and the server's local timezone.
    This tool does not depend on a PE file being loaded.

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
    Checks the status and progress of a background analysis task.

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

    if task["status"] == "completed":
        result_data = task.get("result")
        full_response = {**response, "result": result_data}
        return await _check_mcp_response_size(ctx, full_response, f"check_task_status_{task_id}")

    elif task["status"] == "failed":
        response["error"] = task.get("error", "Unknown error")

    elif task["status"] == "running":
        response["hint"] = "Task is still processing. Poll again shortly with check_task_status."

    return response


@tool_decorator
async def set_api_key(ctx: Context, key_name: str, key_value: str) -> Dict[str, str]:
    """
    Stores an API key in the user's persistent configuration (~/.pemcp/config.json).
    The key is saved securely (file permissions restricted to owner only) and will
    be recalled automatically in future sessions.

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
    Retrieves the current PeMCP configuration, including stored API keys (masked),
    which keys are overridden by environment variables, and runtime environment info.

    Includes container detection, writable paths, host mount mappings, and a
    recommended export path — essential for AI clients to know where they can
    write files without trial-and-error.

    This tool does not depend on a PE file being loaded.

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
    }

    # Add environment/path information
    config["_environment"] = _get_environment_info()

    return config
