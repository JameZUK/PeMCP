"""MCP tools for configuration, task status, and utility functions."""
import datetime
from typing import Dict, Any
from pemcp.config import (
    state, Context,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    YARA_AVAILABLE, STRINGSIFTER_AVAILABLE, REQUESTS_AVAILABLE,
)
from pemcp.user_config import get_config_value, set_config_value, get_masked_config
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size


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

    set_config_value(key_name, key_value.strip())
    await ctx.info(f"API key '{key_name}' saved to persistent configuration.")

    return {
        "status": "success",
        "message": f"Key '{key_name}' saved successfully. It will be used automatically in future sessions.",
        "note": "Environment variables always take priority over stored keys.",
    }


@tool_decorator
async def get_config(ctx: Context) -> Dict[str, Any]:
    """
    Retrieves the current PeMCP configuration, including stored API keys (masked)
    and which keys are overridden by environment variables.

    This tool does not depend on a PE file being loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing the current configuration with sensitive values masked.
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

    return config
