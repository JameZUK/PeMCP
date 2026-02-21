"""MCP tool for session summary — helps the AI get up to speed on prior work."""
from collections import Counter
from typing import Dict, Any
from pemcp.config import state, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.state import TASK_RUNNING


@tool_decorator
async def get_session_summary(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Returns a comprehensive summary of the current session and any prior
    session data for the loaded file. Includes file info, notes, tool history
    (both current and previous session), angr status, and suggested next tools.

    Designed to help an AI analyst quickly get up to speed on what has
    already been done with this binary.

    This tool does not require a file to be loaded (returns minimal info
    if no file is loaded).

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary with session summary sections.
    """
    result: Dict[str, Any] = {"status": "success"}

    # File info
    if state.filepath and state.pe_data:
        hashes = (state.pe_data.get("file_hashes") or {})
        result["file_info"] = {
            "filepath": state.filepath,
            "sha256": hashes.get("sha256"),
            "md5": hashes.get("md5"),
            "mode": state.pe_data.get("mode", "unknown"),
            "loaded_from_cache": getattr(state, "loaded_from_cache", False),
        }
    else:
        result["file_info"] = {"status": "no_file_loaded"}
        return result

    # Notes
    notes = state.get_notes()
    result["notes"] = {
        "count": len(notes),
        "notes": notes[:50],
        "by_category": dict(Counter(n.get("category", "general") for n in notes)),
    }

    # Current session tool history
    current_history = state.get_tool_history()
    tool_counts = Counter(h["tool_name"] for h in current_history)
    result["current_session"] = {
        "tools_run_count": len(current_history),
        "tools_run": current_history[-30:],
        "tool_counts": dict(tool_counts),
    }

    # Previous session history
    prev = getattr(state, "previous_session_history", []) or []
    if prev:
        prev_counts = Counter(h["tool_name"] for h in prev)
        result["previous_session"] = {
            "tools_run_count": len(prev),
            "tools_run": prev[-30:],
            "tool_counts": dict(prev_counts),
            "last_activity": prev[-1].get("timestamp") if prev else None,
        }

    # Angr status
    if ANGR_AVAILABLE:
        angr_task = state.get_task("startup-angr")
        if angr_task:
            result["angr_status"] = {
                "status": angr_task.get("status"),
                "progress_percent": angr_task.get("progress_percent", 0),
                "progress_message": angr_task.get("progress_message", ""),
            }
        else:
            proj, cfg = state.get_angr_snapshot()
            result["angr_status"] = {
                "status": "ready" if proj else "not_initialized",
                "cfg_available": cfg is not None,
            }

    # Suggested next tools
    suggested = []
    ran_tools = set(h["tool_name"] for h in current_history)
    ran_tools |= set(h["tool_name"] for h in prev)

    if "get_triage_report" not in ran_tools:
        suggested.append("get_triage_report")
    if ANGR_AVAILABLE and "decompile_function_with_angr" not in ran_tools:
        suggested.append("decompile_function_with_angr")
    if "get_pe_summary" not in ran_tools:
        suggested.append("get_pe_summary")

    if suggested:
        result["suggested_next_tools"] = suggested

    return await _check_mcp_response_size(ctx, result, "get_session_summary")
