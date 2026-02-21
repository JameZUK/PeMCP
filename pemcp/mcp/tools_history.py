"""MCP tools for viewing and managing the tool invocation history."""
from typing import Dict, Any, Optional
from pemcp.config import state, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size


@tool_decorator
async def get_tool_history(
    ctx: Context,
    tool_name: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Retrieve the history of tools run during this session.
    Each entry includes the tool name, timestamp, parameters used,
    a brief result summary, and duration in milliseconds.

    Use this to review what analysis steps have already been performed,
    avoid redundant work, and understand the investigation timeline.
    Previous session history (from prior runs on the same file) is also
    available when a file is loaded from cache.

    For a higher-level view of what was *learned* (not just what ran),
    use get_analysis_digest() instead.

    Args:
        ctx: The MCP Context object.
        tool_name: (Optional[str]) Filter history to a specific tool name.
        limit: (int) Maximum number of history entries to return. Default: 50.

    Returns:
        A dictionary with history entries, counts, and previous session count
        if available.
    """
    entries = state.get_tool_history(tool_name=tool_name)
    total = len(entries)
    entries = entries[-limit:]  # most recent entries

    result: Dict[str, Any] = {
        "status": "success",
        "history": entries,
        "count": len(entries),
        "total": total,
    }

    # Include previous session history count if available
    prev = getattr(state, "previous_session_history", [])
    if prev:
        result["previous_session_count"] = len(prev)

    return await _check_mcp_response_size(ctx, result, "get_tool_history")


@tool_decorator
async def clear_tool_history(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Clear all tool history entries for the current session.
    This does not affect the cached history from previous sessions.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary with the count of entries cleared.
    """
    count = state.clear_tool_history()
    await ctx.info(f"Tool history cleared: {count} entries removed.")
    return {"status": "success", "entries_cleared": count}
