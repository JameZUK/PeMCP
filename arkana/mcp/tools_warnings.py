"""MCP tools for retrieving library warnings captured during analysis."""
from collections import Counter
from typing import Dict, Any, Optional

from arkana.config import state, Context
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.constants import MAX_TOOL_LIMIT
from arkana.mcp._input_helpers import _paginate_field


@tool_decorator
async def get_analysis_warnings(
    ctx: Context,
    logger_name: Optional[str] = None,
    level: Optional[str] = None,
    tool_name: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    [Phase: diagnostic] Returns library warnings captured during analysis.

    Libraries like angr, cle, pyvex, capa, FLOSS etc. emit warnings that explain
    analysis limitations — failed decompilations, unsupported instructions, corrupt
    structures. These are normally only visible in Docker logs. This tool surfaces
    them to help understand why certain analyses may have failed or returned
    incomplete results.

    Warnings are deduplicated: repeated identical messages increment a count rather
    than creating new entries. Each warning includes the originating logger, level,
    message, which MCP tool or background task triggered it, and occurrence count.

    When to use: Call after a tool returns unexpected/incomplete results, or after
    opening a complex binary, to understand what went wrong internally.

    Args:
        ctx: The MCP Context object.
        logger_name: Filter by logger name (e.g. "angr.analyses.loopfinder").
        level: Filter by level (e.g. "WARNING", "ERROR", "CRITICAL").
        tool_name: Filter by the MCP tool that was active when the warning fired.
        offset: Start index for pagination (default 0).
        limit: Max warnings to return (default 50).

    Returns:
        Dictionary with warnings list (most recent first), pagination info,
        and summary counts by logger and level.
    """
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    offset = max(0, offset)

    warnings = state.get_warnings(
        logger_name=logger_name,
        level=level,
        tool_name=tool_name,
    )

    # Most recent first
    warnings.reverse()

    # Summary counts (computed before pagination)
    by_logger: Dict[str, int] = dict(Counter(w["logger"] for w in warnings))
    by_level: Dict[str, int] = dict(Counter(w["level"] for w in warnings))
    total_with_repeats = sum(w.get("count", 1) for w in warnings)

    page, pag = _paginate_field(warnings, offset, limit)

    result: Dict[str, Any] = {
        "status": "success",
        "warnings": page,
        "warnings_pagination": pag,
        "total_unique": len(warnings),
        "total_with_repeats": total_with_repeats,
        "by_logger": by_logger,
        "by_level": by_level,
    }

    return await _check_mcp_response_size(ctx, result, "get_analysis_warnings")


@tool_decorator
async def clear_analysis_warnings(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: diagnostic] Clears all captured library warnings.

    Use this to reset the warning buffer after reviewing warnings, or when
    starting a new phase of analysis on the same binary.

    Returns:
        Dictionary with status and count of warnings cleared.
    """
    count = state.clear_warnings()
    return {"status": "success", "warnings_cleared": count}
