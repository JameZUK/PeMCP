"""MCP tools for analysis cache management."""
from typing import Dict, Any
from pemcp.config import state, Context, analysis_cache
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size


@tool_decorator
async def get_cache_stats(ctx: Context) -> Dict[str, Any]:
    """
    Returns statistics about the disk-based analysis cache (~/.pemcp/cache/).
    Shows entry count, total size, utilization, and a list of cached files.

    This tool does not require a file to be loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary with cache statistics including entry count, size,
        and per-entry details.
    """
    await ctx.info("Retrieving cache statistics...")
    return analysis_cache.get_stats()


@tool_decorator
async def clear_analysis_cache(ctx: Context) -> Dict[str, Any]:
    """
    Clears the entire disk-based analysis cache (~/.pemcp/cache/).
    Removes all cached file analysis results. This frees disk space but
    means the next file open will require a full re-analysis.

    This tool does not require a file to be loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary with the number of entries removed and space freed.
    """
    await ctx.info("Clearing analysis cache...")
    result = analysis_cache.clear()
    await ctx.info(
        f"Cache cleared: {result['entries_removed']} entries, "
        f"{result['space_freed_mb']} MB freed."
    )
    return {"status": "success", **result}


@tool_decorator
async def remove_cached_analysis(ctx: Context, sha256_hash: str) -> Dict[str, Any]:
    """
    Removes a specific cached analysis result by its SHA256 file hash.
    Use get_cache_stats to see which hashes are cached.

    This tool does not require a file to be loaded.

    Args:
        ctx: The MCP Context object.
        sha256_hash: (str) The full SHA256 hash (64 hex characters) of the
            file whose cached analysis should be removed.

    Returns:
        A dictionary confirming removal or indicating the entry was not found.
    """
    sha = sha256_hash.lower().strip()
    if len(sha) != 64 or not all(c in "0123456789abcdef" for c in sha):
        raise ValueError("Invalid SHA256 hash. Must be 64 hex characters.")

    await ctx.info(f"Removing cache entry for {sha[:16]}...")
    existed = analysis_cache.remove_entry_by_hash(sha)

    if existed:
        return {"status": "success", "message": f"Cache entry for {sha[:16]}... removed."}
    return {"status": "not_found", "message": f"No cache entry found for {sha[:16]}..."}
