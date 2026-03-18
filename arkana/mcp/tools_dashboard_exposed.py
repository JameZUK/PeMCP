"""MCP tool wrappers for dashboard data functions (search, entropy, reports)."""
import asyncio
import os

from typing import Dict, Any, Optional

from arkana.config import state, logger, Context
from arkana.constants import MAX_TOOL_LIMIT
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.utils import validate_regex_pattern


@tool_decorator
async def search_decompiled_code(
    ctx: Context,
    query: str,
    case_sensitive: bool = False,
    max_results: int = 50,
) -> Dict[str, Any]:
    """
    [Phase: analysis] Search across all cached decompiled function code for a pattern.

    When to use: When you want to find specific code patterns, strings, or API calls
    across all decompiled functions without decompiling each one individually.
    Next steps: decompile_function_with_angr() to view full function,
    get_analysis_context_for_function() for comprehensive context.

    Args:
        query: Search pattern (regex supported). Max 500 characters.
        case_sensitive: Whether the search is case-sensitive. Default False.
        max_results: Maximum number of matching functions to return (1-100000). Default 50.
    """
    _check_pe_loaded("search_decompiled_code")

    if not query or not query.strip():
        return {"error": "Search query cannot be empty."}

    query = query.strip()
    if len(query) > 500:
        return {"error": f"Query too long ({len(query)} chars). Maximum is 500 characters."}

    validate_regex_pattern(query)

    max_results = max(1, min(max_results, MAX_TOOL_LIMIT))

    from arkana.dashboard.state_api import search_decompiled_code as _search_fn

    result = await asyncio.to_thread(_search_fn, query, max_results)

    # state_api.search_decompiled_code doesn't support case_sensitive natively,
    # so we filter post-hoc if case_sensitive is True and the search was case-insensitive
    # (state_api always does case-insensitive). For case-sensitive, re-filter.
    if case_sensitive and result.get("results"):
        import re
        try:
            pat = re.compile(query)
        except re.error:
            pat = None

        if pat:
            filtered = []
            for r in result["results"]:
                lines = r.get("lines_with_context", [])
                matching = [
                    ln for ln in lines
                    if pat.search(ln.get("text", ""))
                ]
                if matching:
                    r["lines_with_context"] = matching
                    filtered.append(r)
            result["results"] = filtered
            result["total_matches"] = len(filtered)

    return await _check_mcp_response_size(ctx, result, "search_decompiled_code",
                                          limit_param_info="Use max_results to limit output.")


@tool_decorator
async def get_entropy_analysis(
    ctx: Context,
    include_heatmap: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: triage] Get entropy analysis for the loaded binary (per-section and overall).

    When to use: To detect packed/encrypted sections (high entropy >7.0) or empty sections
    (near-zero entropy). Useful for identifying obfuscation, packing, or embedded payloads.
    Next steps: detect_packing() if high entropy detected, get_hex_dump() to inspect sections,
    analyze_entropy_by_offset() for fine-grained offset-level analysis.

    Args:
        include_heatmap: Include byte-level entropy data for visualization. Default True.
    """
    _check_pe_loaded("get_entropy_analysis")

    from arkana.dashboard.state_api import get_entropy_data as _entropy_fn

    result = await asyncio.to_thread(_entropy_fn)

    if not include_heatmap and "heatmap" in result:
        del result["heatmap"]
    if not include_heatmap and "byte_entropy" in result:
        del result["byte_entropy"]

    return await _check_mcp_response_size(ctx, result, "get_entropy_analysis",
                                          limit_param_info="Set include_heatmap=False to reduce size.")


@tool_decorator
async def generate_report(
    ctx: Context,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: reporting] Generate a comprehensive markdown analysis report for the loaded binary.

    When to use: When you have completed your analysis and want to produce a structured report
    summarising findings, risk assessment, IOCs, function analysis, and timeline.
    Next steps: add_note(category='conclusion') to add final assessment, export_project() to save all data.

    Args:
        output_path: Optional file path to save the report. If not provided, returns report text only.
    """
    _check_pe_loaded("generate_report")

    from arkana.dashboard.state_api import generate_report_text as _report_fn

    result = await asyncio.to_thread(_report_fn)

    if not result.get("available"):
        return {"error": "No analysis data available to generate a report. Load and analyse a file first."}

    if output_path:
        resolved = os.path.realpath(output_path)
        state.check_path_allowed(resolved)

        report_text = result.get("report", "")
        report_bytes = report_text.encode("utf-8")

        from arkana.mcp._refinery_helpers import _write_output_and_register_artifact
        artifact_info = _write_output_and_register_artifact(
            resolved, report_bytes, "generate_report", "Analysis report (markdown)"
        )
        result["saved_to"] = artifact_info.get("path", resolved)
        result["file_size"] = len(report_bytes)

    return await _check_mcp_response_size(ctx, result, "generate_report",
                                          limit_param_info="Use output_path to save to file instead.")
