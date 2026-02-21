"""MCP tools for session summary and analysis digest — helps the AI get up to speed."""
import time
from collections import Counter
from typing import Dict, Any, List, Optional
from pemcp.config import state, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.state import TASK_RUNNING


def _detect_analysis_phase() -> str:
    """Determine what phase of analysis the session is in."""
    if not state.filepath or not state.pe_data:
        return "not_started"

    current_history = state.get_tool_history()
    ran_tools = set(h["tool_name"] for h in current_history)
    prev = getattr(state, "previous_session_history", []) or []
    ran_tools |= set(h["tool_name"] for h in prev)

    advanced_tools = {
        "find_path_to_address", "emulate_function_execution",
        "find_path_with_custom_input", "emulate_with_watchpoints",
        "run_speakeasy_emulation", "run_qiling_emulation",
    }
    exploring_tools = {
        "decompile_function_with_angr", "get_annotated_disassembly",
        "get_function_cfg", "get_forward_slice", "get_backward_slice",
        "get_reaching_definitions", "get_cross_reference_map",
    }

    if ran_tools & advanced_tools:
        return "advanced"
    if ran_tools & exploring_tools:
        return "exploring"
    if "get_triage_report" in ran_tools:
        return "triaged"
    return "file_loaded"


@tool_decorator
async def get_session_summary(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Returns a comprehensive summary of the current session and any prior
    session data for the loaded file. Includes file info, notes, tool history
    (both current and previous session), angr status, analysis phase, and
    suggested next tools.

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

    # Analysis phase — where are we in the workflow?
    result["analysis_phase"] = _detect_analysis_phase()

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
        suggested.append("get_triage_report(compact=True)")
    if "get_function_map" not in ran_tools and ANGR_AVAILABLE:
        suggested.append("get_function_map()")
    if "get_focused_imports" not in ran_tools:
        suggested.append("get_focused_imports()")
    if ANGR_AVAILABLE and "decompile_function_with_angr" not in ran_tools:
        suggested.append("decompile_function_with_angr")

    # Notes-related suggestions based on analysis phase
    phase = result["analysis_phase"]
    func_notes = [n for n in notes if n.get("category") == "function"]
    if phase in ("exploring", "advanced") and not func_notes:
        suggested.append("auto_note_function(address) — record findings after decompiling each function")
    if notes and "get_analysis_digest" not in ran_tools:
        suggested.append("get_analysis_digest() — review accumulated findings")

    if suggested:
        result["suggested_next_tools"] = suggested

    return await _check_mcp_response_size(ctx, result, "get_session_summary")


@tool_decorator
async def get_analysis_digest(
    ctx: Context,
    include_function_summaries: bool = True,
    include_iocs: bool = True,
    since_last_digest: bool = False,
) -> Dict[str, Any]:
    """
    Returns a structured digest of what has been learned about the binary so far.
    Aggregates triage findings, function notes, IOCs, and tool history into
    a context-efficient summary.

    Unlike get_session_summary (which shows what tools ran), this shows what
    was *learned*. Call this periodically during analysis to refresh your
    understanding without re-reading earlier tool outputs.

    Args:
        ctx: The MCP Context object.
        include_function_summaries: (bool) Include one-line summaries of explored functions. Default True.
        include_iocs: (bool) Include extracted IOCs. Default True.
        since_last_digest: (bool) If True, only show findings since the last
            time this tool was called. Default False.

    Returns:
        A dictionary with binary profile, key findings, explored functions,
        IOCs, coverage stats, and unexplored high-priority targets.
    """
    _check_pe_loaded("get_analysis_digest")

    now = time.time()
    cutoff = state.last_digest_timestamp if since_last_digest else 0.0

    result: Dict[str, Any] = {}

    # Binary profile from cached triage
    triage = getattr(state, '_cached_triage', None)
    if triage:
        risk = triage.get('risk_level', 'UNKNOWN')
        score = triage.get('risk_score', 0)
        mode = (state.pe_data or {}).get('mode', 'unknown')
        packing = triage.get('packing_assessment', {})
        packed = packing.get('likely_packed', False) if isinstance(packing, dict) else False
        packer = packing.get('packer_name', '') if isinstance(packing, dict) else ''
        sig = triage.get('digital_signature', {})
        signed = sig.get('embedded_signature_present', False) if isinstance(sig, dict) else False

        parts = [mode.upper()]
        if packed:
            parts.append(f"packed ({packer})" if packer else "packed")
        parts.append("signed" if signed else "unsigned")
        parts.append(f"{risk} risk (score {score})")
        result["binary_profile"] = ', '.join(parts)
    else:
        result["binary_profile"] = "Triage not yet run — call get_triage_report() first"

    # Key findings from notes (tool_result category)
    all_notes = state.get_notes()
    key_findings = []
    for note in all_notes:
        if note.get("category") == "tool_result":
            key_findings.append(note.get("content", ""))
    result["key_findings"] = key_findings[:15]

    # Function summaries from notes (function category)
    if include_function_summaries:
        func_notes = [n for n in all_notes if n.get("category") == "function"]
        result["functions_explored"] = [
            {
                "addr": n.get("address", "?"),
                "one_liner": n.get("content", ""),
            }
            for n in func_notes[:30]
        ]

    # IOCs from cached triage
    if include_iocs and triage:
        net_iocs = triage.get("network_iocs", {})
        if isinstance(net_iocs, dict):
            result["iocs_collected"] = {
                "ips": net_iocs.get("ip_addresses", [])[:10],
                "urls": net_iocs.get("urls", [])[:10],
                "domains": net_iocs.get("domains", [])[:10],
                "registry_keys": net_iocs.get("registry_keys", [])[:10],
            }

    # Coverage
    total_functions = 0
    if ANGR_AVAILABLE and state.angr_cfg:
        try:
            total_functions = sum(
                1 for f in state.angr_cfg.functions.values()
                if not f.is_simprocedure and not f.is_syscall
            )
        except Exception:
            pass

    func_note_count = len([n for n in all_notes if n.get("category") == "function"])
    if total_functions > 0:
        pct = round(func_note_count / total_functions * 100, 1)
    else:
        pct = 0.0
    result["coverage"] = {
        "functions_explored": func_note_count,
        "total_functions": total_functions,
        "pct": f"{pct}%",
    }

    # Unexplored high-priority functions (from cached function scores)
    scored = getattr(state, '_cached_function_scores', None)
    if scored:
        explored_addrs = {n.get("address") for n in all_notes if n.get("category") == "function"}
        unexplored = [
            f for f in scored
            if f.get("addr") not in explored_addrs and f.get("score", 0) > 10
        ]
        result["unexplored_high_priority"] = [
            f"{f['addr']} ({f['name']}) — score {f['score']}, {f.get('reason', '')}"
            for f in unexplored[:10]
        ]

    # Analyst notes (general category)
    general_notes = [n.get("content", "") for n in all_notes if n.get("category") == "general"]
    if general_notes:
        result["analyst_notes"] = general_notes[:10]

    # Analysis phase
    result["analysis_phase"] = _detect_analysis_phase()

    # Update timestamp for since_last_digest
    state.last_digest_timestamp = now

    return await _check_mcp_response_size(ctx, result, "get_analysis_digest")
