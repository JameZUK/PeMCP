"""MCP tools for session summary and analysis digest — helps the AI get up to speed."""
import datetime
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
    compact: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: context] Returns a comprehensive summary of the current session and any
    prior session data for the loaded file. Includes file info, notes, tool history,
    angr status, analysis phase, and suggested next tools.

    When to use: Call when resuming work on a previously analyzed binary, or when
    you need to understand what has already been done before deciding next steps.

    Designed to help an AI analyst quickly get up to speed. The response includes
    'analysis_phase' (not_started → file_loaded → triaged → exploring → advanced)
    and 'suggested_next_tools' based on what hasn't been run yet.

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

    # Current session tool history
    current_history = state.get_tool_history()

    if compact:
        # Compact: phase + counts only, no full lists
        tool_counts = Counter(h["tool_name"] for h in current_history)
        result["notes_count"] = len(notes)
        result["notes_by_category"] = dict(Counter(n.get("category", "general") for n in notes))
        result["tools_run_count"] = len(current_history)
        result["unique_tools"] = len(tool_counts)
        if ANGR_AVAILABLE:
            angr_task = state.get_task("startup-angr")
            if angr_task:
                result["angr"] = angr_task.get("status", "unknown")
            else:
                proj, cfg = state.get_angr_snapshot()
                result["angr"] = "ready" if proj else "not_initialized"
        else:
            result["angr"] = "unavailable"
        return result

    result["notes"] = {
        "count": len(notes),
        "notes": notes[:50],
        "by_category": dict(Counter(n.get("category", "general") for n in notes)),
    }

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
    [Phase: context] Returns a structured digest of what has been LEARNED about
    the binary so far — aggregates triage findings, function notes, IOCs, and
    coverage stats into a single context-efficient summary.

    When to use: Call periodically during analysis to refresh your understanding
    without re-reading earlier tool outputs. Essential for maintaining context in
    long analysis sessions. Unlike get_session_summary (which shows what tools
    ran), this shows what was *discovered*.

    Typical next steps after reviewing the digest:
      - If unexplored_high_priority functions listed → decompile_function_with_angr()
      - If coverage is low → get_function_complexity_list() to find interesting targets
      - If IOCs found → get_virustotal_report_for_loaded_file(), search_floss_strings()

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
    last_ts = state.last_digest_timestamp if since_last_digest else 0.0
    result: Dict[str, Any] = {}

    if since_last_digest and last_ts > 0:
        result["since_last_digest"] = True
        result["last_digest_at"] = datetime.datetime.fromtimestamp(
            last_ts, datetime.timezone.utc
        ).isoformat()

    # Binary profile from cached triage (always included — cheap context)
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

    # Helper to filter notes by timestamp when since_last_digest is active
    def _note_is_new(note: Dict[str, Any]) -> bool:
        if last_ts <= 0:
            return True
        created = note.get("created_at") or note.get("updated_at", "")
        if not created:
            return True
        try:
            dt = datetime.datetime.fromisoformat(created)
            return dt.timestamp() > last_ts
        except (ValueError, TypeError):
            return True

    # Key findings from notes (tool_result category)
    all_notes = state.get_notes()
    key_findings = []
    for note in all_notes:
        if note.get("category") == "tool_result" and _note_is_new(note):
            key_findings.append(note.get("content", ""))
    result["key_findings"] = key_findings[:15]

    # Function summaries from notes (function category)
    if include_function_summaries:
        func_notes = [n for n in all_notes if n.get("category") == "function" and _note_is_new(n)]
        result["functions_explored"] = [
            {
                "addr": n.get("address", "?"),
                "one_liner": n.get("content", ""),
            }
            for n in func_notes[:30]
        ]

    # IOCs from cached triage (always included — small and context-critical)
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
    general_notes = [
        n.get("content", "") for n in all_notes
        if n.get("category") == "general" and _note_is_new(n)
    ]
    if general_notes:
        result["analyst_notes"] = general_notes[:10]

    # Analysis phase
    result["analysis_phase"] = _detect_analysis_phase()

    # Update timestamp for since_last_digest
    state.last_digest_timestamp = now

    return await _check_mcp_response_size(ctx, result, "get_analysis_digest")


@tool_decorator
async def get_progress_overview(
    ctx: Context,
) -> Dict[str, Any]:
    """
    [Phase: context] Lightweight progress snapshot — cheap enough to call at the
    start of every turn. Returns analysis phase, note counts, tool call count,
    function coverage percentage, and angr status in a single small response.

    When to use: Call at the start of each turn to orient yourself. Use
    get_analysis_digest() when you need full findings detail, or
    get_session_summary() when you need tool history and suggestions.

    Does not require a file to be loaded (returns minimal info if no file is open).

    Args:
        ctx: The MCP Context object.

    Returns:
        A compact dictionary with progress metrics.
    """
    result: Dict[str, Any] = {
        "analysis_phase": _detect_analysis_phase(),
    }

    if not state.filepath or not state.pe_data:
        result["file_loaded"] = False
        return result

    result["file_loaded"] = True
    hashes = (state.pe_data.get("file_hashes") or {})
    result["sha256"] = hashes.get("sha256", "")[:16] + "..."

    # Note counts by category
    notes = state.get_notes()
    by_cat = Counter(n.get("category", "general") for n in notes)
    result["notes"] = {
        "total": len(notes),
        "general": by_cat.get("general", 0),
        "function": by_cat.get("function", 0),
        "tool_result": by_cat.get("tool_result", 0),
    }

    # Tool history count
    current_history = state.get_tool_history()
    result["tool_calls"] = len(current_history)

    # Function coverage
    total_functions = 0
    if ANGR_AVAILABLE and state.angr_cfg:
        try:
            total_functions = sum(
                1 for f in state.angr_cfg.functions.values()
                if not f.is_simprocedure and not f.is_syscall
            )
        except Exception:
            pass

    func_explored = by_cat.get("function", 0)
    if total_functions > 0:
        pct = round(func_explored / total_functions * 100, 1)
    else:
        pct = 0.0
    result["coverage_pct"] = f"{pct}%"
    result["functions_total"] = total_functions

    # Angr status (one-liner)
    if ANGR_AVAILABLE:
        angr_task = state.get_task("startup-angr")
        if angr_task and angr_task.get("status") == TASK_RUNNING:
            result["angr"] = f"loading ({angr_task.get('progress_percent', 0)}%)"
        elif state.angr_cfg is not None:
            result["angr"] = "ready"
        else:
            result["angr"] = "not_initialized"
    else:
        result["angr"] = "unavailable"

    return result


# ===================================================================
#  Phase-based tool discovery
# ===================================================================

_TOOLS_BY_PHASE = {
    "triage": [
        ("get_triage_report", "START HERE. Comprehensive automated triage with risk scoring."),
        ("classify_binary_purpose", "AI-free classification of binary type and purpose."),
        ("detect_binary_format", "Detect file format (PE, ELF, Mach-O, shellcode, etc.)."),
        ("get_analyzed_file_summary", "Quick overview of loaded file structure."),
        ("detect_packing", "Detect packing/obfuscation with multiple heuristics."),
    ],
    "explore": [
        ("get_function_map", "Scored function list — prioritize what to decompile."),
        ("get_hex_dump", "Inspect raw bytes at a specific offset. Accepts hex: '0x1b22d8'."),
        ("detect_crypto_constants", "Scan for AES S-boxes, SHA constants, RC4 init."),
        ("identify_crypto_algorithm", "Deep crypto identification with confidence scoring."),
        ("extract_config_automated", "Auto-extract C2 URLs, IPs, domains, registry keys."),
        ("get_focused_imports", "Suspicious imports with risk categorization."),
        ("search_floss_strings", "Search FLOSS-extracted strings."),
        ("extract_steganography", "Detect data hidden after image EOF markers."),
        ("analyze_entropy_by_offset", "Sliding-window entropy to find encrypted/packed regions."),
        ("scan_for_embedded_files", "Detect embedded PE, ZIP, ELF within the binary."),
    ],
    "deep-dive": [
        ("decompile_function_with_angr", "Decompile a function to pseudocode."),
        ("find_path_to_address", "Symbolic execution to reach a target address."),
        ("get_reaching_definitions", "Data flow: what values reach a point."),
        ("get_data_dependencies", "Track data dependencies for a function."),
        ("brute_force_simple_crypto", "Try XOR/RC4/ADD against encrypted data."),
        ("auto_extract_crypto_keys", "Search for crypto keys near constants."),
        ("emulate_binary_with_qiling", "Full OS emulation with Qiling Framework."),
        ("run_speakeasy_emulation", "Windows API emulation with Speakeasy."),
        ("try_all_unpackers", "Orchestrate multiple unpacking methods."),
        ("find_oep_heuristic", "Detect Original Entry Point of packed binaries."),
        ("diff_payloads", "Compare two binary payloads byte-by-byte."),
    ],
    "context": [
        ("add_note", "Record a finding — essential for long analysis sessions."),
        ("get_notes", "Retrieve analysis notes."),
        ("auto_note_function", "Auto-generate behavioral summary after decompiling."),
        ("get_analysis_digest", "Aggregated findings overview — call periodically."),
        ("get_session_summary", "Full session summary with tool history."),
        ("get_progress_overview", "Lightweight progress snapshot."),
        ("suggest_next_action", "AI-free recommendations based on current findings."),
    ],
    "utility": [
        ("export_project", "Export session as portable archive."),
        ("import_project", "Import a previous session archive."),
        ("generate_analysis_report", "Generate markdown report from findings."),
        ("auto_name_sample", "Suggest descriptive filename for the sample."),
        ("get_iocs_structured", "Export IOCs in JSON/CSV/STIX format."),
        ("get_cache_stats", "View analysis cache statistics."),
        ("list_tools_by_phase", "This tool — discover tools by analysis phase."),
    ],
}


@tool_decorator
async def list_tools_by_phase(
    ctx: Context,
    phase: str = "all",
) -> Dict[str, Any]:
    """
    [Phase: utility] Lists available tools organized by analysis phase. Helps
    discover the right tool for your current workflow stage.

    Phases: triage, explore, deep-dive, context, utility, or 'all'.

    When to use: When you're unsure which tools are available for your current
    analysis stage, or when starting work on a new binary.

    Args:
        ctx: MCP Context.
        phase: Analysis phase to filter by. Default 'all' shows everything.
    """
    phase = phase.lower().replace("_", "-")
    if phase == "all":
        result = {}
        for p, tools in _TOOLS_BY_PHASE.items():
            result[p] = [{"tool": t, "description": d} for t, d in tools]
        return {
            "phases": result,
            "current_phase": _detect_analysis_phase(),
            "hint": "Use suggest_next_action() for personalized recommendations.",
        }
    elif phase in _TOOLS_BY_PHASE:
        tools = _TOOLS_BY_PHASE[phase]
        return {
            "phase": phase,
            "tools": [{"tool": t, "description": d} for t, d in tools],
            "count": len(tools),
            "current_phase": _detect_analysis_phase(),
        }
    else:
        return {
            "error": f"Unknown phase '{phase}'.",
            "available_phases": list(_TOOLS_BY_PHASE.keys()),
        }


# ===================================================================
#  Intelligent next-action suggestion
# ===================================================================

@tool_decorator
async def suggest_next_action(
    ctx: Context,
) -> Dict[str, Any]:
    """
    [Phase: context] Analyzes current session state — triage results, notes,
    tool history, function scores — and recommends 3-5 specific next steps
    with rationale. No LLM involved, purely rule-based.

    When to use: When you're unsure what to do next, or after completing a
    phase of analysis. More specific than get_session_summary().

    Args:
        ctx: MCP Context.
    """
    suggestions: List[Dict[str, str]] = []

    phase = _detect_analysis_phase()

    # Gather context
    history = state.get_tool_history()
    ran_tools = set(h["tool_name"] for h in history)
    prev = getattr(state, "previous_session_history", []) or []
    ran_tools |= set(h["tool_name"] for h in prev)
    notes = state.get_notes() if state.filepath else []
    triage = getattr(state, '_cached_triage', None)
    func_scores = getattr(state, '_cached_function_scores', None)

    if phase == "not_started" or not state.filepath:
        return {
            "phase": phase,
            "suggestions": [
                {"tool": "open_file(filepath='...')", "rationale": "No file loaded. Load a binary to begin analysis."},
            ],
        }

    # --- Phase: file_loaded ---
    if phase == "file_loaded":
        suggestions.append({
            "tool": "get_triage_report(compact=True)",
            "rationale": "File loaded but not triaged yet. Start with automated triage for risk assessment.",
        })
        return {"phase": phase, "suggestions": suggestions}

    # --- Phase: triaged ---
    if "get_triage_report" in ran_tools and triage:
        risk_level = triage.get("risk_level", "")
        sus_imports = triage.get("suspicious_imports", [])

        if "get_function_map" not in ran_tools and ANGR_AVAILABLE:
            suggestions.append({
                "tool": "get_function_map(compact=True)",
                "rationale": "Get scored function list to prioritize decompilation targets.",
            })

        # Check for crypto indicators
        has_crypto = any(
            isinstance(imp, dict) and "crypt" in imp.get("function", "").lower()
            for imp in sus_imports
        )
        if has_crypto and "identify_crypto_algorithm" not in ran_tools:
            suggestions.append({
                "tool": "identify_crypto_algorithm()",
                "rationale": "Triage found crypto imports. Identify which algorithms are used.",
            })

        # Check for networking
        has_network = any(
            isinstance(imp, dict) and any(n in imp.get("function", "").lower()
                for n in ["internet", "http", "url", "socket", "connect"])
            for imp in sus_imports
        )
        if has_network and "extract_config_automated" not in ran_tools:
            suggestions.append({
                "tool": "extract_config_automated()",
                "rationale": "Networking imports found. Extract C2 configuration automatically.",
            })

        # Check packing
        packing = triage.get("packing_assessment", {})
        if isinstance(packing, dict) and packing.get("likely_packed"):
            if "try_all_unpackers" not in ran_tools:
                suggestions.append({
                    "tool": "try_all_unpackers()",
                    "rationale": f"Binary appears packed ({packing.get('packer_name', 'unknown')}). Try automated unpacking.",
                })

    # --- Phase: exploring / advanced ---
    if func_scores and ANGR_AVAILABLE:
        explored_addrs = {n.get("address") for n in notes if n.get("category") == "function"}
        unexplored = [
            f for f in func_scores
            if f.get("addr") not in explored_addrs and f.get("score", 0) > 10
        ]
        if unexplored:
            top = unexplored[0]
            suggestions.append({
                "tool": f"decompile_function_with_angr(address='{top['addr']}')",
                "rationale": f"Highest-scored unexplored function: {top.get('name', '?')} (score {top.get('score', 0)})",
            })

    # Notes-related suggestions
    func_notes = [n for n in notes if n.get("category") == "function"]
    if "decompile_function_with_angr" in ran_tools and not func_notes:
        suggestions.append({
            "tool": "auto_note_function(address=<last_decompiled>)",
            "rationale": "You've decompiled functions but haven't recorded findings. Use auto_note_function() after each decompile.",
        })

    # Digest suggestion
    if len(notes) >= 5 and "get_analysis_digest" not in ran_tools:
        suggestions.append({
            "tool": "get_analysis_digest()",
            "rationale": f"You have {len(notes)} notes accumulated. Review findings digest.",
        })

    # Report suggestion for advanced phase
    if phase == "advanced" and "generate_analysis_report" not in ran_tools:
        suggestions.append({
            "tool": "generate_analysis_report()",
            "rationale": "Analysis is well advanced. Generate a comprehensive report.",
        })

    # Ensure we have at least one suggestion
    if not suggestions:
        suggestions.append({
            "tool": "get_analysis_digest()",
            "rationale": "Review accumulated findings to decide next steps.",
        })

    return {
        "phase": phase,
        "suggestions": suggestions[:5],
        "tools_used": len(ran_tools),
        "notes_count": len(notes),
    }


# ===================================================================
#  Analysis timeline
# ===================================================================

@tool_decorator
async def get_analysis_timeline(
    ctx: Context,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: context] Merges tool history with notes into a chronological timeline
    of analysis activity. Shows what was done and discovered, in order.

    When to use: When reviewing what happened during an analysis session,
    or when documenting the analysis workflow.

    Args:
        ctx: MCP Context.
        limit: Max timeline entries. Default 20.
    """
    events: List[Dict[str, Any]] = []

    # Add tool history entries
    for h in state.get_tool_history():
        events.append({
            "timestamp": h.get("timestamp", ""),
            "type": "tool",
            "name": h.get("tool_name", "?"),
            "summary": h.get("result_summary", ""),
            "duration_ms": h.get("duration_ms", 0),
        })

    # Add notes as events
    for n in state.get_notes():
        events.append({
            "timestamp": n.get("created_at", ""),
            "type": "note",
            "category": n.get("category", "general"),
            "content": n.get("content", "")[:200],
            "address": n.get("address"),
        })

    # Sort by timestamp
    events.sort(key=lambda e: e.get("timestamp", ""))

    # Take the most recent entries
    events = events[-limit:]

    return {
        "timeline": events,
        "total_events": len(state.get_tool_history()) + len(state.get_notes()),
        "returned": len(events),
        "phase": _detect_analysis_phase(),
    }
