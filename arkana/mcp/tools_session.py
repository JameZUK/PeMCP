"""MCP tools for session summary and analysis digest — helps the AI get up to speed."""
import datetime
import time
from collections import Counter
from typing import Dict, Any, List, Optional
from arkana.config import state, Context, ANGR_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.constants import MAX_TOOL_LIMIT
from arkana.state import TASK_RUNNING
from arkana.mcp._input_helpers import _paginate_field


_ADVANCED_TOOLS = frozenset({
    "find_path_to_address", "emulate_function_execution",
    "find_path_with_custom_input", "emulate_with_watchpoints",
    "run_speakeasy_emulation", "run_qiling_emulation",
})
_EXPLORING_TOOLS = frozenset({
    "decompile_function_with_angr", "get_annotated_disassembly",
    "get_function_cfg", "get_forward_slice", "get_backward_slice",
    "get_reaching_definitions", "get_cross_reference_map",
})


_phase_caches: Dict[int, Dict[str, Any]] = {}  # keyed by id(state) for session isolation


def _detect_analysis_phase() -> str:
    """Determine what phase of analysis the session is in.

    Uses a short TTL cache (2s) keyed on tool_history length to avoid
    recomputing on every call (e.g. from dashboard polling).
    """
    if not state.filepath or not state.pe_data:
        return "not_started"

    now = time.monotonic()
    history = state.get_tool_history()
    history_len = len(history) if history else 0
    sid = id(state)
    _pc = _phase_caches.get(sid)
    if (_pc is not None
            and _pc["version"] == history_len
            and now - _pc["time"] < 2.0
            and _pc["result"] is not None):
        return _pc["result"]

    ran_tools = set(h["tool_name"] for h in history)
    prev = getattr(state, "previous_session_history", []) or []
    ran_tools |= set(h["tool_name"] for h in prev)

    if ran_tools & _ADVANCED_TOOLS:
        result = "advanced"
    elif ran_tools & _EXPLORING_TOOLS:
        result = "exploring"
    elif "get_triage_report" in ran_tools:
        result = "triaged"
    else:
        result = "file_loaded"

    # Evict stale entries to prevent unbounded growth
    if len(_phase_caches) > 100:
        oldest = sorted(_phase_caches, key=lambda k: _phase_caches[k]["time"])
        for k in oldest[:len(_phase_caches) - 50]:
            del _phase_caches[k]
    _phase_caches[sid] = {"result": result, "version": history_len, "time": now}
    return result


@tool_decorator
async def get_session_summary(
    ctx: Context,
    compact: bool = False,
    notes_offset: int = 0,
    notes_limit: int = 50,
    history_limit: int = 30,
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
        notes_offset: Start index for notes list (default 0).
        notes_limit: Max notes to return (default 50).
        history_limit: Max tool history entries to return (default 30).

    Returns:
        A dictionary with session summary sections.
    """
    history_limit = max(1, min(history_limit, MAX_TOOL_LIMIT))
    notes_limit = max(1, min(notes_limit, MAX_TOOL_LIMIT))
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

    notes_page, notes_pag = _paginate_field(notes, notes_offset, notes_limit)
    result["notes"] = {
        "count": len(notes),
        "notes": notes_page,
        "notes_pagination": notes_pag,
        "by_category": dict(Counter(n.get("category", "general") for n in notes)),
    }

    tool_counts = Counter(h["tool_name"] for h in current_history)
    # Default: show the most recent entries
    hist_offset = max(0, len(current_history) - history_limit)
    hist_page, hist_pag = _paginate_field(current_history, hist_offset, history_limit)
    result["current_session"] = {
        "tools_run_count": len(current_history),
        "tools_run": hist_page,
        "tools_run_pagination": hist_pag,
        "tool_counts": dict(tool_counts),
    }

    # Previous session history
    prev = getattr(state, "previous_session_history", []) or []
    if prev:
        prev_counts = Counter(h["tool_name"] for h in prev)
        prev_offset = max(0, len(prev) - history_limit)
        prev_page, prev_pag = _paginate_field(prev, prev_offset, history_limit)
        result["previous_session"] = {
            "tools_run_count": len(prev),
            "tools_run": prev_page,
            "tools_run_pagination": prev_pag,
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

    # Enrichment status
    enrichment_task = state.get_task("auto-enrichment")
    if enrichment_task:
        result["enrichment_status"] = {
            "status": enrichment_task.get("status"),
            "progress_percent": enrichment_task.get("progress_percent", 0),
            "progress_message": enrichment_task.get("progress_message", ""),
        }

    # Dashboard triage flags (user-tagged functions)
    triage_snapshot = state.get_all_triage_snapshot()
    if triage_snapshot:
        flagged = [addr for addr, s in triage_snapshot.items() if s == "flagged"]
        suspicious = [addr for addr, s in triage_snapshot.items() if s == "suspicious"]
        clean = [addr for addr, s in triage_snapshot.items() if s == "clean"]
        triage_info = {"total_tagged": len(triage_snapshot)}
        if flagged:
            triage_info["flagged"] = flagged
        if suspicious:
            triage_info["suspicious"] = suspicious
        if clean:
            triage_info["clean"] = clean
        result["user_triage_flags"] = triage_info

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

    # Surface library warning count if any exist
    warning_count = state.get_warning_count()
    if warning_count > 0:
        result["analysis_warnings"] = {
            "count": warning_count,
            "hint": "Library warnings were captured during analysis. Call get_analysis_warnings() to review them.",
        }

    return await _check_mcp_response_size(ctx, result, "get_session_summary")


@tool_decorator
async def get_analysis_digest(
    ctx: Context,
    include_function_summaries: bool = True,
    include_iocs: bool = True,
    since_last_digest: bool = False,
    findings_offset: int = 0,
    findings_limit: int = 15,
    functions_offset: int = 0,
    functions_limit: int = 30,
    ioc_offset: int = 0,
    ioc_limit: int = 10,
    unexplored_offset: int = 0,
    unexplored_limit: int = 10,
    notes_offset: int = 0,
    notes_limit: int = 10,
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
        findings_offset: Start index for key_findings list (default 0).
        findings_limit: Max key findings to return (default 15).
        functions_offset: Start index for functions_explored list (default 0).
        functions_limit: Max explored functions to return (default 30).
        ioc_offset: Start index for each IOC category (default 0).
        ioc_limit: Max IOCs per category to return (default 10).
        unexplored_offset: Start index for unexplored_high_priority (default 0).
        unexplored_limit: Max unexplored functions to return (default 10).
        notes_offset: Start index for analyst_notes (default 0).
        notes_limit: Max analyst notes to return (default 10).

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

    # Build a notes-by-category lookup (cached via result_cache, 1hr TTL, version-keyed)
    all_notes = state.get_notes()
    _notes_count = len(all_notes)
    _notes_version = sum(len(n.get("content", "")) for n in all_notes)
    _digest_cache_key = ("_notes_by_cat", _notes_count, _notes_version)
    notes_by_cat = state.result_cache.get("_digest_notes_by_cat", _digest_cache_key)
    if notes_by_cat is None:
        notes_by_cat_build: Dict[str, list] = {}
        for note in all_notes:
            cat = note.get("category", "general")
            notes_by_cat_build.setdefault(cat, []).append(note)
        notes_by_cat = notes_by_cat_build
        state.result_cache.set("_digest_notes_by_cat", _digest_cache_key, [notes_by_cat])
    elif isinstance(notes_by_cat, list) and notes_by_cat:
        notes_by_cat = notes_by_cat[0]

    # Key findings from notes (tool_result category)
    key_findings = []
    for note in notes_by_cat.get("tool_result", []):
        if _note_is_new(note):
            key_findings.append(note.get("content", ""))
    kf_page, kf_pag = _paginate_field(key_findings, findings_offset, findings_limit)
    result["key_findings"] = kf_page
    result["key_findings_pagination"] = kf_pag

    # Function summaries from notes (function category)
    if include_function_summaries:
        func_notes = [n for n in notes_by_cat.get("function", []) if _note_is_new(n)]
        func_entries = [
            {
                "addr": n.get("address", "?"),
                "one_liner": n.get("content", ""),
            }
            for n in func_notes
        ]
        fe_page, fe_pag = _paginate_field(func_entries, functions_offset, functions_limit)
        result["functions_explored"] = fe_page
        result["functions_explored_pagination"] = fe_pag

    # IOCs from cached triage (always included — small and context-critical)
    if include_iocs and triage:
        net_iocs = triage.get("network_iocs", {})
        if isinstance(net_iocs, dict):
            ips_page, ips_pag = _paginate_field(net_iocs.get("ip_addresses", []), ioc_offset, ioc_limit)
            urls_page, urls_pag = _paginate_field(net_iocs.get("urls", []), ioc_offset, ioc_limit)
            doms_page, doms_pag = _paginate_field(net_iocs.get("domains", []), ioc_offset, ioc_limit)
            regs_page, regs_pag = _paginate_field(net_iocs.get("registry_keys", []), ioc_offset, ioc_limit)
            result["iocs_collected"] = {
                "ips": ips_page, "ips_pagination": ips_pag,
                "urls": urls_page, "urls_pagination": urls_pag,
                "domains": doms_page, "domains_pagination": doms_pag,
                "registry_keys": regs_page, "registry_keys_pagination": regs_pag,
            }

    # Coverage
    total_functions = 0
    _, _digest_cfg = state.get_angr_snapshot()
    if ANGR_AVAILABLE and _digest_cfg:
        try:
            total_functions = sum(
                1 for f in _digest_cfg.functions.values()
                if not f.is_simprocedure and not f.is_syscall
            )
        except Exception:
            pass

    func_note_count = len(notes_by_cat.get("function", []))
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
        explored_addrs = {n.get("address") for n in notes_by_cat.get("function", [])}
        unexplored = [
            f"{f['addr']} ({f['name']}) — score {f['score']}, {f.get('reason', '')}"
            for f in scored
            if f.get("addr") not in explored_addrs and f.get("score", 0) > 10
        ]
        ue_page, ue_pag = _paginate_field(unexplored, unexplored_offset, unexplored_limit)
        result["unexplored_high_priority"] = ue_page
        result["unexplored_high_priority_pagination"] = ue_pag

    # Analyst notes (general category)
    general_notes = [
        n.get("content", "") for n in notes_by_cat.get("general", [])
        if _note_is_new(n)
    ]
    if general_notes:
        an_page, an_pag = _paginate_field(general_notes, notes_offset, notes_limit)
        result["analyst_notes"] = an_page
        result["analyst_notes_pagination"] = an_pag

    # Dashboard triage flags (user-tagged functions)
    triage_snapshot = state.get_all_triage_snapshot()
    if triage_snapshot:
        flagged = [addr for addr, s in triage_snapshot.items() if s == "flagged"]
        suspicious = [addr for addr, s in triage_snapshot.items() if s == "suspicious"]
        if flagged or suspicious:
            result["user_flagged_functions"] = {}
            if flagged:
                result["user_flagged_functions"]["flagged"] = flagged
            if suspicious:
                result["user_flagged_functions"]["suspicious"] = suspicious
            result["user_flagged_functions"]["hint"] = (
                "These functions were flagged by the analyst via the dashboard. "
                "Prioritize investigating them with decompile_function_with_angr()."
            )

    # Analysis phase
    result["analysis_phase"] = _detect_analysis_phase()

    # Surface library warning counts if any exist
    warning_count = state.get_warning_count()
    if warning_count > 0:
        warnings = state.get_warnings()
        error_count = sum(1 for w in warnings if w.get("level") in ("ERROR", "CRITICAL"))
        result["library_warnings"] = {
            "unique_warnings": warning_count,
            "errors": error_count,
            "hint": "Call get_analysis_warnings() to review library warnings that may explain incomplete results.",
        }

    # Update timestamp for since_last_digest
    state.last_digest_timestamp = now

    return await _check_mcp_response_size(ctx, result, "get_analysis_digest")


@tool_decorator
async def get_progress_overview(
    ctx: Context,
    include_suggestions: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: context] Lightweight progress snapshot — cheap enough to call at the
    start of every turn. Returns analysis phase, note counts, tool call count,
    function coverage percentage, angr status, and optionally top-3 next-action
    suggestions in a single small response.

    When to use: Call at the start of each turn to orient yourself. This is the
    recommended single tool for quick context — it replaces the need to call
    suggest_next_action() separately. Use get_analysis_digest() when you need
    full findings detail, or get_session_summary() when you need tool history.

    Does not require a file to be loaded (returns minimal info if no file is open).

    Args:
        ctx: The MCP Context object.
        include_suggestions: (bool) If True (default), include top-3 next-action
            suggestions. Set to False to skip suggestion generation.

    Returns:
        A compact dictionary with progress metrics and optional suggestions.
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
    # H6: Use snapshot to prevent race condition with concurrent CFG invalidation
    total_functions = 0
    _, progress_cfg = state.get_angr_snapshot()
    if ANGR_AVAILABLE and progress_cfg:
        try:
            total_functions = sum(
                1 for f in progress_cfg.functions.values()
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
        elif progress_cfg is not None:
            result["angr"] = "ready"
        else:
            result["angr"] = "not_initialized"
    else:
        result["angr"] = "unavailable"

    # Include top-3 suggestions when requested
    if include_suggestions:
        result["suggestions"] = _build_suggestions(max_suggestions=3)

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
        ("get_angr_partial_functions", "List functions discovered so far (works during/after CFG build)."),
        ("get_hex_dump", "Inspect raw bytes at a specific offset. Accepts hex: '0x1b22d8'."),
        ("detect_crypto_constants", "Scan for AES S-boxes, SHA constants, RC4 init."),
        ("identify_crypto_algorithm", "Deep crypto identification with confidence scoring."),
        ("extract_config_automated", "Auto-extract C2 URLs, IPs, domains, registry keys."),
        ("get_focused_imports", "Suspicious imports with risk categorization."),
        ("search_floss_strings", "Search FLOSS-extracted strings."),
        ("extract_steganography", "Detect data hidden after image EOF markers."),
        ("analyze_entropy_by_offset", "Sliding-window entropy to find encrypted/packed regions."),
        ("scan_for_embedded_files", "Detect embedded PE, ZIP, ELF within the binary."),
        ("scan_for_api_hashes", "Scan for API hash constants (ror13, djb2, crc32, fnv1a) used by shellcode/malware."),
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
        ("parse_binary_struct", "Parse binary data with a field schema (uint32, cstring, etc.)."),
        ("extract_config_for_family", "KB-driven config extraction for a known malware family."),
    ],
    "context": [
        ("add_note", "Record a finding — essential for long analysis sessions."),
        ("get_notes", "Retrieve analysis notes."),
        ("auto_note_function", "Auto-generate behavioral summary after decompiling."),
        ("get_analysis_digest", "Aggregated findings overview — call periodically."),
        ("get_session_summary", "Full session summary with tool history."),
        ("get_progress_overview", "Lightweight progress snapshot with top-3 suggestions. Preferred over suggest_next_action."),
        ("suggest_next_action", "Detailed 5-suggestion recommendations. Use get_progress_overview for quick context."),
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


_SPECIALIZED_TOOL_GROUPS: Dict[str, List[tuple]] = {
    "format-specific": [
        ("elf_analyze", "Comprehensive ELF binary analysis."),
        ("elf_dwarf_info", "Extract DWARF debug information from ELF."),
        ("macho_analyze", "Comprehensive Mach-O binary analysis."),
        ("dotnet_analyze", "Analyze .NET assembly metadata and types."),
        ("dotnet_disassemble_method", "Disassemble a specific .NET method."),
        ("go_analyze", "Analyze Go binary metadata and symbols."),
        ("rust_analyze", "Analyze Rust binary metadata."),
        ("rust_demangle_symbols", "Demangle Rust symbol names."),
    ],
    "emulation": [
        ("emulate_binary_with_qiling", "Full OS emulation with Qiling Framework."),
        ("emulate_shellcode_with_qiling", "Emulate raw shellcode with Qiling."),
        ("qiling_trace_execution", "Trace execution with Qiling."),
        ("qiling_hook_api_calls", "Hook API calls during Qiling emulation."),
        ("qiling_dump_unpacked_binary", "Dump unpacked binary from Qiling memory."),
        ("qiling_resolve_api_hashes", "Resolve API hashes via Qiling emulation."),
        ("qiling_memory_search", "Search Qiling emulation memory."),
        ("emulate_pe_with_windows_apis", "Windows API emulation with Speakeasy."),
        ("emulate_shellcode_with_speakeasy", "Shellcode emulation with Speakeasy."),
        ("emulate_function_execution", "Emulate a single function with angr."),
        ("emulate_with_watchpoints", "Emulate with memory watchpoints."),
    ],
    "refinery": [
        ("refinery_pipeline", "Run a multi-step Binary Refinery pipeline."),
        ("refinery_xor", "XOR decode/encode with Binary Refinery."),
        ("refinery_decrypt", "Decrypt data with Binary Refinery (AES, RC4, etc.)."),
        ("refinery_decompress", "Decompress data (zlib, gzip, LZMA, etc.)."),
        ("refinery_extract_iocs", "Extract IOCs using Binary Refinery."),
        ("refinery_carve", "Carve embedded files from binary data."),
        ("refinery_deobfuscate_script", "Deobfuscate scripts (PowerShell, VBS, JS)."),
        ("refinery_pe_operations", "PE-specific operations (overlay, resources, etc.)."),
        ("refinery_codec", "Encode/decode data (base64, hex, etc.)."),
        ("refinery_dotnet", ".NET-specific Binary Refinery operations."),
        ("refinery_auto_decrypt", "Automated decryption attempts."),
        ("refinery_list_units", "List all available Binary Refinery units."),
    ],
    "advanced-analysis": [
        ("get_reaching_definitions", "Data flow: what values reach a point."),
        ("get_data_dependencies", "Track data dependencies for a function."),
        ("get_control_dependencies", "Control flow dependencies for a function."),
        ("propagate_constants", "Constant propagation analysis."),
        ("get_value_set_analysis", "Value set analysis for a function."),
        ("get_dominators", "Dominator tree for a function."),
        ("get_backward_slice", "Backward slice from a program point."),
        ("get_forward_slice", "Forward slice from a program point."),
        ("find_path_to_address", "Symbolic execution to reach a target."),
        ("find_path_with_custom_input", "Symbolic execution with custom inputs."),
        ("detect_self_modifying_code", "Detect self-modifying code patterns."),
        ("find_code_caves", "Find unused code regions in the binary."),
        ("scan_for_indirect_jumps", "Find indirect jump/call targets."),
        ("identify_cpp_classes", "Identify C++ class hierarchies."),
        ("get_call_graph", "Generate function call graph."),
        ("find_anti_debug_comprehensive", "Comprehensive anti-debug detection."),
    ],
}


@tool_decorator
async def list_tools_by_phase(
    ctx: Context,
    phase: str = "all",
    include_specialized: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: utility] Lists available tools organized by analysis phase. Helps
    discover the right tool for your current workflow stage.

    Phases: triage, explore, deep-dive, context, utility, or 'all'.
    Specialized groups: format-specific, emulation, refinery, advanced-analysis.

    When to use: When you're unsure which tools are available for your current
    analysis stage, or when starting work on a new binary.

    Args:
        ctx: MCP Context.
        phase: Analysis phase or specialized group to filter by. Default 'all'.
        include_specialized: (bool) If True, include specialized tool groups
            (format-specific, emulation, refinery, advanced-analysis) in 'all' output.
            Default False.
    """
    phase = phase.lower().replace("_", "-")

    # Check if requesting a specialized group directly
    if phase in _SPECIALIZED_TOOL_GROUPS:
        tools = _SPECIALIZED_TOOL_GROUPS[phase]
        return {
            "group": phase,
            "tools": [{"tool": t, "description": d} for t, d in tools],
            "count": len(tools),
            "current_phase": _detect_analysis_phase(),
        }

    if phase == "all":
        result: Dict[str, Any] = {}
        for p, tools in _TOOLS_BY_PHASE.items():
            result[p] = [{"tool": t, "description": d} for t, d in tools]
        if include_specialized:
            for group_name, tools in _SPECIALIZED_TOOL_GROUPS.items():
                result[group_name] = [{"tool": t, "description": d} for t, d in tools]
        return {
            "phases": result,
            "current_phase": _detect_analysis_phase(),
            "specialized_groups": list(_SPECIALIZED_TOOL_GROUPS.keys()),
            "hint": "Use phase='<group>' to list a specialized group, or include_specialized=True to see all.",
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
            "error": f"Unknown phase or group '{phase}'.",
            "available_phases": list(_TOOLS_BY_PHASE.keys()),
            "available_specialized_groups": list(_SPECIALIZED_TOOL_GROUPS.keys()),
        }


# ===================================================================
#  Intelligent next-action suggestion
# ===================================================================

def _build_suggestions(max_suggestions: int = 5) -> List[Dict[str, str]]:
    """Build rule-based next-action suggestions from current session state.

    Shared logic used by both suggest_next_action (full detail) and
    get_progress_overview (compact top-3).
    """
    suggestions: List[Dict[str, str]] = []
    phase = _detect_analysis_phase()

    history = state.get_tool_history()
    ran_tools = set(h["tool_name"] for h in history)
    prev = getattr(state, "previous_session_history", []) or []
    ran_tools |= set(h["tool_name"] for h in prev)
    notes = state.get_notes() if state.filepath else []
    triage = getattr(state, '_cached_triage', None)
    func_scores = getattr(state, '_cached_function_scores', None)

    if phase == "not_started" or not state.filepath:
        return [{"tool": "open_file(filepath='...')", "rationale": "No file loaded. Load a binary to begin analysis."}]

    # --- Phase: file_loaded ---
    if phase == "file_loaded":
        suggestions.append({
            "tool": "get_triage_report(compact=True)",
            "rationale": "File loaded but not triaged yet. Start with automated triage for risk assessment.",
        })
        return suggestions[:max_suggestions]

    # --- Phase: triaged ---
    if "get_triage_report" in ran_tools and triage:
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

    # --- User-flagged functions from dashboard (highest priority) ---
    user_triage = state.get_all_triage_snapshot()
    if user_triage and ANGR_AVAILABLE:
        flagged_addrs = [addr for addr, s in user_triage.items() if s == "flagged"]
        suspicious_addrs = [addr for addr, s in user_triage.items() if s == "suspicious"]
        explored_addrs_for_triage = {n.get("address") for n in notes if n.get("category") == "function"}
        # Prioritize flagged functions that haven't been noted yet
        for addr in flagged_addrs[:3]:
            if addr not in explored_addrs_for_triage:
                suggestions.insert(0, {
                    "tool": f"decompile_function_with_angr(function_address='{addr}')",
                    "rationale": f"FLAGGED by analyst via dashboard — priority investigation target.",
                })
        for addr in suspicious_addrs[:2]:
            if addr not in explored_addrs_for_triage:
                suggestions.append({
                    "tool": f"decompile_function_with_angr(function_address='{addr}')",
                    "rationale": f"Marked SUSPICIOUS by analyst via dashboard — investigate.",
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

    return suggestions[:max_suggestions]


@tool_decorator
async def suggest_next_action(
    ctx: Context,
    max_suggestions: int = 5,
) -> Dict[str, Any]:
    """
    [Phase: context] Analyzes current session state — triage results, notes,
    tool history, function scores — and recommends 3-5 specific next steps
    with rationale. No LLM involved, purely rule-based.

    When to use: When you need detailed recommendations with rationale. For a
    quick overview with suggestions included, prefer get_progress_overview()
    which is cheaper and includes top-3 suggestions.

    Args:
        ctx: MCP Context.
        max_suggestions: Max suggestions to return (default 5).
    """
    max_suggestions = max(1, min(max_suggestions, 20))
    phase = _detect_analysis_phase()
    suggestions = _build_suggestions(max_suggestions=max_suggestions)

    notes = state.get_notes() if state.filepath else []
    history = state.get_tool_history()
    ran_tools = set(h["tool_name"] for h in history)
    prev = getattr(state, "previous_session_history", []) or []
    ran_tools |= set(h["tool_name"] for h in prev)

    return {
        "phase": phase,
        "suggestions": suggestions,
        "tools_used": len(ran_tools),
        "notes_count": len(notes),
    }


# ===================================================================
#  Analysis timeline
# ===================================================================

@tool_decorator
async def get_analysis_timeline(
    ctx: Context,
    offset: int = -1,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: context] Merges tool history with notes into a chronological timeline
    of analysis activity. Shows what was done and discovered, in order.

    When to use: When reviewing what happened during an analysis session,
    or when documenting the analysis workflow.

    Args:
        ctx: MCP Context.
        offset: Start index into the timeline. Default -1 means "most recent entries"
            (i.e. offset = total - limit). Pass 0 to start from the beginning.
        limit: Max timeline entries. Default 20.
    """
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    # Fetch once, reuse for both iteration and count
    tool_history = state.get_tool_history()
    all_notes = state.get_notes()
    total_events = len(tool_history) + len(all_notes)

    # Cache the merged+sorted event list (keyed on event count + content version)
    _content_version = sum(len(n.get("content", "")) for n in all_notes)
    _timeline_cache_key = ("_timeline", total_events, _content_version)
    events = state.result_cache.get("_timeline_events", _timeline_cache_key)
    if events is None:
        events = []

        # Add tool history entries
        for h in tool_history:
            events.append({
                "timestamp": h.get("timestamp", ""),
                "type": "tool",
                "name": h.get("tool_name", "?"),
                "summary": h.get("result_summary", ""),
                "duration_ms": h.get("duration_ms", 0),
            })

        # Add notes as events
        for n in all_notes:
            events.append({
                "timestamp": n.get("created_at", ""),
                "type": "note",
                "category": n.get("category", "general"),
                "content": n.get("content", "")[:200],
                "address": n.get("address"),
            })

        # Sort by timestamp
        events.sort(key=lambda e: e.get("timestamp") or "")
        state.result_cache.set("_timeline_events", _timeline_cache_key, events)

    # Resolve default offset (most recent entries)
    if offset < 0:
        real_offset = max(0, len(events) - limit)
    else:
        real_offset = offset

    recent, pag = _paginate_field(events, real_offset, limit)

    return {
        "timeline": recent,
        "total_events": total_events,
        "returned": len(recent),
        "_pagination": pag,
        "phase": _detect_analysis_phase(),
    }
