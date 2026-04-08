"""Functions to extract dashboard-ready data from AnalyzerState."""
import bisect
import copy
import datetime
import itertools
import logging
import math
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Arkana.dashboard")

from arkana.state import (
    _default_state, _session_registry, _registry_lock,
    TASK_RUNNING, TASK_OVERTIME, TASK_COMPLETED, TASK_FAILED,
)
from arkana.constants import (
    MAX_PROJECT_COMPARE_PAIRS,
    PROJECT_COMPARE_TIME_BUDGET_S,
)


# M7-v10: Shared phase detection helper using canonical tool sets
# Import the frozensets from tools_session to avoid duplication/drift
def _detect_phase_for_state(st) -> str:
    """Determine analysis phase from an explicit state object.

    Uses canonical tool sets from tools_session and efficient accessors.
    """
    if not st.filepath or not st.pe_data:
        return "not_started"

    from arkana.mcp.tools_session import _ADVANCED_TOOLS, _EXPLORING_TOOLS

    ran_tools = st.get_ran_tool_names()
    prev = getattr(st, "previous_session_history", []) or []
    ran_tools |= set(h.get("tool_name", "") for h in prev)

    if ran_tools & _ADVANCED_TOOLS:
        return "advanced"
    if ran_tools & _EXPLORING_TOOLS:
        return "exploring"
    if "get_triage_report" in ran_tools:
        return "triaged"
    return "file_loaded"


def _get_state():
    """Return the most relevant AnalyzerState for dashboard reads.

    In stdio mode the MCP SDK still creates a session, so tools write to a
    per-session state instead of ``_default_state``.  We check the session
    registry for any state that has a file loaded and prefer that over the
    (potentially empty) default state.

    When multiple sessions exist, prefer the one with the most recent activity
    (latest tool_history timestamp) to avoid nondeterministic dict iteration.
    """
    with _registry_lock:
        candidates = [*_session_registry.values(), _default_state]
        # Snapshot sessions with an active tool (fallback)
        active_candidates = [
            st for st in _session_registry.values()
            if getattr(st, "active_tool", None) is not None
        ]

    # Now iterate candidates outside the lock to avoid holding it
    file_candidates = [st for st in candidates if st.filepath is not None]
    if file_candidates:
        if len(file_candidates) == 1:
            return file_candidates[0]
        # L3-v8: Use last_active (simple float, no lock/copy) instead of
        # get_tool_history() which copies the entire deque per session.
        return max(file_candidates, key=lambda st: st.last_active)

    # Fall back to a session with an active tool (e.g. open_file loading)
    if active_candidates:
        return active_candidates[0]

    return _default_state


# H11: Use _state_uuid instead of id(st) to avoid key reuse after GC
_func_lookup_cache: Dict[str, tuple] = {}  # _state_uuid -> (expire_time, entries, starts)
_FUNC_LOOKUP_TTL = 5  # seconds
_MAX_FUNC_LOOKUP_CACHE = 4  # max state objects to cache

# Cache for overview enrichment (capa/YARA/FLOSS function link resolution)
_overview_enrichment_cache: Dict[str, tuple] = {}  # _state_uuid -> (expire, enriched_data)
_OVERVIEW_ENRICHMENT_TTL = 10  # seconds — enrichment data changes slowly
_MAX_OVERVIEW_ENRICHMENT_CACHE = 4  # max cached entries

# M19: Cache for get_overview_data (2s TTL)
_overview_cache: Dict[str, tuple] = {}  # _state_uuid -> (expire_time, data)
_OVERVIEW_TTL = 2  # seconds
_MAX_OVERVIEW_CACHE = 4  # max cached overview snapshots

# M5: Cache for get_functions_data (2s TTL)
_functions_cache: Dict[str, tuple] = {}  # _state_uuid -> (expire_time, version_key, data)
_FUNCTIONS_TTL = 2  # seconds
_MAX_FUNCTIONS_CACHE = 4  # max cached function lists

# M8: Cache for get_strings_data (2s TTL)
_strings_cache: Dict[str, tuple] = {}  # _state_uuid -> (expire_time, version_key, data)
_STRINGS_TTL = 2  # seconds
_MAX_STRINGS_CACHE = 4  # max cached string listings

# Shared lock protecting all module-level caches above
_cache_lock = threading.Lock()


def _cleanup_session_caches(state_uuid: str) -> None:
    """L5-v8: Remove stale entries for a reaped session from module-level caches.

    Called from the session reaper in state.py to prevent stale entries
    from accumulating after session cleanup.
    """
    with _cache_lock:
        for cache in [_func_lookup_cache, _overview_enrichment_cache,
                      _overview_cache, _functions_cache, _strings_cache]:
            cache.pop(state_uuid, None)


def _build_score_lookup(st) -> Dict[str, int]:
    """Build addr→score mapping from cached enrichment scores."""
    lookup: Dict[str, int] = {}
    cached_scores = getattr(st, "_cached_function_scores", None)
    if cached_scores:
        for s in cached_scores:
            lookup[s.get("addr", "")] = s.get("score", 0)
    return lookup


def _build_function_lookup(st) -> tuple:
    """Build a sorted list of (start, end, addr_hex, name) from angr KB + renames.

    Results are cached per-state for ``_FUNC_LOOKUP_TTL`` seconds to avoid
    rebuilding on every dashboard poll (overview, strings, timeline, etc.).

    Returns ``(entries, starts)`` where *starts* is a pre-computed list of
    start addresses for use with `bisect`.  Returns ``([], [])`` if angr
    is unavailable or no CFG loaded.
    """
    now = time.time()
    cache_key = st._state_uuid
    with _cache_lock:
        cached = _func_lookup_cache.get(cache_key)
        if cached is not None:
            expire_time, cached_fp, entries, starts = cached
            if now < expire_time and cached_fp == st.filepath:
                return entries, starts

    empty = ([], [])
    if st.angr_project is None or st.angr_cfg is None:
        with _cache_lock:
            _func_lookup_cache[cache_key] = (now + _FUNC_LOOKUP_TTL, st.filepath, [], [])
        return empty
    try:
        kb = st.angr_project.kb
        if not hasattr(kb, "functions"):
            with _cache_lock:
                _func_lookup_cache[cache_key] = (now + _FUNC_LOOKUP_TTL, st.filepath, [], [])
            return empty
    except Exception:
        with _cache_lock:
            _func_lookup_cache[cache_key] = (now + _FUNC_LOOKUP_TTL, st.filepath, [], [])
        return empty

    renames = st.get_renames().get("functions", {})
    entries = []
    for addr, func in kb.functions.items():
        addr_hex = hex(addr)
        name = renames.get(addr_hex, func.name or addr_hex)
        size = func.size or 1
        entries.append((addr, addr + size, addr_hex, name))
    entries.sort(key=lambda e: e[0])
    starts = [e[0] for e in entries]  # pre-compute for bisect

    with _cache_lock:
        # Evict oldest entries if cache grows too large
        if len(_func_lookup_cache) >= _MAX_FUNC_LOOKUP_CACHE:
            oldest_key = min(_func_lookup_cache, key=lambda k: _func_lookup_cache[k][0])
            del _func_lookup_cache[oldest_key]

        _func_lookup_cache[cache_key] = (now + _FUNC_LOOKUP_TTL, st.filepath, entries, starts)
    return entries, starts


def _find_containing_function(func_lookup: tuple, va: int):
    """Binary search for the function containing virtual address *va*.

    *func_lookup* is a ``(entries, starts)`` tuple from
    ``_build_function_lookup``.  Returns ``(addr_hex, name)`` or ``None``.
    """
    entries, starts = func_lookup
    if not entries:
        return None
    idx = bisect.bisect_right(starts, va) - 1
    if idx < 0:
        return None
    entry = entries[idx]
    if entry[0] <= va < entry[1]:
        return (entry[2], entry[3])
    return None


def _file_offset_to_va(st, file_offset: int):
    """Convert a PE file offset to a virtual address using pefile.

    Returns the VA as an ``int``, or ``None`` on failure.
    """
    pe = st.pe_object
    if pe is None:
        return None
    try:
        if not hasattr(pe, "get_rva_from_offset") or not hasattr(pe, "OPTIONAL_HEADER"):
            return None
        rva = pe.get_rva_from_offset(file_offset)
        if rva is None:
            return None
        return rva + pe.OPTIONAL_HEADER.ImageBase
    except Exception:
        return None


def _is_executable_va(st, va: int) -> bool:
    """Check if a VA falls within a section with execute permission."""
    pe = st.pe_object
    if pe is None:
        return False
    try:
        image_base = pe.OPTIONAL_HEADER.ImageBase
        rva = va - image_base
        for section in pe.sections:
            sec_start = section.VirtualAddress
            sec_end = sec_start + max(section.Misc_VirtualSize, section.SizeOfRawData)
            if sec_start <= rva < sec_end:
                return bool(section.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
        return False  # not in any section (e.g. PE header)
    except Exception:
        return False


def _apply_overview_enrichment(st, pe_data: dict, floss: dict, binary_summary: dict):
    """Resolve function links for capa, YARA, FLOSS, and high-value strings.

    Results are cached per-state for ``_OVERVIEW_ENRICHMENT_TTL`` seconds
    to avoid rebuilding VA maps on every dashboard poll.
    """
    func_lookup = _build_function_lookup(st)
    has_funcs = bool(func_lookup[0])

    # Check enrichment cache (includes file hash to prevent cross-file pollution)
    now = time.time()
    cache_key = st._state_uuid
    func_count = len(func_lookup[0]) if has_funcs else 0
    floss_strs = floss.get("strings", {}) if isinstance(floss, dict) else {}
    file_hash = pe_data.get("file_hashes", {}).get("sha256", "") if isinstance(pe_data, dict) else ""
    version = (
        file_hash,
        func_count,
        len(binary_summary.get("capabilities", [])),
        len(binary_summary.get("yara_matches", [])),
        len(floss_strs.get("decoded_strings", [])) if isinstance(floss_strs, dict) else 0,
        len(floss_strs.get("stack_strings", [])) if isinstance(floss_strs, dict) else 0,
        len(binary_summary.get("high_value_strings", [])),
        len(binary_summary.get("ioc_urls", [])),
        len(binary_summary.get("ioc_ips", [])),
        len(binary_summary.get("ioc_domains", [])),
    )
    with _cache_lock:
        cached = _overview_enrichment_cache.get(cache_key)
    if cached is not None:
        expire_time, cached_version, cached_data = cached
        if now < expire_time and cached_version == version:
            for key in ("capabilities", "yara_matches", "floss_top_decoded",
                        "floss_top_stack", "high_value_strings",
                        "ioc_urls", "ioc_ips", "ioc_domains"):
                if key in cached_data:
                    binary_summary[key] = cached_data[key]
            return

    # --- Compute enrichment ---

    # Helper: resolve VA to function name, with raw-VA fallback
    def _resolve_va(va_int, va_hex=None):
        """Returns (func_addr, func_name) or None."""
        hit = _find_containing_function(func_lookup, va_int) if has_funcs else None
        if hit:
            return hit
        # Raw VA fallback only when angr has no functions (e.g. .NET)
        if not has_funcs:
            if va_hex is None:
                va_hex = hex(va_int)
            return (va_hex, va_hex)
        return None

    # Capa capabilities → match addresses → containing function
    if binary_summary.get("capabilities") and 'capa_analysis' in pe_data:
        capa_results = pe_data['capa_analysis']
        if isinstance(capa_results, dict) and isinstance(capa_results.get('results'), dict):
            capa_rules = capa_results['results'].get('rules', {})
            for cap in binary_summary["capabilities"]:
                cap_name = cap.get("capability", "")
                for _rule_id, rule_details in capa_rules.items():
                    meta = rule_details.get('meta', {})
                    if meta.get('name') == cap_name:
                        matches = rule_details.get('matches')
                        first_addr = None
                        if isinstance(matches, dict) and matches:
                            first_addr = next(iter(matches))
                        elif isinstance(matches, list) and matches:
                            item = matches[0]
                            if isinstance(item, list) and item and isinstance(item[0], dict):
                                first_addr = item[0].get("value")
                        if isinstance(first_addr, int):
                            cap["match_addr"] = hex(first_addr)
                            resolved = _resolve_va(first_addr)
                            if resolved:
                                cap["func_addr"] = resolved[0]
                                cap["func_name"] = resolved[1]
                        break

    # YARA matches → first string offset → file offset → VA → function
    if binary_summary.get("yara_matches"):
        raw_yara = pe_data.get('yara_matches', [])
        yara_by_rule = {}
        if isinstance(raw_yara, list):
            for ym in raw_yara:
                if isinstance(ym, dict):
                    yara_by_rule[ym.get('rule', ym.get('name', ''))] = ym
        for ym_summary in binary_summary["yara_matches"]:
            raw = yara_by_rule.get(ym_summary.get("rule"))
            if not raw:
                continue
            strings = raw.get("strings", [])
            if not isinstance(strings, list) or not strings:
                continue
            first_str = strings[0]
            if not isinstance(first_str, dict):
                continue
            offset_hex = first_str.get("offset")
            if not offset_hex:
                continue
            try:
                file_offset = int(offset_hex, 16)
            except (ValueError, TypeError):
                continue
            va = _file_offset_to_va(st, file_offset)
            if va is not None and _is_executable_va(st, va):
                ym_summary["match_addr"] = hex(va)
                resolved = _resolve_va(va)
                if resolved:
                    ym_summary["func_addr"] = resolved[0]
                    ym_summary["func_name"] = resolved[1]

    # Build combined FLOSS string→VA map (used for FLOSS top, high-value, and IOC enrichment)
    floss_string_va_map = {}  # string_text → VA hex
    if isinstance(floss, dict):
        floss_strings_data = floss.get("strings", {})
        if isinstance(floss_strings_data, dict):
            for s in floss_strings_data.get("decoded_strings", []):
                if isinstance(s, dict) and s.get("decoding_routine_va"):
                    floss_string_va_map[s.get("string", "")] = s["decoding_routine_va"]
            for s in floss_strings_data.get("stack_strings", []):
                if isinstance(s, dict) and s.get("function_va"):
                    floss_string_va_map.setdefault(s.get("string", ""), s["function_va"])
            for s in floss_strings_data.get("static_strings", []):
                if not isinstance(s, dict):
                    continue
                text = s.get("string", "")
                if text in floss_string_va_map:
                    continue
                refs = s.get("references")
                if isinstance(refs, list) and refs:
                    first_ref = refs[0]
                    if isinstance(first_ref, str):
                        floss_string_va_map[text] = first_ref
                        continue
                # Fallback: convert file offset → VA for strings without references
                offset_hex = s.get("offset")
                if offset_hex:
                    try:
                        file_off = int(offset_hex, 16)
                        va = _file_offset_to_va(st, file_off)
                        if va is not None:
                            floss_string_va_map[text] = hex(va)
                    except (ValueError, TypeError):
                        pass

    # Helper: enrich a string with function link from the FLOSS VA map
    def _enrich_from_floss(text, entry_dict):
        va_hex = floss_string_va_map.get(text)
        if va_hex:
            try:
                va_int = int(va_hex, 16)
                resolved = _resolve_va(va_int, va_hex)
                if resolved:
                    entry_dict["func_addr"] = resolved[0]
                    entry_dict["func_name"] = resolved[1]
            except (ValueError, TypeError):
                pass

    # FLOSS top decoded/stack → enrich with function links
    if isinstance(floss, dict):
        if binary_summary.get("floss_top_decoded"):
            enriched_decoded = []
            for item in binary_summary["floss_top_decoded"]:
                full_text = item.get("_full", item.get("string", "")) if isinstance(item, dict) else str(item)
                display = item.get("string", full_text[:120]) if isinstance(item, dict) else str(item)[:120]
                entry = {"string": display}
                _enrich_from_floss(full_text, entry)
                enriched_decoded.append(entry)
            binary_summary["floss_top_decoded"] = enriched_decoded

        if binary_summary.get("floss_top_stack"):
            enriched_stack = []
            for item in binary_summary["floss_top_stack"]:
                full_text = item.get("_full", item.get("string", "")) if isinstance(item, dict) else str(item)
                display = item.get("string", full_text[:120]) if isinstance(item, dict) else str(item)[:120]
                entry = {"string": display}
                _enrich_from_floss(full_text, entry)
                enriched_stack.append(entry)
            binary_summary["floss_top_stack"] = enriched_stack

    # High-value strings → cross-ref with FLOSS for function VAs
    if binary_summary.get("high_value_strings"):
        for hv in binary_summary["high_value_strings"]:
            _enrich_from_floss(hv.get("_full", hv.get("string", "")), hv)

    # Network IOCs → cross-ref with FLOSS for function VAs
    if floss_string_va_map or binary_summary.get("ioc_urls") or binary_summary.get("ioc_ips") or binary_summary.get("ioc_domains"):
        for ioc_key in ("ioc_urls", "ioc_ips", "ioc_domains"):
            items = binary_summary.get(ioc_key, [])
            if not items:
                continue
            enriched = []
            for ioc in items:
                if isinstance(ioc, str):
                    entry = {"value": ioc}
                    _enrich_from_floss(ioc, entry)
                    enriched.append(entry)
                elif isinstance(ioc, dict):
                    _enrich_from_floss(ioc.get("value", ""), ioc)
                    enriched.append(ioc)
                else:
                    enriched.append(ioc)
            binary_summary[ioc_key] = enriched

    # Cache the enriched data (deep-copy the lists we modified)
    enriched_data = {}
    for key in ("capabilities", "yara_matches", "floss_top_decoded",
                "floss_top_stack", "high_value_strings",
                "ioc_urls", "ioc_ips", "ioc_domains"):
        if key in binary_summary:
            enriched_data[key] = copy.deepcopy(binary_summary[key])
    with _cache_lock:
        _overview_enrichment_cache[cache_key] = (now + _OVERVIEW_ENRICHMENT_TTL, version, enriched_data)
        # Evict stale/excess entries
        if len(_overview_enrichment_cache) > _MAX_OVERVIEW_ENRICHMENT_CACHE:
            stale = [k for k, v in _overview_enrichment_cache.items()
                     if k != cache_key and v[0] < now]
            for k in stale:
                del _overview_enrichment_cache[k]
            if len(_overview_enrichment_cache) > _MAX_OVERVIEW_ENRICHMENT_CACHE:
                oldest_key = min(
                    (k for k in _overview_enrichment_cache if k != cache_key),
                    key=lambda k: _overview_enrichment_cache[k][0],
                    default=None,
                )
                if oldest_key:
                    del _overview_enrichment_cache[oldest_key]


def get_overview_data() -> Dict[str, Any]:
    """File info, hashes, phase, coverage stats, background tasks."""
    st = _get_state()

    # M19: Short-TTL cache to avoid redundant work on rapid polling
    now = time.time()
    cache_key = st._state_uuid
    with _cache_lock:
        cached = _overview_cache.get(cache_key)
    if cached is not None:
        expire_time, cached_filepath, cached_data = cached
        if now < expire_time and cached_filepath == st.filepath:
            return copy.deepcopy(cached_data)

    pe_data = st.pe_data or {}

    # Basic file info
    filepath = st.filepath
    filename = os.path.basename(filepath) if filepath else None
    hashes = pe_data.get("file_hashes", {})
    mode = pe_data.get("mode", "pe")
    fmt = pe_data.get("format", mode.upper() if mode else "Unknown")

    # Analysis phase
    phase = _detect_phase(st)

    # Function coverage
    total_funcs = 0
    explored_funcs = 0
    if st.angr_cfg is not None:
        try:
            kb = st.angr_project.kb if st.angr_project else None
            if kb and hasattr(kb, "functions"):
                total_funcs = len(kb.functions)
        except Exception:
            pass
    # Count functions that have been decompiled (appear in result_cache)
    explored_funcs = len(_get_decompiled_addresses())

    # Background tasks
    tasks = []
    now = time.time()
    with st._task_lock:
        for tid, t in st.background_tasks.items():
            task_info = {
                "id": tid,
                "tool": t.get("tool", "unknown"),
                "status": t.get("status", "unknown"),
                "progress_percent": t.get("progress_percent", 0),
                "progress_message": t.get("progress_message", ""),
                "elapsed_s": 0,
                "stall_s": 0,
            }
            created = t.get("created_at_epoch")
            if created:
                task_info["elapsed_s"] = int(now - created)
            last_progress = t.get("last_progress_epoch")
            if last_progress and t.get("status") in (TASK_RUNNING, TASK_OVERTIME):
                stall = int(now - last_progress)
                if stall > 30:  # Only flag as stalled after 30 seconds
                    task_info["stall_s"] = stall
            tasks.append(task_info)

    # Counts
    notes = st.get_notes()
    notes_count = len(notes)
    tool_calls = st.get_tool_history_count()  # L2-v8: avoid full deque copy
    all_artifacts = st.get_artifacts()
    artifacts_count = len(all_artifacts)

    # Binary summary from cached triage
    binary_summary = {}
    triage = getattr(st, "_cached_triage", None)
    if triage and isinstance(triage, dict):
        binary_summary["risk_score"] = triage.get("risk_score", 0)
        binary_summary["risk_level"] = triage.get("risk_level", "UNKNOWN")

        # Packing
        packing = triage.get("packing_assessment", {})
        if isinstance(packing, dict):
            binary_summary["likely_packed"] = packing.get("likely_packed", False)
            binary_summary["packer_name"] = packing.get("packer_name", "")
            binary_summary["entropy"] = packing.get("overall_entropy")

        # Signature
        sig = triage.get("digital_signature", {})
        if isinstance(sig, dict):
            binary_summary["signed"] = sig.get("embedded_signature_present", False)
            binary_summary["signer"] = sig.get("signer_name", "")

        # Security mitigations
        mitigations = triage.get("security_mitigations", {})
        if isinstance(mitigations, dict):
            binary_summary["aslr"] = mitigations.get("aslr", False)
            binary_summary["dep"] = mitigations.get("dep", False)
            binary_summary["cfg"] = mitigations.get("cfg", False)

        # Top findings
        binary_summary["top_findings"] = triage.get("top_findings", [])[:5]

        # Suspicious imports summary
        sus_imports = triage.get("suspicious_imports", [])
        if isinstance(sus_imports, list):
            binary_summary["suspicious_import_count"] = len(sus_imports)

        # Suspicious import categories
        sus_import_summary = triage.get("suspicious_import_summary", {})
        if isinstance(sus_import_summary, dict):
            binary_summary["import_categories"] = sus_import_summary

        # Network IOCs — full lists (top 5 each)
        net_iocs = triage.get("network_iocs", {})
        if isinstance(net_iocs, dict):
            ioc_count = sum(
                len(v) for v in net_iocs.values() if isinstance(v, list)
            )
            binary_summary["ioc_count"] = ioc_count
            binary_summary["ioc_urls"] = net_iocs.get("urls", [])[:5]
            binary_summary["ioc_ips"] = net_iocs.get("ip_addresses", [])[:5]
            binary_summary["ioc_domains"] = net_iocs.get("domains", [])[:5]
            binary_summary["ioc_registry"] = net_iocs.get("registry_paths", [])[:5]

        # Section anomalies
        anomalies = triage.get("section_anomalies", [])
        if isinstance(anomalies, list):
            binary_summary["section_anomaly_count"] = len(anomalies)

        # Timestamp
        ts_analysis = triage.get("timestamp_analysis", {})
        if isinstance(ts_analysis, dict):
            binary_summary["compile_time"] = ts_analysis.get("compile_time", "")
            binary_summary["timestamp_suspicious"] = ts_analysis.get("suspicious", False)

        # Compiler / language (simple + full detail)
        compiler = triage.get("compiler_language", {})
        if isinstance(compiler, dict):
            binary_summary["language"] = compiler.get("language", "")
            binary_summary["compiler_detail"] = {
                "detected_languages": compiler.get("detected_languages", []),
                "go_indicators": compiler.get("go_indicators", []),
                "rust_indicators": compiler.get("rust_indicators", []),
                "delphi_indicators": compiler.get("delphi_indicators", []),
                "msvc_indicators": compiler.get("msvc_indicators", []),
            }
        elif isinstance(compiler, str):
            binary_summary["language"] = compiler

        # Classification (from auto-enrichment)
        classification = getattr(st, "_cached_classification", None)
        if classification and isinstance(classification, dict):
            binary_summary["classification"] = classification.get("primary_type", "")
            binary_summary["classification_confidence"] = classification.get("confidence", "")

    # M8-v9: Single pass over notes to extract hypothesis and conclusion
    hypothesis_notes = []
    conclusion_notes = []
    for n in notes:
        cat = n.get("category")
        if cat == "hypothesis" and n.get("content"):
            hypothesis_notes.append(n)
        elif cat == "conclusion" and n.get("content"):
            conclusion_notes.append(n)
    if hypothesis_notes:
        binary_summary["ai_assessment"] = hypothesis_notes[-1].get("content", "")[:300]
    if conclusion_notes:
        binary_summary["ai_conclusion"] = conclusion_notes[-1].get("content", "")[:10000]

    if triage and isinstance(triage, dict):
        # Capabilities (capa matches) — top 10
        capabilities = triage.get("suspicious_capabilities", [])
        if isinstance(capabilities, list) and capabilities:
            binary_summary["capabilities"] = [
                {
                    "capability": c.get("capability", ""),
                    "namespace": c.get("namespace", ""),
                    "severity": c.get("severity", ""),
                }
                for c in capabilities[:10]
                if isinstance(c, dict)
            ]

        # YARA matches
        yara_matches = triage.get("yara_matches", [])
        if isinstance(yara_matches, list) and yara_matches:
            binary_summary["yara_matches"] = [
                {
                    "rule": y.get("rule", ""),
                    "description": (y.get("meta", {}) or {}).get("description", ""),
                    "tags": y.get("tags", []),
                    "match_count": len(y.get("strings", [])),
                }
                for y in yara_matches
                if isinstance(y, dict)
            ]

        # High-value strings — top 8
        hv_strings = triage.get("high_value_strings", [])
        if isinstance(hv_strings, list) and hv_strings:
            binary_summary["high_value_strings"] = [
                {
                    "string": s.get("string", "")[:120],
                    "_full": s.get("string", ""),
                    "category": s.get("category", ""),
                    "sifter_score": s.get("sifter_score", 0),
                }
                for s in hv_strings[:8]
                if isinstance(s, dict)
            ]

        # Rich header
        rich = triage.get("rich_header_summary", {})
        if isinstance(rich, dict):
            binary_summary["rich_header"] = {
                "present": rich.get("present", False),
                "raw_hash": rich.get("rich_hash", ""),
                "entry_count": rich.get("entry_count", 0),
                "anomaly": rich.get("anomaly", ""),
            }

        # Header anomalies — top 5
        header_anom = triage.get("header_anomalies", [])
        if isinstance(header_anom, list) and header_anom:
            binary_summary["header_anomalies"] = [
                {
                    "issue": a.get("issue", ""),
                    "severity": a.get("severity", ""),
                }
                for a in header_anom[:5]
                if isinstance(a, dict)
            ]

        # TLS callbacks
        tls = triage.get("tls_callbacks", {})
        if isinstance(tls, dict):
            binary_summary["tls_callbacks"] = {
                "present": tls.get("present", False),
                "callback_count": tls.get("callback_count", 0),
                "warning": tls.get("note", ""),
            }

        # Overlay analysis
        overlay = triage.get("overlay_analysis", {})
        if isinstance(overlay, dict):
            binary_summary["overlay"] = {
                "present": overlay.get("present", False),
                "size": overlay.get("size", 0),
                "entropy": overlay.get("entropy", 0),
                "suspected_type": overlay.get("potential_payload_type", ""),
            }

        # Resource anomalies — top 3
        res_anom = triage.get("resource_anomalies", [])
        if isinstance(res_anom, list) and res_anom:
            binary_summary["resource_anomalies"] = [
                {
                    "type": r.get("type", r.get("name", "")),
                    "anomaly": r.get("anomaly", r.get("issue", "")),
                    "entropy": r.get("entropy", 0),
                }
                for r in res_anom[:3]
                if isinstance(r, dict)
            ]

        # Version info anomalies
        ver_info = triage.get("version_info_anomalies", {})
        if isinstance(ver_info, dict):
            ver_anomalies = ver_info.get("anomalies", [])
            if ver_anomalies or ver_info.get("original_filename"):
                binary_summary["version_info"] = {
                    "original_filename": ver_info.get("original_filename", ""),
                    "company_name": ver_info.get("company_name", ""),
                    "anomalies": ver_anomalies[:3] if isinstance(ver_anomalies, list) else [],
                }

        # .NET indicators
        dotnet = triage.get("dotnet_indicators", {})
        if isinstance(dotnet, dict) and dotnet.get("is_dotnet"):
            binary_summary["dotnet"] = {
                "is_dotnet": True,
                "clr_version": dotnet.get("clr_version", ""),
                "assembly_name": dotnet.get("assembly_name", ""),
            }

        # Export anomalies
        exp_anom = triage.get("export_anomalies", {})
        if isinstance(exp_anom, dict):
            ord_count = exp_anom.get("ordinal_only_count", 0)
            fwd_count = exp_anom.get("forwarded_count", 0)
            if ord_count or fwd_count:
                binary_summary["export_anomalies"] = {
                    "ordinal_only_count": ord_count,
                    "forwarded_count": fwd_count,
                }

        # Delay-load risks
        delay = triage.get("delay_load_risks", {})
        if isinstance(delay, dict):
            dll_count = delay.get("delay_load_dll_count", 0)
            sus_apis = delay.get("suspicious_delay_loaded_apis", [])
            if dll_count or sus_apis:
                binary_summary["delay_load"] = {
                    "dll_count": dll_count,
                    "suspicious_apis": [
                        a.get("function", str(a)) if isinstance(a, dict) else str(a)
                        for a in (sus_apis[:3] if isinstance(sus_apis, list) else [])
                    ],
                }

        # ELF security
        elf_sec = triage.get("elf_security", {})
        if isinstance(elf_sec, dict) and elf_sec:
            binary_summary["elf_security"] = elf_sec

        # Mach-O security
        macho_sec = triage.get("macho_security", {})
        if isinstance(macho_sec, dict) and macho_sec:
            binary_summary["macho_security"] = macho_sec

        # Expanded security mitigations
        mitigations = triage.get("security_mitigations", {})
        if isinstance(mitigations, dict):
            binary_summary["cet"] = mitigations.get("cet", False)
            binary_summary["xfg"] = mitigations.get("xfg", False)
            binary_summary["no_seh"] = mitigations.get("no_seh", False)
            binary_summary["high_entropy_aslr"] = mitigations.get(
                "high_entropy_aslr", False
            )

    # File size
    binary_summary["file_size"] = pe_data.get("file_size", 0)

    # PEiD
    peid = pe_data.get("peid_matches", [])
    if isinstance(peid, list) and peid:
        binary_summary["peid"] = peid[:3]

    # Import summary
    imports = pe_data.get("imports", [])
    if isinstance(imports, list):
        dll_count = len(imports)
        func_count = sum(
            len(d.get("symbols", [])) for d in imports if isinstance(d, dict)
        )
        binary_summary["import_dlls"] = dll_count
        binary_summary["import_functions"] = func_count

    # String counts
    basic_strings = pe_data.get("basic_ascii_strings", [])
    binary_summary["basic_string_count"] = len(basic_strings) if isinstance(basic_strings, list) else 0

    floss = pe_data.get("floss_analysis", {})
    if isinstance(floss, dict):
        floss_strings = floss.get("strings", {})
        if isinstance(floss_strings, dict):
            binary_summary["floss_static_count"] = len(floss_strings.get("static_strings", []))
            binary_summary["floss_stack_count"] = len(floss_strings.get("stack_strings", []))
            binary_summary["floss_decoded_count"] = len(floss_strings.get("decoded_strings", []))
            # Top decoded/stack strings for overview display
            decoded = floss_strings.get("decoded_strings", [])
            stack = floss_strings.get("stack_strings", [])
            top_decoded = []
            for s in decoded[:10]:
                if isinstance(s, dict):
                    full = s.get("string", str(s))
                    top_decoded.append({"string": full[:120], "_full": full})
                elif isinstance(s, str):
                    top_decoded.append({"string": s[:120], "_full": s})
            top_stack = []
            for s in stack[:10]:
                if isinstance(s, dict):
                    full = s.get("string", str(s))
                    top_stack.append({"string": full[:120], "_full": full})
                elif isinstance(s, str):
                    top_stack.append({"string": s[:120], "_full": s})
            if top_decoded:
                binary_summary["floss_top_decoded"] = top_decoded
            if top_stack:
                binary_summary["floss_top_stack"] = top_stack
        floss_status = floss.get("status", "")
        binary_summary["floss_status"] = floss_status

    # --- Enrich items with function links (cached) ---
    try:
        _apply_overview_enrichment(st, pe_data, floss, binary_summary)
    except Exception:
        logger.debug("Overview enrichment failed", exc_info=True)

    # Triage flags from dashboard
    triage_status = st.get_all_triage_snapshot()
    triage_counts = {}
    if triage_status:
        for s in triage_status.values():
            triage_counts[s] = triage_counts.get(s, 0) + 1

    # Recent notes (last 5)
    recent_notes = []
    note_func_lookup = _build_function_lookup(st)
    for n in reversed(notes[-5:]):
        note_entry = {
            "category": n.get("category", "general"),
            "content": n.get("content", "")[:200],
            "address": n.get("address"),
            "timestamp": (n.get("created_at", "") or "")[:19],
        }
        # Resolve note address to containing function
        addr_str = n.get("address")
        if addr_str and note_func_lookup[0]:
            try:
                addr_int = int(addr_str, 16)
                hit = _find_containing_function(note_func_lookup, addr_int)
                if hit:
                    note_entry["func_addr"] = hit[0]
                    note_entry["func_name"] = hit[1]
            except (ValueError, TypeError):
                pass
        recent_notes.append(note_entry)

    # Renames count
    renames = st.get_renames()
    rename_count = len(renames.get("functions", {}))
    rename_var_count = sum(
        len(v) for v in renames.get("variables", {}).values()
        if isinstance(v, dict)
    )
    label_count = len(renames.get("labels", {}))

    # Custom types count
    custom_types = getattr(st, "custom_types", {}) or {}
    custom_type_count = (
        len(custom_types.get("structs", {}))
        + len(custom_types.get("enums", {}))
    )

    # Recent artifacts (last 5)
    recent_artifacts = [
        {
            "description": a.get("description", "")[:100],
            "detected_type": a.get("detected_type", ""),
            "source_tool": a.get("source_tool", ""),
        }
        for a in all_artifacts[-5:]
    ]

    # Active tool (for loading status)
    active_tool = None
    active_tools = []
    active_tool_progress = 0
    active_tool_total = 100
    with st._active_tool_lock:
        active_tool = st.active_tool
        active_tools = list(st._active_tools)
        active_tool_progress = st.active_tool_progress
        active_tool_total = st.active_tool_total

    # Resource usage (process-level memory/CPU)
    try:
        from arkana.resource_monitor import get_resource_snapshot
        resource_usage = get_resource_snapshot()
    except Exception:
        resource_usage = None

    # Active project context (Phase 2: PROJECTS feature)
    active_project_info = None
    try:
        _proj = st.get_active_project() if hasattr(st, "get_active_project") else None
        if _proj is not None:
            _dash_state = {}
            try:
                manifest = getattr(_proj, "manifest", None)
                if manifest is not None:
                    _dash_state = dict(getattr(manifest, "dashboard_state", {}) or {})
            except Exception:
                _dash_state = {}
            active_project_info = {
                "id": getattr(_proj, "id", None),
                "name": getattr(_proj, "name", None),
                "scratch": bool(getattr(_proj, "is_scratch", False)),
                "dashboard_state": _dash_state,
            }
    except Exception:
        active_project_info = None

    result = {
        "file_loaded": filepath is not None,
        "filename": filename,
        "filepath": os.path.basename(filepath) if filepath else None,
        "active_project": active_project_info,
        "format": fmt,
        "mode": mode,
        "sha256": hashes.get("sha256"),
        "md5": hashes.get("md5"),
        "phase": phase,
        "total_functions": total_funcs,
        "explored_functions": explored_funcs,
        "background_tasks": tasks,
        "notes_count": notes_count,
        "tool_calls": tool_calls,
        "artifacts_count": artifacts_count,
        "binary_summary": binary_summary,
        "triage_counts": triage_counts,
        "recent_notes": recent_notes,
        "rename_count": rename_count,
        "rename_var_count": rename_var_count,
        "label_count": label_count,
        "custom_type_count": custom_type_count,
        "recent_artifacts": recent_artifacts,
        "active_tool": active_tool,
        "active_tools": active_tools,
        "active_tool_progress": active_tool_progress,
        "active_tool_total": active_tool_total,
        "resource_usage": resource_usage,
    }

    # M-E5: Cache the result — deep copy only on write (callers get deep copy on read).
    # This avoids the previous double-copy pattern where both write and read did deepcopy.
    with _cache_lock:
        _overview_cache[cache_key] = (time.time() + _OVERVIEW_TTL, st.filepath, copy.deepcopy(result))
        # Evict stale entries
        if len(_overview_cache) > _MAX_OVERVIEW_CACHE:
            stale = [k for k, (exp, _fp, _data) in _overview_cache.items() if time.time() > exp]
            for k in stale:
                _overview_cache.pop(k, None)

    # Return the original (not-yet-shared) result directly — it was just built
    # and hasn't been exposed to any other code path yet.
    return result


def get_functions_data(sort_by: str = "address",
                       filter_triage: Optional[str] = None,
                       min_score: float = 0.0,
                       search: str = "",
                       sort_asc: bool = True) -> List[Dict[str, Any]]:
    """Function list with risk scores, complexity, triage status."""
    st = _get_state()
    functions = []

    if st.angr_project is None or st.angr_cfg is None:
        return functions

    # M5: Short TTL cache keyed on parameters + state identity
    now = time.time()
    cache_key = st._state_uuid
    # Use function-relevant change signals instead of tool_history length
    _renames = st.get_renames()
    _triage_snap = st.get_all_triage_snapshot()
    version_key = (sort_by, filter_triage, min_score, search, sort_asc,
                   getattr(st, 'filepath', None),
                   len(_renames.get('functions', {})),
                   len(_triage_snap))
    with _cache_lock:
        cached = _functions_cache.get(cache_key)
        if cached is not None:
            expire_time, cached_version, cached_data = cached
            if now < expire_time and cached_version == version_key:
                # Return shallow copy — inner dicts are shared references.
                # All consumers (JSON serialization, Jinja2 templates) are read-only.
                return list(cached_data)

    try:
        kb = st.angr_project.kb
        if not hasattr(kb, "functions"):
            return functions

        # H4-v10: Reuse snapshots from version key computation
        triage = _triage_snap
        renames = _renames.get("functions", {})
        decompiled_addrs = _get_decompiled_addresses()

        score_lookup = _build_score_lookup(st)

        # Build address->notes lookup from function notes
        notes_by_addr: Dict[str, List[str]] = {}
        for n in st.get_notes(category="function"):
            addr = n.get("address")
            if addr:
                notes_by_addr.setdefault(addr, []).append(n.get("content", ""))

        for addr, func in kb.functions.items():
            addr_hex = hex(addr)
            is_renamed = addr_hex in renames
            name = renames.get(addr_hex, func.name)
            size = func.size if hasattr(func, "size") else 0
            complexity = 0
            if hasattr(func, "graph") and func.graph is not None:
                try:
                    complexity = func.graph.number_of_nodes()
                except (AttributeError, TypeError, RuntimeError):
                    pass

            func_notes = notes_by_addr.get(addr_hex, [])
            is_decompiled = addr_hex in decompiled_addrs
            functions.append({
                "address": addr_hex,
                "name": name,
                "size": size,
                "complexity": complexity,
                "score": score_lookup.get(addr_hex, 0),
                "triage_status": triage.get(addr_hex, "unreviewed"),
                "has_note": len(func_notes) > 0,
                "notes": func_notes,
                "is_decompiled": is_decompiled,
                "is_renamed": is_renamed,
                "is_simprocedure": getattr(func, "is_simprocedure", False),
                "is_plt": getattr(func, "is_plt", False),
            })
    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error reading function data from angr KB", exc_info=True)

    # Filter
    if filter_triage and filter_triage != "all":
        functions = [f for f in functions if f["triage_status"] == filter_triage]
    if min_score > 0:
        functions = [f for f in functions if f.get("score", 0) >= min_score]
    if search:
        search_lower = search[:500].lower()
        functions = [f for f in functions if search_lower in f["name"].lower() or search_lower in f["address"].lower()]

    # Sort
    rev = not sort_asc
    if sort_by == "name":
        functions.sort(key=lambda f: f["name"].lower(), reverse=rev)
    elif sort_by == "size":
        functions.sort(key=lambda f: f["size"], reverse=rev)
    elif sort_by == "complexity":
        functions.sort(key=lambda f: f["complexity"], reverse=rev)
    elif sort_by == "score":
        functions.sort(key=lambda f: f["score"], reverse=rev)
    elif sort_by == "triage":
        order = {"flagged": 0, "suspicious": 1, "unreviewed": 2, "clean": 3}
        functions.sort(key=lambda f: order.get(f["triage_status"], 99), reverse=rev)
    else:
        functions.sort(key=lambda f: int(f["address"], 16), reverse=rev)

    # M5: Store in cache
    with _cache_lock:
        if len(_functions_cache) >= _MAX_FUNCTIONS_CACHE and cache_key not in _functions_cache:
            oldest_k = min(_functions_cache, key=lambda k: _functions_cache[k][0])
            _functions_cache.pop(oldest_k, None)
        _functions_cache[cache_key] = (now + _FUNCTIONS_TTL, version_key, functions)

    return functions


def get_callgraph_data() -> Dict[str, Any]:
    """Nodes + edges formatted for Cytoscape.js."""
    st = _get_state()
    nodes = []
    edges = []
    total_functions = 0

    if st.angr_project is None or st.angr_cfg is None:
        return {"nodes": nodes, "edges": edges, "truncated": False, "total_functions": 0}

    try:
        kb = st.angr_project.kb
        if not hasattr(kb, "functions"):
            return {"nodes": nodes, "edges": edges}

        triage = st.get_all_triage_snapshot()
        renames = st.get_renames().get("functions", {})
        decompiled_addrs = _get_decompiled_addresses()

        score_lookup = _build_score_lookup(st)

        # Build set of addresses with function notes
        noted_addrs = set()
        for n in st.get_notes(category="function"):
            a = n.get("address")
            if a:
                noted_addrs.add(a)

        # Build node list (limit to 500 for performance)
        all_func_addrs = list(kb.functions.keys())
        total_functions = len(all_func_addrs)
        func_addrs = all_func_addrs[:500]
        addr_set = set(func_addrs)

        # M6: Build edges first to compute degree maps, then merge into node loop
        in_deg: Dict[str, int] = {}
        out_deg: Dict[str, int] = {}
        if hasattr(kb, "callgraph"):
            cg = kb.callgraph
            max_edges = 5000
            for caller, callee in cg.edges():
                if caller in addr_set and callee in addr_set:
                    src = hex(caller)
                    tgt = hex(callee)
                    edges.append({"data": {"source": src, "target": tgt}})
                    out_deg[src] = out_deg.get(src, 0) + 1
                    in_deg[tgt] = in_deg.get(tgt, 0) + 1
                    if len(edges) >= max_edges:
                        break

        # Build nodes with degree counts and size in a single pass
        for addr in func_addrs:
            func = kb.functions[addr]
            addr_hex = hex(addr)
            is_renamed = addr_hex in renames
            name = renames.get(addr_hex, func.name)
            complexity = 0
            if hasattr(func, "graph") and func.graph is not None:
                try:
                    complexity = func.graph.number_of_nodes()
                except (AttributeError, TypeError, RuntimeError):
                    pass
            explored = is_renamed or addr_hex in decompiled_addrs or addr_hex in noted_addrs
            size = func.size if hasattr(func, "size") else 0
            nodes.append({
                "data": {
                    "id": addr_hex,
                    "label": name,
                    "triage": triage.get(addr_hex, "unreviewed"),
                    "complexity": complexity,
                    "score": score_lookup.get(addr_hex, 0),
                    "explored": "yes" if explored else "no",
                    "renamed": "yes" if is_renamed else "no",
                    "in_deg": in_deg.get(addr_hex, 0),
                    "out_deg": out_deg.get(addr_hex, 0),
                    "size": size,
                }
            })

    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error building call graph data from angr KB", exc_info=True)

    return {
        "nodes": nodes,
        "edges": edges,
        "truncated": total_functions > 500,
        "total_functions": total_functions,
    }


def get_imports_data(search: str = "") -> Dict[str, Any]:
    """Import/export tables for the imports dashboard page."""
    st = _get_state()
    pe_data = st.pe_data or {}
    search_lower = search[:500].lower().strip()

    # Imports
    raw_imports = pe_data.get("imports", [])
    import_dlls = []
    total_import_funcs = 0
    if isinstance(raw_imports, list):
        for dll_entry in raw_imports:
            if not isinstance(dll_entry, dict):
                continue
            dll_name = dll_entry.get("dll", dll_entry.get("name", "?"))
            symbols = dll_entry.get("symbols", dll_entry.get("functions", []))
            if not isinstance(symbols, list):
                symbols = []
            funcs = []
            for sym in symbols:
                if isinstance(sym, dict):
                    fname = sym.get("name", sym.get("function", ""))
                    addr = sym.get("address", sym.get("addr", ""))
                    ordinal = sym.get("ordinal", "")
                elif isinstance(sym, str):
                    fname = sym
                    addr = ""
                    ordinal = ""
                else:
                    continue
                if search_lower and search_lower not in fname.lower() and search_lower not in dll_name.lower():
                    continue
                funcs.append({
                    "name": fname,
                    "address": addr,
                    "ordinal": ordinal,
                })
            if funcs or not search_lower:
                total_import_funcs += len(funcs)
                import_dlls.append({
                    "dll": dll_name,
                    "functions": funcs,
                    "count": len(funcs),
                })

    # Exports
    raw_exports = pe_data.get("exports", {})
    exports = []
    if isinstance(raw_exports, dict):
        for exp in raw_exports.get("functions", raw_exports.get("symbols", [])):
            if isinstance(exp, dict):
                ename = exp.get("name", exp.get("function", ""))
                addr = exp.get("address", exp.get("addr", ""))
                ordinal = exp.get("ordinal", "")
                if search_lower and search_lower not in ename.lower():
                    continue
                exports.append({
                    "name": ename,
                    "address": addr,
                    "ordinal": ordinal,
                })
    elif isinstance(raw_exports, list):
        for exp in raw_exports:
            if isinstance(exp, dict):
                ename = exp.get("name", exp.get("function", ""))
                addr = exp.get("address", exp.get("addr", ""))
                ordinal = exp.get("ordinal", "")
                if search_lower and search_lower not in ename.lower():
                    continue
                exports.append({
                    "name": ename,
                    "address": addr,
                    "ordinal": ordinal,
                })

    # Suspicious import info from triage
    suspicious_apis = []
    triage = getattr(st, "_cached_triage", None)
    if triage and isinstance(triage, dict):
        sus = triage.get("suspicious_imports", [])
        if isinstance(sus, list):
            suspicious_apis = [
                s.get("function", str(s)) if isinstance(s, dict) else str(s)
                for s in sus[:50]
            ]
        sus_summary = triage.get("suspicious_import_summary", {})
        if isinstance(sus_summary, dict):
            import_categories = sus_summary
        else:
            import_categories = {}
    else:
        import_categories = {}

    # Enrich export addresses with function links
    func_lookup = _build_function_lookup(st)
    if func_lookup[0]:
        for exp in exports:
            addr = exp.get("address", "")
            if addr:
                try:
                    va_int = int(addr, 16) if isinstance(addr, str) else int(addr)
                    hit = _find_containing_function(func_lookup, va_int)
                    if hit:
                        exp["func_addr"] = hit[0]
                        exp["func_name"] = hit[1]
                except (ValueError, TypeError):
                    pass

    return {
        "imports": import_dlls,
        "total_import_dlls": len(import_dlls),
        "total_import_functions": total_import_funcs,
        "exports": exports,
        "total_exports": len(exports),
        "suspicious_apis": suspicious_apis,
        "import_categories": import_categories,
        "search": search,
    }


def get_sections_data() -> Dict[str, Any]:
    """Section names, VA ranges, sizes, permissions, entropy, plus PE metadata."""
    st = _get_state()
    pe_data = st.pe_data or {}
    sections = []

    # Try PE sections from pe_data
    raw_sections = pe_data.get("sections", [])
    if isinstance(raw_sections, list):
        for s in raw_sections:
            if isinstance(s, dict):
                sections.append({
                    "name": s.get("name", "?"),
                    "virtual_address": s.get("virtual_address", s.get("va", "?")),
                    "virtual_size": s.get("virtual_size", s.get("vsize", 0)),
                    "raw_size": s.get("raw_size", s.get("size_of_raw_data", 0)),
                    "entropy": s.get("entropy", 0),
                    "permissions": _section_permissions(s),
                })

    # Data directories
    data_dirs = pe_data.get("data_directories", [])
    if not isinstance(data_dirs, list):
        data_dirs = []

    # Resources summary
    resources = pe_data.get("resources", pe_data.get("resources_summary", []))
    if not isinstance(resources, list):
        resources = []

    return {
        "sections": sections,
        "data_directories": data_dirs,
        "resources": resources,
    }


def get_timeline_data(limit: int = 100) -> List[Dict[str, Any]]:
    """Merged tool_history + notes, chronological."""
    st = _get_state()
    entries = []

    # Tool history
    for h in st.get_tool_history():
        # Include request parameters for detail view
        params = h.get("parameters", {})
        # Compact param display: skip ctx and large values
        display_params = {}
        for k, v in (params or {}).items():
            if k == "ctx":
                continue
            if isinstance(v, str):
                display_params[k] = v[:300] + "..." if len(v) > 300 else v
            elif isinstance(v, (int, float, bool)):
                display_params[k] = v
            elif isinstance(v, (dict, list)):
                s = str(v)
                display_params[k] = s[:300] + "..." if len(s) > 300 else s
            else:
                display_params[k] = str(v)[:300]
        full_summary = h.get("result_summary", "")
        entries.append({
            "type": "tool",
            "timestamp": h.get("timestamp", ""),
            "timestamp_epoch": h.get("timestamp_epoch", 0),
            "name": h.get("tool_name", "?"),
            "summary": full_summary[:200],
            "full_summary": full_summary[:2000] if len(full_summary) > 200 else "",
            "duration_ms": h.get("duration_ms", 0),
            "parameters": display_params,
        })

    # Notes — enrich with function links
    func_lookup = _build_function_lookup(st)
    for n in st.get_notes():
        ts = n.get("created_at", "")
        # Parse ISO timestamp to epoch for sorting
        epoch = 0
        try:
            dt = datetime.datetime.fromisoformat(ts)
            epoch = dt.timestamp()
        except (ValueError, TypeError, AttributeError):
            pass
        note_entry: Dict[str, Any] = {
            "type": "note",
            "timestamp": ts,
            "timestamp_epoch": epoch,
            "name": n.get("category", "note"),
            "summary": n.get("content", "")[:200],
            "duration_ms": 0,
            "address": n.get("address", ""),
        }
        addr_str = n.get("address")
        if addr_str and func_lookup[0]:
            try:
                addr_int = int(addr_str, 16)
                hit = _find_containing_function(func_lookup, addr_int)
                if hit:
                    note_entry["func_addr"] = hit[0]
                    note_entry["func_name"] = hit[1]
            except (ValueError, TypeError):
                pass
        entries.append(note_entry)

    # Sort by timestamp
    entries.sort(key=lambda e: e["timestamp_epoch"])
    result = entries[-limit:]

    # Inject active tools as live entries at the end
    with st._active_tool_lock:
        active_tools = list(st._active_tools)
        progress = st.active_tool_progress
        total = st.active_tool_total
    now = time.time()
    for tool_name in active_tools:
        result.append({
            "type": "active",
            "timestamp": "",
            "timestamp_epoch": now,
            "name": tool_name,
            "summary": f"Running... {progress}%",
            "duration_ms": 0,
            "progress": progress,
            "total": total,
        })

    return result


def get_notes_data(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """All notes with optional category filter, enriched with function links."""
    st = _get_state()
    notes = st.get_notes(category=category)
    func_lookup = _build_function_lookup(st)
    enriched = []
    for n in notes:
        entry = dict(n)  # shallow copy — avoid mutating canonical note dicts
        addr_str = entry.get("address")
        if addr_str and func_lookup[0]:
            try:
                addr_int = int(addr_str, 16)
                hit = _find_containing_function(func_lookup, addr_int)
                if hit:
                    entry["func_addr"] = hit[0]
                    entry["func_name"] = hit[1]
            except (ValueError, TypeError):
                pass
        enriched.append(entry)
    return enriched


def get_decompiled_code(address_hex: str) -> Dict[str, Any]:
    """Return cached decompilation for a function, or indicate not cached."""
    try:
        from arkana.mcp.tools_angr import _get_cached_lines, _get_cached_meta
        from arkana.mcp._rename_helpers import (
            apply_function_renames_to_lines,
            apply_variable_renames_to_lines,
            get_display_name,
        )
    except ImportError:
        return {"cached": False, "error": "angr not available"}

    try:
        addr_int = int(address_hex, 16)
    except (ValueError, TypeError):
        return {"cached": False, "error": "invalid address"}

    # Build cache key using _get_state() — not _make_decompile_key() which
    # uses the StateProxy contextvar (not set in dashboard threads).
    st = _get_state()
    cache_key = (st._state_uuid, addr_int)
    cached_lines = _get_cached_lines(cache_key)
    if cached_lines is None:
        return {"cached": False}

    from arkana.mcp.tools_angr import _get_cached_meta
    meta = _get_cached_meta(cache_key)
    # Apply renames
    renamed_lines = apply_function_renames_to_lines(cached_lines)
    renamed_lines = apply_variable_renames_to_lines(renamed_lines, hex(addr_int))
    display_name = get_display_name(hex(addr_int), meta.get("function_name", "unknown"))

    return {
        "cached": True,
        "function_name": display_name,
        "address": meta.get("address", hex(addr_int)),
        "lines": renamed_lines,
        "line_count": len(renamed_lines),
    }


def trigger_decompile(address_hex: str) -> Dict[str, Any]:
    """Trigger a new decompilation and cache the result. Runs synchronously (call from thread)."""
    from arkana.imports import ANGR_AVAILABLE
    if not ANGR_AVAILABLE:
        return {"cached": False, "error": "angr is not available"}

    st = _get_state()
    if st.angr_project is None:
        return {"cached": False, "error": "No angr project loaded. Open a file first."}

    try:
        addr_int = int(address_hex, 16)
    except (ValueError, TypeError):
        return {"cached": False, "error": "invalid address"}

    from arkana.mcp.tools_angr import _get_cached_lines, _get_cached_meta, _set_decompile_meta
    from arkana.mcp._angr_helpers import _ensure_project_and_cfg, _build_region_cfg
    from arkana.mcp._rename_helpers import (
        apply_function_renames_to_lines,
        apply_variable_renames_to_lines,
        get_display_name,
    )

    # Build cache key using _get_state() — not _make_decompile_key() which
    # uses the StateProxy contextvar (not set in dashboard threads).
    cache_key = (st._state_uuid, addr_int)
    cached_lines = _get_cached_lines(cache_key)
    if cached_lines is not None:
        meta = _get_cached_meta(cache_key)
        renamed_lines = apply_function_renames_to_lines(cached_lines)
        renamed_lines = apply_variable_renames_to_lines(renamed_lines, hex(addr_int))
        display_name = get_display_name(hex(addr_int), meta.get("function_name", "unknown"))
        return {
            "cached": True,
            "function_name": display_name,
            "address": meta.get("address", hex(addr_int)),
            "lines": renamed_lines,
            "line_count": len(renamed_lines),
        }

    # Resolve function and decompile
    project, cfg = st.get_angr_snapshot()
    if project is None:
        return {"cached": False, "error": "angr project not initialized"}

    if cfg is not None:
        addr_to_use = addr_int
        if addr_to_use not in cfg.functions:
            if (st.pe_object
                    and hasattr(st.pe_object, 'OPTIONAL_HEADER')
                    and st.pe_object.OPTIONAL_HEADER):
                image_base = st.pe_object.OPTIONAL_HEADER.ImageBase
                potential_va = addr_int + image_base
                if potential_va in cfg.functions:
                    addr_to_use = potential_va
        try:
            func = cfg.functions[addr_to_use]
        except KeyError:
            return {"cached": False, "error": f"No function found at {hex(addr_int)}"}
        decompiler_cfg = cfg.model
    else:
        try:
            local_cfg = _build_region_cfg(project, addr_int)
        except Exception:
            logger.debug("Failed to build local CFG for %s", hex(addr_int), exc_info=True)
            return {"cached": False, "error": "Failed to build local CFG"}
        addr_to_use = addr_int
        if addr_to_use not in local_cfg.functions:
            if (st.pe_object
                    and hasattr(st.pe_object, 'OPTIONAL_HEADER')
                    and st.pe_object.OPTIONAL_HEADER):
                image_base = st.pe_object.OPTIONAL_HEADER.ImageBase
                potential_va = addr_int + image_base
                if potential_va in local_cfg.functions:
                    addr_to_use = potential_va
        try:
            func = local_cfg.functions[addr_to_use]
        except KeyError:
            return {"cached": False, "error": f"No function found at {hex(addr_int)} in local CFG"}
        decompiler_cfg = local_cfg.model

    # L2-v10: Signal on-demand decompile to enrichment sweep for cooperative yielding
    st._decompile_on_demand_count += 1
    # Acquire decompile lock for mutual exclusion with background enrichment sweep
    _waited = 0
    while not st._decompile_lock.acquire(timeout=5):
        _waited += 5
        if _waited >= 60:
            st._decompile_on_demand_count -= 1
            return {"cached": False, "error": f"Decompilation lock busy after {_waited}s — background enrichment may be running. Try again shortly."}
        logger.info("Dashboard decompile: waiting for lock (%ds)...", _waited)
    try:
        from arkana.mcp._angr_helpers import _safe_decompile, DECOMPILE_FALLBACK_NOTE
        dec, used_fallback = _safe_decompile(project, func, decompiler_cfg)
        if not dec.codegen:
            return {"cached": False, "error": "Decompilation produced no code"}

        all_lines = dec.codegen.text.splitlines()
        meta = {
            "function_name": func.name,
            "address": hex(addr_to_use),
            "lines": all_lines,
        }
        if used_fallback:
            meta["note"] = DECOMPILE_FALLBACK_NOTE
        _set_decompile_meta(cache_key, meta)
        st._newly_decompiled.append(hex(addr_to_use))

        # Persist to disk cache (throttled, non-blocking)
        try:
            from arkana.enrichment import save_decompile_cache_async
            save_decompile_cache_async(st)
        except Exception:
            pass
    except Exception:
        return {"cached": False, "error": "Decompilation failed"}
    finally:
        st._decompile_on_demand_count -= 1
        st._decompile_lock.release()

    renamed_lines = apply_function_renames_to_lines(all_lines)
    renamed_lines = apply_variable_renames_to_lines(renamed_lines, hex(addr_int))
    display_name = get_display_name(hex(addr_int), func.name)

    result = {
        "cached": True,
        "function_name": display_name,
        "address": hex(addr_to_use),
        "lines": renamed_lines,
        "line_count": len(renamed_lines),
    }
    if used_fallback:
        result["note"] = DECOMPILE_FALLBACK_NOTE
    return result


def _detect_phase(st) -> str:
    """Determine analysis phase from state.

    M7-v10: Delegates to shared helper using canonical tool sets from tools_session.
    """
    return _detect_phase_for_state(st)



def _get_decompiled_addresses() -> set:
    """Return set of hex addresses that have been decompiled for the current session."""
    addrs = set()
    try:
        from arkana.mcp.tools_angr import _decompile_meta, _decompile_meta_lock
        st = _get_state()
        if st is None:
            return addrs
        session_uuid = st._state_uuid
        # M6-v10: Filter inside the lock to avoid copying all keys
        with _decompile_meta_lock:
            for key in _decompile_meta:
                if isinstance(key, tuple) and len(key) >= 2 and key[0] == session_uuid:
                    addrs.add(hex(key[1]))
    except Exception:
        logger.debug("Error reading decompile meta keys", exc_info=True)
    return addrs


def _iter_string_sources(pe_data: dict):
    """Yield (list_of_dicts, type_label) for each string source in pe_data."""
    basic = pe_data.get("basic_ascii_strings", [])
    if isinstance(basic, list):
        yield basic, "ASCII"

    floss = pe_data.get("floss_analysis", {})
    if isinstance(floss, dict):
        strings_dict = floss.get("strings", {})
        if isinstance(strings_dict, dict):
            static = strings_dict.get("static_strings", [])
            if isinstance(static, list):
                yield static, "STATIC"
            stack = strings_dict.get("stack_strings", [])
            if isinstance(stack, list):
                yield stack, "STACK"
            decoded = strings_dict.get("decoded_strings", [])
            if isinstance(decoded, list):
                yield decoded, "DECODED"
            tight = strings_dict.get("tight_strings", [])
            if isinstance(tight, list):
                yield tight, "TIGHT"


def get_strings_data(
    search: str = "",
    string_type: str = "all",
    category: str = "",
    min_score: float = 0.0,
    sort_by: str = "score",
    sort_asc: bool = False,
    offset: int = 0,
    limit: int = 100,
) -> Dict[str, Any]:
    """Unified string listing with search, filter, sort, and pagination."""
    st = _get_state()
    pe_data = st.pe_data or {}

    # M8: Short TTL cache keyed on parameters + state identity
    now = time.time()
    cache_key = st._state_uuid
    version_key = (search, string_type, category, min_score, sort_by, sort_asc,
                   offset, limit, getattr(st, 'filepath', None),
                   len(st.pe_data) if st.pe_data else 0)
    with _cache_lock:
        cached = _strings_cache.get(cache_key)
        if cached is not None:
            expire_time, cached_version, cached_data = cached
            if now < expire_time and cached_version == version_key:
                return cached_data

    all_strings = []
    type_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}

    # M-E6: Pre-compute filters so we can apply them during iteration
    # instead of building the full list first, reducing memory pressure.
    search_lower = search[:500].lower().strip() if search else ""
    type_lower = string_type.lower().strip() if string_type else "all"
    cat_lower = category.lower().strip() if category else ""

    for items, type_label in _iter_string_sources(pe_data):
        count = 0
        # M-E6: Skip entire source if type filter doesn't match
        if type_lower and type_lower != "all" and type_label.lower() != type_lower:
            # Still need to count items for type_counts
            for item in items:
                if isinstance(item, dict) and "error" not in item:
                    count += 1
                elif isinstance(item, str):
                    count += 1
            type_counts[type_label] = count
            continue
        for item in items:
            if isinstance(item, str):
                # basic_ascii_strings can be plain strings
                item = {"string": item, "offset": ""}
            if not isinstance(item, dict):
                continue
            if "error" in item:
                continue
            count += 1

            s = item.get("string", str(item))
            sifter_score = item.get("sifter_score", 0)
            cat = item.get("category", "")
            address = ""
            function_va = ""
            extra = ""

            if type_label == "ASCII":
                address = str(item.get("offset", ""))
            elif type_label == "STATIC":
                address = str(item.get("offset", ""))
                refs = item.get("references", [])
                if isinstance(refs, list) and refs:
                    extra = f"{len(refs)} refs"
                    # Use first reference's function_va for function linking
                    for ref in refs:
                        if isinstance(ref, dict) and ref.get("function_va"):
                            function_va = str(ref["function_va"])
                            break
            elif type_label == "STACK":
                address = str(item.get("string_va", ""))
                function_va = str(item.get("function_va", ""))
            elif type_label == "DECODED":
                address = str(item.get("string_va", ""))
                dec_va = item.get("decoding_routine_va", item.get("decoder_va", ""))
                if dec_va:
                    function_va = str(dec_va)
                    extra = f"decoder: {dec_va}"
            elif type_label == "TIGHT":
                address = str(item.get("address_or_offset", ""))
                function_va = str(item.get("function_va", ""))

            # Track categories
            if cat:
                category_counts[cat] = category_counts.get(cat, 0) + 1

            score_val = sifter_score if isinstance(sifter_score, (int, float)) else 0

            # M-E6: Apply filters during iteration to avoid building the full list
            if search_lower and search_lower not in s.lower():
                continue
            if cat_lower and cat.lower() != cat_lower:
                continue
            if min_score > 0 and score_val < min_score:
                continue

            all_strings.append({
                "string": s,
                "type": type_label,
                "address": address,
                "sifter_score": score_val,
                "category": cat,
                "function_va": function_va,
                "extra": extra,
            })

        type_counts[type_label] = count

    total_unfiltered = sum(type_counts.values())

    # Enrich filtered strings with func_addr/func_name (post-filter for performance)
    func_lookup = _build_function_lookup(st)
    for item in all_strings:
        fva = item.get("function_va", "")
        if not fva:
            continue
        try:
            va_int = int(fva, 16)
            hit = _find_containing_function(func_lookup, va_int) if func_lookup[0] else None
            if hit:
                item["func_addr"] = hit[0]
                item["func_name"] = hit[1]
            else:
                # Fallback: use raw VA as link (e.g. .NET binaries without angr functions)
                item["func_addr"] = fva if fva.startswith("0x") else hex(va_int)
                item["func_name"] = fva if fva.startswith("0x") else hex(va_int)
        except (ValueError, TypeError):
            pass

    # Sort
    if sort_by == "length":
        all_strings.sort(key=lambda s: len(s["string"]), reverse=not sort_asc)
    elif sort_by == "type":
        all_strings.sort(key=lambda s: s["type"], reverse=not sort_asc)
    elif sort_by == "address":
        def _addr_key(s):
            a = s["address"]
            try:
                return int(a, 16) if a.startswith("0x") else int(a)
            except (ValueError, TypeError):
                return 0
        all_strings.sort(key=_addr_key, reverse=not sort_asc)
    else:  # score (default)
        all_strings.sort(key=lambda s: s["sifter_score"], reverse=not sort_asc)

    total = len(all_strings)
    page = all_strings[offset:offset + limit]

    result = {
        "strings": page,
        "total": total,
        "total_unfiltered": total_unfiltered,
        "offset": offset,
        "limit": limit,
        "type_counts": type_counts,
        "category_counts": category_counts,
    }

    # M8: Store in cache
    with _cache_lock:
        if len(_strings_cache) >= _MAX_STRINGS_CACHE and cache_key not in _strings_cache:
            oldest_k = min(_strings_cache, key=lambda k: _strings_cache[k][0])
            _strings_cache.pop(oldest_k, None)
        _strings_cache[cache_key] = (now + _STRINGS_TTL, version_key, result)

    return result


def global_search(query: str, limit_per_category: int = 10) -> Dict[str, Any]:
    """Search across functions, strings, imports, and notes."""
    st = _get_state()
    pe_data = st.pe_data or {}
    query_lower = query[:500].lower().strip()
    results: Dict[str, list] = {
        "functions": [],
        "strings": [],
        "imports": [],
        "notes": [],
    }

    if not query_lower:
        return results

    # Functions
    if st.angr_project is not None and st.angr_cfg is not None:
        try:
            kb = st.angr_project.kb
            renames = st.get_renames().get("functions", {})
            if hasattr(kb, "functions"):
                for addr, func in kb.functions.items():
                    if len(results["functions"]) >= limit_per_category:
                        break
                    addr_hex = hex(addr)
                    name = renames.get(addr_hex, func.name)
                    if query_lower in name.lower() or query_lower in addr_hex.lower():
                        results["functions"].append({
                            "address": addr_hex,
                            "name": name,
                        })
        except (AttributeError, KeyError, TypeError, RuntimeError):
            pass

    # Strings
    for items, type_label in _iter_string_sources(pe_data):
        if len(results["strings"]) >= limit_per_category:
            break
        for item in items:
            if len(results["strings"]) >= limit_per_category:
                break
            if isinstance(item, str):
                s = item
                address = ""
            elif isinstance(item, dict):
                if "error" in item:
                    continue
                s = item.get("string", "")
                address = str(item.get("offset", item.get("string_va", item.get("address_or_offset", ""))))
            else:
                continue
            if query_lower in s.lower():
                results["strings"].append({
                    "string": s[:200],
                    "type": type_label,
                    "address": address,
                })

    # Imports
    raw_imports = pe_data.get("imports", [])
    if isinstance(raw_imports, list):
        for dll_entry in raw_imports:
            if len(results["imports"]) >= limit_per_category:
                break
            if not isinstance(dll_entry, dict):
                continue
            dll_name = dll_entry.get("dll", dll_entry.get("name", "?"))
            symbols = dll_entry.get("symbols", dll_entry.get("functions", []))
            if not isinstance(symbols, list):
                symbols = []
            dll_matched = query_lower in dll_name.lower()
            for sym in symbols:
                if len(results["imports"]) >= limit_per_category:
                    break
                fname = sym.get("name", sym.get("function", "")) if isinstance(sym, dict) else str(sym)
                if dll_matched or query_lower in fname.lower():
                    results["imports"].append({
                        "dll": dll_name,
                        "function": fname,
                    })

    # Notes
    for n in st.get_notes():
        if len(results["notes"]) >= limit_per_category:
            break
        content = n.get("content", "")
        if query_lower in content.lower():
            results["notes"].append({
                "content": content[:200],
                "category": n.get("category", "general"),
                "address": n.get("address", ""),
            })

    return results


def get_function_analysis_data(address_hex: str) -> Dict[str, Any]:
    """Return combined xrefs, strings, suspicious APIs, and complexity for a function.

    Used by the callgraph sidebar tabbed panel.
    """
    st = _get_state()
    score_lookup = _build_score_lookup(st)

    result: Dict[str, Any] = {
        "address": address_hex,
        "name": "",
        "score": score_lookup.get(address_hex, 0),
        "callers": [],
        "callees": [],
        "suspicious_apis": [],
        "strings": [],
        "complexity": {"blocks": 0, "edges": 0},
    }

    if st.angr_project is None or st.angr_cfg is None:
        # Still try strings even without angr
        str_data = get_function_strings_data(address_hex)
        result["strings"] = str_data.get("strings", [])[:20]
        return result

    try:
        addr_int = int(address_hex, 16)
    except (ValueError, TypeError):
        return result

    try:
        from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB
    except ImportError:
        CATEGORIZED_IMPORTS_DB = {}

    try:
        kb = st.angr_project.kb
        renames = st.get_renames().get("functions", {})

        # Function name
        if hasattr(kb, "functions") and addr_int in kb.functions:
            func = kb.functions[addr_int]
            result["name"] = renames.get(hex(addr_int), func.name)
            # Complexity
            try:
                result["complexity"]["blocks"] = len(func.block_addrs_set)
            except (AttributeError, TypeError):
                pass
            try:
                result["complexity"]["edges"] = func.graph.number_of_edges()  # L7-v10: O(1)
            except (AttributeError, TypeError):
                pass
        else:
            result["name"] = renames.get(hex(addr_int), address_hex)

        # Callers / callees from callgraph (bounded to prevent oversized responses)
        _MAX_XREFS = 200
        if hasattr(kb, "callgraph") and addr_int in kb.callgraph:
            cg = kb.callgraph
            seen_suspicious = set()

            # Callers (predecessors)
            for pred in cg.predecessors(addr_int):
                if len(result["callers"]) >= _MAX_XREFS:
                    result["callers_truncated"] = True
                    break
                pred_hex = hex(pred)
                name = renames.get(pred_hex, "")
                if not name and hasattr(kb, "functions") and pred in kb.functions:
                    name = kb.functions[pred].name
                name = name or pred_hex
                complexity = 0
                if hasattr(kb, "functions") and pred in kb.functions:
                    try:
                        complexity = len(kb.functions[pred].block_addrs_set)
                    except (AttributeError, TypeError):
                        pass
                triage = st.get_triage_status(pred_hex)
                result["callers"].append({
                    "address": pred_hex,
                    "name": name,
                    "triage": triage,
                    "complexity": complexity,
                    "score": score_lookup.get(pred_hex, 0),
                })

            # Callees (successors)
            for succ in cg.successors(addr_int):
                if len(result["callees"]) >= _MAX_XREFS:
                    result["callees_truncated"] = True
                    break
                succ_hex = hex(succ)
                name = renames.get(succ_hex, "")
                if not name and hasattr(kb, "functions") and succ in kb.functions:
                    name = kb.functions[succ].name
                name = name or succ_hex
                complexity = 0
                if hasattr(kb, "functions") and succ in kb.functions:
                    try:
                        complexity = len(kb.functions[succ].block_addrs_set)
                    except (AttributeError, TypeError):
                        pass
                triage = st.get_triage_status(succ_hex)
                callee_entry: Dict[str, Any] = {
                    "address": succ_hex,
                    "name": name,
                    "triage": triage,
                    "complexity": complexity,
                    "score": score_lookup.get(succ_hex, 0),
                }
                # Check for suspicious API
                api_info = CATEGORIZED_IMPORTS_DB.get(name)
                if api_info:
                    risk, category = api_info
                    callee_entry["suspicious"] = {"risk": risk, "category": category}
                    if name not in seen_suspicious:
                        seen_suspicious.add(name)
                        result["suspicious_apis"].append({
                            "name": name,
                            "risk": risk,
                            "category": category,
                        })
                result["callees"].append(callee_entry)

    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error reading analysis for %s", address_hex, exc_info=True)

    # Strings (reuse existing function, limit 20)
    str_data = get_function_strings_data(address_hex)
    result["strings"] = str_data.get("strings", [])[:20]

    return result


def get_function_xrefs_data(address_hex: str) -> Dict[str, Any]:
    """Return callers and callees for a function address."""
    st = _get_state()
    callers = []
    callees = []

    if st.angr_project is None or st.angr_cfg is None:
        return {"callers": callers, "callees": callees}

    try:
        addr_int = int(address_hex, 16)
    except (ValueError, TypeError):
        return {"callers": callers, "callees": callees, "error": "invalid address"}

    try:
        kb = st.angr_project.kb
        renames = st.get_renames().get("functions", {})
        if hasattr(kb, "callgraph"):
            cg = kb.callgraph
            # Callers (predecessors)
            if addr_int in cg:
                for pred in cg.predecessors(addr_int):
                    pred_hex = hex(pred)
                    name = renames.get(pred_hex, "")
                    if not name and hasattr(kb, "functions") and pred in kb.functions:
                        name = kb.functions[pred].name
                    callers.append({"address": pred_hex, "name": name or pred_hex})
                # Callees (successors)
                for succ in cg.successors(addr_int):
                    succ_hex = hex(succ)
                    name = renames.get(succ_hex, "")
                    if not name and hasattr(kb, "functions") and succ in kb.functions:
                        name = kb.functions[succ].name
                    callees.append({"address": succ_hex, "name": name or succ_hex})
    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error reading xrefs for %s", address_hex, exc_info=True)

    return {"callers": callers, "callees": callees}


def get_function_strings_data(address_hex: str) -> Dict[str, Any]:
    """Return strings associated with a function address."""
    st = _get_state()
    pe_data = st.pe_data or {}
    found = []
    addr_lower = address_hex.lower().strip()

    floss = pe_data.get("floss_analysis", {})
    if not isinstance(floss, dict):
        return {"strings": found}

    strings_dict = floss.get("strings", {})
    if not isinstance(strings_dict, dict):
        return {"strings": found}

    # Stack strings: match function_va
    for item in strings_dict.get("stack_strings", []):
        if len(found) >= 100:
            break
        if isinstance(item, dict) and "error" not in item:
            fva = str(item.get("function_va", "")).lower()
            if fva == addr_lower:
                found.append({
                    "string": item.get("string", ""),
                    "type": "STACK",
                    "address": str(item.get("string_va", "")),
                })

    # Tight strings: match function_va
    for item in strings_dict.get("tight_strings", []):
        if len(found) >= 100:
            break
        if isinstance(item, dict) and "error" not in item:
            fva = str(item.get("function_va", "")).lower()
            if fva == addr_lower:
                found.append({
                    "string": item.get("string", ""),
                    "type": "TIGHT",
                    "address": str(item.get("address_or_offset", "")),
                })

    # Static strings: match references[].function_va
    for item in strings_dict.get("static_strings", []):
        if len(found) >= 100:
            break
        if isinstance(item, dict) and "error" not in item:
            refs = item.get("references", [])
            if isinstance(refs, list):
                for ref in refs:
                    if isinstance(ref, dict):
                        fva = str(ref.get("function_va", "")).lower()
                        if fva == addr_lower:
                            found.append({
                                "string": item.get("string", ""),
                                "type": "STATIC",
                                "address": str(item.get("offset", "")),
                            })
                            break

    return {"strings": found}


def _section_permissions(section: dict) -> str:
    """Extract permission string from section data."""
    # Try raw integer first (e.g. from pefile Characteristics attribute)
    chars = section.get("characteristics", 0)
    if isinstance(chars, str):
        return chars
    perms = ""
    if isinstance(chars, (int, float)) and int(chars) != 0:
        chars = int(chars)
        if chars & 0x20000000:
            perms += "X"
        if chars & 0x40000000:
            perms += "R"
        if chars & 0x80000000:
            perms += "W"
    if perms:
        return perms
    # Fallback: pefile dump_dict stores Characteristics in a sub-dict
    # with key "Value" — also check characteristics_list from our parser
    chars_dict = section.get("Characteristics", {})
    if isinstance(chars_dict, dict):
        raw = chars_dict.get("Value", 0)
        if isinstance(raw, (int, float)) and int(raw) != 0:
            raw = int(raw)
            if raw & 0x20000000:
                perms += "X"
            if raw & 0x40000000:
                perms += "R"
            if raw & 0x80000000:
                perms += "W"
    if perms:
        return perms
    # Fallback: characteristics_list from pe.py parser
    chars_list = section.get("characteristics_list", [])
    if isinstance(chars_list, list):
        for c in chars_list:
            cs = str(c).upper()
            if "EXECUTE" in cs and "X" not in perms:
                perms += "X"
            if "READ" in cs and "R" not in perms:
                perms += "R"
            if "WRITE" in cs and "W" not in perms:
                perms += "W"
    return perms or "?"


def get_floss_summary() -> Dict[str, Any]:
    """Extract FLOSS analysis summary for the strings page detail panel."""
    st = _get_state()
    pe_data = st.pe_data or {}
    floss = pe_data.get("floss_analysis")

    if not floss or not isinstance(floss, dict):
        return {"available": False}

    status = floss.get("status", "unknown")
    strings_data = floss.get("strings", {})
    if not isinstance(strings_data, dict):
        strings_data = {}

    static = strings_data.get("static_strings", [])
    stack = strings_data.get("stack_strings", [])
    decoded = strings_data.get("decoded_strings", [])
    tight = strings_data.get("tight_strings", [])

    # Filter out error entries
    static = [s for s in static if isinstance(s, dict) and "string" in s]
    stack = [s for s in stack if isinstance(s, dict) and "string" in s]
    decoded = [s for s in decoded if isinstance(s, dict) and "string" in s]
    tight = [s for s in tight if isinstance(s, dict) and "string" in s]

    type_counts = {
        "STATIC": len(static),
        "STACK": len(stack),
        "DECODED": len(decoded),
        "TIGHT": len(tight),
    }

    # Top decoded strings (most interesting for malware analysis)
    top_decoded = [s.get("string", "")[:200] for s in decoded[:10]]
    top_stack = [s.get("string", "")[:200] for s in stack[:10]]

    # Metadata
    metadata = floss.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    config = floss.get("analysis_config", {})
    if not isinstance(config, dict):
        config = {}

    return {
        "available": True,
        "status": status,
        "type_counts": type_counts,
        "total_floss_strings": sum(type_counts.values()),
        "top_decoded": top_decoded,
        "top_stack": top_stack,
        "floss_version": metadata.get("version", ""),
        "analysis_config": {
            k: v for k, v in config.items()
            if k in ("min_length", "language", "timeout")
        } if config else {},
    }


# ---------------------------------------------------------------------------
#  Hex dump data (Batch 1a)
# ---------------------------------------------------------------------------

def get_hex_dump_data(offset: int = 0, length: int = 256) -> Dict[str, Any]:
    """Read raw bytes from the loaded binary and return hex dump lines."""
    st = _get_state()
    if not st.filepath:
        return {"lines": [], "offset": 0, "total_size": 0, "error": "no file loaded"}
    try:
        file_size = os.path.getsize(st.filepath)
    except OSError:
        return {"lines": [], "offset": 0, "total_size": 0, "error": "file not accessible"}

    offset = max(0, min(offset, file_size))
    length = max(1, min(length, 4096))
    end = min(offset + length, file_size)

    lines = []
    try:
        with open(st.filepath, "rb") as f:
            f.seek(offset)
            data = f.read(end - offset)
        for i in range(0, len(data), 16):
            row = data[i:i + 16]
            addr = offset + i
            hex_bytes = " ".join(f"{b:02x}" for b in row)
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            lines.append({
                "offset": f"0x{addr:08x}",
                "hex": hex_bytes,
                "ascii": ascii_repr,
            })
    except (OSError, IOError):
        return {"lines": [], "offset": offset, "total_size": file_size, "error": "read error"}

    return {"lines": lines, "offset": offset, "length": len(data), "total_size": file_size}


# ---------------------------------------------------------------------------
#  MITRE / Threat Intel data (Batch 1b)
# ---------------------------------------------------------------------------

def get_mitre_data() -> Dict[str, Any]:
    """Return MITRE ATT&CK mappings and IOC data from enrichment cache."""
    st = _get_state()
    techniques = {}
    tactics = {}
    iocs = {}

    # MITRE from enrichment cache
    cached_mitre = getattr(st, "_cached_mitre_mapping", None)
    if cached_mitre and isinstance(cached_mitre, dict):
        raw_techniques = cached_mitre.get("techniques", [])
        if isinstance(raw_techniques, list):
            for t in raw_techniques:
                if isinstance(t, dict):
                    tid = t.get("technique_id", t.get("id", ""))
                    if tid:
                        tactic = t.get("tactic", "unknown")
                        if tactic not in tactics:
                            tactics[tactic] = []
                        entry = {
                            "id": tid,
                            "name": t.get("name", tid),
                            "confidence": t.get("confidence", ""),
                            "source": t.get("source", ""),
                            "description": t.get("description", "")[:300],
                        }
                        tactics[tactic].append(entry)
                        techniques[tid] = entry
        elif isinstance(raw_techniques, dict):
            for tid, detail in raw_techniques.items():
                if isinstance(detail, dict):
                    tactic = detail.get("tactic", "unknown")
                    if tactic not in tactics:
                        tactics[tactic] = []
                    entry = {
                        "id": tid,
                        "name": detail.get("name", tid),
                        "confidence": detail.get("confidence", ""),
                        "source": detail.get("source", ""),
                        "description": detail.get("description", "")[:300],
                    }
                    tactics[tactic].append(entry)
                    techniques[tid] = entry

    # IOCs from enrichment cache
    cached_iocs = getattr(st, "_cached_iocs", None)
    if cached_iocs and isinstance(cached_iocs, dict):
        for ioc_type in ("urls", "ips", "domains", "emails", "crypto_wallets",
                         "registry_keys", "file_paths", "mutexes"):
            items = cached_iocs.get(ioc_type, [])
            if isinstance(items, list) and items:
                iocs[ioc_type] = items[:100]

    # Also pull from pe_data network IOCs
    pe_data = st.pe_data or {}
    binary_summary = pe_data.get("binary_summary", {})
    if isinstance(binary_summary, dict):
        net_iocs = binary_summary.get("network_iocs", {})
        if isinstance(net_iocs, dict):
            for k, v in net_iocs.items():
                if isinstance(v, list) and v and k not in iocs:
                    iocs[k] = v[:100]

    return {
        "techniques": techniques,
        "tactics": tactics,
        "iocs": iocs,
        "technique_count": len(techniques),
        "tactic_count": len(tactics),
        "ioc_count": sum(len(v) for v in iocs.values()),
    }


# ---------------------------------------------------------------------------
#  CAPA capabilities data (Batch 1c)
# ---------------------------------------------------------------------------

def _extract_capa_address(raw) -> str:
    """Extract a hex address string from various capa address formats.

    Capa v9 (pydantic) serializes match dicts with complex Address keys as
    lists of ``[address_obj, match_result]`` pairs.  Address objects can be:
    - ``{"type": "absolute", "value": 4198400}``
    - ``{"type": "call", "value": {"caller": ..., "position": ...}}``
    - A plain int (e.g. ``4198400``)
    - A string (e.g. ``"0x401000"`` or ``"(4198400, file)"``)
    - A list pair ``[address_obj, match_result]``
    """
    # List pair: first element is the address, second is the match result
    if isinstance(raw, list) and len(raw) >= 1:
        raw = raw[0]

    # Dict address object (capa v9 frozen model)
    if isinstance(raw, dict):
        val = raw.get("value", raw)
        # Nested address (e.g. "call" type with caller sub-object)
        if isinstance(val, dict):
            val = val.get("value", val.get("caller", {}).get("value", val))
        # Tuple-as-list (e.g. [4198400, 0])
        if isinstance(val, (list, tuple)) and val:
            val = val[0]
        if isinstance(val, int):
            return hex(val)
        return str(val)

    if isinstance(raw, int):
        return hex(raw)

    return str(raw)


def get_capa_data() -> Dict[str, Any]:
    """Return capa rule matches grouped by ATT&CK tactic or MBC objective."""
    st = _get_state()
    pe_data = st.pe_data or {}
    capa = pe_data.get("capa_analysis", {})
    if not isinstance(capa, dict):
        return {"rules": [], "attack_mapping": {}, "mbc_mapping": {}, "stats": {}, "available": False}

    capa_results = capa.get("results", {}) if isinstance(capa, dict) else {}
    rules_raw = capa_results.get("rules", capa_results.get("capabilities",
                capa.get("rules", capa.get("capabilities", []))))
    rules = []
    attack_mapping = {}
    mbc_mapping = {}

    func_lookup = _build_function_lookup(st)

    if isinstance(rules_raw, dict):
        for name, detail in rules_raw.items():
            if not isinstance(detail, dict):
                continue
            meta = detail.get("meta", detail)
            addresses = []
            raw_addrs = detail.get("addresses", detail.get("matches", []))
            if isinstance(raw_addrs, dict):
                raw_addrs = list(raw_addrs.keys())
            elif not isinstance(raw_addrs, list):
                raw_addrs = []
            for a in raw_addrs[:20]:
                addr_str = _extract_capa_address(a)
                entry = {"address": addr_str}
                try:
                    va_int = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                    hit = _find_containing_function(func_lookup, va_int)
                    if hit:
                        entry["func_addr"] = hit[0]
                        entry["func_name"] = hit[1]
                except (ValueError, TypeError):
                    pass
                addresses.append(entry)
            rule_entry = {
                "name": name,
                "namespace": meta.get("namespace", ""),
                "scope": meta.get("scope", ""),
                "description": meta.get("description", "")[:300],
                "addresses": addresses,
            }
            rules.append(rule_entry)
            # ATT&CK mapping
            attack = meta.get("attack", meta.get("att&ck", []))
            if isinstance(attack, list):
                for att in attack:
                    if isinstance(att, dict):
                        tid = att.get("id", att.get("technique", ""))
                        tactic = att.get("tactic", "unknown")
                    elif isinstance(att, str):
                        tid = att
                        tactic = "unknown"
                    else:
                        continue
                    if tid:
                        if tactic not in attack_mapping:
                            attack_mapping[tactic] = []
                        attack_mapping[tactic].append({"id": tid, "rule": name})
            # MBC mapping
            mbc = meta.get("mbc", [])
            if isinstance(mbc, list):
                for m in mbc:
                    if isinstance(m, dict):
                        obj = m.get("objective", "unknown")
                        if obj not in mbc_mapping:
                            mbc_mapping[obj] = []
                        mbc_mapping[obj].append({"id": m.get("id", ""), "behavior": m.get("behavior", ""), "rule": name})
    elif isinstance(rules_raw, list):
        for item in rules_raw:
            if isinstance(item, dict):
                rules.append({
                    "name": item.get("name", item.get("rule", "?")),
                    "namespace": item.get("namespace", ""),
                    "scope": item.get("scope", ""),
                    "description": item.get("description", "")[:300],
                    "addresses": [],
                })

    return {
        "rules": rules,
        "attack_mapping": attack_mapping,
        "mbc_mapping": mbc_mapping,
        "stats": {
            "total_rules": len(rules),
            "total_attack_tactics": len(attack_mapping),
            "total_mbc_objectives": len(mbc_mapping),
        },
        "available": bool(rules),
    }


# ---------------------------------------------------------------------------
#  Per-function CFG data (Batch 1d)
# ---------------------------------------------------------------------------

def get_function_cfg_data(address_hex: str) -> Dict[str, Any]:
    """Return basic-block CFG nodes and edges for a single function."""
    st = _get_state()
    nodes = []
    edges = []

    if st.angr_project is None or st.angr_cfg is None:
        return {"nodes": nodes, "edges": edges, "error": "no CFG available"}

    try:
        addr_int = int(address_hex, 16)
    except (ValueError, TypeError):
        return {"nodes": nodes, "edges": edges, "error": "invalid address"}

    try:
        kb = st.angr_project.kb
        if not hasattr(kb, "functions") or addr_int not in kb.functions:
            return {"nodes": nodes, "edges": edges, "error": "function not found"}

        func = kb.functions[addr_int]
        renames = st.get_renames().get("functions", {})
        func_name = renames.get(address_hex, func.name or address_hex)

        # Iterate basic blocks
        if hasattr(func, "graph"):
            graph = func.graph
            for node in graph.nodes():
                block_addr = node.addr if hasattr(node, "addr") else 0
                block_size = node.size if hasattr(node, "size") else 0
                insn_count = 0
                if hasattr(node, "instructions") and node.instructions is not None:
                    insn_count = node.instructions
                nodes.append({
                    "addr": hex(block_addr),
                    "size": block_size,
                    "instructions": insn_count,
                })
            for src, dst in graph.edges():
                src_addr = src.addr if hasattr(src, "addr") else 0
                dst_addr = dst.addr if hasattr(dst, "addr") else 0
                edge_type = "unconditional"
                # Detect conditional edges (basic heuristic)
                if hasattr(graph, "out_degree") and graph.out_degree(src) > 1:
                    edge_type = "conditional"
                edges.append({
                    "src": hex(src_addr),
                    "dst": hex(dst_addr),
                    "type": edge_type,
                })

        return {"nodes": nodes, "edges": edges, "function_name": func_name}

    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error getting CFG for %s", address_hex, exc_info=True)
        return {"nodes": nodes, "edges": edges, "error": "analysis error"}


# ---------------------------------------------------------------------------
#  Disassembly data (Batch 1e)
# ---------------------------------------------------------------------------

def get_disassembly_data(address_hex: str, count: int = 200) -> Dict[str, Any]:
    """Return disassembly instructions for a function."""
    st = _get_state()
    instructions = []

    if st.angr_project is None:
        return {"instructions": instructions, "error": "no angr project"}

    try:
        addr_int = int(address_hex, 16)
    except (ValueError, TypeError):
        return {"instructions": instructions, "error": "invalid address"}

    count = max(1, min(count, 2000))

    try:
        kb = st.angr_project.kb
        if hasattr(kb, "functions") and addr_int in kb.functions:
            func = kb.functions[addr_int]
            # Get all blocks in the function
            block_addrs = sorted(func.block_addrs_set) if hasattr(func, "block_addrs_set") else [addr_int]
            for baddr in block_addrs:
                if len(instructions) >= count:
                    break
                try:
                    block = st.angr_project.factory.block(baddr)
                    if hasattr(block, "capstone") and block.capstone:
                        for insn in block.capstone.insns:
                            if len(instructions) >= count:
                                break
                            instructions.append({
                                "address": hex(insn.address),
                                "bytes": " ".join(f"{b:02x}" for b in insn.bytes),
                                "mnemonic": insn.mnemonic,
                                "op_str": insn.op_str,
                            })
                except Exception:
                    continue
        else:
            # Fallback: disassemble from address
            try:
                block = st.angr_project.factory.block(addr_int)
                if hasattr(block, "capstone") and block.capstone:
                    for insn in block.capstone.insns:
                        if len(instructions) >= count:
                            break
                        instructions.append({
                            "address": hex(insn.address),
                            "bytes": " ".join(f"{b:02x}" for b in insn.bytes),
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str,
                        })
            except Exception:
                pass

    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error getting disassembly for %s", address_hex, exc_info=True)

    return {"instructions": instructions, "function_address": address_hex}


# ---------------------------------------------------------------------------
#  Function variables data (Batch 1f)
# ---------------------------------------------------------------------------

def get_function_variables_data(address_hex: str) -> Dict[str, Any]:
    """Return parameters and local variables for a function."""
    st = _get_state()
    params = []
    locals_list = []
    cc_info = ""

    if st.angr_project is None:
        return {"parameters": params, "locals": locals_list, "error": "no angr project"}

    try:
        addr_int = int(address_hex, 16)
    except (ValueError, TypeError):
        return {"parameters": params, "locals": locals_list, "error": "invalid address"}

    try:
        kb = st.angr_project.kb
        if not hasattr(kb, "functions") or addr_int not in kb.functions:
            return {"parameters": params, "locals": locals_list, "error": "function not found"}

        func = kb.functions[addr_int]
        # Variable recovery manager
        if hasattr(kb, "variables") and hasattr(kb.variables, "get_function_manager"):
            try:
                var_mgr = kb.variables.get_function_manager(addr_int)
                if var_mgr:
                    for var in var_mgr.get_variables():
                        var_entry = {
                            "name": getattr(var, "name", "?"),
                            "size": getattr(var, "size", 0),
                            "category": getattr(var, "category", ""),
                        }
                        if hasattr(var, "region") and var.region:
                            var_entry["region"] = str(var.region)
                        if hasattr(var, "ident"):
                            var_entry["ident"] = str(var.ident)
                        if getattr(var, "is_parameter", False):
                            params.append(var_entry)
                        else:
                            locals_list.append(var_entry)
            except (AttributeError, TypeError):
                pass

        # Calling convention info
        cc_info = ""
        if hasattr(func, "calling_convention") and func.calling_convention:
            cc_info = str(func.calling_convention)

    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error getting variables for %s", address_hex, exc_info=True)

    return {
        "parameters": params,
        "locals": locals_list,
        "calling_convention": cc_info,
        "function_address": address_hex,
    }


# ---------------------------------------------------------------------------
#  Entropy data (Batch 1g)
# ---------------------------------------------------------------------------

def _compute_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0 – 8.0).

    Uses collections.Counter (C implementation) for fast byte counting.
    """
    if not data:
        return 0.0
    from collections import Counter
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _compute_entropy_streaming(filepath: str, max_size: int = 50 * 1024 * 1024) -> float:
    """Compute Shannon entropy by streaming the file in chunks."""
    from collections import Counter
    counts = Counter()
    total = 0
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                counts.update(chunk)
                total += len(chunk)
                if total >= max_size:
                    break
    except OSError:
        return 0.0
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def get_entropy_data() -> Dict[str, Any]:
    """Return per-section entropy plus optional byte-level entropy for heatmap."""
    st = _get_state()
    sections = []
    overall = 0.0

    pe_data = st.pe_data or {}
    raw_sections = pe_data.get("sections", [])
    filepath = st.filepath

    # Per-section entropy (from parsed data)
    if isinstance(raw_sections, list):
        for s in raw_sections:
            if isinstance(s, dict):
                sections.append({
                    "name": s.get("name", "?"),
                    "entropy": s.get("entropy", 0),
                    "virtual_address": s.get("virtual_address", s.get("va", "?")),
                    "virtual_size": s.get("virtual_size", s.get("vsize", 0)),
                    "raw_size": s.get("raw_size", s.get("size_of_raw_data", 0)),
                    "permissions": _section_permissions(s),
                })

    # Overall file entropy (streamed to avoid loading entire file into memory)
    if filepath:
        try:
            file_size = os.path.getsize(filepath)
            if file_size <= 50 * 1024 * 1024:  # 50MB limit
                overall = _compute_entropy_streaming(filepath)
        except OSError:
            pass

    # Byte-level entropy for heatmap (sample 256 blocks)
    heatmap = []
    if filepath:
        try:
            file_size = os.path.getsize(filepath)
            if file_size > 0:
                block_count = min(256, file_size)
                block_size = max(1, file_size // block_count)
                with open(filepath, "rb") as f:
                    for i in range(block_count):
                        f.seek(i * block_size)
                        chunk = f.read(min(block_size, 4096))
                        if chunk:
                            heatmap.append(round(_compute_entropy(chunk), 2))
        except OSError:
            pass

    return {
        "sections": sections,
        "overall": overall,
        "heatmap": heatmap,
        "file_size": os.path.getsize(filepath) if filepath and os.path.exists(filepath) else 0,
    }


# ---------------------------------------------------------------------------
#  Resources data (Batch 1h)
# ---------------------------------------------------------------------------

def get_resources_data() -> Dict[str, Any]:
    """Return PE resource directory entries with entropy flagging."""
    st = _get_state()
    pe_data = st.pe_data or {}
    resources = pe_data.get("resources", pe_data.get("resources_summary", []))
    if not isinstance(resources, list):
        resources = []

    enriched = []
    for r in resources:
        if not isinstance(r, dict):
            continue
        entry = {
            "type": r.get("type", r.get("resource_type", "?")),
            "name": r.get("name", r.get("resource_name", "?")),
            "size": r.get("size", 0),
            "language": r.get("language", r.get("lang", "?")),
            "rva": r.get("rva", r.get("offset", "")),
            "entropy": r.get("entropy", 0),
        }
        # Flag high-entropy resources
        try:
            if float(entry["entropy"]) > 7.0:
                entry["high_entropy"] = True
        except (ValueError, TypeError):
            pass
        enriched.append(entry)

    return {"resources": enriched, "total": len(enriched)}


# ---------------------------------------------------------------------------
#  Triage report data (Batch 1i)
# ---------------------------------------------------------------------------

def get_triage_report_data() -> Dict[str, Any]:
    """Return triage report data from enrichment cache."""
    st = _get_state()
    cached = getattr(st, "_cached_triage", None)
    if cached and isinstance(cached, dict):
        return {
            "available": True,
            "risk_level": cached.get("risk_level", cached.get("overall_risk", "unknown")),
            "risk_score": cached.get("risk_score", 0),
            "findings": cached.get("findings", cached.get("key_findings", []))[:50],
            "suspicious_count": cached.get("suspicious_count", 0),
            "capabilities_count": cached.get("capabilities_count", 0),
            "mitigations": cached.get("mitigations", {}),
        }
    return {"available": False}


# ---------------------------------------------------------------------------
#  Packing data (Batch 1j)
# ---------------------------------------------------------------------------

def get_packing_data() -> Dict[str, Any]:
    """Return packing/classification data from enrichment cache."""
    st = _get_state()
    cached = getattr(st, "_cached_classification", None)
    if cached and isinstance(cached, dict):
        packing = cached.get("packing", cached.get("packing_analysis", {}))
        if not isinstance(packing, dict):
            packing = {}
        return {
            "available": True,
            "packed_likelihood": packing.get("packed_likelihood", packing.get("is_packed", "unknown")),
            "packing_score": packing.get("score", packing.get("packing_score", 0)),
            "indicators": packing.get("indicators", packing.get("evidence", []))[:20],
            "packer_name": packing.get("packer", packing.get("packer_name", "")),
            "classification": cached.get("classification", cached.get("binary_type", "")),
        }
    return {"available": False}


# ---------------------------------------------------------------------------
#  Similarity hashes data (Batch 1k)
# ---------------------------------------------------------------------------

def get_similarity_data() -> Dict[str, Any]:
    """Return similarity hashes from enrichment cache."""
    st = _get_state()
    cached = getattr(st, "_cached_similarity_hashes", None)
    if cached and isinstance(cached, dict):
        return {
            "available": True,
            "ssdeep": cached.get("ssdeep", ""),
            "tlsh": cached.get("tlsh", ""),
            "imphash": cached.get("imphash", ""),
        }

    # Fallback: try pe_data file hashes
    pe_data = st.pe_data or {}
    hashes = pe_data.get("file_hashes", {})
    if isinstance(hashes, dict) and hashes.get("imphash"):
        return {
            "available": True,
            "ssdeep": hashes.get("ssdeep", ""),
            "tlsh": hashes.get("tlsh", ""),
            "imphash": hashes.get("imphash", ""),
        }
    return {"available": False}


# ---------------------------------------------------------------------------
#  Custom types data (for Types page)
# ---------------------------------------------------------------------------

def get_custom_types_data() -> Dict[str, Any]:
    """Return user-defined structs and enums from state."""
    st = _get_state()
    custom_types = getattr(st, "custom_types", {})
    if not isinstance(custom_types, dict):
        custom_types = {}

    structs = []
    enums = []
    for name, typedef in custom_types.items():
        if not isinstance(typedef, dict):
            continue
        kind = typedef.get("kind", "struct")
        if kind == "enum":
            enums.append({
                "name": name,
                "size": typedef.get("size", 0),
                "values": typedef.get("values", {}),
            })
        else:
            structs.append({
                "name": name,
                "size": typedef.get("size", 0),
                "fields": typedef.get("fields", []),
            })

    return {"structs": structs, "enums": enums, "total": len(structs) + len(enums)}


# ---------------------------------------------------------------------------
#  Function similarity data (for SIM button)
# ---------------------------------------------------------------------------

def get_function_similarity_data(address_hex: str) -> Dict[str, Any]:
    """Return BSim similarity matches for a function."""
    st = _get_state()
    matches = []

    cached_scores = getattr(st, "_cached_function_scores", None)
    if not cached_scores:
        return {"matches": matches, "available": False}

    # Find the target function score entry
    target = None
    for entry in cached_scores:
        if isinstance(entry, dict) and entry.get("addr", "").lower() == address_hex.lower():
            target = entry
            break

    if not target:
        return {"matches": matches, "available": False}

    # Return other functions sorted by similarity to target score
    target_score = target.get("score", 0)
    renames = st.get_renames().get("functions", {})
    for entry in cached_scores:
        if isinstance(entry, dict):
            addr = entry.get("addr", "")
            if addr.lower() == address_hex.lower():
                continue
            score = entry.get("score", 0)
            name = renames.get(addr, entry.get("name", addr))
            matches.append({
                "address": addr,
                "name": name,
                "score": score,
                "similarity": max(0, 100 - abs(target_score - score)),
            })

    matches.sort(key=lambda m: m["similarity"], reverse=True)
    return {"matches": matches[:20], "available": True}


# ---------------------------------------------------------------------------
#  Export report data
# ---------------------------------------------------------------------------

def get_export_report_data() -> Dict[str, Any]:
    """Generate a comprehensive analysis report for export."""
    st = _get_state()
    pe_data = st.pe_data or {}

    report = {
        "file_info": {},
        "risk": {},
        "sections": [],
        "imports_summary": {},
        "capabilities": [],
        "findings": [],
        "iocs": {},
        "notes": [],
        "tool_history_count": 0,
    }

    # File info
    hashes = pe_data.get("file_hashes", {})
    if isinstance(hashes, dict):
        report["file_info"] = {
            "filename": os.path.basename(st.filepath) if st.filepath else "",
            "sha256": hashes.get("sha256", ""),
            "md5": hashes.get("md5", ""),
            "sha1": hashes.get("sha1", ""),
            "size": hashes.get("file_size", 0),
        }

    # Risk from triage
    cached_triage = getattr(st, "_cached_triage", None)
    if cached_triage and isinstance(cached_triage, dict):
        report["risk"] = {
            "level": cached_triage.get("risk_level", cached_triage.get("overall_risk", "unknown")),
            "score": cached_triage.get("risk_score", 0),
        }
        report["findings"] = cached_triage.get("findings", cached_triage.get("key_findings", []))[:100]

    # Sections
    raw_sections = pe_data.get("sections", [])
    if isinstance(raw_sections, list):
        for s in raw_sections:
            if isinstance(s, dict):
                report["sections"].append({
                    "name": s.get("name", "?"),
                    "entropy": s.get("entropy", 0),
                    "permissions": _section_permissions(s),
                })

    # Capabilities
    capa = pe_data.get("capa_analysis", {})
    if isinstance(capa, dict):
        rules = capa.get("rules", capa.get("capabilities", []))
        if isinstance(rules, dict):
            report["capabilities"] = list(rules.keys())[:100]
        elif isinstance(rules, list):
            report["capabilities"] = [r.get("name", "?") if isinstance(r, dict) else str(r) for r in rules[:100]]

    # IOCs
    cached_iocs = getattr(st, "_cached_iocs", None)
    if cached_iocs and isinstance(cached_iocs, dict):
        report["iocs"] = {k: v[:50] for k, v in cached_iocs.items() if isinstance(v, list) and v}

    # Notes
    report["notes"] = [
        {"category": n.get("category", ""), "content": n.get("content", "")[:500], "address": n.get("address", "")}
        for n in st.get_notes()[:100]
    ]

    report["tool_history_count"] = st.get_tool_history_count()  # L2-v8

    return report


# ---------------------------------------------------------------------------
#  Full-text decompiled code search (Batch 4)
# ---------------------------------------------------------------------------

def search_decompiled_code(query: str, max_results: int = 100) -> Dict[str, Any]:
    """Search across all cached decompiled function code for a substring.

    Returns matching lines with function context.
    """
    result: Dict[str, Any] = {
        "query": query,
        "total_matches": 0,
        "results": [],
        "searched_functions": 0,
        "total_cached": 0,
    }
    if not query or not query.strip():
        return result

    # M4: Bound query length to prevent excessive memory/CPU
    query = query.strip()[:500]
    query_lower = query.lower()

    try:
        from arkana.mcp.tools_angr import _decompile_meta, _decompile_meta_lock
        from arkana.mcp._rename_helpers import (
            apply_function_renames_to_lines,
            apply_variable_renames_to_lines,
            get_display_name,
        )
    except ImportError:
        return result

    st = _get_state()
    if st is None:
        return result
    session_uuid = st._state_uuid
    renames = st.get_renames().get("functions", {})

    with _decompile_meta_lock:
        # Only search entries belonging to the current session
        meta_snapshot = {k: v for k, v in _decompile_meta.items()
                        if isinstance(k, tuple) and len(k) >= 2 and k[0] == session_uuid}

    result["total_cached"] = len(meta_snapshot)
    matches = []

    for cache_key, meta in meta_snapshot.items():
        addr_int = cache_key[1]
        addr_hex = hex(addr_int)
        raw_lines = meta.get("lines", [])
        if not raw_lines:
            continue

        result["searched_functions"] += 1

        # Apply renames for display
        lines = apply_function_renames_to_lines(raw_lines)
        lines = apply_variable_renames_to_lines(lines, addr_hex)
        func_name = get_display_name(addr_hex, meta.get("function_name", addr_hex))
        if addr_hex in renames:
            func_name = renames[addr_hex]

        for line_num, line in enumerate(lines, 1):
            if query_lower in line.lower():
                # Context: 1 line before and after
                ctx_before = lines[line_num - 2] if line_num >= 2 else ""
                ctx_after = lines[line_num] if line_num < len(lines) else ""
                matches.append({
                    "function_name": func_name,
                    "address": addr_hex,
                    "line_number": line_num,
                    "line_text": line,
                    "context_before": ctx_before,
                    "context_after": ctx_after,
                })
                if len(matches) >= max_results:
                    break
        if len(matches) >= max_results:
            break

    result["total_matches"] = len(matches)
    result["results"] = matches
    return result


# ---------------------------------------------------------------------------
#  BSim signature database data (for Similarity page)
# ---------------------------------------------------------------------------

# Module-level cache for BSim triage results (keyed by sha256)
_bsim_triage_cache: Dict[str, tuple] = {}  # sha256 -> (expire_time, result)
_BSIM_TRIAGE_TTL = 300.0  # 5 minutes — triage is expensive

_BSIM_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _validate_sha256(sha256: str) -> bool:
    """Return True if sha256 is a valid 64-char hex string."""
    return bool(_BSIM_HEX64_RE.match(sha256))


def get_bsim_db_stats() -> Dict[str, Any]:
    """Return BSim signature DB statistics.  No angr needed — pure SQLite read."""
    try:
        from arkana.mcp._bsim_features import get_db_path, _get_connection
    except ImportError:
        return {"available": False, "error": "BSim module not available"}

    db = get_db_path()
    if not db.exists():
        return {
            "available": True,
            "total_binaries": 0,
            "total_functions": 0,
            "user_entries": 0,
            "library_entries": 0,
            "db_size_bytes": 0,
            "current_indexed": False,
            "current_sha256": "",
        }

    st = _get_state()
    current_sha256 = ""
    pe_data = st.pe_data or {}
    file_hashes = pe_data.get("file_hashes", {})
    if isinstance(file_hashes, dict):
        current_sha256 = file_hashes.get("sha256", "")

    conn = _get_connection(db)
    try:
        total_f = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
        # Single query for binary counts by source
        user_b = 0
        lib_b = 0
        for row in conn.execute(
            "SELECT source, COUNT(*) FROM binaries GROUP BY source"
        ).fetchall():
            if row[0] == "library":
                lib_b = row[1]
            else:
                user_b = row[1]
        total_b = user_b + lib_b

        current_indexed = False
        if current_sha256:
            row = conn.execute(
                "SELECT 1 FROM binaries WHERE sha256 = ? LIMIT 1",
                (current_sha256,),
            ).fetchone()
            current_indexed = row is not None

        return {
            "available": True,
            "total_binaries": total_b,
            "total_functions": total_f,
            "user_entries": user_b,
            "library_entries": lib_b,
            "db_size_bytes": db.stat().st_size,
            "current_indexed": current_indexed,
            "current_sha256": current_sha256,
        }
    except Exception:
        logger.debug("BSim DB stats query failed", exc_info=True)
        return {"available": False, "error": "Failed to read signature DB"}
    finally:
        conn.close()


# Project membership cache — `_project_membership_for_shas` walks every
# project's member list per call, which is fine for one-shot use but the
# dashboard polls the BSim DB and triage tabs every ~10s. We build a full
# {sha256: [{id, name}]} reverse-index ONCE and cache it for a few seconds.
# Invalidated by mtime on the projects index file (cheap stat) so creates/
# deletes/renames flush the cache the next call.
_PROJECT_MEMBERSHIP_TTL_S = 10.0
_project_membership_cache: Dict[str, Any] = {
    "expires": 0.0,
    "index_mtime": 0.0,
    "map": {},  # sha256_lower → [{id, name}, ...]
}
_project_membership_lock = threading.Lock()


def _build_full_project_membership() -> Dict[str, List[Dict[str, str]]]:
    """Walk every project once and return ``{sha256: [{id, name}, ...]}``.

    O(P * M) where P = projects, M = members per project. Used by
    ``_project_membership_for_shas`` as the underlying source — the
    cache wraps this so dashboard polls don't pay the walk cost on
    every request.
    """
    try:
        from arkana.projects import project_manager
    except ImportError:
        return {}
    full: Dict[str, List[Dict[str, str]]] = {}
    try:
        projects = project_manager.list(sort_by="name")
    except Exception:
        return full
    for proj in projects:
        try:
            members = proj.snapshot_members()
            pid = proj.id
            pname = proj.name
        except Exception:
            continue
        entry = {"id": pid, "name": pname}
        for member in members:
            sha_l = (member.get("sha256") or "").lower()
            if sha_l:
                full.setdefault(sha_l, []).append(entry)
    return full


def _get_project_membership_map() -> Dict[str, List[Dict[str, str]]]:
    """Return the cached full membership map, refreshing on TTL or mtime."""
    try:
        from arkana.projects import INDEX_FILE
        index_mtime = INDEX_FILE.stat().st_mtime if INDEX_FILE.exists() else 0.0
    except Exception:
        index_mtime = 0.0
    now = time.time()
    with _project_membership_lock:
        if (now < _project_membership_cache["expires"]
                and index_mtime == _project_membership_cache["index_mtime"]):
            return _project_membership_cache["map"]
    fresh = _build_full_project_membership()
    with _project_membership_lock:
        _project_membership_cache["map"] = fresh
        _project_membership_cache["expires"] = now + _PROJECT_MEMBERSHIP_TTL_S
        _project_membership_cache["index_mtime"] = index_mtime
    return fresh


def _project_membership_for_shas(sha256_list: List[str]) -> Dict[str, List[Dict[str, str]]]:
    """Build a ``{sha256: [{id, name}, ...]}`` map for the given sha256s.

    Backed by the in-memory cache from ``_get_project_membership_map`` so
    dashboard polls of the BSim DB / triage tabs don't pay the O(P*M) walk
    on every request. Cache is invalidated by mtime on the projects index
    file plus a 10s TTL ceiling.
    """
    if not sha256_list:
        return {}
    wanted = {s.lower() for s in sha256_list if s}
    if not wanted:
        return {}
    full = _get_project_membership_map()
    return {sha: list(full.get(sha, [])) for sha in wanted}


def get_bsim_indexed_binaries() -> Dict[str, Any]:
    """List all indexed binaries in the BSim DB for the DATABASE tab.

    Each row is enriched with a ``projects`` field listing every project
    that contains the binary as a member, so the dashboard can show
    "which project does this signature belong to" without an extra
    round-trip per row.
    """
    try:
        from arkana.mcp._bsim_features import list_indexed_binaries
    except ImportError:
        return {"binaries": [], "error": "BSim module not available"}

    try:
        binaries = list_indexed_binaries()
        sha_list = [b.get("sha256", "") for b in binaries if b.get("sha256")]
        membership = _project_membership_for_shas(sha_list)
        for b in binaries:
            sha = (b.get("sha256") or "").lower()
            b["projects"] = membership.get(sha, [])
        return {"binaries": binaries, "total": len(binaries)}
    except Exception:
        logger.debug("BSim list binaries failed", exc_info=True)
        return {"binaries": [], "error": "Failed to read signature DB"}


def get_bsim_triage_data(cache_only: bool = False) -> Dict[str, Any]:
    """Run BSim triage or return cached results.

    This is expensive (iterates all functions).  Results are cached for
    ``_BSIM_TRIAGE_TTL`` seconds keyed by the loaded file's SHA256.

    When *cache_only* is True, return cached results without computing.
    Used by the page-load auto-fetch to avoid expensive surprise computation.
    """
    st = _get_state()
    pe_data = st.pe_data or {}
    file_hashes = pe_data.get("file_hashes", {})
    sha256 = file_hashes.get("sha256", "") if isinstance(file_hashes, dict) else ""
    if not sha256:
        return {"available": False, "error": "No file loaded"}

    # Check cache. Project membership is enriched AFTER fetch (not stored
    # in the cached payload) so a project rename/create/delete during the
    # TTL window is reflected immediately on the next read.
    now = time.time()
    with _cache_lock:
        cached = _bsim_triage_cache.get(sha256)
    if cached is not None:
        expire_time, result = cached
        if now < expire_time:
            return _enrich_triage_with_projects(result)

    if cache_only:
        return {"available": False, "cached": False}

    if st.angr_project is None or st.angr_cfg is None:
        return {"available": False, "error": "angr CFG not ready"}

    try:
        from arkana.mcp._bsim_features import (
            get_db_path, extract_function_features, query_similar_functions,
            is_trivial_function, compute_feature_idf,
        )
    except ImportError:
        return {"available": False, "error": "BSim module not available"}

    db = get_db_path()
    if not db.exists():
        return {"available": True, "results": [], "total_functions_analyzed": 0,
                "functions_with_matches": 0, "indexed_binaries_matched": 0}

    project = st.angr_project
    cfg = st.angr_cfg

    all_funcs = [
        f for f in cfg.functions.values()
        if not is_trivial_function(f)
    ]
    all_funcs.sort(key=lambda f: f.addr)
    total = len(all_funcs)

    arch = None
    try:
        arch = project.arch.name
    except Exception:
        pass

    idf = compute_feature_idf()
    binary_matches: Dict[str, Dict[str, Any]] = {}
    functions_matched = 0
    renames = st.get_renames().get("functions", {})

    for func in all_funcs:
        try:
            features = extract_function_features(project, cfg, func, include_vex=False)
            matches = query_similar_functions(
                target_features=features,
                threshold=0.7,
                metrics="combined",
                limit=3,
                source_architecture=arch,
                idf_weights=idf,
            )
            if matches:
                functions_matched += 1
                for match in matches:
                    msha = match["binary_sha256"]
                    if msha not in binary_matches:
                        binary_matches[msha] = {
                            "binary_sha256": msha,
                            "binary_filename": match["binary_filename"],
                            "architecture": match.get("architecture", ""),
                            "source": match.get("source", "user"),
                            "library_name": match.get("library_name"),
                            "shared_functions": [],
                            "similarity_sum": 0.0,
                            "confidence_sum": 0.0,
                        }
                    entry = binary_matches[msha]
                    addr_hex = hex(func.addr)
                    func_name = renames.get(addr_hex, func.name or f"sub_{func.addr:x}")
                    if not any(sf["source_address"] == addr_hex for sf in entry["shared_functions"]):
                        entry["shared_functions"].append({
                            "source_address": addr_hex,
                            "source_name": func_name,
                            "match_address": match.get("address", ""),
                            "match_name": match["name"],
                            "similarity": round(match["scores"].get("combined", 0), 4),
                            "confidence": round(match.get("confidence", 0), 2),
                        })
                        entry["similarity_sum"] += match["scores"].get("combined", 0)
                        entry["confidence_sum"] += match.get("confidence", 0)
        except Exception:
            logger.debug("BSim triage feature extraction failed for %#x", func.addr, exc_info=True)

    results = []
    for entry in binary_matches.values():
        count = len(entry["shared_functions"])
        avg_sim = entry["similarity_sum"] / count if count else 0
        avg_conf = entry["confidence_sum"] / count if count else 0
        top_matches = sorted(
            entry["shared_functions"],
            key=lambda m: m.get("confidence", 0) * m.get("similarity", 0),
            reverse=True,
        )[:20]
        results.append({
            "binary_sha256": entry["binary_sha256"],
            "binary_filename": entry["binary_filename"],
            "architecture": entry.get("architecture", ""),
            "source": entry.get("source", "user"),
            "library_name": entry.get("library_name"),
            "shared_function_count": count,
            "shared_function_ratio": round(count / max(total, 1), 3),
            "avg_similarity": round(avg_sim, 4),
            "avg_confidence": round(avg_conf, 2),
            "top_matches": top_matches,
        })

    results.sort(key=lambda r: r.get("avg_similarity", 0) * r.get("avg_confidence", 0) * r.get("shared_function_count", 0), reverse=True)
    results = results[:20]

    # NOTE: project membership is NOT stored in the cached payload — it's
    # enriched on every read via ``_enrich_triage_with_projects`` so a
    # project create/rename/delete during the TTL window is reflected
    # immediately on the next call.

    result = {
        "available": True,
        "binary": os.path.basename(st.filepath) if st.filepath else "",
        "total_functions_analyzed": total,
        "functions_with_matches": functions_matched,
        "indexed_binaries_matched": len(results),
        "results": results,
    }

    # Cache the result WITHOUT the projects field — see _enrich_triage_with_projects
    with _cache_lock:
        if len(_bsim_triage_cache) >= 4:
            oldest = min(_bsim_triage_cache, key=lambda k: _bsim_triage_cache[k][0])
            del _bsim_triage_cache[oldest]
        _bsim_triage_cache[sha256] = (time.time() + _BSIM_TRIAGE_TTL, result)

    return _enrich_triage_with_projects(result)


def _enrich_triage_with_projects(triage_result: Dict[str, Any]) -> Dict[str, Any]:
    """Add a ``projects: [{id, name}]`` field to every entry in
    ``triage_result['results']`` based on the current project membership.

    Called on EVERY triage read (cached and uncached) so a project create/
    rename/delete during the cache TTL window is immediately reflected in
    the next response. The underlying ``_project_membership_for_shas`` call
    is itself memoised with a short TTL + index-mtime invalidation, so this
    enrichment is essentially free on the hot path.
    """
    results = triage_result.get("results") or []
    if not results:
        return triage_result
    membership = _project_membership_for_shas([r["binary_sha256"] for r in results])
    enriched_results = []
    for r in results:
        r_copy = dict(r)
        r_copy["projects"] = membership.get((r["binary_sha256"] or "").lower(), [])
        enriched_results.append(r_copy)
    enriched = dict(triage_result)
    enriched["results"] = enriched_results
    return enriched


def get_bsim_triage_function_matches(binary_sha256: str) -> Dict[str, Any]:
    """Return function-level match details for a matched binary from triage cache."""
    if not _validate_sha256(binary_sha256):
        return {"error": "Invalid SHA256 format"}

    # Look through triage cache for the match
    now = time.time()
    with _cache_lock:
        for _sha, (expire_time, result) in _bsim_triage_cache.items():
            if now >= expire_time:
                continue
            for entry in result.get("results", []):
                if entry.get("binary_sha256") == binary_sha256:
                    return {
                        "available": True,
                        "binary_filename": entry.get("binary_filename", ""),
                        "binary_sha256": binary_sha256,
                        "shared_function_count": entry.get("shared_function_count", 0),
                        "avg_similarity": entry.get("avg_similarity", 0),
                        "matches": entry.get("top_matches", []),
                    }

    return {"available": False, "error": "No cached triage data for this binary"}


def get_project_comparison_data(project_a_id: str,
                                project_b_id: str,
                                threshold: float = 0.7,
                                top_match_limit: int = 30) -> Dict[str, Any]:
    """Compare every member of *project_a_id* against every member of *project_b_id*.

    For each ``(member_a, member_b)`` pair where both binaries are indexed
    in the BSim DB, runs ``compare_indexed_binaries`` and returns a matrix
    of pair-level similarity scores plus a project-level aggregate.

    Used by the new "PROJECTS" sub-tab on the Similarity page so users can
    quickly see "does my loader project share code with my payload project?"
    without manually opening each binary in turn.

    Returns
    -------
    dict with:
      - ``available``: bool
      - ``project_a`` / ``project_b``: ``{id, name, member_count}``
      - ``pairs``: list of per-pair comparison rows
      - ``aggregate``: {pair_count, indexed_pair_count, total_shared,
                        avg_jaccard, avg_similarity, max_jaccard}
      - ``unindexed_members``: list of {sha256, filename, project} for
        members that aren't in the BSim DB (so the UI can prompt the user
        to index them).
    """
    if project_a_id == project_b_id:
        return {"available": False, "error": "Pick two different projects"}
    # Threshold validation: clamp NaN/inf and bound to [0, 1].
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        threshold = 0.7
    if not math.isfinite(threshold):
        threshold = 0.7
    threshold = max(0.0, min(threshold, 1.0))
    try:
        from arkana.projects import project_manager
    except ImportError:
        return {"available": False, "error": "projects module unavailable"}
    try:
        from arkana.mcp._bsim_features import (
            compare_indexed_binaries, is_binaries_indexed_batch,
            get_db_path, _get_connection,
        )
    except ImportError:
        return {"available": False, "error": "BSim module unavailable"}

    proj_a = project_manager.get(project_a_id)
    proj_b = project_manager.get(project_b_id)
    if proj_a is None:
        return {"available": False, "error": f"Project {project_a_id} not found"}
    if proj_b is None:
        return {"available": False, "error": f"Project {project_b_id} not found"}

    members_a = proj_a.snapshot_members()
    members_b = proj_b.snapshot_members()
    if not members_a or not members_b:
        return {
            "available": True,
            "project_a": {"id": proj_a.id, "name": proj_a.name, "member_count": len(members_a)},
            "project_b": {"id": proj_b.id, "name": proj_b.name, "member_count": len(members_b)},
            "pairs": [],
            "aggregate": {
                "pair_count": 0, "indexed_pair_count": 0, "total_shared": 0,
                "avg_jaccard": 0.0, "avg_similarity": 0.0, "max_jaccard": 0.0,
            },
            "unindexed_members": [],
        }

    # Hard pair-count cap. M*N pairs of compare_indexed_binaries can pin a
    # dashboard worker thread for many minutes — refuse outright when the
    # caller picks two huge projects rather than silently truncating.
    pair_grid_size = len(members_a) * len(members_b)
    if pair_grid_size > MAX_PROJECT_COMPARE_PAIRS:
        return {
            "available": False,
            "error": (
                f"Comparing {len(members_a)} × {len(members_b)} = {pair_grid_size} "
                f"pairs exceeds the dashboard cap of {MAX_PROJECT_COMPARE_PAIRS}. "
                f"Pick smaller projects or compare members individually."
            ),
            "pair_count": pair_grid_size,
            "max_pair_count": MAX_PROJECT_COMPARE_PAIRS,
        }

    # Open ONE sqlite connection and reuse it across the entire pair grid.
    # The previous implementation paid a connect/close cost per pair.
    db = get_db_path()
    if not db.exists():
        return {"available": False, "error": "BSim DB does not exist"}

    conn = _get_connection(db)
    try:
        # Batched index check — one IN(...) query for both sides instead
        # of 2*(M+N) connection-open/close round-trips.
        all_shas = [m["sha256"] for m in members_a] + [m["sha256"] for m in members_b]
        index_map = is_binaries_indexed_batch(all_shas, conn=conn)
        indexed_a = {m["sha256"]: index_map.get(m["sha256"].lower(), False)
                     for m in members_a}
        indexed_b = {m["sha256"]: index_map.get(m["sha256"].lower(), False)
                     for m in members_b}

        unindexed: List[Dict[str, str]] = []
        for m in members_a:
            if not indexed_a.get(m["sha256"]):
                unindexed.append({
                    "sha256": m["sha256"], "filename": m["filename"],
                    "project": proj_a.name,
                })
        for m in members_b:
            if not indexed_b.get(m["sha256"]):
                unindexed.append({
                    "sha256": m["sha256"], "filename": m["filename"],
                    "project": proj_b.name,
                })

        pairs: List[Dict[str, Any]] = []
        indexed_pair_count = 0
        total_shared = 0
        sum_jaccard = 0.0
        sum_similarity = 0.0
        max_jaccard = 0.0
        # Project-level wallclock budget — each pair can also burn its own
        # per-pair budget inside compare_indexed_binaries. The overall cap
        # protects against death-by-many-small-pairs.
        deadline = time.monotonic() + PROJECT_COMPARE_TIME_BUDGET_S
        truncated = False

        for ma in members_a:
            if time.monotonic() > deadline:
                truncated = True
                break
            for mb in members_b:
                if time.monotonic() > deadline:
                    truncated = True
                    break
                entry = {
                    "a_sha256": ma["sha256"],
                    "a_filename": ma["filename"],
                    "b_sha256": mb["sha256"],
                    "b_filename": mb["filename"],
                    "available": False,
                    "shared_function_count": 0,
                    "jaccard": 0.0,
                    "avg_similarity": 0.0,
                }
                if not indexed_a.get(ma["sha256"]) or not indexed_b.get(mb["sha256"]):
                    entry["error"] = "one or both binaries not indexed"
                    pairs.append(entry)
                    continue
                try:
                    result = compare_indexed_binaries(
                        ma["sha256"], mb["sha256"],
                        threshold=threshold,
                        top_match_limit=top_match_limit,
                        conn=conn,
                    )
                except Exception as exc:
                    logger.debug("project comparison failed for pair", exc_info=True)
                    entry["error"] = f"comparison failed: {exc}"
                    pairs.append(entry)
                    continue
                if not result.get("available"):
                    entry["error"] = result.get("error", "comparison unavailable")
                    pairs.append(entry)
                    continue
                entry["available"] = True
                entry["shared_function_count"] = result.get("shared_function_count", 0)
                entry["jaccard"] = result.get("jaccard", 0.0)
                entry["avg_similarity"] = result.get("avg_similarity", 0.0)
                entry["total_functions_a"] = result.get("total_functions_a", 0)
                entry["total_functions_b"] = result.get("total_functions_b", 0)
                # matched_a/matched_b counts are how the UI surfaces asymmetric
                # collapses (e.g. "20 A funcs collapsed onto 1 B func").
                entry["matched_a_count"] = result.get("matched_a_count", 0)
                entry["matched_b_count"] = result.get("matched_b_count", 0)
                # Prune top_matches from zero-shared pairs to keep payload
                # size sane. Empty lists save ~80 bytes per zero pair which
                # adds up across a 500-pair grid.
                if entry["shared_function_count"] > 0:
                    entry["top_matches"] = result.get("top_matches", [])
                indexed_pair_count += 1
                total_shared += entry["shared_function_count"]
                sum_jaccard += entry["jaccard"]
                sum_similarity += entry["avg_similarity"]
                if entry["jaccard"] > max_jaccard:
                    max_jaccard = entry["jaccard"]
                pairs.append(entry)
            else:
                continue
            break  # outer loop hit deadline
    finally:
        conn.close()

    pairs.sort(key=lambda p: (p["jaccard"], p["shared_function_count"]), reverse=True)
    avg_jaccard = (sum_jaccard / indexed_pair_count) if indexed_pair_count else 0.0
    avg_similarity = (sum_similarity / indexed_pair_count) if indexed_pair_count else 0.0

    result_payload: Dict[str, Any] = {
        "available": True,
        "project_a": {"id": proj_a.id, "name": proj_a.name, "member_count": len(members_a)},
        "project_b": {"id": proj_b.id, "name": proj_b.name, "member_count": len(members_b)},
        "threshold": threshold,
        "pairs": pairs,
        "aggregate": {
            "pair_count": len(pairs),
            "indexed_pair_count": indexed_pair_count,
            "total_shared": total_shared,
            "avg_jaccard": round(avg_jaccard, 4),
            "avg_similarity": round(avg_similarity, 4),
            "max_jaccard": round(max_jaccard, 4),
        },
        "unindexed_members": unindexed,
    }
    if truncated:
        result_payload["truncated"] = True
        result_payload["note"] = (
            f"Hit {PROJECT_COMPARE_TIME_BUDGET_S}s overall time budget; "
            f"{len(pairs)}/{pair_grid_size} pairs analysed."
        )
    return result_payload


def get_bsim_db_health() -> Dict[str, Any]:
    """Run BSim DB validation and return health diagnostics."""
    try:
        from arkana.mcp._bsim_features import get_db_path, _get_connection
    except ImportError:
        return {"error": "BSim module not available"}

    db = get_db_path()
    if not db.exists():
        return {"status": "empty", "message": "Signature DB does not exist."}

    conn = _get_connection(db)
    try:
        total_f = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
        user_count = 0
        lib_count = 0
        for row in conn.execute(
            "SELECT source, COUNT(*) FROM binaries GROUP BY source"
        ).fetchall():
            if row[0] == "library":
                lib_count = row[1]
            else:
                user_count = row[1]
        total_b = user_count + lib_count

        binaries = []
        for row in conn.execute(
            "SELECT filename, function_count, architecture, source, library_name "
            "FROM binaries ORDER BY indexed_at DESC"
        ).fetchall():
            binaries.append(dict(row))

        # Sanity test: sample random functions, query themselves
        sanity_results = []
        all_passed = True
        if total_f > 0:
            from arkana.mcp._bsim_features import (
                _row_to_features, compute_similarity,
            )
            sample_rows = conn.execute(
                "SELECT * FROM functions ORDER BY RANDOM() LIMIT 10"
            ).fetchall()
            for row in sample_rows:
                try:
                    features = _row_to_features(row)
                    scores = compute_similarity(features, features)
                    self_sim = scores.get("combined", 0)
                    passed = self_sim >= 0.95
                    if not passed:
                        all_passed = False
                    sanity_results.append({
                        "name": row["name"] or f"sub_{row['address']:x}",
                        "self_similarity": round(self_sim, 4),
                        "pass": passed,
                    })
                except Exception:
                    sanity_results.append({
                        "name": row["name"] or "unknown",
                        "self_similarity": 0,
                        "pass": False,
                    })
                    all_passed = False

        health = []
        if all_passed:
            health.append("All checks passed")
        else:
            health.append("Self-match test had failures")
        if total_f == 0:
            health.append("Database is empty — index some binaries")

        return {
            "status": "success",
            "stats": {
                "total_binaries": total_b,
                "total_functions": total_f,
                "user_entries": user_count,
                "library_entries": lib_count,
            },
            "binaries": binaries,
            "sanity_test": {
                "samples_tested": len(sanity_results),
                "all_passed": all_passed,
                "results": sanity_results,
            },
            "health": health,
        }
    except Exception:
        logger.debug("BSim DB health check failed", exc_info=True)
        return {"error": "Health check failed"}
    finally:
        conn.close()


def delete_bsim_binary(sha256: str) -> Dict[str, Any]:
    """Delete a single binary from the BSim signature DB."""
    if not _validate_sha256(sha256):
        return {"error": "Invalid SHA256 format"}

    try:
        from arkana.mcp._bsim_features import get_db_path, _get_connection, _db_write_lock
    except ImportError:
        return {"error": "BSim module not available"}

    db = get_db_path()
    if not db.exists():
        return {"error": "Signature DB does not exist"}

    with _db_write_lock:
        conn = _get_connection(db)
        try:
            cursor = conn.execute(
                "DELETE FROM binaries WHERE sha256 = ?", (sha256,)
            )
            conn.commit()
            if cursor.rowcount == 0:
                return {"error": "Binary not found in DB"}
        except Exception:
            logger.debug("BSim delete binary failed", exc_info=True)
            return {"error": "Delete failed"}
        finally:
            conn.close()
    # Invalidate triage cache — deleted binary may appear in cached results
    with _cache_lock:
        _bsim_triage_cache.clear()
    return {"status": "success", "deleted_sha256": sha256}


def clear_bsim_db() -> Dict[str, Any]:
    """Clear all entries from the BSim signature DB."""
    try:
        from arkana.mcp._bsim_features import get_db_path, _get_connection, _db_write_lock
    except ImportError:
        return {"error": "BSim module not available"}

    db = get_db_path()
    if not db.exists():
        return {"status": "success", "message": "DB already empty"}

    with _db_write_lock:
        conn = _get_connection(db)
        try:
            conn.execute("DELETE FROM functions")
            conn.execute("DELETE FROM binaries")
            conn.commit()
        except Exception:
            logger.debug("BSim clear DB failed", exc_info=True)
            return {"error": "Clear failed"}
        finally:
            conn.close()
    # Clear triage cache outside DB lock to avoid nested locking
    with _cache_lock:
        _bsim_triage_cache.clear()
    return {"status": "success", "message": "All entries cleared"}


def index_current_binary() -> Dict[str, Any]:
    """Index the currently loaded binary into the BSim signature DB."""
    st = _get_state()
    if st.angr_project is None or st.angr_cfg is None:
        return {"error": "angr CFG not ready. Wait for background analysis."}

    pe_data = st.pe_data or {}
    file_hashes = pe_data.get("file_hashes", {})
    sha256 = file_hashes.get("sha256", "") if isinstance(file_hashes, dict) else ""
    if not sha256:
        return {"error": "No file loaded"}

    try:
        from arkana.mcp._bsim_features import (
            extract_function_features, store_binary_features,
            is_trivial_function,
        )
    except ImportError:
        return {"error": "BSim module not available"}

    project = st.angr_project
    cfg = st.angr_cfg
    filepath = st.filepath or ""

    arch = "unknown"
    try:
        arch = project.arch.name
    except Exception:
        pass

    all_funcs = [
        f for f in cfg.functions.values()
        if not is_trivial_function(f)
    ]

    features_list = []
    for func in all_funcs:
        try:
            feat = extract_function_features(project, cfg, func, include_vex=False)
            features_list.append(feat)
        except Exception:
            logger.debug("BSim index feature extraction failed for %#x", func.addr, exc_info=True)

    file_size = 0
    try:
        file_size = os.path.getsize(filepath)
    except Exception:
        pass

    try:
        binary_id = store_binary_features(
            sha256=sha256,
            filename=os.path.basename(filepath),
            architecture=arch,
            file_size=file_size,
            features_list=features_list,
        )
        # Invalidate triage cache since DB changed
        with _cache_lock:
            _bsim_triage_cache.clear()
        return {
            "status": "success",
            "binary_id": binary_id,
            "functions_indexed": len(features_list),
            "sha256": sha256,
        }
    except Exception:
        logger.debug("BSim index failed", exc_info=True)
        return {"error": "Indexing failed"}


# ---------------------------------------------------------------------------
#  Binary diff data (Batch 4)
# ---------------------------------------------------------------------------

def get_diff_data(file_path_b: str, limit: int = 50) -> Dict[str, Any]:
    """Run angr BinDiff between the loaded binary and a second binary.

    Returns categorised function lists: identical, differing, unmatched-A, unmatched-B.
    """
    st = _get_state()
    if st.angr_project is None or st.angr_cfg is None:
        return {"error": "No angr project/CFG loaded. Open a file first."}

    try:
        from arkana.imports import ANGR_AVAILABLE
        if not ANGR_AVAILABLE:
            return {"error": "angr is not available"}
        import angr
    except ImportError:
        return {"error": "angr is not available"}

    limit = max(1, min(limit, 500))

    # Validate file_path_b — must be a real file, no path traversal
    file_path_b = os.path.realpath(file_path_b)
    if not os.path.isfile(file_path_b):
        return {"error": "File not found or not accessible"}
    # M-S7: Also validate via state.check_path_allowed() as defense-in-depth,
    # even when ARKANA_SAMPLES_DIR is not set.
    samples_dir = os.environ.get("ARKANA_SAMPLES_DIR", "")
    if samples_dir:
        samples_real = os.path.realpath(samples_dir)
        if not file_path_b.startswith(samples_real + os.sep) and file_path_b != samples_real:
            return {"error": "File must be within the samples directory"}
    try:
        st.check_path_allowed(file_path_b)
    except RuntimeError:
        return {"error": "File path is outside the allowed directories"}

    proj_a = st.angr_project
    cfg_a = st.angr_cfg
    renames_a = st.get_renames().get("functions", {})
    file_a = os.path.basename(st.filepath) if st.filepath else "file_a"

    proj_b = None
    cfg_b = None
    try:
        proj_b = angr.Project(file_path_b, auto_load_libs=False)
        cfg_b = proj_b.analyses.CFGFast()

        bd = proj_a.analyses.BinDiff(proj_b, cfg_a=cfg_a.model, cfg_b=cfg_b.model)

        identical = []
        differing = []
        unmatched_a = []
        unmatched_b = []

        def _func_addr(f):
            """Extract hex address from a function object or raw integer."""
            if isinstance(f, int):
                return hex(f)
            if hasattr(f, "addr"):
                return hex(f.addr)
            return hex(int(f)) if str(f).isdigit() else str(f)

        def _func_name(f, fallback=""):
            """Extract name from a function object, or return fallback."""
            if hasattr(f, "name"):
                return str(f.name)
            return fallback

        # Identical functions
        try:
            for fa, fb in list(getattr(bd, "identical_functions", []))[:limit]:
                addr_a = _func_addr(fa)
                addr_b = _func_addr(fb)
                name_a = renames_a.get(addr_a, _func_name(fa, addr_a))
                identical.append({"addr_a": addr_a, "addr_b": addr_b, "name": name_a})
        except Exception:
            logger.debug("Skipped identical_functions during diff", exc_info=True)

        # Differing functions
        try:
            for fa, fb in list(getattr(bd, "differing_functions", []))[:limit]:
                addr_a = _func_addr(fa)
                addr_b = _func_addr(fb)
                name_a = renames_a.get(addr_a, _func_name(fa, addr_a))
                name_b = _func_name(fb, addr_b)
                differing.append({"addr_a": addr_a, "name_a": name_a, "addr_b": addr_b, "name_b": name_b})
        except Exception:
            logger.debug("Skipped differing_functions during diff", exc_info=True)

        # Unmatched in A
        try:
            for f in list(getattr(bd, "unmatched_from_a", getattr(bd, "unmatched_a", [])))[:limit]:
                addr = _func_addr(f)
                name = renames_a.get(addr, _func_name(f, addr))
                unmatched_a.append({"addr": addr, "name": name})
        except Exception:
            logger.debug("Skipped unmatched_from_a during diff", exc_info=True)

        # Unmatched in B
        try:
            for f in list(getattr(bd, "unmatched_from_b", getattr(bd, "unmatched_b", [])))[:limit]:
                addr = _func_addr(f)
                name = _func_name(f, addr)
                unmatched_b.append({"addr": addr, "name": name})
        except Exception:
            logger.debug("Skipped unmatched_from_b during diff", exc_info=True)

        return {
            "file_a": file_a,
            "file_b": os.path.basename(file_path_b),
            "identical_count": len(identical),
            "differing_count": len(differing),
            "unmatched_a_count": len(unmatched_a),
            "unmatched_b_count": len(unmatched_b),
            "identical_functions": identical,
            "differing_functions": differing,
            "unmatched_in_a": unmatched_a,
            "unmatched_in_b": unmatched_b,
        }

    except Exception:
        logger.debug("BinDiff error", exc_info=True)
        return {"error": "BinDiff analysis failed"}
    finally:
        # Cleanup angr objects for the second binary
        try:
            del cfg_b
            del proj_b
        except Exception:
            pass


# ---------------------------------------------------------------------------
#  File listing for dashboard file browser
# ---------------------------------------------------------------------------

_MAX_LIST_FILES = 10000  # hard cap to prevent DoS on large/misconfigured directories
_MAX_LIST_DEPTH = 10     # maximum directory recursion depth
# M-E7: Cache file listings to avoid repeated filesystem walks + magic byte reads
_list_files_cache: Dict[str, tuple] = {}  # samples_path -> (expire_time, result)
_LIST_FILES_TTL = 10.0  # seconds
_MAX_LIST_FILES_CACHE = 4  # max cached directory listings


def get_list_files_data(search: str = "", sort_by: str = "name") -> Dict[str, Any]:
    """List files in the configured samples directory for the dashboard file browser.

    Returns a list of files with name, relative path, size, and format hint.
    Full filesystem paths are never exposed to the client.
    """
    st = _get_state()
    samples_path = getattr(st, "samples_path", None) or getattr(_default_state, "samples_path", None)
    if not samples_path or not os.path.isdir(samples_path):
        return {"files": [], "error": "No samples directory configured"}

    # Resolve to real path once to prevent symlink traversal
    resolved_samples = os.path.realpath(samples_path)

    # M-E7: Check cache before filesystem walk (search/sort applied post-cache)
    now = time.time()
    with _cache_lock:
        cached_entry = _list_files_cache.get(resolved_samples)
    if cached_entry is not None:
        expire_time, cached_files, cached_truncated = cached_entry
        if now < expire_time:
            files = cached_files
            truncated = cached_truncated
            # Skip filesystem walk — jump to search/sort below
            return _apply_list_files_filters(files, truncated, search, sort_by)

    from arkana.mcp._format_helpers import get_magic_hint

    files = []
    truncated = False
    try:
        for root, dirs, filenames in os.walk(resolved_samples, followlinks=False):
            # Enforce depth limit
            depth = root[len(resolved_samples):].count(os.sep)
            if depth >= _MAX_LIST_DEPTH:
                dirs.clear()
                continue
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in filenames:
                if fname.startswith("."):
                    continue
                if len(files) >= _MAX_LIST_FILES:
                    truncated = True
                    break
                full_path = os.path.join(root, fname)
                # Verify resolved path stays within samples directory
                real_file = os.path.realpath(full_path)
                if not real_file.startswith(resolved_samples + os.sep) and real_file != resolved_samples:
                    continue
                try:
                    stat_info = os.stat(full_path)
                    size = stat_info.st_size
                    if size >= 1_048_576:
                        size_human = f"{size / 1_048_576:.1f} MB"
                    elif size >= 1024:
                        size_human = f"{size / 1024:.1f} KB"
                    else:
                        size_human = f"{size} B"
                    fmt = get_magic_hint(full_path)
                    rel_path = os.path.relpath(full_path, resolved_samples)
                    files.append({
                        "name": fname,
                        "relative_path": rel_path,
                        "size_bytes": size,
                        "size_human": size_human,
                        "format_hint": fmt,
                    })
                except (OSError, ValueError):
                    continue
            if truncated:
                break
    except OSError:
        return {"files": [], "error": "Failed to read samples directory"}

    # M-E7: Cache the raw file list (before search/sort) for reuse
    with _cache_lock:
        _list_files_cache[resolved_samples] = (time.time() + _LIST_FILES_TTL, files, truncated)
        # L9: Evict oldest entries if cache grows too large
        if len(_list_files_cache) > _MAX_LIST_FILES_CACHE:
            oldest_key = min(_list_files_cache, key=lambda k: _list_files_cache[k][0])
            _list_files_cache.pop(oldest_key, None)

    return _apply_list_files_filters(files, truncated, search, sort_by)


def _apply_list_files_filters(files: list, truncated: bool, search: str, sort_by: str) -> Dict[str, Any]:
    """Apply search and sort to a file listing."""
    if search:
        search_lower = search.lower()
        files = [f for f in files if search_lower in f["name"].lower()]
    else:
        # M13-v14: Shallow copy to avoid mutating the cached list during sort
        files = list(files)

    sort_lower = sort_by.lower()
    if sort_lower == "size":
        files.sort(key=lambda f: f.get("size_bytes", 0), reverse=True)
    elif sort_lower == "format":
        files.sort(key=lambda f: f.get("format_hint", ""))
    else:
        files.sort(key=lambda f: f["name"].lower())

    result = {"files": files, "total": len(files)}
    if truncated:
        result["truncated"] = True
    return result


# ---------------------------------------------------------------------------
#  Analysis Digest (read-only, no side effects)
# ---------------------------------------------------------------------------

def get_digest_data() -> Dict[str, Any]:
    """Return structured analysis digest for the dashboard.

    Mirrors ``get_analysis_digest()`` from ``tools_session.py`` but never
    updates ``last_digest_timestamp`` (dashboard is read-only).
    """
    st = _get_state()
    result: Dict[str, Any] = {"available": False}

    if not st.filepath or not st.pe_data:
        return result

    result["available"] = True

    # --- Binary profile ---
    triage = getattr(st, "_cached_triage", None)
    if triage and isinstance(triage, dict):
        risk = triage.get("risk_level", "UNKNOWN")
        score = triage.get("risk_score", 0)
        mode = (st.pe_data or {}).get("mode", "unknown")
        packing = triage.get("packing_assessment", {})
        packed = packing.get("likely_packed", False) if isinstance(packing, dict) else False
        packer = packing.get("packer_name", "") if isinstance(packing, dict) else ""
        sig = triage.get("digital_signature", {})
        signed = sig.get("embedded_signature_present", False) if isinstance(sig, dict) else False

        parts = [mode.upper()]
        if packed:
            parts.append(f"packed ({packer})" if packer else "packed")
        parts.append("signed" if signed else "unsigned")
        parts.append(f"{risk} risk (score {score})")
        result["binary_profile"] = ", ".join(parts)
    else:
        result["binary_profile"] = "Triage not yet run"

    # --- Analysis phase ---
    phase = _detect_analysis_phase(st)
    result["analysis_phase"] = phase

    # --- Coverage ---
    total_functions = 0
    try:
        from arkana.imports import ANGR_AVAILABLE
        if ANGR_AVAILABLE and st.angr_cfg:
            total_functions = sum(
                1 for f in st.angr_cfg.functions.values()
                if not f.is_simprocedure and not f.is_syscall
            )
    except Exception:
        pass

    all_notes = st.get_notes()
    func_note_count = len([n for n in all_notes if n.get("category") == "function"])
    pct = round(func_note_count / total_functions * 100, 1) if total_functions > 0 else 0.0
    result["coverage"] = {
        "explored": func_note_count,
        "total": total_functions,
        "pct": f"{pct}%",
    }

    # --- Key findings (tool_result notes) ---
    key_findings = [
        n.get("content", "")
        for n in all_notes
        if n.get("category") == "tool_result"
    ][:15]
    result["key_findings"] = key_findings

    # --- Conclusion / hypothesis ---
    try:
        from arkana.mcp._rename_helpers import get_display_name
    except ImportError:
        get_display_name = None

    conclusion_parts: list = []
    classification = getattr(st, "_cached_classification", None)
    if classification and isinstance(classification, dict):
        purpose = classification.get("primary_type", "")
        confidence = classification.get("confidence", "")
        if purpose:
            line = f"Binary classified as: {purpose}"
            if confidence:
                line += f" (confidence: {confidence})"
            conclusion_parts.append(line)

    if triage and isinstance(triage, dict):
        suspicious_imports = triage.get("suspicious_imports", [])
        if isinstance(suspicious_imports, list) and suspicious_imports:
            count = len(suspicious_imports)
            top = [s.get("name", str(s)) if isinstance(s, dict) else str(s)
                   for s in suspicious_imports[:5]]
            conclusion_parts.append(
                f"{count} suspicious import(s): {', '.join(top)}"
            )
        capabilities = triage.get("capabilities", [])
        if isinstance(capabilities, list) and capabilities:
            conclusion_parts.append(
                f"Capabilities: {', '.join(str(c) for c in capabilities[:5])}"
            )
        network = triage.get("network_iocs", {})
        if isinstance(network, dict):
            urls = network.get("urls", [])
            ips = network.get("ips", [])
            domains = network.get("domains", [])
            net_items = urls + ips + domains
            if net_items:
                conclusion_parts.append(
                    f"Network indicators: {', '.join(str(i) for i in net_items[:5])}"
                )

    iocs = getattr(st, "_cached_iocs", None)
    if iocs and isinstance(iocs, dict):
        total_iocs = sum(
            len(v) for v in iocs.values() if isinstance(v, list)
        )
        if total_iocs > 0:
            conclusion_parts.append(f"Total IOCs extracted: {total_iocs}")

    if key_findings:
        conclusion_parts.append(
            f"{len(key_findings)} key finding(s) recorded from analysis tools"
        )

    func_notes = [n for n in all_notes if n.get("category") == "function"]
    hypothesis_notes = [
        n for n in all_notes if n.get("category") == "hypothesis"
    ]
    if hypothesis_notes:
        for hn in hypothesis_notes[:3]:
            conclusion_parts.append(f"Hypothesis: {hn.get('content', '')[:200]}")

    conclusion_notes = [
        n for n in all_notes if n.get("category") == "conclusion"
    ]
    if conclusion_notes:
        for cn in conclusion_notes[:2]:
            conclusion_parts.append(f"Conclusion: {cn.get('content', '')[:200]}")

    result["conclusion"] = conclusion_parts

    # --- Unexplored high-priority ---
    scored = getattr(st, "_cached_function_scores", None)
    unexplored_hp = []
    if scored:
        explored_addrs = {n.get("address") for n in func_notes}
        for f in scored:
            if not isinstance(f, dict):
                continue
            addr = f.get("addr", "")
            if addr in explored_addrs or f.get("score", 0) <= 10:
                continue
            name = f.get("name", addr)
            if get_display_name:
                name = get_display_name(addr, name)
            unexplored_hp.append({
                "addr": addr,
                "name": name,
                "score": f.get("score", 0),
                "reason": f.get("reason", ""),
            })
            if len(unexplored_hp) >= 10:
                break
    result["unexplored_high_priority"] = unexplored_hp

    # --- Analyst notes (general) ---
    general_notes = [
        {"content": n.get("content", "")[:300], "category": n.get("category", "general")}
        for n in all_notes
        if n.get("category") == "general"
    ][:10]
    result["analyst_notes"] = general_notes

    # --- User triage flags ---
    triage_snapshot = st.get_all_triage_snapshot()
    flagged = []
    suspicious = []
    if triage_snapshot:
        for addr, s in triage_snapshot.items():
            if s == "flagged":
                flagged.append(addr)
            elif s == "suspicious":
                suspicious.append(addr)
    result["user_flags"] = {"flagged": flagged, "suspicious": suspicious}

    return result


def _detect_analysis_phase(st) -> str:
    """Determine analysis phase for a given state object.

    M7-v10: Delegates to shared helper using canonical tool sets from tools_session.
    """
    return _detect_phase_for_state(st)


# ---------------------------------------------------------------------------
#  Generate Markdown Report
# ---------------------------------------------------------------------------

def generate_report_text() -> Dict[str, Any]:
    """Generate a markdown analysis report for the dashboard.

    Reuses logic from ``generate_analysis_report()`` in ``tools_workflow.py``.
    """
    import datetime as _dt

    st = _get_state()
    if not st.filepath or not st.pe_data:
        return {"available": False, "report": "", "format": "markdown", "filename": "report.md"}

    pe_data = st.pe_data or {}
    hashes = pe_data.get("file_hashes", {})
    if not isinstance(hashes, dict):
        hashes = {}
    filepath = st.filepath or "unknown"
    filename = os.path.basename(filepath)

    triage = getattr(st, "_cached_triage", None) or {}
    notes = st.get_notes()
    prev_history = getattr(st, "previous_session_history", None) or []
    cur_history = st.get_tool_history()
    history = list(itertools.chain(prev_history, cur_history))  # H2-v11: avoid list concat copy

    risk_level = triage.get("risk_level", "UNKNOWN")
    risk_score = triage.get("risk_score", 0)
    mode = pe_data.get("mode", "unknown")
    key_findings = [n["content"] for n in notes if n.get("category") == "tool_result"][:10]

    sections: List[str] = []

    # --- Executive Summary ---
    sections.append(f"# Malware Analysis Report: {filename}\n")
    sections.append(f"**Date:** {_dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
    sections.append("## Executive Summary\n")
    sections.append(f"- **Risk Level:** {risk_level} (score: {risk_score})")
    sections.append(f"- **File Type:** {mode}")
    sections.append(f"- **Tools Used:** {len(history)} invocations")
    sections.append(f"- **Functions Explored:** {len([n for n in notes if n.get('category') == 'function'])}")
    sections.append("")

    # --- File Information ---
    sections.append("## File Information\n")
    sections.append("| Property | Value |")
    sections.append("|----------|-------|")
    sections.append(f"| Filename | {filename} |")
    sections.append(f"| MD5 | {hashes.get('md5', 'N/A')} |")
    sections.append(f"| SHA-256 | {hashes.get('sha256', 'N/A')} |")

    file_size = pe_data.get("file_size")
    if not file_size and triage:
        file_info = triage.get("file_info", {})
        if isinstance(file_info, dict):
            file_size = file_info.get("file_size")
    if not file_size:
        try:
            file_size = os.path.getsize(filepath)
        except OSError:
            file_size = None
    if file_size and isinstance(file_size, (int, float)):
        sb = int(file_size)
        if sb >= 1_048_576:
            sh = f"{sb / 1_048_576:.1f} MB"
        elif sb >= 1024:
            sh = f"{sb / 1024:.1f} KB"
        else:
            sh = f"{sb} B"
        sections.append(f"| Size | {sb:,} bytes ({sh}) |")
    else:
        sections.append("| Size | N/A |")
    sections.append(f"| Format | {mode} |")
    sections.append("")

    # --- Risk Assessment ---
    if triage:
        sections.append("## Risk Assessment\n")
        sections.append(f"**Risk Level:** {risk_level} ({risk_score}/100)\n")
        sus_imports = triage.get("suspicious_imports", [])
        if sus_imports:
            sections.append("### Suspicious Imports\n")
            for imp in sus_imports[:15]:
                if isinstance(imp, dict):
                    sections.append(f"- **{imp.get('risk', '?')}**: {imp.get('function', '?')} ({imp.get('dll', '?')})")
            sections.append("")
        packing = triage.get("packing_assessment", {})
        if isinstance(packing, dict) and packing.get("likely_packed"):
            sections.append("### Packing\n")
            sections.append(f"Binary appears packed: {packing.get('packer_name', 'unknown packer')}")
            sections.append("")

    # --- Key Findings ---
    if key_findings:
        sections.append("## Key Findings\n")
        for i, finding in enumerate(key_findings, 1):
            sections.append(f"{i}. {finding}")
        sections.append("")

    # --- Functions Explored ---
    func_notes = [n for n in notes if n.get("category") == "function"]
    if func_notes:
        sections.append("## Explored Functions\n")
        sections.append("| Address | Summary |")
        sections.append("|---------|---------|")
        for n in func_notes[:30]:
            sections.append(f"| {n.get('address', '?')} | {n.get('content', '?')} |")
        sections.append("")

    # --- IOCs ---
    net_iocs = triage.get("network_iocs", {})
    if isinstance(net_iocs, dict):
        has_iocs = any(net_iocs.get(k) for k in ["ip_addresses", "urls", "domains"])
        if has_iocs:
            sections.append("## Indicators of Compromise\n")
            for category in ["ip_addresses", "urls", "domains", "registry_keys"]:
                items = net_iocs.get(category, [])
                if items:
                    sections.append(f"### {category.replace('_', ' ').title()}\n")
                    for item in items[:20]:
                        sections.append(f"- {item}")
                    sections.append("")

    # --- Analyst Notes ---
    general_notes = [n for n in notes if n.get("category") == "general"]
    if general_notes:
        sections.append("## Analyst Notes\n")
        for n in general_notes:
            sections.append(f"- {n.get('content', '')}")
        sections.append("")

    # --- Tool History ---
    sections.append("## Analysis Timeline\n")
    sections.append(f"Total tool invocations: {len(history)}\n")
    from collections import Counter
    tool_counts = Counter(h.get("tool_name", "") for h in history)
    sections.append("### Most Used Tools\n")
    for tool_name, count in tool_counts.most_common(10):
        sections.append(f"- {tool_name}: {count}x")
    sections.append("")

    report_text = "\n".join(sections)

    # Suggested filename
    safe_base = re.sub(r"[^a-zA-Z0-9_\-.]", "_", os.path.splitext(filename)[0])[:100]
    dl_filename = f"arkana_report_{safe_base}.md" if safe_base else "arkana_report.md"

    return {
        "available": True,
        "report": report_text,
        "format": "markdown",
        "filename": dl_filename,
    }


# ---------------------------------------------------------------------------
#  IOC Summary (overview card)
# ---------------------------------------------------------------------------

def get_ioc_summary_data() -> Dict[str, Any]:
    """Return a compact IOC summary for the overview card."""
    st = _get_state()
    iocs: Dict[str, list] = {}

    # From cached IOCs (enrichment)
    cached_iocs = getattr(st, "_cached_iocs", None)
    if cached_iocs and isinstance(cached_iocs, dict):
        for ioc_type in ("urls", "ips", "domains", "emails", "registry_keys", "file_paths", "mutexes"):
            items = cached_iocs.get(ioc_type, [])
            if isinstance(items, list) and items:
                iocs[ioc_type] = items[:10]

    # Also from triage network_iocs
    triage = getattr(st, "_cached_triage", None)
    if triage and isinstance(triage, dict):
        net_iocs = triage.get("network_iocs", {})
        if isinstance(net_iocs, dict):
            for k in ("ip_addresses", "urls", "domains"):
                items = net_iocs.get(k, [])
                # Normalize key names
                norm_key = k.replace("ip_addresses", "ips")
                if isinstance(items, list) and items and norm_key not in iocs:
                    iocs[norm_key] = items[:10]

    total = sum(len(v) for v in iocs.values())
    return {
        "available": total > 0,
        "iocs": iocs,
        "total": total,
    }


# ---------------------------------------------------------------------------
#  Capabilities Summary (overview card)
# ---------------------------------------------------------------------------

def get_capabilities_summary_data() -> Dict[str, Any]:
    """Return a compact capabilities summary for the overview card."""
    st = _get_state()
    pe_data = st.pe_data or {}
    capa = pe_data.get("capa_analysis", {})
    if not isinstance(capa, dict):
        return {"available": False, "capabilities": [], "total": 0}

    capa_results = capa.get("results", {}) if isinstance(capa, dict) else {}
    rules_raw = capa_results.get("rules", capa_results.get("capabilities",
                capa.get("rules", capa.get("capabilities", []))))
    names: List[str] = []

    if isinstance(rules_raw, dict):
        for name in rules_raw:
            names.append(str(name))
    elif isinstance(rules_raw, list):
        for r in rules_raw:
            if isinstance(r, dict):
                names.append(r.get("name", str(r)))
            else:
                names.append(str(r))

    return {
        "available": len(names) > 0,
        "capabilities": names[:20],
        "total": len(names),
    }


# ---------------------------------------------------------------------------
#  Settings
# ---------------------------------------------------------------------------

def get_settings_data() -> Dict[str, Any]:
    """Return structured settings data for the settings page."""
    from arkana.user_config import get_all_settings, get_dashboard_theme
    from collections import OrderedDict

    all_settings = get_all_settings()
    current_theme = get_dashboard_theme()

    # Group settings by group name (preserving insertion order)
    groups: Dict[str, list] = OrderedDict()
    for s in all_settings:
        group = s["group"]
        if group == "Appearance":
            continue  # Theme is handled separately
        groups.setdefault(group, []).append(s)

    return {
        "current_theme": current_theme,
        "groups": groups,
    }
