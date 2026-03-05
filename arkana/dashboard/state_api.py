"""Functions to extract dashboard-ready data from AnalyzerState."""
import datetime
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Arkana.dashboard")

from arkana.state import (
    _default_state, _session_registry, _registry_lock,
    TASK_RUNNING, TASK_COMPLETED, TASK_FAILED,
)


def _get_state():
    """Return the most relevant AnalyzerState for dashboard reads.

    In stdio mode the MCP SDK still creates a session, so tools write to a
    per-session state instead of ``_default_state``.  We check the session
    registry for any state that has a file loaded and prefer that over the
    (potentially empty) default state.  Also checks for states with an active
    tool running (e.g. open_file in progress).
    """
    with _registry_lock:
        # Prefer a session with a file loaded
        for st in _session_registry.values():
            if st.filepath is not None:
                return st
        # Fall back to a session with an active tool (e.g. open_file loading)
        for st in _session_registry.values():
            if getattr(st, "active_tool", None) is not None:
                return st
    return _default_state


def get_overview_data() -> Dict[str, Any]:
    """File info, hashes, phase, coverage stats, background tasks."""
    st = _get_state()
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
    explored_funcs = _count_explored_functions(st)

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
            if last_progress and t.get("status") == TASK_RUNNING:
                stall = int(now - last_progress)
                if stall > 30:  # Only flag as stalled after 30 seconds
                    task_info["stall_s"] = stall
            tasks.append(task_info)

    # Counts
    notes = st.get_notes()
    notes_count = len(notes)
    tool_calls = len(st.get_tool_history())
    artifacts_count = len(st.get_artifacts())

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

    # Triage flags from dashboard
    triage_status = st.get_all_triage_snapshot()
    triage_counts = {}
    if triage_status:
        for s in triage_status.values():
            triage_counts[s] = triage_counts.get(s, 0) + 1

    # Recent notes (last 5)
    recent_notes = []
    for n in reversed(notes[-5:]):
        recent_notes.append({
            "category": n.get("category", "general"),
            "content": n.get("content", "")[:200],
            "address": n.get("address"),
            "timestamp": (n.get("created_at", "") or "")[:19],
        })

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
    all_artifacts = st.get_artifacts()
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
    active_tool_progress = 0
    active_tool_total = 100
    with st._active_tool_lock:
        active_tool = st.active_tool
        active_tool_progress = st.active_tool_progress
        active_tool_total = st.active_tool_total

    return {
        "file_loaded": filepath is not None,
        "filename": filename,
        "filepath": filepath,
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
        "active_tool_progress": active_tool_progress,
        "active_tool_total": active_tool_total,
    }


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

    try:
        kb = st.angr_project.kb
        if not hasattr(kb, "functions"):
            return functions

        triage = getattr(st, "triage_status", {})
        renames = st.get_renames().get("functions", {})
        decompiled_addrs = _get_decompiled_addresses()

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
                    complexity = len(list(func.graph.nodes()))
                except (AttributeError, TypeError, RuntimeError):
                    pass

            func_notes = notes_by_addr.get(addr_hex, [])
            is_decompiled = addr_hex in decompiled_addrs
            functions.append({
                "address": addr_hex,
                "name": name,
                "size": size,
                "complexity": complexity,
                "triage_status": triage.get(addr_hex, "unreviewed"),
                "has_note": len(func_notes) > 0,
                "notes": func_notes,
                "is_decompiled": is_decompiled,
                "is_renamed": is_renamed,
            })
    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error reading function data from angr KB", exc_info=True)

    # Filter
    if filter_triage and filter_triage != "all":
        functions = [f for f in functions if f["triage_status"] == filter_triage]
    if min_score > 0:
        functions = [f for f in functions if f.get("risk_score", 0) >= min_score]
    if search:
        search_lower = search[:500].lower()
        functions = [f for f in functions if search_lower in f["name"].lower() or search_lower in f["address"].lower()]

    # Sort
    rev = not sort_asc
    if sort_by == "name":
        functions.sort(key=lambda f: f["name"].lower(), reverse=rev)
    elif sort_by == "size":
        functions.sort(key=lambda f: f["size"], reverse=not rev)
    elif sort_by == "complexity":
        functions.sort(key=lambda f: f["complexity"], reverse=not rev)
    elif sort_by == "triage":
        order = {"flagged": 0, "suspicious": 1, "unreviewed": 2, "clean": 3}
        functions.sort(key=lambda f: order.get(f["triage_status"], 99), reverse=rev)
    else:
        functions.sort(key=lambda f: int(f["address"], 16), reverse=rev)

    return functions


def get_callgraph_data() -> Dict[str, Any]:
    """Nodes + edges formatted for Cytoscape.js."""
    st = _get_state()
    nodes = []
    edges = []

    if st.angr_project is None or st.angr_cfg is None:
        return {"nodes": nodes, "edges": edges}

    try:
        kb = st.angr_project.kb
        if not hasattr(kb, "functions"):
            return {"nodes": nodes, "edges": edges}

        triage = getattr(st, "triage_status", {})
        renames = st.get_renames().get("functions", {})
        decompiled_addrs = _get_decompiled_addresses()

        # Build set of addresses with function notes
        noted_addrs = set()
        for n in st.get_notes(category="function"):
            a = n.get("address")
            if a:
                noted_addrs.add(a)

        # Build node list (limit to 500 for performance)
        func_addrs = list(kb.functions.keys())[:500]
        addr_set = set(func_addrs)

        for addr in func_addrs:
            func = kb.functions[addr]
            addr_hex = hex(addr)
            is_renamed = addr_hex in renames
            name = renames.get(addr_hex, func.name)
            complexity = 0
            if hasattr(func, "graph") and func.graph is not None:
                try:
                    complexity = len(list(func.graph.nodes()))
                except (AttributeError, TypeError, RuntimeError):
                    pass
            explored = is_renamed or addr_hex in decompiled_addrs or addr_hex in noted_addrs
            nodes.append({
                "data": {
                    "id": addr_hex,
                    "label": name,
                    "triage": triage.get(addr_hex, "unreviewed"),
                    "complexity": complexity,
                    "explored": "yes" if explored else "no",
                    "renamed": "yes" if is_renamed else "no",
                }
            })

        # Build edges from call graph
        if hasattr(kb, "callgraph"):
            cg = kb.callgraph
            for caller, callee in cg.edges():
                if caller in addr_set and callee in addr_set:
                    edges.append({
                        "data": {
                            "source": hex(caller),
                            "target": hex(callee),
                        }
                    })

    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error building call graph data from angr KB", exc_info=True)

    return {"nodes": nodes, "edges": edges}


def get_sections_data() -> List[Dict[str, Any]]:
    """Section names, VA ranges, sizes, permissions, entropy."""
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

    return sections


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
        entries.append({
            "type": "tool",
            "timestamp": h.get("timestamp", ""),
            "timestamp_epoch": h.get("timestamp_epoch", 0),
            "name": h.get("tool_name", "?"),
            "summary": h.get("result_summary", "")[:200],
            "duration_ms": h.get("duration_ms", 0),
            "parameters": display_params,
        })

    # Notes
    for n in st.get_notes():
        ts = n.get("created_at", "")
        # Parse ISO timestamp to epoch for sorting
        epoch = 0
        try:
            dt = datetime.datetime.fromisoformat(ts)
            epoch = dt.timestamp()
        except (ValueError, TypeError, AttributeError):
            pass
        entries.append({
            "type": "note",
            "timestamp": ts,
            "timestamp_epoch": epoch,
            "name": n.get("category", "note"),
            "summary": n.get("content", "")[:200],
            "duration_ms": 0,
        })

    # Sort by timestamp
    entries.sort(key=lambda e: e["timestamp_epoch"])
    result = entries[-limit:]

    # Inject active tool as a live entry at the end
    with st._active_tool_lock:
        if st.active_tool:
            result.append({
                "type": "active",
                "timestamp": "",
                "timestamp_epoch": time.time(),
                "name": st.active_tool,
                "summary": f"Running... {st.active_tool_progress}%",
                "duration_ms": 0,
                "progress": st.active_tool_progress,
                "total": st.active_tool_total,
            })

    return result


def get_notes_data(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """All notes with optional category filter."""
    st = _get_state()
    return st.get_notes(category=category)


def _detect_phase(st) -> str:
    """Determine analysis phase from state."""
    if not st.filepath or not st.pe_data:
        return "not_started"

    current_history = st.get_tool_history()
    ran_tools = set(h["tool_name"] for h in current_history)
    prev = getattr(st, "previous_session_history", []) or []
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


def _count_explored_functions(st) -> int:
    """Count functions that have been explored via decompilation."""
    return len(_get_decompiled_addresses())


def _get_decompiled_addresses() -> set:
    """Return set of hex addresses that have been decompiled (in cache)."""
    addrs = set()
    try:
        from arkana.mcp.tools_angr import _decompile_cache
        for key in _decompile_cache.keys("decompile_function_with_angr"):
            # Cache key is a tuple: (target_addr,) where target_addr is int
            if isinstance(key, tuple) and key:
                addrs.add(hex(key[0]))
    except Exception:
        logger.debug("Error reading decompile cache keys", exc_info=True)
    return addrs


def _section_permissions(section: dict) -> str:
    """Extract permission string from section data."""
    chars = section.get("characteristics", 0)
    if isinstance(chars, str):
        return chars
    perms = ""
    # PE section characteristic flags
    if isinstance(chars, (int, float)):
        chars = int(chars)
        if chars & 0x20000000:
            perms += "X"
        if chars & 0x40000000:
            perms += "R"
        if chars & 0x80000000:
            perms += "W"
    return perms or "?"
