"""Functions to extract dashboard-ready data from AnalyzerState."""
import os
import time
from typing import Any, Dict, List, Optional

from arkana.state import (
    _default_state, _session_registry, _registry_lock,
    TASK_RUNNING, TASK_COMPLETED, TASK_FAILED,
)


def _get_state():
    """Return the most relevant AnalyzerState for dashboard reads.

    In stdio mode the MCP SDK still creates a session, so tools write to a
    per-session state instead of ``_default_state``.  We check the session
    registry for any state that has a file loaded and prefer that over the
    (potentially empty) default state.
    """
    with _registry_lock:
        for st in _session_registry.values():
            if st.filepath is not None:
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
    with st._task_lock:
        for tid, t in st.background_tasks.items():
            tasks.append({
                "id": tid,
                "tool": t.get("tool", "unknown"),
                "status": t.get("status", "unknown"),
                "progress_percent": t.get("progress_percent", 0),
                "progress_message": t.get("progress_message", ""),
            })

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

        # Network IOCs
        net_iocs = triage.get("network_iocs", {})
        if isinstance(net_iocs, dict):
            ioc_count = sum(
                len(v) for v in net_iocs.values() if isinstance(v, list)
            )
            binary_summary["ioc_count"] = ioc_count

        # Section anomalies
        anomalies = triage.get("section_anomalies", [])
        if isinstance(anomalies, list):
            binary_summary["section_anomaly_count"] = len(anomalies)

        # Timestamp
        ts_analysis = triage.get("timestamp_analysis", {})
        if isinstance(ts_analysis, dict):
            binary_summary["compile_time"] = ts_analysis.get("compile_time", "")
            binary_summary["timestamp_suspicious"] = ts_analysis.get("suspicious", False)

        # Compiler / language
        compiler = triage.get("compiler_language", {})
        if isinstance(compiler, dict):
            binary_summary["language"] = compiler.get("language", "")
        elif isinstance(compiler, str):
            binary_summary["language"] = compiler

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

        # Build address->notes lookup from function notes
        notes_by_addr: Dict[str, List[str]] = {}
        for n in st.get_notes(category="function"):
            addr = n.get("address")
            if addr:
                notes_by_addr.setdefault(addr, []).append(n.get("content", ""))

        for addr, func in kb.functions.items():
            addr_hex = hex(addr)
            name = renames.get(addr_hex, func.name)
            size = func.size if hasattr(func, "size") else 0
            complexity = 0
            if hasattr(func, "graph") and func.graph is not None:
                try:
                    complexity = len(list(func.graph.nodes()))
                except Exception:
                    pass

            func_notes = notes_by_addr.get(addr_hex, [])
            functions.append({
                "address": addr_hex,
                "name": name,
                "size": size,
                "complexity": complexity,
                "triage_status": triage.get(addr_hex, "unreviewed"),
                "has_note": len(func_notes) > 0,
                "notes": func_notes,
            })
    except Exception:
        pass

    # Filter
    if filter_triage and filter_triage != "all":
        functions = [f for f in functions if f["triage_status"] == filter_triage]
    if min_score > 0:
        functions = [f for f in functions if f.get("risk_score", 0) >= min_score]
    if search:
        search_lower = search.lower()
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

        # Build node list (limit to 500 for performance)
        func_addrs = list(kb.functions.keys())[:500]
        addr_set = set(func_addrs)

        for addr in func_addrs:
            func = kb.functions[addr]
            addr_hex = hex(addr)
            name = renames.get(addr_hex, func.name)
            complexity = 0
            if hasattr(func, "graph") and func.graph is not None:
                try:
                    complexity = len(list(func.graph.nodes()))
                except Exception:
                    pass
            nodes.append({
                "data": {
                    "id": addr_hex,
                    "label": name,
                    "triage": triage.get(addr_hex, "unreviewed"),
                    "complexity": complexity,
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

    except Exception:
        pass

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
            if isinstance(v, str) and len(v) > 300:
                display_params[k] = v[:300] + "..."
            else:
                display_params[k] = v
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
            import datetime
            dt = datetime.datetime.fromisoformat(ts)
            epoch = dt.timestamp()
        except Exception:
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
    return entries[-limit:]


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
    count = 0
    try:
        # The decompile cache is module-level in tools_angr, not per-state
        from arkana.mcp.tools_angr import _decompile_cache
        with _decompile_cache._lock:
            bucket = _decompile_cache._store.get("decompile_function_with_angr")
            if bucket:
                count = len(bucket)
    except Exception:
        pass
    return count


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
