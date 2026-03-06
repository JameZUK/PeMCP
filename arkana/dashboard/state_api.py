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
    (potentially empty) default state.

    When multiple sessions exist, prefer the one with the most recent activity
    (latest tool_history timestamp) to avoid nondeterministic dict iteration.
    """
    with _registry_lock:
        # Collect candidates with a loaded file
        file_candidates = [
            st for st in _session_registry.values()
            if st.filepath is not None
        ]
        if file_candidates:
            if len(file_candidates) == 1:
                return file_candidates[0]
            # Pick the session with the most recent tool call
            def _last_activity(st):
                hist = st.get_tool_history()
                if hist:
                    return hist[-1].get("timestamp_epoch", 0)
                return 0
            return max(file_candidates, key=_last_activity)

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
                    top_decoded.append(s.get("string", str(s))[:120])
                elif isinstance(s, str):
                    top_decoded.append(s[:120])
            top_stack = []
            for s in stack[:10]:
                if isinstance(s, dict):
                    top_stack.append(s.get("string", str(s))[:120])
                elif isinstance(s, str):
                    top_stack.append(s[:120])
            if top_decoded:
                binary_summary["floss_top_decoded"] = top_decoded
            if top_stack:
                binary_summary["floss_top_stack"] = top_stack
        floss_status = floss.get("status", "")
        binary_summary["floss_status"] = floss_status

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

        # Build edges from call graph and compute degree counts
        in_deg: Dict[str, int] = {}
        out_deg: Dict[str, int] = {}
        if hasattr(kb, "callgraph"):
            cg = kb.callgraph
            for caller, callee in cg.edges():
                if caller in addr_set and callee in addr_set:
                    src = hex(caller)
                    tgt = hex(callee)
                    edges.append({"data": {"source": src, "target": tgt}})
                    out_deg[src] = out_deg.get(src, 0) + 1
                    in_deg[tgt] = in_deg.get(tgt, 0) + 1

        # Enrich nodes with degree counts and function size
        for node in nodes:
            d = node["data"]
            addr_hex = d["id"]
            d["in_deg"] = in_deg.get(addr_hex, 0)
            d["out_deg"] = out_deg.get(addr_hex, 0)
            # Function byte size
            try:
                func = kb.functions[int(addr_hex, 16)]
                d["size"] = func.size if hasattr(func, "size") else 0
            except (KeyError, ValueError, TypeError):
                d["size"] = 0

    except (AttributeError, KeyError, TypeError, RuntimeError):
        logger.debug("Error building call graph data from angr KB", exc_info=True)

    return {"nodes": nodes, "edges": edges}


def get_imports_data(search: str = "") -> Dict[str, Any]:
    """Import/export tables for the imports dashboard page."""
    st = _get_state()
    pe_data = st.pe_data or {}
    search_lower = search.lower().strip()

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


def get_decompiled_code(address_hex: str) -> Dict[str, Any]:
    """Return cached decompilation for a function, or indicate not cached."""
    try:
        from arkana.mcp.tools_angr import _decompile_cache, _decompile_meta
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

    cache_key = (addr_int,)
    cached_lines = _decompile_cache.get("decompile_function_with_angr", cache_key)
    if cached_lines is None:
        return {"cached": False}

    meta = _decompile_meta.get(cache_key, {})
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

    from arkana.mcp.tools_angr import _decompile_cache, _decompile_meta
    from arkana.mcp._angr_helpers import _ensure_project_and_cfg, _build_region_cfg
    from arkana.mcp._rename_helpers import (
        apply_function_renames_to_lines,
        apply_variable_renames_to_lines,
        get_display_name,
    )

    # Check cache first (may have been populated since the GET)
    cache_key = (addr_int,)
    cached_lines = _decompile_cache.get("decompile_function_with_angr", cache_key)
    if cached_lines is not None:
        meta = _decompile_meta.get(cache_key, {})
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
        except Exception as e:
            return {"cached": False, "error": f"Failed to build local CFG: {e}"}
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

    try:
        dec = project.analyses.Decompiler(func, cfg=decompiler_cfg)
        if not dec.codegen:
            return {"cached": False, "error": "Decompilation produced no code"}
    except Exception as e:
        return {"cached": False, "error": f"Decompilation failed: {e}"}

    all_lines = dec.codegen.text.splitlines()
    _decompile_cache.set("decompile_function_with_angr", cache_key, all_lines)
    _decompile_meta[cache_key] = {
        "function_name": func.name,
        "address": hex(addr_to_use),
    }

    renamed_lines = apply_function_renames_to_lines(all_lines)
    renamed_lines = apply_variable_renames_to_lines(renamed_lines, hex(addr_int))
    display_name = get_display_name(hex(addr_int), func.name)

    return {
        "cached": True,
        "function_name": display_name,
        "address": hex(addr_to_use),
        "lines": renamed_lines,
        "line_count": len(renamed_lines),
    }


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

    all_strings = []
    type_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}

    for items, type_label in _iter_string_sources(pe_data):
        count = 0
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
            elif type_label == "STACK":
                address = str(item.get("string_va", ""))
                function_va = str(item.get("function_va", ""))
            elif type_label == "DECODED":
                address = str(item.get("string_va", ""))
                dec_va = item.get("decoding_routine_va", item.get("decoder_va", ""))
                if dec_va:
                    extra = f"decoder: {dec_va}"
            elif type_label == "TIGHT":
                address = str(item.get("address_or_offset", ""))
                function_va = str(item.get("function_va", ""))

            # Track categories
            if cat:
                category_counts[cat] = category_counts.get(cat, 0) + 1

            all_strings.append({
                "string": s,
                "type": type_label,
                "address": address,
                "sifter_score": sifter_score if isinstance(sifter_score, (int, float)) else 0,
                "category": cat,
                "function_va": function_va,
                "extra": extra,
            })

        type_counts[type_label] = count

    total_unfiltered = len(all_strings)

    # Filters
    search_lower = search[:500].lower().strip() if search else ""
    type_lower = string_type.lower().strip() if string_type else "all"

    if search_lower:
        all_strings = [s for s in all_strings if search_lower in s["string"].lower()]
    if type_lower and type_lower != "all":
        all_strings = [s for s in all_strings if s["type"].lower() == type_lower]
    if category:
        cat_lower = category.lower().strip()
        all_strings = [s for s in all_strings if s["category"].lower() == cat_lower]
    if min_score > 0:
        all_strings = [s for s in all_strings if s["sifter_score"] >= min_score]

    # Sort
    if sort_by == "length":
        all_strings.sort(key=lambda s: len(s["string"]), reverse=not sort_asc)
    elif sort_by == "type":
        all_strings.sort(key=lambda s: s["type"], reverse=not sort_asc)
    elif sort_by == "address":
        all_strings.sort(key=lambda s: s["address"], reverse=not sort_asc)
    else:  # score (default)
        all_strings.sort(key=lambda s: s["sifter_score"], reverse=not sort_asc)

    total = len(all_strings)
    page = all_strings[offset:offset + limit]

    return {
        "strings": page,
        "total": total,
        "total_unfiltered": total_unfiltered,
        "offset": offset,
        "limit": limit,
        "type_counts": type_counts,
        "category_counts": category_counts,
    }


def global_search(query: str, limit_per_category: int = 10) -> Dict[str, Any]:
    """Search across functions, strings, imports, and notes."""
    st = _get_state()
    pe_data = st.pe_data or {}
    query_lower = query.lower().strip()
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
    result: Dict[str, Any] = {
        "address": address_hex,
        "name": "",
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
                result["complexity"]["edges"] = len(list(func.graph.edges()))
            except (AttributeError, TypeError):
                pass
        else:
            result["name"] = renames.get(hex(addr_int), address_hex)

        # Callers / callees from callgraph
        if hasattr(kb, "callgraph") and addr_int in kb.callgraph:
            cg = kb.callgraph
            seen_suspicious = set()

            # Callers (predecessors)
            for pred in cg.predecessors(addr_int):
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
                })

            # Callees (successors)
            for succ in cg.successors(addr_int):
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
