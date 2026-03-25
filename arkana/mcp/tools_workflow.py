"""MCP tools for analysis workflow — report generation and sample naming."""
import asyncio
import datetime
import json
import os
import re
import itertools
from collections import Counter  # L5-v9: module-level import

from typing import Dict, Any, List, Optional

from arkana.config import state, logger, Context, ANGR_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._refinery_helpers import _write_output_and_register_artifact


# ===================================================================
#  Module-level constant maps (moved from inside auto_name_sample
#  for efficiency — avoids re-creating dicts on every call)
# ===================================================================

_IMPORT_CAPABILITY_MAP = {
    # Anti-debug / anti-analysis
    "isdebuggerpresent": "antidbg",
    "checkremotedebugger": "antidbg",
    "ntqueryinformationprocess": "antidbg",
    "queryperformancecounter": "antidbg",
    "gettickcount": "antidbg",
    # Process manipulation
    "terminateprocess": "procmgmt",
    "openprocess": "procmgmt",
    "createprocess": "procmgmt",
    # Code injection
    "createremotethread": "inject",
    "writeprocessmemory": "inject",
    "virtualallocex": "inject",
    "ntunmapviewofsection": "inject",
    # IPC / named pipes
    "createnamedpipe": "namedpipe",
    "connectnamedpipe": "namedpipe",
    "callnamedpipe": "namedpipe",
    # Keylogging / input hooking
    "setwindowshookex": "keylog",
    "getasynckeystate": "keylog",
    "getkeystate": "keylog",
    # Crypto
    "cryptencrypt": "crypto",
    "cryptdecrypt": "crypto",
    "bcryptencrypt": "crypto",
    "bcryptdecrypt": "crypto",
    "cryptderivekey": "crypto",
    # Networking
    "internetopen": "net",
    "httpsendrequest": "net",
    "httpopen": "net",
    "urldownloadtofile": "net",
    "wsastartup": "net",
    # Persistence
    "createservice": "persist",
    "regsetvalue": "persist",
    "regcreatekey": "persist",
    # Execution
    "winexec": "exec",
    "shellexecute": "exec",
    # Anti-VM / VM detection
    "getsystemfirmwaretable": "antivm",
    "enumservicesstatusex": "antivm",
}

_CAPA_SUB_NAMESPACE_LABELS = {
    "anti-analysis/anti-vm": "antivm",
    "anti-analysis/anti-debugging": "antidbg",
    "anti-analysis/obfuscation": "obfusc",
    "data-manipulation/encryption": "crypto",
    "data-manipulation/hashing": "crypto",
}

_CAPA_NAMESPACE_LABELS = {
    "anti-analysis": "antidbg",
    "persistence": "persist",
    "collection": "collect",
    "credential-access": "credtheft",
    "defense-evasion": "evasion",
    "execution": "exec",
    "impact": "impact",
    "c2": "c2",
    "exfiltration": "exfil",
    "lateral-movement": "lateral",
    "data-manipulation": "crypto",
    "discovery": "recon",
    "communication": "comms",
    "privilege-escalation": "privesc",
}


# ===================================================================
#  Tool 1: generate_analysis_report
# ===================================================================

@tool_decorator
async def generate_analysis_report(
    ctx: Context,
    format: str = "markdown",
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: utility] Generates a comprehensive analysis report from all accumulated
    findings: file info, triage results, explored functions, IOCs, notes, and
    tool history.

    When to use: When finishing an analysis session and need to document findings,
    or when sharing results with colleagues.

    Args:
        ctx: MCP Context.
        format: Output format: 'markdown' (default) or 'text'.
        output_path: (Optional[str]) Save report to this path and register as artifact.
    """
    await ctx.info("Generating analysis report")
    _check_pe_loaded("generate_analysis_report")

    fmt = format.lower()
    if fmt not in ("markdown", "text"):
        return {"error": f"Unsupported format '{format}'. Use 'markdown' or 'text'."}

    pe_data = state.pe_data or {}
    hashes = pe_data.get("file_hashes", {})
    filepath = state.filepath or "unknown"
    filename = os.path.basename(filepath)

    # Gather all data sources
    triage = getattr(state, '_cached_triage', None) or {}
    notes = state.get_notes()
    # M9-v10: Use itertools.chain instead of list concatenation
    prev = getattr(state, "previous_session_history", []) or []
    current = state.get_tool_history()
    history = list(itertools.chain(prev, current))

    # Build report
    sections = []

    # --- Executive Summary ---
    risk_level = triage.get("risk_level", "UNKNOWN")
    risk_score = triage.get("risk_score", 0)
    mode = pe_data.get("mode", "unknown")

    key_findings = [
        n["content"].replace("\\n", "\n").replace("\\t", "\t")
        for n in notes if n.get("category") == "tool_result"
    ][:10]

    if fmt == "markdown":
        sections.append(f"# Malware Analysis Report: {filename}\n")
        sections.append(f"**Date:** {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
        sections.append("## Executive Summary\n")
        sections.append(f"- **Risk Level:** {risk_level} (score: {risk_score})")
        sections.append(f"- **File Type:** {mode}")
        sections.append(f"- **Tools Used:** {len(history)} invocations")
        sections.append(f"- **Functions Explored:** {len([n for n in notes if n.get('category') == 'function'])}")
        sections.append("")

        # --- File Information ---
        sections.append("## File Information\n")
        sections.append(f"| Property | Value |")
        sections.append(f"|----------|-------|")
        sections.append(f"| Filename | {filename} |")
        sections.append(f"| MD5 | {hashes.get('md5', 'N/A')} |")
        sections.append(f"| SHA-256 | {hashes.get('sha256', 'N/A')} |")
        # file_size fallback chain: pe_data → triage.file_info → os.path.getsize()
        file_size = pe_data.get('file_size')
        if not file_size and triage:
            file_info = triage.get('file_info', {})
            if isinstance(file_info, dict):
                file_size = file_info.get('file_size')
        if not file_size:
            try:
                file_size = os.path.getsize(filepath)
            except OSError:
                file_size = None
        if file_size and isinstance(file_size, (int, float)):
            size_bytes = int(file_size)
            if size_bytes >= 1_048_576:
                size_human = f"{size_bytes / 1_048_576:.1f} MB"
            elif size_bytes >= 1024:
                size_human = f"{size_bytes / 1024:.1f} KB"
            else:
                size_human = f"{size_bytes} B"
            size_display = f"{size_bytes:,} bytes ({size_human})"
        else:
            size_display = "N/A"
        sections.append(f"| Size | {size_display} |")
        sections.append(f"| Format | {mode} |")
        sections.append("")

        # --- Risk Assessment ---
        if triage:
            sections.append("## Risk Assessment\n")
            sections.append(f"**Risk Level:** {risk_level} ({risk_score}/100)\n")

            # Suspicious imports
            sus_imports = triage.get("suspicious_imports", [])
            if sus_imports:
                sections.append("### Suspicious Imports\n")
                for imp in sus_imports[:15]:
                    if isinstance(imp, dict):
                        sections.append(f"- **{imp.get('risk', '?')}**: {imp.get('function', '?')} ({imp.get('dll', '?')})")
                sections.append("")

            # Packing assessment
            packing = triage.get("packing_assessment", {})
            if isinstance(packing, dict) and packing.get("likely_packed"):
                sections.append(f"### Packing\n")
                sections.append(f"Binary appears packed: {packing.get('packer_name', 'unknown packer')}")
                sections.append("")

        # --- Capabilities / Key Findings ---
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
        general_notes = [n for n in notes if n.get("category") == "general"][:50]
        if general_notes:
            sections.append("## Analyst Notes\n")
            for n in general_notes:
                sections.append(f"- {n.get('content', '')}")
            sections.append("")

        # --- Tool History Summary ---
        sections.append("## Analysis Timeline\n")
        sections.append(f"Total tool invocations: {len(history)}\n")
        tool_counts = Counter(h["tool_name"] for h in history)
        sections.append("### Most Used Tools\n")
        for tool_name, count in tool_counts.most_common(10):
            sections.append(f"- {tool_name}: {count}x")
        sections.append("")

        report_text = "\n".join(sections)
    else:
        # Plain text format
        lines = [f"MALWARE ANALYSIS REPORT: {filename}"]
        lines.append(f"Date: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"Risk: {risk_level} ({risk_score}/100)")
        lines.append(f"MD5: {hashes.get('md5', 'N/A')}")
        lines.append(f"SHA-256: {hashes.get('sha256', 'N/A')}")
        lines.append("")
        if key_findings:
            lines.append("KEY FINDINGS:")
            for f in key_findings:
                lines.append(f"  - {f}")
        report_text = "\n".join(lines)

    response: Dict[str, Any] = {
        "report": report_text,
        "format": fmt,
        "sections_count": len(sections) if fmt == "markdown" else 1,
    }
    if output_path:
        text_bytes = report_text.encode("utf-8")
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, text_bytes, "generate_analysis_report",
            f"Analysis report ({fmt})",
        )
        response["artifact"] = artifact_meta
    return await _check_mcp_response_size(ctx, response, "generate_analysis_report")


# ===================================================================
#  Tool 2: auto_name_sample
# ===================================================================

@tool_decorator
async def auto_name_sample(
    ctx: Context,
) -> Dict[str, Any]:
    """
    [Phase: utility] Suggests a descriptive filename for the loaded binary based
    on its capabilities, classification, C2 indicators, and file type.

    Example output: 'service_keylogger_c2_192.168.105.250.dll'

    When to use: After analysis to give the sample a meaningful name for
    organization and reporting.

    Args:
        ctx: MCP Context.
    """
    await ctx.info("Generating descriptive sample name")
    _check_pe_loaded("auto_name_sample")

    pe_data = state.pe_data or {}
    triage = getattr(state, '_cached_triage', None) or {}

    parts = []

    # --- Binary type from PE headers (lightweight classification) ---
    mode = pe_data.get("mode", "unknown")
    binary_class = None
    if "dll" in mode.lower():
        file_ext = ".dll"
        parts.append("dll")
        binary_class = "dll"
    elif "elf" in mode.lower():
        file_ext = ".elf"
        binary_class = "elf"
    elif "shellcode" in mode.lower():
        file_ext = ".bin"
        binary_class = "shellcode"
    else:
        file_ext = ".exe"
        # Determine binary class from PE headers
        nt_headers = pe_data.get("nt_headers", {})
        file_header = nt_headers.get("file_header", {}) if isinstance(nt_headers, dict) else {}
        optional_header = nt_headers.get("optional_header", {}) if isinstance(nt_headers, dict) else {}
        characteristics = file_header.get("characteristics", file_header.get("Characteristics", 0))
        subsystem = optional_header.get("subsystem", optional_header.get("Subsystem", 0))
        if isinstance(characteristics, dict):
            characteristics = characteristics.get("Value", 0)
        if isinstance(subsystem, dict):
            subsystem = subsystem.get("Value", 0)
        # Check DLL flag
        if isinstance(characteristics, int) and characteristics & 0x2000:
            file_ext = ".dll"
            binary_class = "dll"
            parts.append("dll")
        elif subsystem == 1:
            binary_class = "driver"
            parts.append("driver")
            file_ext = ".sys"
        elif subsystem == 2:
            binary_class = "gui"
            parts.append("gui")
        elif subsystem == 3:
            binary_class = "console"
            parts.append("console")
        # Check for service imports
        imports_data = pe_data.get("imports", [])
        if isinstance(imports_data, list):
            for dll_entry in imports_data:
                if isinstance(dll_entry, dict):
                    for sym in dll_entry.get("symbols", []):
                        name = (sym.get("name") or "") if isinstance(sym, dict) else ""
                        if name in ("StartServiceCtrlDispatcherA", "StartServiceCtrlDispatcherW",
                                    "RegisterServiceCtrlHandlerA", "RegisterServiceCtrlHandlerW"):
                            binary_class = "service"
                            # Replace gui/console with service
                            if parts and parts[0] in ("gui", "console"):
                                parts[0] = "service"
                            elif not parts:
                                parts.append("service")
                            break
                    if binary_class == "service":
                        break

    # --- Malware classification from notes ---
    notes = state.get_notes()
    classification_keywords = {
        "ransomware": "ransom", "keylogger": "keylog", "backdoor": "backdoor",
        "dropper": "dropper", "loader": "loader", "worm": "worm",
        "trojan": "trojan", "miner": "miner", "stealer": "stealer",
        "rat": "rat", "botnet": "bot", "rootkit": "rootkit",
    }

    found_type = None
    for note in notes:
        content = note.get("content", "").lower()
        for keyword, short_name in classification_keywords.items():
            if keyword in content:
                found_type = short_name
                break
        if found_type:
            break

    # --- Behavioral capabilities from suspicious imports ---
    sus_imports = triage.get("suspicious_imports", [])
    capabilities = set()
    for imp in sus_imports:
        if isinstance(imp, dict):
            func = imp.get("function", "").lower()
            for pattern, label in _IMPORT_CAPABILITY_MAP.items():
                if pattern in func:
                    capabilities.add(label)
                    break

    # Also scan all imports directly (not just suspicious ones) for key behaviors
    # This catches APIs like CreateNamedPipe that may not be in the suspicious DB
    imports_data = pe_data.get("imports", [])
    if isinstance(imports_data, list):
        for dll_entry in imports_data:
            if isinstance(dll_entry, dict):
                for sym in dll_entry.get("symbols", []):
                    func = (sym.get("name") or "") if isinstance(sym, dict) else ""
                    func_lower = func.lower()
                    for pattern, label in _IMPORT_CAPABILITY_MAP.items():
                        if pattern in func_lower:
                            capabilities.add(label)
                            break

    # Scan capa capabilities for additional labels
    sus_caps = triage.get("suspicious_capabilities", [])
    if isinstance(sus_caps, list):
        for cap in sus_caps:
            full_ns = ""
            if isinstance(cap, dict):
                full_ns = cap.get("namespace", "").lower()
            elif isinstance(cap, str):
                full_ns = cap.lower()
            # Check sub-namespaces first for precise categorization
            label = None
            for prefix, sub_label in _CAPA_SUB_NAMESPACE_LABELS.items():
                if full_ns.startswith(prefix):
                    label = sub_label
                    break
            if not label:
                ns_top = full_ns.split("/")[0]
                label = _CAPA_NAMESPACE_LABELS.get(ns_top)
            if label:
                capabilities.add(label)

    # --- Packer indicator (early, right after binary class) ---
    packing = triage.get("packing_assessment", {})
    is_packed = isinstance(packing, dict) and packing.get("likely_packed")
    if is_packed:
        parts.append("packed")

    # Add malware type or top capabilities to name
    if found_type:
        parts.append(found_type)
    if capabilities:
        # Add up to 5 capabilities (after type, if any)
        for cap in sorted(capabilities)[:5]:
            if cap not in parts:
                parts.append(cap)

    # --- Risk level hint ---
    risk_level = triage.get("risk_level", "")
    if risk_level in ("HIGH", "CRITICAL"):
        parts.append(risk_level.lower())

    # --- Size hint ---
    file_info = triage.get("file_info", {})
    file_size = file_info.get("file_size") if isinstance(file_info, dict) else None
    if not file_size:
        try:
            file_size = os.path.getsize(state.filepath) if state.filepath else None
        except OSError:
            file_size = None
    if isinstance(file_size, (int, float)):
        if file_size > 10_000_000:
            parts.append("large")
        elif file_size < 10_000:
            parts.append("tiny")

    # --- C2 indicator ---
    net_iocs = triage.get("network_iocs", {})
    if isinstance(net_iocs, dict):
        ips = net_iocs.get("ip_addresses", [])
        domains = net_iocs.get("domains", [])
        if ips:
            c2 = ips[0] if isinstance(ips[0], str) else str(ips[0])
            parts.append(f"c2_{c2.replace('.', '_')}")
        elif domains:
            domain = domains[0] if isinstance(domains[0], str) else str(domains[0])
            # Shorten long domains
            if len(domain) > 20:
                domain = domain[:17] + "..."
            parts.append(f"c2_{domain.replace('.', '_')}")

    # Build the name
    if not parts:
        # Fallback: use hash prefix
        hashes = pe_data.get("file_hashes", {})
        sha = hashes.get("sha256", "unknown")[:8]
        parts.append(f"sample_{sha}")

    suggested_name = "_".join(parts) + file_ext
    # Sanitize: remove characters that aren't filename-safe
    suggested_name = re.sub(r'[^\w\-.]', '_', suggested_name)
    suggested_name = re.sub(r'_+', '_', suggested_name).strip('_')

    return {
        "suggested_name": suggested_name,
        "parts": {
            "binary_class": binary_class or "unknown",
            "malware_type": found_type or "unknown",
            "capabilities": sorted(capabilities),
            "c2": bool(net_iocs and (net_iocs.get("ip_addresses") or net_iocs.get("domains"))),
            "packed": bool(is_packed),
            "risk_level": risk_level or "unknown",
        },
    }


# ===================================================================
#  Tool 3: generate_cti_report
# ===================================================================

def _format_file_size(size_bytes: int) -> str:
    """Format byte count into a human-readable string."""
    if size_bytes >= 1_048_576:
        return f"{size_bytes:,} bytes ({size_bytes / 1_048_576:.1f} MB)"
    elif size_bytes >= 1024:
        return f"{size_bytes:,} bytes ({size_bytes / 1024:.1f} KB)"
    return f"{size_bytes:,} bytes"


def _get_executive_summary(notes: List[Dict[str, Any]], triage: Dict[str, Any]) -> str:
    """Build executive summary from conclusion/hypothesis notes or triage."""
    # Prefer conclusion notes first, then hypothesis
    for category in ("conclusion", "hypothesis"):
        for note in notes:
            if note.get("category") == category:
                return note.get("content", "").replace("\\n", "\n").replace("\\t", "\t")

    # Fall back to auto-generated summary from triage
    if triage:
        risk_level = triage.get("risk_level", "UNKNOWN")
        risk_score = triage.get("risk_score", 0)
        packing = triage.get("packing_assessment", {})
        packed = packing.get("likely_packed", False) if isinstance(packing, dict) else False
        packer_name = packing.get("packer_name", "") if isinstance(packing, dict) else ""
        parts = [f"Risk assessment: {risk_level} (score {risk_score}/100)."]
        if packed:
            parts.append(f"Sample appears packed ({packer_name})." if packer_name else "Sample appears packed.")
        sus_caps = triage.get("suspicious_capabilities", [])
        if isinstance(sus_caps, list) and sus_caps:
            parts.append(f"{len(sus_caps)} suspicious capabilities detected.")
        sus_imports = triage.get("suspicious_imports", [])
        if isinstance(sus_imports, list) and sus_imports:
            high_risk = [i for i in sus_imports if isinstance(i, dict) and i.get("risk") in ("HIGH", "CRITICAL")]
            if high_risk:
                parts.append(f"{len(high_risk)} high/critical-risk imports identified.")
        return " ".join(parts)

    return "No analysis data available. Run get_triage_report() first."


def _build_cti_markdown(
    pe_data: Dict[str, Any],
    triage: Dict[str, Any],
    classification: Optional[Dict[str, Any]],
    similarity_hashes: Optional[Dict[str, Any]],
    mitre_mapping: Optional[Dict[str, Any]],
    cached_iocs: Optional[Dict[str, Any]],
    notes: List[Dict[str, Any]],
    filepath: str,
) -> str:
    """Build a structured CTI report in markdown format."""
    hashes = pe_data.get("file_hashes", {})
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections: List[str] = []

    # ── Title ──
    sections.append(f"# Malware Analysis Report\n")

    # ── Executive Summary ──
    sections.append("## Executive Summary\n")
    sections.append(_get_executive_summary(notes, triage))
    sections.append("")

    # ── Sample Information ──
    sections.append("## Sample Information\n")
    sections.append("| Field | Value |")
    sections.append("|-------|-------|")
    sections.append(f"| SHA256 | {hashes.get('sha256', 'N/A')} |")
    sections.append(f"| MD5 | {hashes.get('md5', 'N/A')} |")
    sections.append(f"| SHA1 | {hashes.get('sha1', 'N/A')} |")

    # File type from classification or pe_data mode
    file_type = pe_data.get("mode", "unknown")
    if classification and isinstance(classification, dict):
        primary = classification.get("primary_type")
        if primary:
            file_type = primary
    sections.append(f"| File Type | {file_type} |")

    # File size
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
        sections.append(f"| File Size | {_format_file_size(int(file_size))} |")
    else:
        sections.append("| File Size | N/A |")

    # Architecture
    nt_headers = pe_data.get("nt_headers", {})
    file_header = nt_headers.get("file_header", {}) if isinstance(nt_headers, dict) else {}
    machine = file_header.get("machine", file_header.get("Machine", "N/A"))
    if isinstance(machine, dict):
        machine = machine.get("Value", "N/A")
    sections.append(f"| Architecture | {machine} |")

    # Compile time
    time_date_stamp = file_header.get("time_date_stamp", file_header.get("TimeDateStamp", "N/A"))
    if isinstance(time_date_stamp, dict):
        time_date_stamp = time_date_stamp.get("Value", "N/A")
    sections.append(f"| Compile Time | {time_date_stamp} |")

    # Similarity hashes
    if similarity_hashes and isinstance(similarity_hashes, dict):
        ssdeep = similarity_hashes.get("ssdeep", "N/A")
        tlsh_val = similarity_hashes.get("tlsh", "N/A")
        imphash = similarity_hashes.get("imphash", "N/A")
        sections.append(f"| ssdeep | {ssdeep} |")
        sections.append(f"| TLSH | {tlsh_val} |")
        sections.append(f"| Imphash | {imphash} |")
    else:
        imphash = hashes.get("imphash", "N/A")
        if imphash != "N/A":
            sections.append(f"| Imphash | {imphash} |")

    sections.append("")

    # ── Classification ──
    if classification and isinstance(classification, dict):
        classifications = classification.get("classifications", [])
        if classifications:
            sections.append("## Classification\n")
            for cls in classifications[:10]:
                sections.append(f"- {cls}")
            evidence = classification.get("evidence", [])
            if evidence:
                sections.append("\n**Evidence:**\n")
                for ev in evidence[:10]:
                    sections.append(f"- {ev}")
            sections.append("")

    # ── MITRE ATT&CK Mapping ──
    if mitre_mapping and isinstance(mitre_mapping, dict):
        techniques = mitre_mapping.get("techniques", [])
        if techniques:
            sections.append("## MITRE ATT&CK Mapping\n")
            sections.append("| Technique | Name | Tactic | Evidence |")
            sections.append("|-----------|------|--------|----------|")
            for tech in techniques[:30]:
                tech_id = tech.get("id", "")
                name = tech.get("name", "")
                tactic = tech.get("tactic", "").replace("-", " ").title()
                sources = tech.get("sources", [])
                evidence_str = "; ".join(
                    s.get("rule", s.get("function", s.get("detail", s.get("type", ""))))
                    for s in sources[:3]
                    if isinstance(s, dict)
                )
                sections.append(f"| {tech_id} | {name} | {tactic} | {evidence_str} |")
            tc = mitre_mapping.get("tactics_covered", 0)
            tt = mitre_mapping.get("tactics_total", 0)
            sections.append(f"\n*{len(techniques)} techniques across {tc}/{tt} tactics*")
            sections.append("")
        else:
            sections.append("## MITRE ATT&CK Mapping\n")
            sections.append("No techniques mapped. Run `map_mitre_attack()` for ATT&CK analysis.")
            sections.append("")
    else:
        sections.append("## MITRE ATT&CK Mapping\n")
        sections.append("Not analyzed. Run `map_mitre_attack()` to generate MITRE mappings.")
        sections.append("")

    # ── Indicators of Compromise ──
    iocs_data = {}
    if cached_iocs and isinstance(cached_iocs, dict):
        iocs_data = cached_iocs.get("iocs", {})
    elif triage:
        # Fall back to triage network_iocs
        net_iocs = triage.get("network_iocs", {})
        if isinstance(net_iocs, dict):
            iocs_data = {
                "ipv4": net_iocs.get("ip_addresses", []),
                "urls": net_iocs.get("urls", []),
                "domains": net_iocs.get("domains", []),
                "registry_keys": net_iocs.get("registry_keys", []),
            }

    has_network = any(iocs_data.get(k) for k in ("ipv4", "urls", "domains"))
    has_host = any(iocs_data.get(k) for k in ("registry_keys", "mutexes", "file_paths"))
    has_hashes = bool(iocs_data.get("file_hashes"))

    if has_network or has_host or has_hashes:
        sections.append("## Indicators of Compromise\n")
        if has_network:
            sections.append("### Network Indicators\n")
            sections.append("| Type | Value |")
            sections.append("|------|-------|")
            for ip in (iocs_data.get("ipv4") or [])[:20]:
                sections.append(f"| IPv4 | {ip} |")
            for domain in (iocs_data.get("domains") or [])[:20]:
                sections.append(f"| Domain | {domain} |")
            for url in (iocs_data.get("urls") or [])[:20]:
                sections.append(f"| URL | {url} |")
            sections.append("")
        if has_host:
            sections.append("### Host Indicators\n")
            sections.append("| Type | Value |")
            sections.append("|------|-------|")
            for key in (iocs_data.get("registry_keys") or [])[:20]:
                sections.append(f"| Registry Key | {key} |")
            for mutex in (iocs_data.get("mutexes") or [])[:20]:
                sections.append(f"| Mutex | {mutex} |")
            for fp in (iocs_data.get("file_paths") or [])[:20]:
                sections.append(f"| File Path | {fp} |")
            sections.append("")
        if has_hashes:
            sections.append("### File Hashes\n")
            sections.append("| Type | Value |")
            sections.append("|------|-------|")
            for h in (iocs_data.get("file_hashes") or [])[:10]:
                sections.append(f"| Hash | {h} |")
            sections.append("")
    else:
        sections.append("## Indicators of Compromise\n")
        sections.append("No IOCs collected. Run `get_iocs_structured()` to aggregate indicators.")
        sections.append("")

    # ── Capabilities ──
    capa_analysis = pe_data.get("capa_analysis", {})
    if isinstance(capa_analysis, dict) and capa_analysis:
        results = capa_analysis.get("results", {})
        rules = results.get("rules", {}) if isinstance(results, dict) else {}
        if rules:
            # Group by namespace prefix (tactic)
            by_namespace: Dict[str, List[str]] = {}
            for rule_name, rule_details in rules.items():
                meta = rule_details.get("meta", {}) if isinstance(rule_details, dict) else {}
                ns = meta.get("namespace", "other") if isinstance(meta, dict) else "other"
                top_ns = ns.split("/")[0] if ns else "other"
                by_namespace.setdefault(top_ns, []).append(
                    meta.get("name", rule_name) if isinstance(meta, dict) else str(rule_name)
                )
            sections.append("## Capabilities\n")
            for ns_name in sorted(by_namespace.keys()):
                caps = by_namespace[ns_name]
                sections.append(f"### {ns_name.replace('-', ' ').title()}\n")
                for cap in caps[:15]:
                    sections.append(f"- {cap}")
                sections.append("")
    else:
        # Check suspicious_capabilities from triage as fallback
        sus_caps = triage.get("suspicious_capabilities", []) if triage else []
        if isinstance(sus_caps, list) and sus_caps:
            sections.append("## Capabilities\n")
            for cap in sus_caps[:20]:
                if isinstance(cap, dict):
                    sections.append(f"- **{cap.get('severity', '?')}**: {cap.get('capability', '?')} ({cap.get('namespace', '')})")
                elif isinstance(cap, str):
                    sections.append(f"- {cap}")
            sections.append("")

    # ── Anti-Analysis Techniques ──
    anti_analysis_items: List[str] = []
    if triage:
        # Packing
        packing = triage.get("packing_assessment", {})
        if isinstance(packing, dict) and packing.get("likely_packed"):
            packer_name = packing.get("packer_name", "unknown packer")
            anti_analysis_items.append(f"Packed binary ({packer_name})")

        # Anti-debug imports
        sus_imports = triage.get("suspicious_imports", [])
        if isinstance(sus_imports, list):
            for imp in sus_imports:
                if isinstance(imp, dict):
                    func = imp.get("function", "").lower()
                    if any(kw in func for kw in ("isdebuggerpresent", "checkremotedebugger",
                                                  "ntqueryinformationprocess", "outputdebugstring")):
                        anti_analysis_items.append(f"Anti-debug API: {imp.get('function', '?')} ({imp.get('dll', '?')})")

        # Anti-analysis capabilities from capa
        sus_caps = triage.get("suspicious_capabilities", [])
        if isinstance(sus_caps, list):
            for cap in sus_caps:
                if isinstance(cap, dict):
                    ns = cap.get("namespace", "").lower()
                    if "anti-analysis" in ns or "anti-vm" in ns:
                        anti_analysis_items.append(cap.get("capability", "Unknown anti-analysis technique"))

    if anti_analysis_items:
        sections.append("## Anti-Analysis Techniques\n")
        seen = set()
        for item in anti_analysis_items:
            if item not in seen:
                sections.append(f"- {item}")
                seen.add(item)
        sections.append("")

    # ── Detection Rules (YARA from triage) ──
    if triage:
        yara_matches = triage.get("yara_matches", [])
        if isinstance(yara_matches, list) and yara_matches:
            sections.append("## Detection Rules\n")
            sections.append("### YARA Matches\n")
            for match in yara_matches[:10]:
                if isinstance(match, dict):
                    sections.append(f"- **{match.get('rule', '?')}**: {match.get('description', match.get('meta', ''))}")
                elif isinstance(match, str):
                    sections.append(f"- {match}")
            sections.append("")

    # ── Analyst Notes ──
    analyst_notes: List[Dict[str, Any]] = []
    for note in notes:
        cat = note.get("category", "general")
        if cat in ("hypothesis", "conclusion", "general", "ioc"):
            analyst_notes.append(note)

    if analyst_notes:
        sections.append("## Analyst Notes\n")
        for note in analyst_notes[:30]:
            cat = note.get("category", "general")
            content = note.get("content", "").replace("\\n", "\n").replace("\\t", "\t")
            created = note.get("created_at", "")
            if created:
                sections.append(f"- **[{cat}]** ({created}) {content}")
            else:
                sections.append(f"- **[{cat}]** {content}")
        sections.append("")

    # ── Footer ──
    sections.append("---")
    sections.append(f"*Generated by Arkana at {timestamp}*")

    return "\n".join(sections)


def _build_cti_json(
    pe_data: Dict[str, Any],
    triage: Dict[str, Any],
    classification: Optional[Dict[str, Any]],
    similarity_hashes: Optional[Dict[str, Any]],
    mitre_mapping: Optional[Dict[str, Any]],
    cached_iocs: Optional[Dict[str, Any]],
    notes: List[Dict[str, Any]],
    filepath: str,
) -> Dict[str, Any]:
    """Build a structured CTI report as a JSON-friendly dict."""
    hashes = pe_data.get("file_hashes", {})
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report: Dict[str, Any] = {"generated_at": timestamp}

    # Executive summary
    report["executive_summary"] = _get_executive_summary(notes, triage)

    # Sample information
    sample_info: Dict[str, Any] = {
        "filename": os.path.basename(filepath),
        "sha256": hashes.get("sha256", ""),
        "md5": hashes.get("md5", ""),
        "sha1": hashes.get("sha1", ""),
        "file_type": pe_data.get("mode", "unknown"),
    }
    if classification and isinstance(classification, dict):
        primary = classification.get("primary_type")
        if primary:
            sample_info["file_type"] = primary
        sample_info["classifications"] = classification.get("classifications", [])

    # File size
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
        sample_info["file_size"] = int(file_size)

    # Architecture
    nt_headers = pe_data.get("nt_headers", {})
    file_header = nt_headers.get("file_header", {}) if isinstance(nt_headers, dict) else {}
    machine = file_header.get("machine", file_header.get("Machine", ""))
    if isinstance(machine, dict):
        machine = machine.get("Value", "")
    if machine:
        sample_info["architecture"] = machine

    # Compile time
    time_date_stamp = file_header.get("time_date_stamp", file_header.get("TimeDateStamp", ""))
    if isinstance(time_date_stamp, dict):
        time_date_stamp = time_date_stamp.get("Value", "")
    if time_date_stamp:
        sample_info["compile_time"] = time_date_stamp

    # Similarity hashes
    if similarity_hashes and isinstance(similarity_hashes, dict):
        sample_info["ssdeep"] = similarity_hashes.get("ssdeep", "")
        sample_info["tlsh"] = similarity_hashes.get("tlsh", "")
        sample_info["imphash"] = similarity_hashes.get("imphash", "")

    report["sample_info"] = sample_info

    # Risk assessment
    if triage:
        report["risk_assessment"] = {
            "risk_level": triage.get("risk_level", "UNKNOWN"),
            "risk_score": triage.get("risk_score", 0),
        }
        packing = triage.get("packing_assessment", {})
        if isinstance(packing, dict):
            report["risk_assessment"]["packed"] = packing.get("likely_packed", False)
            if packing.get("packer_name"):
                report["risk_assessment"]["packer"] = packing["packer_name"]

    # MITRE ATT&CK
    if mitre_mapping and isinstance(mitre_mapping, dict):
        techniques = mitre_mapping.get("techniques", [])
        report["mitre_attack"] = {
            "technique_count": len(techniques),
            "tactics_covered": mitre_mapping.get("tactics_covered", 0),
            "techniques": [
                {
                    "id": t.get("id", ""),
                    "name": t.get("name", ""),
                    "tactic": t.get("tactic", ""),
                    "confidence": t.get("confidence", 0),
                }
                for t in techniques[:50]
            ],
        }

    # IOCs
    if cached_iocs and isinstance(cached_iocs, dict):
        report["iocs"] = cached_iocs.get("iocs", {})
        report["ioc_total"] = cached_iocs.get("total_iocs", 0)
    elif triage:
        net_iocs = triage.get("network_iocs", {})
        if isinstance(net_iocs, dict):
            report["iocs"] = {
                "ipv4": net_iocs.get("ip_addresses", []),
                "urls": net_iocs.get("urls", []),
                "domains": net_iocs.get("domains", []),
                "registry_keys": net_iocs.get("registry_keys", []),
            }

    # Capabilities from capa
    capa_analysis = pe_data.get("capa_analysis", {})
    if isinstance(capa_analysis, dict) and capa_analysis:
        results = capa_analysis.get("results", {})
        rules = results.get("rules", {}) if isinstance(results, dict) else {}
        if rules:
            cap_list = []
            for rule_name, rule_details in rules.items():
                meta = rule_details.get("meta", {}) if isinstance(rule_details, dict) else {}
                cap_list.append({
                    "name": meta.get("name", rule_name) if isinstance(meta, dict) else str(rule_name),
                    "namespace": meta.get("namespace", "") if isinstance(meta, dict) else "",
                })
            report["capabilities"] = cap_list

    # Analyst notes
    analyst_notes = []
    for note in notes:
        cat = note.get("category", "general")
        if cat in ("hypothesis", "conclusion", "general", "ioc"):
            analyst_notes.append({
                "category": cat,
                "content": note.get("content", ""),
                "created_at": note.get("created_at", ""),
            })
    if analyst_notes:
        report["analyst_notes"] = analyst_notes[:30]

    return report


@tool_decorator
async def generate_cti_report(
    ctx: Context,
    format: str = "markdown",
    output_path: str = "",
) -> Dict[str, Any]:
    """Generate a structured Cyber Threat Intelligence (CTI) report.

    Phase: 7 — Report

    Aggregates triage, IOCs, MITRE ATT&CK mapping, capabilities, C2 config,
    malware family identification, and analyst notes into a comprehensive
    CTI report suitable for sharing with SOC teams or threat intelligence
    platforms.

    When to use: After completing analysis — produces a shareable report with
    all findings, IOCs, MITRE mappings, and analyst notes in one document.

    Args:
        ctx: MCP Context.
        format: Output format — "markdown" (default) or "json".
        output_path: Optional file path to save the report (registered as artifact).
    """
    await ctx.info("Generating CTI report")
    _check_pe_loaded("generate_cti_report")

    fmt = format.lower()
    if fmt not in ("markdown", "json"):
        return {"error": f"Unsupported format '{format}'. Use 'markdown' or 'json'."}

    pe_data = state.pe_data or {}
    filepath = state.filepath or "unknown"
    notes = state.get_notes()
    triage = getattr(state, '_cached_triage', None) or {}
    classification = getattr(state, '_cached_classification', None)
    similarity_hashes = getattr(state, '_cached_similarity_hashes', None)
    mitre_mapping = getattr(state, '_cached_mitre_mapping', None)
    cached_iocs = getattr(state, '_cached_iocs', None)

    if fmt == "markdown":
        report_text = _build_cti_markdown(
            pe_data, triage, classification, similarity_hashes,
            mitre_mapping, cached_iocs, notes, filepath,
        )
        response: Dict[str, Any] = {
            "report": report_text,
            "format": "markdown",
        }
    else:
        report_data = _build_cti_json(
            pe_data, triage, classification, similarity_hashes,
            mitre_mapping, cached_iocs, notes, filepath,
        )
        response = {
            "report": report_data,
            "format": "json",
        }

    # Include a summary of what data sources were available
    response["data_sources"] = {
        "triage": bool(triage),
        "classification": classification is not None,
        "similarity_hashes": similarity_hashes is not None,
        "mitre_mapping": mitre_mapping is not None,
        "iocs": cached_iocs is not None,
        "notes_count": len(notes),
    }

    if output_path:
        if fmt == "markdown":
            text_bytes = report_text.encode("utf-8")
        else:
            text_bytes = json.dumps(report_data, indent=2, default=str).encode("utf-8")
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, text_bytes, "generate_cti_report",
            f"CTI report ({fmt})",
        )
        response["artifact"] = artifact_meta

    return await _check_mcp_response_size(ctx, response, "generate_cti_report")
