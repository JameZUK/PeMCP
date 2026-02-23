"""MCP tools for analysis workflow — report generation and sample naming."""
import datetime
import os
import re

from typing import Dict, Any, List, Optional

from pemcp.config import state, logger, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size


# ===================================================================
#  Tool 1: generate_analysis_report
# ===================================================================

@tool_decorator
async def generate_analysis_report(
    ctx: Context,
    format: str = "markdown",
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
    history = state.get_tool_history()

    # Build report
    sections = []

    # --- Executive Summary ---
    risk_level = triage.get("risk_level", "UNKNOWN")
    risk_score = triage.get("risk_score", 0)
    mode = pe_data.get("mode", "unknown")

    key_findings = [n["content"] for n in notes if n.get("category") == "tool_result"][:10]

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
        sections.append(f"| Size | {pe_data.get('file_size', 'N/A')} bytes |")
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
        general_notes = [n for n in notes if n.get("category") == "general"]
        if general_notes:
            sections.append("## Analyst Notes\n")
            for n in general_notes:
                sections.append(f"- {n.get('content', '')}")
            sections.append("")

        # --- Tool History Summary ---
        sections.append("## Analysis Timeline\n")
        sections.append(f"Total tool invocations: {len(history)}\n")
        from collections import Counter
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

    return await _check_mcp_response_size(ctx, {
        "report": report_text,
        "format": fmt,
        "sections_count": len(sections) if fmt == "markdown" else 1,
    }, "generate_analysis_report")


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

    # --- Binary type ---
    mode = pe_data.get("mode", "unknown")
    if "dll" in mode.lower():
        file_ext = ".dll"
        parts.append("dll")
    elif "exe" in mode.lower():
        file_ext = ".exe"
    elif "elf" in mode.lower():
        file_ext = ".elf"
    else:
        file_ext = ".bin"

    # --- Classification ---
    # Check notes for classification hints
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

    # Check suspicious imports for capability hints
    sus_imports = triage.get("suspicious_imports", [])
    capabilities = set()
    for imp in sus_imports:
        if isinstance(imp, dict):
            func = imp.get("function", "").lower()
            if "key" in func and ("log" in func or "hook" in func or "input" in func):
                capabilities.add("keylog")
            if "crypt" in func:
                capabilities.add("crypto")
            if "internet" in func or "http" in func or "url" in func:
                capabilities.add("net")
            if "createservice" in func or "regset" in func:
                capabilities.add("persist")
            if "createremotethread" in func or "writeprocessmemory" in func:
                capabilities.add("inject")

    if found_type:
        parts.append(found_type)
    elif capabilities:
        parts.append("_".join(sorted(capabilities)[:2]))

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

    # --- Packer info ---
    packing = triage.get("packing_assessment", {})
    if isinstance(packing, dict) and packing.get("likely_packed"):
        packer = packing.get("packer_name", "")
        if packer:
            parts.append(f"packed_{packer.lower().replace(' ', '_')[:10]}")

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
            "type": found_type or "unknown",
            "capabilities": sorted(capabilities),
            "c2": bool(net_iocs and (net_iocs.get("ip_addresses") or net_iocs.get("domains"))),
            "packed": bool(packing and isinstance(packing, dict) and packing.get("likely_packed")),
        },
    }
