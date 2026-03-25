"""MCP tools for importing and correlating sandbox analysis reports.

Supports CAPE, Cuckoo, ANY.RUN, Hybrid Analysis, and Joe Sandbox JSON reports.
"""
import asyncio
import json
import logging
import os
from typing import Any, Dict, Optional

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator, _check_mcp_response_size

_MAX_REPORT_SIZE = 256 * 1024 * 1024  # 256 MB


@tool_decorator
async def import_sandbox_report(
    ctx: Context,
    file_path: str,
    format: str = "auto",
) -> Dict[str, Any]:
    """Import a sandbox analysis report for correlation with static findings.

    Phase: 6 -- Intel

    Parses JSON reports from CAPE, Cuckoo, ANY.RUN, Hybrid Analysis, or
    Joe Sandbox into a unified schema. The imported data is stored on the
    session for correlation with static analysis results.

    Args:
        file_path: Path to the sandbox JSON report file
        format: Report format -- "auto" (detect), "cape", "cuckoo", "anyrun",
                "hybrid_analysis", or "joe"
    """
    # Validate path
    abs_path = os.path.realpath(file_path)
    state.check_path_allowed(abs_path)

    if not os.path.isfile(abs_path):
        return {"error": f"File not found: {file_path}"}

    file_size = os.path.getsize(abs_path)
    if file_size > _MAX_REPORT_SIZE:
        return {"error": f"Report too large ({file_size / 1024 / 1024:.1f} MB). Max: 256 MB."}
    if file_size == 0:
        return {"error": "Report file is empty."}

    def _parse():
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        from arkana.parsers.sandbox import parse_sandbox_report
        return parse_sandbox_report(data, format=format)

    result = await asyncio.to_thread(_parse)

    if result.get("error"):
        return result

    state._sandbox_report = result

    summary = {
        "status": "imported",
        "sandbox": result.get("sandbox", "unknown"),
        "verdict": result.get("verdict", "unknown"),
        "threat_score": result.get("threat_score"),
        "malware_family": result.get("malware_family"),
        "network_indicators": {
            "domains": len(result.get("network", {}).get("contacted_domains", [])),
            "ips": len(result.get("network", {}).get("contacted_ips", [])),
            "urls": len(result.get("network", {}).get("http_requests", [])),
        },
        "processes": len(result.get("processes", [])),
        "mitre_techniques": len(result.get("mitre_techniques", [])),
        "signatures": len(result.get("signatures", [])),
        "has_extracted_config": result.get("extracted_config") is not None,
        "next_step": "Call correlate_static_dynamic() to compare with static analysis findings.",
    }

    return await _check_mcp_response_size(ctx, summary, "import_sandbox_report")


@tool_decorator
async def correlate_static_dynamic(
    ctx: Context,
) -> Dict[str, Any]:
    """Correlate sandbox dynamic analysis with Arkana's static analysis findings.

    Phase: 6 -- Intel

    Compares imported sandbox report data with static analysis results to
    identify confirmed IOCs, dynamic-only indicators, unexercised capabilities,
    and MITRE ATT&CK technique overlap.

    Requires: import_sandbox_report() must be called first.
    """
    if state._sandbox_report is None:
        return {"error": "No sandbox report imported. Call import_sandbox_report() first."}

    report = state._sandbox_report
    result: Dict[str, Any] = {"sandbox_info": {
        "sandbox": report.get("sandbox", ""),
        "verdict": report.get("verdict", ""),
        "threat_score": report.get("threat_score"),
    }}

    # -- IOC Correlation -----------------------------------------------------
    static_iocs = state._cached_iocs or {}
    # _cached_iocs stores IOCs under "iocs" key from _collect_iocs_internal
    iocs_data = static_iocs.get("iocs", static_iocs)
    dynamic_net = report.get("network", {})

    static_ips = set(iocs_data.get("ipv4", []))
    dynamic_ips = set(dynamic_net.get("contacted_ips", []))
    static_domains = set(iocs_data.get("domains", []))
    dynamic_domains = set(dynamic_net.get("contacted_domains", []))
    static_urls = set(iocs_data.get("urls", []))
    dynamic_urls = set(u.get("url", "") for u in dynamic_net.get("http_requests", []))

    result["ioc_correlation"] = {
        "confirmed_ips": sorted(static_ips & dynamic_ips)[:100],
        "confirmed_domains": sorted(static_domains & dynamic_domains)[:100],
        "confirmed_urls": sorted(static_urls & dynamic_urls)[:50],
        "dynamic_only_ips": sorted(dynamic_ips - static_ips)[:100],
        "dynamic_only_domains": sorted(dynamic_domains - static_domains)[:100],
        "static_only_ips": sorted(static_ips - dynamic_ips)[:100],
        "static_only_domains": sorted(static_domains - dynamic_domains)[:100],
        "summary": {
            "confirmed": len(static_ips & dynamic_ips) + len(static_domains & dynamic_domains),
            "dynamic_only": len(dynamic_ips - static_ips) + len(dynamic_domains - static_domains),
            "static_only": len(static_ips - dynamic_ips) + len(static_domains - dynamic_domains),
        },
    }

    # -- MITRE Correlation ---------------------------------------------------
    static_mitre = state._cached_mitre_mapping or {}
    static_techniques = set()
    for tech in static_mitre.get("techniques", []):
        tid = tech.get("id", "") if isinstance(tech, dict) else str(tech)
        if tid:
            static_techniques.add(tid)

    dynamic_techniques = set()
    for tech in report.get("mitre_techniques", []):
        tid = tech.get("id", "")
        if tid:
            dynamic_techniques.add(tid)

    result["mitre_correlation"] = {
        "confirmed_techniques": sorted(static_techniques & dynamic_techniques),
        "static_only": sorted(static_techniques - dynamic_techniques),
        "dynamic_only": sorted(dynamic_techniques - static_techniques),
        "static_count": len(static_techniques),
        "dynamic_count": len(dynamic_techniques),
    }

    # -- API Correlation -----------------------------------------------------
    # Compare static imports with dynamic API calls
    pe_data = state.pe_data or {}
    static_imports = set()
    for dll_info in pe_data.get("imports", {}).get("import_details", []):
        if isinstance(dll_info, dict):
            for imp in dll_info.get("imports", []):
                name = imp.get("name", "") if isinstance(imp, dict) else str(imp)
                if name:
                    static_imports.add(name)

    dynamic_apis = set()
    for api_entry in report.get("api_summary", {}).get("top_apis", []):
        api_name = api_entry.get("api", "")
        if api_name:
            dynamic_apis.add(api_name)

    result["api_correlation"] = {
        "called_and_imported": sorted(static_imports & dynamic_apis)[:50],
        "dynamic_only_apis": sorted(dynamic_apis - static_imports)[:50],
        "imported_not_called": len(static_imports - dynamic_apis),
        "import_coverage": round(len(static_imports & dynamic_apis) / max(1, len(static_imports)) * 100, 1),
    }

    # -- Config Correlation --------------------------------------------------
    if report.get("extracted_config"):
        config = report["extracted_config"]
        config_c2 = set(config.get("c2_servers", []))

        result["config_correlation"] = {
            "family": config.get("family", ""),
            "confirmed_c2": sorted((config_c2 & dynamic_ips) | (config_c2 & dynamic_domains))[:20],
            "uncontacted_c2": sorted(config_c2 - dynamic_ips - dynamic_domains)[:20],
        }

    # -- Overall Assessment --------------------------------------------------
    confirmed = result["ioc_correlation"]["summary"]["confirmed"]
    dynamic_only = result["ioc_correlation"]["summary"]["dynamic_only"]
    mitre_confirmed = len(result["mitre_correlation"]["confirmed_techniques"])

    if confirmed > 5 and mitre_confirmed > 3:
        confidence = "high"
    elif confirmed > 0 or mitre_confirmed > 0:
        confidence = "medium"
    else:
        confidence = "low"

    result["overall_assessment"] = (
        f"Static/dynamic correlation: {confirmed} confirmed IOCs, "
        f"{dynamic_only} dynamic-only indicators, "
        f"{mitre_confirmed} confirmed MITRE techniques. "
        f"Confidence: {confidence}."
    )
    result["confidence_level"] = confidence

    return await _check_mcp_response_size(ctx, result, "correlate_static_dynamic")


@tool_decorator
async def get_sandbox_summary(
    ctx: Context,
) -> Dict[str, Any]:
    """Get a summary of the imported sandbox report.

    Phase: 6 -- Intel

    Returns metadata and indicator counts from the imported sandbox report
    without running correlation. Useful for checking what data is available.
    """
    if state._sandbox_report is None:
        return {"status": "no_report", "message": "No sandbox report imported. Use import_sandbox_report() first."}

    report = state._sandbox_report
    net = report.get("network", {})

    return {
        "status": "loaded",
        "sandbox": report.get("sandbox", ""),
        "verdict": report.get("verdict", ""),
        "threat_score": report.get("threat_score"),
        "malware_family": report.get("malware_family"),
        "sample": report.get("sample", {}),
        "indicators": {
            "dns_queries": len(net.get("dns_queries", [])),
            "http_requests": len(net.get("http_requests", [])),
            "contacted_ips": len(net.get("contacted_ips", [])),
            "contacted_domains": len(net.get("contacted_domains", [])),
            "dropped_files": len(report.get("files", {}).get("dropped", [])),
            "registry_keys": len(report.get("files", {}).get("registry_keys", [])),
            "mutexes": len(report.get("files", {}).get("mutexes", [])),
        },
        "processes": len(report.get("processes", [])),
        "mitre_techniques": len(report.get("mitre_techniques", [])),
        "signatures": len(report.get("signatures", [])),
        "has_api_summary": bool(report.get("api_summary", {}).get("top_apis")),
        "has_extracted_config": report.get("extracted_config") is not None,
    }
