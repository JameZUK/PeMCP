"""Sandbox report parsers -- adapters for CAPE, Cuckoo, ANY.RUN, Hybrid Analysis, Joe Sandbox.

Each adapter normalizes a sandbox-specific JSON report into a unified schema
suitable for correlation with Arkana's static analysis results.
"""
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Arkana")

# -- Limits ------------------------------------------------------------------
MAX_SANDBOX_DNS = 500
MAX_SANDBOX_HTTP = 500
MAX_SANDBOX_CONNECTIONS = 1000
MAX_SANDBOX_DROPPED = 200
MAX_SANDBOX_PROCESSES = 100
MAX_SANDBOX_API_TOP = 50
MAX_SANDBOX_NOTABLE_CALLS = 20
MAX_SANDBOX_MITRE = 100
MAX_SANDBOX_SIGNATURES = 200


def detect_sandbox_format(data: Dict[str, Any]) -> str:
    """Auto-detect sandbox format from report JSON structure."""
    if "CAPE" in data:
        return "cape"
    if "behavior" in data and "processes" in data.get("behavior", {}):
        # Cuckoo and CAPE share structure, but CAPE has the "CAPE" key
        return "cuckoo"
    if isinstance(data.get("processes"), list) and any(
        isinstance(p, dict) and "uuid" in p for p in data.get("processes", [])[:5]
    ):
        return "anyrun"
    if "mitre_attcks" in data or ("verdict" in data and "threat_score" in data):
        return "hybrid_analysis"
    if "mitreattack" in data or "signaturedetections" in data:
        return "joe"
    return "unknown"


def parse_sandbox_report(data: Dict[str, Any], format: str = "auto") -> Dict[str, Any]:
    """Parse a sandbox report into the unified schema."""
    if format == "auto":
        format = detect_sandbox_format(data)

    adapters = {
        "cape": _parse_cape,
        "cuckoo": _parse_cuckoo,
        "anyrun": _parse_anyrun,
        "hybrid_analysis": _parse_hybrid_analysis,
        "joe": _parse_joe,
    }

    adapter = adapters.get(format)
    if not adapter:
        return {"error": f"Unknown sandbox format: {format}. Supported: {', '.join(adapters.keys())}"}

    try:
        result = adapter(data)
        result["sandbox"] = format
        _validate_and_normalize(result)
        return result
    except Exception as e:
        logger.warning("Sandbox parse failed for format %s: %s", format, e)
        return {"error": f"Failed to parse {format} report: {str(e)[:300]}"}


def _safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts."""
    current = d
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current


def _parse_cape(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse CAPE Sandbox report."""
    target = data.get("target", {}).get("file", {})
    network = data.get("network", {})
    behavior = data.get("behavior", {})
    cape = data.get("CAPE", {})

    result = _empty_report()

    # Sample info
    result["sample"] = {
        "sha256": target.get("sha256", ""),
        "md5": target.get("md5", ""),
        "sha1": target.get("sha1", ""),
        "filename": target.get("name", ""),
        "file_size": target.get("size", 0),
    }

    # Verdict
    result["verdict"] = "malicious" if data.get("malscore", 0) >= 5 else "suspicious"
    result["threat_score"] = int(min(100, data.get("malscore", 0) * 10))

    # Network
    result["network"] = _parse_network_common(network)

    # Processes
    result["processes"] = _parse_processes_cuckoo(behavior)

    # API summary
    result["api_summary"] = _parse_api_summary_cuckoo(behavior)

    # MITRE from signatures
    result["mitre_techniques"] = _parse_mitre_from_signatures(data.get("signatures", []))

    # Signatures
    result["signatures"] = _parse_signatures_cuckoo(data.get("signatures", []))

    # Dropped files
    result["files"] = _parse_dropped_cuckoo(data)

    # CAPE-specific: extracted configs
    configs = cape.get("configs", []) or []
    if configs:
        first_config = configs[0] if configs else {}
        result["extracted_config"] = {
            "family": first_config.get("type", ""),
            "c2_servers": first_config.get("c2", [])[:50],
            "encryption_keys": [],
            "raw": first_config if len(str(first_config)) < 10000 else None,
        }

    # Malware family from CAPE
    if configs and configs[0].get("type"):
        result["malware_family"] = configs[0]["type"]

    return result


def _parse_cuckoo(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Cuckoo Sandbox report."""
    target = data.get("target", {}).get("file", {})
    network = data.get("network", {})
    behavior = data.get("behavior", {})

    result = _empty_report()

    result["sample"] = {
        "sha256": target.get("sha256", ""),
        "md5": target.get("md5", ""),
        "sha1": target.get("sha1", ""),
        "filename": target.get("name", ""),
        "file_size": target.get("size", 0),
    }

    result["verdict"] = "malicious" if data.get("info", {}).get("score", 0) >= 5 else "suspicious"
    result["threat_score"] = int(min(100, data.get("info", {}).get("score", 0) * 10))

    result["network"] = _parse_network_common(network)
    result["processes"] = _parse_processes_cuckoo(behavior)
    result["api_summary"] = _parse_api_summary_cuckoo(behavior)
    result["mitre_techniques"] = _parse_mitre_from_signatures(data.get("signatures", []))
    result["signatures"] = _parse_signatures_cuckoo(data.get("signatures", []))
    result["files"] = _parse_dropped_cuckoo(data)

    return result


def _parse_anyrun(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse ANY.RUN report."""
    result = _empty_report()

    # Sample - ANY.RUN structure varies; try common paths
    result["sample"] = {
        "sha256": _safe_get(data, "analysis", "content", "hashes", "sha256", default=""),
        "md5": _safe_get(data, "analysis", "content", "hashes", "md5", default=""),
        "sha1": _safe_get(data, "analysis", "content", "hashes", "sha1", default=""),
        "filename": _safe_get(data, "analysis", "content", "fileName", default=""),
        "file_size": _safe_get(data, "analysis", "content", "fileSize", default=0),
    }

    # Processes
    for proc in (data.get("processes") or [])[:MAX_SANDBOX_PROCESSES]:
        result["processes"].append({
            "pid": proc.get("pid", 0),
            "ppid": proc.get("ppid"),
            "name": proc.get("image", proc.get("fileName", "")),
            "command_line": proc.get("commandLine", ""),
            "is_main": proc.get("mainProcess", False),
        })

    # Network
    net = data.get("network", {})
    dns_list = []
    for req in (net.get("dnsRequests") or [])[:MAX_SANDBOX_DNS]:
        dns_list.append({
            "domain": req.get("domain", ""),
            "resolved_ips": req.get("ips", [])[:10],
            "timestamp": req.get("time"),
        })

    http_list = []
    for req in (net.get("httpRequests") or [])[:MAX_SANDBOX_HTTP]:
        http_list.append({
            "url": req.get("url", ""),
            "method": req.get("method", ""),
            "host": req.get("host", ""),
            "port": req.get("port"),
        })

    connections = []
    for conn in (net.get("connections") or [])[:MAX_SANDBOX_CONNECTIONS]:
        connections.append({
            "ip": conn.get("ip", ""),
            "port": conn.get("port", 0),
            "protocol": conn.get("protocol", "tcp"),
        })

    result["network"] = {
        "dns_queries": dns_list,
        "http_requests": http_list,
        "connections": connections,
        "contacted_domains": list(set(d["domain"] for d in dns_list if d["domain"]))[:200],
        "contacted_ips": list(set(c["ip"] for c in connections if c["ip"]))[:200],
    }

    # MITRE
    for tech in (data.get("mitre") or [])[:MAX_SANDBOX_MITRE]:
        result["mitre_techniques"].append({
            "id": tech.get("id", ""),
            "name": tech.get("name", ""),
            "tactic": (tech.get("phases") or [""])[0] if tech.get("phases") else "",
            "source": "behavioral",
        })

    # Signatures/incidents
    for inc in (data.get("incidents") or [])[:MAX_SANDBOX_SIGNATURES]:
        severity_map = {0: "low", 1: "medium", 2: "high", 3: "critical"}
        result["signatures"].append({
            "name": inc.get("title", ""),
            "description": inc.get("desc", ""),
            "severity": severity_map.get(inc.get("threatLevel", 0), "medium"),
            "attck_id": (inc.get("mitre") or [None])[0] if inc.get("mitre") else None,
        })

    return result


def _parse_hybrid_analysis(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Hybrid Analysis (Falcon Sandbox) report."""
    result = _empty_report()

    result["sample"] = {
        "sha256": data.get("sha256", ""),
        "md5": data.get("md5", ""),
        "sha1": data.get("sha1", ""),
        "filename": data.get("submit_name", ""),
        "file_size": data.get("size", 0),
    }

    verdict_map = {1: "clean", 2: "clean", 3: "suspicious", 4: "suspicious", 5: "malicious"}
    result["verdict"] = verdict_map.get(data.get("verdict", 3), "suspicious")
    result["threat_score"] = data.get("threat_score", 0)
    result["malware_family"] = data.get("vx_family")

    # Network
    domains = data.get("domains") or []
    hosts = data.get("hosts") or []
    urls = data.get("analysis_related_urls") or []

    result["network"] = {
        "dns_queries": [{"domain": d, "resolved_ips": [], "timestamp": None} for d in domains[:MAX_SANDBOX_DNS]],
        "http_requests": [{"url": u.get("url", u) if isinstance(u, dict) else str(u), "method": "", "host": "", "port": None} for u in urls[:MAX_SANDBOX_HTTP]],
        "connections": [{"ip": h, "port": 0, "protocol": "tcp"} for h in hosts[:MAX_SANDBOX_CONNECTIONS]],
        "contacted_domains": domains[:200],
        "contacted_ips": hosts[:200],
    }

    # MITRE
    for tech in (data.get("mitre_attcks") or [])[:MAX_SANDBOX_MITRE]:
        result["mitre_techniques"].append({
            "id": tech.get("technique", ""),
            "name": "",
            "tactic": tech.get("tactic", ""),
            "source": "behavioral",
        })

    # Signatures
    for sig in (data.get("signatures") or [])[:MAX_SANDBOX_SIGNATURES]:
        level_map = {"info": "low", "notice": "medium", "warning": "high", "alert": "critical"}
        result["signatures"].append({
            "name": sig.get("name", ""),
            "description": sig.get("description", ""),
            "severity": level_map.get(sig.get("threat_level_human", "notice"), "medium"),
            "attck_id": sig.get("attck_id"),
        })

    # Dropped files
    for f in (data.get("extracted_files") or [])[:MAX_SANDBOX_DROPPED]:
        result["files"]["dropped"].append({
            "filename": f.get("name", ""),
            "sha256": f.get("sha256"),
            "md5": f.get("md5"),
            "size": f.get("file_size"),
            "type": f.get("type_tags", [None])[0] if f.get("type_tags") else None,
        })

    return result


def _parse_joe(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Joe Sandbox report."""
    result = _empty_report()

    # Joe uses a quirky XML-to-JSON structure
    fi = data.get("fileinfo", {})
    result["sample"] = {
        "sha256": fi.get("sha256", ""),
        "md5": fi.get("md5", ""),
        "sha1": fi.get("sha1", ""),
        "filename": fi.get("filename", ""),
        "file_size": fi.get("filesize", 0),
    }

    # Network IOCs
    ip_info = data.get("ipinfo", {}).get("ip", []) or []
    if isinstance(ip_info, dict):
        ip_info = [ip_info]
    domain_info = data.get("domaininfo", {}).get("domain", []) or []
    if isinstance(domain_info, dict):
        domain_info = [domain_info]

    result["network"] = {
        "dns_queries": [{"domain": d.get("@name", ""), "resolved_ips": [], "timestamp": None} for d in domain_info[:MAX_SANDBOX_DNS]],
        "http_requests": [],
        "connections": [{"ip": ip.get("@ip", ""), "port": 0, "protocol": "tcp"} for ip in ip_info[:MAX_SANDBOX_CONNECTIONS]],
        "contacted_domains": [d.get("@name", "") for d in domain_info[:200]],
        "contacted_ips": [ip.get("@ip", "") for ip in ip_info[:200]],
    }

    # MITRE
    mitre = data.get("mitreattack", {})
    tactics = mitre.get("tactic", []) or []
    if isinstance(tactics, dict):
        tactics = [tactics]
    for tactic in tactics:
        techniques = tactic.get("technique", []) or []
        if isinstance(techniques, dict):
            techniques = [techniques]
        for tech in techniques[:MAX_SANDBOX_MITRE]:
            result["mitre_techniques"].append({
                "id": tech.get("id", ""),
                "name": tech.get("name", ""),
                "tactic": tactic.get("name", ""),
                "source": "behavioral",
            })

    # Signatures
    sigs = data.get("signatureinfo", {}).get("sig", []) or []
    if isinstance(sigs, dict):
        sigs = [sigs]
    for sig in sigs[:MAX_SANDBOX_SIGNATURES]:
        impact_map = {"0": "low", "1": "medium", "2": "high", "3": "critical"}
        result["signatures"].append({
            "name": sig.get("@desc", sig.get("@name", "")),
            "description": sig.get("@desc", ""),
            "severity": impact_map.get(str(sig.get("@impact", "1")), "medium"),
            "attck_id": None,
        })

    return result


# -- Common helpers ----------------------------------------------------------

def _empty_report() -> Dict[str, Any]:
    """Return an empty unified report structure."""
    return {
        "sandbox": "",
        "report_id": "",
        "sample": {"sha256": "", "md5": "", "sha1": "", "filename": "", "file_size": 0},
        "analysis_time": "",
        "verdict": "unknown",
        "threat_score": None,
        "malware_family": None,
        "network": {
            "dns_queries": [],
            "http_requests": [],
            "connections": [],
            "contacted_domains": [],
            "contacted_ips": [],
        },
        "files": {"dropped": [], "registry_keys": [], "mutexes": []},
        "processes": [],
        "api_summary": {"total_calls": None, "top_apis": [], "categories": {}, "notable_calls": []},
        "mitre_techniques": [],
        "signatures": [],
        "extracted_config": None,
    }


def _parse_network_common(network: Dict[str, Any]) -> Dict[str, Any]:
    """Parse network data from Cuckoo/CAPE format."""
    dns_list = []
    for entry in (network.get("dns") or [])[:MAX_SANDBOX_DNS]:
        answers = entry.get("answers", [])
        ips = [a.get("data", "") for a in answers if a.get("type") == "A"] if isinstance(answers, list) else []
        dns_list.append({
            "domain": entry.get("request", ""),
            "resolved_ips": ips[:10],
            "timestamp": None,
        })

    http_list = []
    for entry in (network.get("http") or [])[:MAX_SANDBOX_HTTP]:
        http_list.append({
            "url": entry.get("uri", ""),
            "method": entry.get("method", ""),
            "host": entry.get("host", ""),
            "port": entry.get("port"),
        })

    connections = []
    for entry in (network.get("tcp") or [])[:MAX_SANDBOX_CONNECTIONS]:
        connections.append({
            "ip": entry.get("dst", ""),
            "port": entry.get("dport", 0),
            "protocol": "tcp",
        })
    for entry in (network.get("udp") or [])[:MAX_SANDBOX_CONNECTIONS - len(connections)]:
        connections.append({
            "ip": entry.get("dst", ""),
            "port": entry.get("dport", 0),
            "protocol": "udp",
        })

    all_domains = set(d["domain"] for d in dns_list if d["domain"])
    all_ips = set(c["ip"] for c in connections if c["ip"])
    all_ips.update(ip for d in dns_list for ip in d["resolved_ips"])
    for h in (network.get("hosts") or []):
        if isinstance(h, str):
            all_ips.add(h)

    return {
        "dns_queries": dns_list,
        "http_requests": http_list,
        "connections": connections,
        "contacted_domains": sorted(all_domains)[:200],
        "contacted_ips": sorted(all_ips)[:200],
    }


def _parse_processes_cuckoo(behavior: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse process tree from Cuckoo/CAPE behavior section."""
    processes = []
    for proc in (behavior.get("processes") or [])[:MAX_SANDBOX_PROCESSES]:
        processes.append({
            "pid": proc.get("pid", 0),
            "ppid": proc.get("ppid"),
            "name": proc.get("process_name", ""),
            "command_line": proc.get("command_line", ""),
            "is_main": proc.get("pid") == (behavior.get("processes") or [{}])[0].get("pid"),
        })
    return processes


def _parse_api_summary_cuckoo(behavior: Dict[str, Any]) -> Dict[str, Any]:
    """Build API call summary from Cuckoo/CAPE behavior."""
    api_counts: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    notable_calls = []
    total = 0

    # apistats is {pid: {api_name: count}}
    for pid_stats in (behavior.get("apistats") or {}).values():
        if isinstance(pid_stats, dict):
            for api, count in pid_stats.items():
                count = int(count) if isinstance(count, (int, float, str)) else 0
                api_counts[api] = api_counts.get(api, 0) + count
                total += count

    # Sort by count, take top N
    sorted_apis = sorted(api_counts.items(), key=lambda x: x[1], reverse=True)
    top_apis = [{"api": name, "count": count} for name, count in sorted_apis[:MAX_SANDBOX_API_TOP]]

    # Notable calls from enhanced behavior
    for entry in (behavior.get("enhanced") or [])[:MAX_SANDBOX_NOTABLE_CALLS]:
        if isinstance(entry, dict):
            notable_calls.append({
                "api": entry.get("event", ""),
                "args": {k: str(v)[:100] for k, v in entry.items() if k != "event"},
                "return_value": None,
            })

    return {
        "total_calls": total if total > 0 else None,
        "top_apis": top_apis,
        "categories": categories,
        "notable_calls": notable_calls,
    }


def _parse_mitre_from_signatures(signatures: list) -> List[Dict[str, Any]]:
    """Extract MITRE techniques from Cuckoo/CAPE signatures."""
    techniques = []
    seen = set()
    for sig in (signatures or []):
        for mark in (sig.get("marks") or []):
            if isinstance(mark, dict):
                technique = mark.get("attack_id") or mark.get("ttp")
                if technique and technique not in seen:
                    seen.add(technique)
                    techniques.append({
                        "id": technique,
                        "name": sig.get("description", ""),
                        "tactic": "",
                        "source": "signature",
                    })
        # Also check sig-level attack info
        ttp = sig.get("ttp") or sig.get("attack")
        if isinstance(ttp, list):
            for t in ttp:
                tid = t if isinstance(t, str) else t.get("id", "") if isinstance(t, dict) else ""
                if tid and tid not in seen:
                    seen.add(tid)
                    techniques.append({
                        "id": tid,
                        "name": sig.get("description", ""),
                        "tactic": "",
                        "source": "signature",
                    })
    return techniques[:MAX_SANDBOX_MITRE]


def _parse_signatures_cuckoo(signatures: list) -> List[Dict[str, Any]]:
    """Parse signatures from Cuckoo/CAPE."""
    result = []
    severity_map = {1: "low", 2: "medium", 3: "high"}
    for sig in (signatures or [])[:MAX_SANDBOX_SIGNATURES]:
        result.append({
            "name": sig.get("name", ""),
            "description": sig.get("description", ""),
            "severity": severity_map.get(sig.get("severity", 1), "medium"),
            "attck_id": sig.get("ttp"),
        })
    return result


def _parse_dropped_cuckoo(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse dropped files from Cuckoo/CAPE."""
    dropped = []
    for f in (data.get("dropped") or [])[:MAX_SANDBOX_DROPPED]:
        dropped.append({
            "filename": f.get("name", ""),
            "sha256": f.get("sha256"),
            "md5": f.get("md5"),
            "size": f.get("size"),
            "type": f.get("type"),
        })

    # Extract mutexes and registry keys from behavior
    behavior = data.get("behavior", {})
    mutexes = []
    registry_keys = []
    for entry in (behavior.get("summary", {}).get("mutex", []) or [])[:100]:
        if isinstance(entry, str):
            mutexes.append(entry)
    for entry in (behavior.get("summary", {}).get("regkey_written", []) or [])[:100]:
        if isinstance(entry, str):
            registry_keys.append(entry)

    return {"dropped": dropped, "registry_keys": registry_keys, "mutexes": mutexes}


def _validate_and_normalize(report: Dict[str, Any]) -> None:
    """Validate and normalize the unified report in-place."""
    # Normalize verdict
    if report.get("verdict") not in ("clean", "suspicious", "malicious"):
        report["verdict"] = "unknown"

    # Clamp threat score
    if report.get("threat_score") is not None:
        report["threat_score"] = max(0, min(100, int(report["threat_score"])))

    # Filter non-routable/invalid IPs
    valid_ips = []
    for ip in report.get("network", {}).get("contacted_ips", []):
        if ip and isinstance(ip, str) and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            valid_ips.append(ip)
    report.setdefault("network", {})["contacted_ips"] = valid_ips[:200]

    # Remove empty strings from domain lists
    domains = report.get("network", {}).get("contacted_domains", [])
    report["network"]["contacted_domains"] = [d for d in domains if d and isinstance(d, str)][:200]
