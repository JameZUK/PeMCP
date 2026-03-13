"""MCP tools for structured IOC (Indicator of Compromise) management.

Aggregates IOCs from triage, string analysis, config extraction, and notes
into structured export formats (JSON, CSV, STIX 2.1).
"""
import asyncio
import datetime
import json
import os
import re
import uuid

from typing import Dict, Any, List, Optional

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._refinery_helpers import _write_output_and_register_artifact


# ===================================================================
#  IOC aggregation helpers
# ===================================================================

_IP_RE = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)")
_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,200}")
# L: Expanded from 13 TLDs to match any 2-16 char TLD, with exclusions for
# common false positives (file extensions, code artifacts).
_DOMAIN_RE = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,16}\b")
_DOMAIN_FALSE_POSITIVE_TLDS = frozenset({
    "dll", "exe", "sys", "drv", "ocx", "cpl", "scr", "tmp", "log", "bak",
    "obj", "lib", "pdb", "ini", "cfg", "xml", "json", "txt", "csv", "html",
    "png", "jpg", "gif", "bmp", "ico", "cur", "ttf", "otf", "woff",
})
_HASH_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_HASH_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_REGISTRY_RE = re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\s\"]{4,200}")
_MUTEX_RE = re.compile(r"(?:Global\\|Local\\)\S{4,100}")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Private IPs to exclude
_PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.", "0.0.", "255.", "169.254.", "172.16.",
                        "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                        "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                        "172.29.", "172.30.", "172.31.")


def _collect_iocs_from_triage() -> Dict[str, set]:
    """Extract IOCs from cached triage results."""
    iocs: Dict[str, set] = {
        "ipv4": set(), "urls": set(), "domains": set(),
        "file_hashes": set(), "registry_keys": set(), "mutexes": set(),
        "emails": set(), "file_paths": set(),
    }
    triage = getattr(state, '_cached_triage', None)
    if not triage:
        return iocs

    net = triage.get("network_iocs", {})
    if isinstance(net, dict):
        for ip in net.get("ip_addresses", []):
            if isinstance(ip, str) and not ip.startswith(_PRIVATE_IP_PREFIXES):
                iocs["ipv4"].add(ip)
        for url in net.get("urls", []):
            if isinstance(url, str):
                iocs["urls"].add(url)
        for domain in net.get("domains", []):
            if isinstance(domain, str):
                iocs["domains"].add(domain)
        for key in net.get("registry_keys", []):
            if isinstance(key, str):
                iocs["registry_keys"].add(key)

    # File hashes from file_info
    hashes = (state.pe_data or {}).get("file_hashes", {})
    if isinstance(hashes, dict):
        for h in ["md5", "sha1", "sha256"]:
            if h in hashes:
                iocs["file_hashes"].add(f"{h}:{hashes[h]}")

    return iocs


_MAX_IOCS_PER_CATEGORY = 10_000


def _collect_iocs_from_notes() -> Dict[str, set]:
    """Extract IOCs mentioned in analysis notes."""
    iocs: Dict[str, set] = {
        "ipv4": set(), "urls": set(), "domains": set(),
        "registry_keys": set(), "mutexes": set(),
        "emails": set(), "file_paths": set(),
    }
    notes = state.get_notes()
    for note in notes:
        content = note.get("content", "")
        for ip in _IP_RE.findall(content):
            if len(iocs["ipv4"]) >= _MAX_IOCS_PER_CATEGORY:
                break
            if not ip.startswith(_PRIVATE_IP_PREFIXES):
                iocs["ipv4"].add(ip)
        for url in _URL_RE.findall(content):
            if len(iocs["urls"]) >= _MAX_IOCS_PER_CATEGORY:
                break
            iocs["urls"].add(url)
        for domain in _DOMAIN_RE.findall(content):
            if len(iocs["domains"]) >= _MAX_IOCS_PER_CATEGORY:
                break
            tld = domain.rsplit(".", 1)[-1].lower()
            if tld not in _DOMAIN_FALSE_POSITIVE_TLDS and not re.match(r"^\d+\.\d+\.\d+", domain):
                iocs["domains"].add(domain)
        for key in _REGISTRY_RE.findall(content):
            if len(iocs["registry_keys"]) >= _MAX_IOCS_PER_CATEGORY:
                break
            iocs["registry_keys"].add(key)
        for mutex in _MUTEX_RE.findall(content):
            if len(iocs["mutexes"]) >= _MAX_IOCS_PER_CATEGORY:
                break
            iocs["mutexes"].add(mutex)
        for email in _EMAIL_RE.findall(content):
            if len(iocs["emails"]) >= _MAX_IOCS_PER_CATEGORY:
                break
            iocs["emails"].add(email)

    return iocs


def _merge_iocs(*ioc_dicts: Dict[str, set]) -> Dict[str, List[str]]:
    """Merge multiple IOC dicts into one with deduplicated sorted lists."""
    merged: Dict[str, set] = {}
    for d in ioc_dicts:
        for category, values in d.items():
            merged.setdefault(category, set()).update(values)
    return {k: sorted(v) for k, v in merged.items() if v}


# ===================================================================
#  STIX 2.1 generation
# ===================================================================

def _ioc_to_stix_pattern(category: str, value: str) -> Optional[str]:
    """Convert an IOC to a STIX 2.1 indicator pattern."""
    # M-S3: Escape single quotes in values to prevent STIX pattern injection
    safe = value.replace("\\", "\\\\").replace("'", "\\'")
    if category == "ipv4":
        return f"[ipv4-addr:value = '{safe}']"
    if category == "urls":
        return f"[url:value = '{safe}']"
    if category == "domains":
        return f"[domain-name:value = '{safe}']"
    if category == "file_hashes":
        parts = value.split(":", 1)
        if len(parts) == 2:
            algo, h = parts
            safe_h = h.replace("\\", "\\\\").replace("'", "\\'")
            return f"[file:hashes.'{algo.upper()}' = '{safe_h}']"
    if category == "registry_keys":
        return f"[windows-registry-key:key = '{safe}']"
    if category == "emails":
        return f"[email-addr:value = '{safe}']"
    return None


def _build_stix_bundle(iocs: Dict[str, List[str]], sample_name: str) -> Dict[str, Any]:
    """Build a STIX 2.1 Bundle from IOCs."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    objects = []

    for category, values in iocs.items():
        for value in values:
            pattern = _ioc_to_stix_pattern(category, value)
            if pattern:
                indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'{category}:{value}')}"
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now,
                    "modified": now,
                    "name": f"{category}: {value}",
                    "description": f"IOC extracted from {sample_name} by Arkana",
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _build_csv(iocs: Dict[str, List[str]]) -> str:
    """Build CSV string from IOCs."""
    # M-S2: Guard against CSV injection — prefix values starting with formula
    # trigger characters to prevent formula injection in spreadsheet apps.
    _DANGEROUS_CSV_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
    lines = ["type,value"]
    for category, values in iocs.items():
        for value in values:
            # Strip newlines to prevent CSV row boundary injection
            escaped = value.replace('\r', ' ').replace('\n', ' ')
            escaped = escaped.replace('"', '""')
            if escaped and escaped[0] in _DANGEROUS_CSV_PREFIXES:
                escaped = "'" + escaped
            lines.append(f'{category},"{escaped}"')
    return "\n".join(lines)


# ===================================================================
#  Internal IOC collection (callable from enrichment)
# ===================================================================

def _collect_iocs_internal(current_state) -> Dict[str, Any]:
    """Collect structured IOCs synchronously. No MCP overhead."""
    from arkana.state import set_current_state
    set_current_state(current_state)

    triage_iocs = _collect_iocs_from_triage()
    notes_iocs = _collect_iocs_from_notes()
    merged = _merge_iocs(triage_iocs, notes_iocs)
    total = sum(len(v) for v in merged.values())
    sample_name = os.path.basename(current_state.filepath) if current_state.filepath else "unknown"

    return {
        "format": "json",
        "total_iocs": total,
        "sample": sample_name,
        "iocs": merged,
        "categories": {k: len(v) for k, v in merged.items()},
    }


# ===================================================================
#  Tool: get_iocs_structured
# ===================================================================

@tool_decorator
async def get_iocs_structured(
    ctx: Context,
    format: str = "json",
    include_file_hashes: bool = True,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: utility] Aggregates IOCs from triage, string analysis, config extraction,
    and analysis notes into a structured export format.

    Sources: triage network_iocs, notes content, file hashes.

    When to use: When preparing a report or exporting IOCs for threat intelligence
    sharing. Deduplicates and categorizes all found indicators.

    Args:
        ctx: MCP Context.
        format: Output format: 'json' (default), 'csv', or 'stix' (STIX 2.1 bundle).
        include_file_hashes: Include sample file hashes as IOCs. Default True.
        output_path: (Optional[str]) Save IOC output to this path and register as artifact.
    """
    await ctx.info(f"Aggregating IOCs (format={format})")
    _check_pe_loaded("get_iocs_structured")

    # Return cached result if enrichment already collected IOCs (JSON only)
    # Skip cache when output_path is set — need to reach the write logic
    fmt = format.lower()
    if fmt == "json" and include_file_hashes and state._cached_iocs and not output_path:
        return state._cached_iocs

    fmt = format.lower()
    if fmt not in ("json", "csv", "stix"):
        return {"error": f"Unsupported format '{format}'. Use 'json', 'csv', or 'stix'."}

    triage_iocs, notes_iocs = await asyncio.to_thread(
        lambda: (_collect_iocs_from_triage(), _collect_iocs_from_notes())
    )

    if not include_file_hashes:
        triage_iocs.pop("file_hashes", None)

    merged = _merge_iocs(triage_iocs, notes_iocs)
    total = sum(len(v) for v in merged.values())
    sample_name = state.filepath.split("/")[-1] if state.filepath else "unknown"

    result: Dict[str, Any] = {
        "format": fmt,
        "total_iocs": total,
        "sample": sample_name,
    }

    if fmt == "json":
        result["iocs"] = merged
    elif fmt == "csv":
        result["csv"] = _build_csv(merged)
    elif fmt == "stix":
        result["stix_bundle"] = _build_stix_bundle(merged, sample_name)

    result["categories"] = {k: len(v) for k, v in merged.items()}

    if total == 0:
        result["hint"] = (
            "No IOCs found. Try running these tools first:\n"
            "  - get_triage_report() for network indicators\n"
            "  - extract_config_automated() for C2 config extraction\n"
            "  - search_floss_strings(query='http') for URL strings"
        )

    if output_path:
        if fmt == "json":
            text_bytes = json.dumps(merged, indent=2).encode("utf-8")
        elif fmt == "csv":
            text_bytes = result.get("csv", "").encode("utf-8")
        elif fmt == "stix":
            text_bytes = json.dumps(result.get("stix_bundle", {}), indent=2).encode("utf-8")
        else:
            text_bytes = b""
        if text_bytes:
            artifact_meta = await asyncio.to_thread(
                _write_output_and_register_artifact,
                output_path, text_bytes, "get_iocs_structured",
                f"IOCs ({fmt}, {total} indicators)",
            )
            result["artifact"] = artifact_meta

    return await _check_mcp_response_size(ctx, result, "get_iocs_structured")
