"""MCP tool for comprehensive automated binary triage."""
import asyncio
import mmap
import os
import re
import struct
import datetime

from typing import Dict, Any, Optional, List, Tuple

from arkana.config import (
    state, logger, Context, analysis_cache,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    STRINGSIFTER_AVAILABLE, YARA_AVAILABLE,
    PYELFTOOLS_AVAILABLE,
)
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._progress_bridge import ProgressBridge
from arkana.mcp._input_helpers import _paginate_field

if PYELFTOOLS_AVAILABLE:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection

if STRINGSIFTER_AVAILABLE:
    import stringsifter.lib.util as sifter_util
    import joblib


# ===================================================================
#  Workflow hints — included in triage output to guide note-taking
# ===================================================================

_TRIAGE_WORKFLOW_HINTS = [
    "Key triage findings have been auto-saved as notes — call get_analysis_digest() to review.",
    "After decompiling a function, call auto_note_function(address) to record what you learned.",
    "Use add_note(content, category='tool_result') to save important manual findings.",
    "Call get_analysis_digest() periodically to see accumulated findings without re-reading earlier outputs.",
]


# ===================================================================
#  Suspicious Import Database — derived from canonical source
# ===================================================================
from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB

# Extract risk-level-only mapping from the canonical (risk, category) DB.
SUSPICIOUS_IMPORTS_DB = {
    name: risk for name, (risk, _) in CATEGORIZED_IMPORTS_DB.items()
}

# Pre-sorted by severity so that CRITICAL matches are found first during
# iteration, and pre-compiled regex for fast O(1) substring matching.
_SUSPICIOUS_IMPORTS_BY_SEVERITY = sorted(
    SUSPICIOUS_IMPORTS_DB.items(),
    key=lambda kv: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(kv[1], 3),
)
_SUSPICIOUS_IMPORTS_PATTERN = re.compile(
    '|'.join(re.escape(name) for name, _ in _SUSPICIOUS_IMPORTS_BY_SEVERITY)
)


# ===================================================================
#  Private helper: collect all string values from analysis data
# ===================================================================

_MAX_TRIAGE_STRINGS = 100_000  # H8: Cap to prevent unbounded memory usage


def _collect_all_string_values() -> Tuple[set, bool]:
    """Gather all string values from floss analysis and basic ASCII strings.

    Returns ``(string_set, was_truncated)`` where *was_truncated* is ``True``
    when the ``_MAX_TRIAGE_STRINGS`` cap was reached.
    """
    all_string_values: set = set()

    # Snapshot pe_data references under lock to avoid reading partially-updated
    # FLOSS data from background threads.
    pe_data = state.pe_data
    if pe_data is None:
        return all_string_values, False
    # L1-v10: _pe_lock is always initialized — removed dead getattr fallback
    with state._pe_lock:
        floss_data = (pe_data.get('floss_analysis') or {}).get('strings', {})
        basic_strings = pe_data.get('basic_ascii_strings', [])

    if isinstance(floss_data, dict):
        for str_list in floss_data.values():
            if isinstance(str_list, list):
                for s in str_list:
                    if isinstance(s, dict):
                        val = s.get('string', '')
                    elif isinstance(s, str):
                        val = s
                    else:
                        continue
                    # Skip strings too short to be network IOCs
                    if len(val) < 8:
                        continue
                    all_string_values.add(val)
                    if len(all_string_values) >= _MAX_TRIAGE_STRINGS:
                        return all_string_values, True

    if isinstance(basic_strings, list):
        for s in basic_strings:
            if isinstance(s, dict):
                val = s.get('string', '')
            elif isinstance(s, str):
                val = s
            else:
                continue
            # Skip strings too short to be network IOCs
            if len(val) < 8:
                continue
            all_string_values.add(val)
            if len(all_string_values) >= _MAX_TRIAGE_STRINGS:
                return all_string_values, True

    return all_string_values, False


# ===================================================================
#  Section 0 — Basic file info
# ===================================================================

def _triage_file_info(indicator_limit: int) -> Dict[str, Any]:
    """Extract basic file information (no risk delta)."""
    file_hashes = state.pe_data.get('file_hashes', {})
    analysis_mode = state.pe_data.get('mode', 'pe')
    file_size = 0
    try:
        if state.filepath and os.path.isfile(state.filepath):
            file_size = os.path.getsize(state.filepath)
    except Exception:
        pass

    return {
        "filepath": state.filepath,
        "md5": file_hashes.get('md5'),
        "sha256": file_hashes.get('sha256'),
        "mode": analysis_mode,
        "file_size": file_size,
        "loaded_from_cache": state.loaded_from_cache,
    }


# ===================================================================
#  Section 0a — Timestamp Anomaly Detection (PE only)
# ===================================================================

def _triage_timestamp_analysis(analysis_mode: str, indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Detect compilation-timestamp anomalies."""
    risk_score = 0

    if analysis_mode == 'pe':
        ts_anomalies: List[str] = []
        nt_headers = state.pe_data.get('nt_headers', {})
        file_header = nt_headers.get('file_header', {})
        # Extract raw TimeDateStamp value (must be numeric)
        raw_ts = None
        for key in ('TimeDateStamp', 'timedatestamp'):
            candidate = file_header.get(key)
            if isinstance(candidate, dict):
                extracted = candidate.get('Value', candidate.get('value'))
                if isinstance(extracted, (int, float)):
                    raw_ts = extracted
            elif isinstance(candidate, (int, float)):
                raw_ts = candidate
            if raw_ts is not None:
                break

        ts_info: Dict[str, Any] = {"raw_timestamp": raw_ts}
        if raw_ts is not None:
            try:
                compile_dt = datetime.datetime.fromtimestamp(int(raw_ts), tz=datetime.timezone.utc)
                ts_info["compile_date"] = compile_dt.isoformat()
                now = datetime.datetime.now(datetime.timezone.utc)
                # Future timestamp
                if compile_dt > now:
                    ts_anomalies.append("Compilation timestamp is in the future")
                    risk_score += 2
                # Epoch zero (1970-01-01)
                if int(raw_ts) == 0:
                    ts_anomalies.append("Timestamp is epoch zero (zeroed/wiped)")
                    risk_score += 1
                # Very old (before Windows NT era, ~1993)
                elif compile_dt.year < 1993:
                    ts_anomalies.append(f"Timestamp predates Windows NT era ({compile_dt.year})")
                    risk_score += 1
                # Known fake timestamps used by Delphi
                elif int(raw_ts) == 0x2A425E19:
                    ts_anomalies.append("Delphi signature timestamp (0x2A425E19) — may be Delphi-compiled or spoofed")
                # Known Borland timestamp
                elif int(raw_ts) == 0x19610714:
                    ts_anomalies.append("Borland linker signature timestamp")
            except (OSError, ValueError, OverflowError):
                ts_anomalies.append("Timestamp value overflows or is unparseable")
                risk_score += 1

        # Check debug directory timestamps for mismatches
        debug_info = state.pe_data.get('debug_info', [])
        if isinstance(debug_info, list) and raw_ts is not None:
            for dbg_entry in debug_info:
                if isinstance(dbg_entry, dict):
                    dbg_ts = dbg_entry.get('TimeDateStamp', dbg_entry.get('timedatestamp'))
                    if isinstance(dbg_ts, dict):
                        dbg_ts = dbg_ts.get('Value', dbg_ts.get('value'))
                    if isinstance(dbg_ts, (int, float)) and dbg_ts != 0 and abs(int(dbg_ts) - int(raw_ts)) > 86400:
                        ts_anomalies.append("Debug directory timestamp differs from PE header by >24h (possible timestomping)")
                        risk_score += 2
                        break

        ts_info["anomalies"] = ts_anomalies
        return ts_info, risk_score
    else:
        return {"note": f"Not applicable for {analysis_mode} mode"}, 0


# ===================================================================
#  Section 1 — Packing Assessment
# ===================================================================

def _triage_packing_assessment(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Assess packing via entropy, PEiD, import count, and section names."""
    risk_score = 0
    sections_data = state.pe_data.get('sections', [])
    peid_data = state.pe_data.get('peid_matches', {})
    imports_data = state.pe_data.get('imports', [])

    max_entropy = 0.0
    high_entropy_sections: List[Dict[str, Any]] = []
    for sec in sections_data:
        if isinstance(sec, dict):
            ent = sec.get('entropy', 0.0)
            if isinstance(ent, (int, float)) and ent > max_entropy:
                max_entropy = ent
            name = sec.get('name', '')
            chars = sec.get('characteristics_str', sec.get('characteristics', ''))
            is_exec = 'EXECUTE' in str(chars).upper() or 'CODE' in str(chars).upper()
            if ent > 7.0 and is_exec:
                high_entropy_sections.append({"name": name, "entropy": round(ent, 3)})
                risk_score += 3
            elif ent > 7.0:
                high_entropy_sections.append({"name": name, "entropy": round(ent, 3)})
                risk_score += 1

    # Count total imported functions
    total_import_funcs = 0
    for dll_entry in imports_data:
        if isinstance(dll_entry, dict):
            total_import_funcs += len(dll_entry.get('symbols', []))

    # PEiD matches
    ep_matches = peid_data.get('ep_matches', [])
    heuristic_matches = peid_data.get('heuristic_matches', [])
    _to_name = lambda m: (m.get('name', m.get('match', 'unknown')) if isinstance(m, dict) else str(m))
    ep_names = [_to_name(m) for m in ep_matches if isinstance(m, (dict, str))]
    heuristic_names = [_to_name(m) for m in heuristic_matches if isinstance(m, (dict, str))]
    packer_names = ep_names + heuristic_names
    if packer_names:
        if peid_data.get("reflective_loader_detected"):
            risk_score += 1  # Reduced from 4 — likely false positive on reflective loader
        else:
            risk_score += 4

    # Known packer section names — strongest signal for packer identification
    PACKER_SECTION_NAMES = {'UPX0', 'UPX1', 'UPX2', '.aspack', '.adata', '.nsp0', '.nsp1',
                            '.perplex', '.themida', '.vmp0', '.vmp1', '.enigma1', '.petite'}
    # Map section names → packer family for ranking
    _SECTION_TO_PACKER = {
        'UPX0': 'UPX', 'UPX1': 'UPX', 'UPX2': 'UPX',
        '.aspack': 'ASPack', '.adata': 'ASPack',
        '.nsp0': 'NsPack', '.nsp1': 'NsPack',
        '.perplex': 'Perplex', '.themida': 'Themida',
        '.vmp0': 'VMProtect', '.vmp1': 'VMProtect',
        '.enigma1': 'Enigma', '.petite': 'Petite',
    }
    suspicious_section_names: List[str] = []
    section_packer_families: set = set()
    for sec in sections_data:
        if isinstance(sec, dict):
            name = sec.get('name', '').strip()
            if name in PACKER_SECTION_NAMES:
                suspicious_section_names.append(name)
                section_packer_families.add(_SECTION_TO_PACKER.get(name, name))
                risk_score += 3

    # Rank PEiD matches by confidence tier:
    #   1. Section-name-confirmed: EP/heuristic match aligns with section names
    #   2. EP match: signature matched at entry point (high confidence)
    #   3. Heuristic match: signature matched somewhere in code (lower confidence)
    # Well-known packer families for boosting EP match confidence
    _KNOWN_PACKER_KEYWORDS = {
        'upx', 'aspack', 'petite', 'fsg', 'mew', 'nspack', 'pecompact',
        'themida', 'vmprotect', 'enigma', 'mpress', 'kkrunchy',
    }
    ranked_matches: List[Dict[str, str]] = []
    seen: set = set()
    for name in ep_names:
        if name in seen:
            continue
        seen.add(name)
        name_lower = name.lower()
        if any(fam.lower() in name_lower for fam in section_packer_families):
            ranked_matches.append({"match": name, "confidence": "high", "source": "ep+sections"})
        elif any(kw in name_lower for kw in _KNOWN_PACKER_KEYWORDS):
            ranked_matches.append({"match": name, "confidence": "high", "source": "entry_point"})
        else:
            ranked_matches.append({"match": name, "confidence": "medium", "source": "entry_point"})
    for name in heuristic_names:
        if name in seen:
            continue
        seen.add(name)
        name_lower = name.lower()
        if any(fam.lower() in name_lower for fam in section_packer_families):
            ranked_matches.append({"match": name, "confidence": "medium", "source": "heuristic+sections"})
        elif any(kw in name_lower for kw in _KNOWN_PACKER_KEYWORDS):
            ranked_matches.append({"match": name, "confidence": "medium", "source": "heuristic"})
        else:
            ranked_matches.append({"match": name, "confidence": "low", "source": "heuristic"})

    # Sort: high > medium > low
    _CONF_ORDER = {"high": 0, "medium": 1, "low": 2}
    ranked_matches.sort(key=lambda m: _CONF_ORDER.get(m["confidence"], 3))

    is_likely_packed = (
        bool(packer_names)
        or len(high_entropy_sections) > 0
        or total_import_funcs < 10
        or bool(suspicious_section_names)
    )

    result: Dict[str, Any] = {
        "likely_packed": is_likely_packed,
        "max_section_entropy": round(max_entropy, 3),
        "high_entropy_executable_sections": high_entropy_sections,
        "peid_matches": [m["match"] for m in ranked_matches],
        "peid_ranked": ranked_matches,
        "total_import_functions": total_import_funcs,
        "minimal_imports": total_import_funcs < 10,
        "packer_section_names": suspicious_section_names,
    }
    # Flag when section names contradict the top PEiD match (e.g., UPX sections
    # but top match says "Armadillo")
    if section_packer_families and ranked_matches:
        top = ranked_matches[0]["match"].lower()
        if not any(fam.lower() in top for fam in section_packer_families):
            result["peid_conflict"] = (
                f"Section names suggest {', '.join(sorted(section_packer_families))} "
                f"but top PEiD match is '{ranked_matches[0]['match']}'. "
                f"Section names are generally more reliable."
            )

    # Propagate reflective loader warning from PEiD scan
    if peid_data.get("reflective_loader_detected"):
        result["reflective_loader_detected"] = True
        result["reflective_loader_indicators"] = peid_data.get("reflective_loader_indicators", [])
        result["reflective_loader_warning"] = peid_data.get("reflective_loader_warning", "")

    return result, risk_score


# ===================================================================
#  Section 2 — Digital Signature Assessment
# ===================================================================

def _triage_digital_signature(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Check digital signature presence and extract signer info."""
    risk_score = 0
    sig_data = state.pe_data.get('digital_signature', {})
    sig_present = sig_data.get('embedded_signature_present', False) if isinstance(sig_data, dict) else False
    sig_valid = None
    sig_signer = None
    if isinstance(sig_data, dict):
        sig_valid = sig_data.get('validation_result')
        # Try to extract signer from various possible locations
        certs = sig_data.get('certificates', sig_data.get('signer_info', []))
        if isinstance(certs, list) and certs:
            first_cert = certs[0] if isinstance(certs[0], dict) else {}
            sig_signer = first_cert.get('subject', first_cert.get('signer'))

    if not sig_present:
        risk_score += 1  # Unsigned binaries are slightly more suspicious

    return {
        "present": sig_present,
        "valid": sig_valid,
        "signer": sig_signer,
    }, risk_score


# ===================================================================
#  Section 2a — Rich Header Summary (PE only)
# ===================================================================

def _triage_rich_header(analysis_mode: str, indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Summarise Rich header build-environment fingerprint (PE only)."""
    risk_score = 0

    if analysis_mode == 'pe':
        rich_data = state.pe_data.get('rich_header')
        if rich_data and isinstance(rich_data, dict):
            entries = rich_data.get('decoded_values', rich_data.get('decoded_entries', []))
            compiler_ids: set = set()
            product_ids: set = set()
            for entry in (entries if isinstance(entries, list) else []):
                if isinstance(entry, dict):
                    comp_id = entry.get('raw_comp_id', entry.get('comp_id'))
                    prod_id = entry.get('product_id_dec', entry.get('product_id_hex'))
                    if comp_id is not None:
                        compiler_ids.add(comp_id)
                    if prod_id is not None:
                        product_ids.add(str(prod_id))
            result: Dict[str, Any] = {
                "present": True,
                "entry_count": len(entries) if isinstance(entries, list) else 0,
                "unique_compiler_ids": len(compiler_ids),
                "unique_product_ids": sorted(product_ids)[:10],
                "checksum_valid": rich_data.get('checksum_valid', rich_data.get('valid')),
                "raw_hash": rich_data.get('hash', rich_data.get('checksum')),
            }
            # Rich header checksum mismatch can indicate tampering
            if rich_data.get('checksum_valid') is False:
                risk_score += 1
                result["anomaly"] = "Rich header checksum mismatch — possible tampering"
            return result, risk_score
        else:
            return {"present": False, "note": "No Rich header (MinGW, Go, Rust, or stripped)"}, 0
    else:
        return {"note": f"Not applicable for {analysis_mode} mode"}, 0


# ===================================================================
#  Section 3 — Suspicious Imports (risk-categorized)
# ===================================================================

def _triage_suspicious_imports(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Identify risk-categorized suspicious API imports."""
    risk_score = 0
    imports_data = state.pe_data.get('imports', [])
    found_imports: List[Dict[str, str]] = []

    if isinstance(imports_data, list):
        for dll_entry in imports_data:
            if not isinstance(dll_entry, dict):
                continue
            dll_name = dll_entry.get('dll_name', 'Unknown')
            for sym in dll_entry.get('symbols', []):
                func_name = sym.get('name', '')
                if not func_name:
                    continue
                # Use precompiled regex for O(1) substring matching against all
                # suspicious names, instead of iterating the full DB per import.
                m = _SUSPICIOUS_IMPORTS_PATTERN.search(func_name)
                if m:
                    matched_name = m.group()
                    severity = SUSPICIOUS_IMPORTS_DB[matched_name]
                    found_imports.append({
                        "function": func_name,
                        "dll": dll_name,
                        "risk": severity,
                    })
                    if severity == "CRITICAL":
                        risk_score += 3
                    elif severity == "HIGH":
                        risk_score += 2
                    elif severity == "MEDIUM":
                        risk_score += 1

    # Sort by severity, then by function name for deterministic output
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    found_imports.sort(key=lambda x: (severity_order.get(x['risk'], 3), x.get('dll', ''), x.get('function', '')))

    return {
        "suspicious_imports": found_imports,
        "suspicious_import_summary": {
            "critical": sum(1 for i in found_imports if i['risk'] == 'CRITICAL'),
            "high": sum(1 for i in found_imports if i['risk'] == 'HIGH'),
            "medium": sum(1 for i in found_imports if i['risk'] == 'MEDIUM'),
        },
    }, risk_score


# ===================================================================
#  Section 4 — Capa Capabilities (severity-mapped)
# ===================================================================

def _triage_capa_capabilities(indicator_limit: int) -> Tuple[List[Dict[str, Any]], int, Optional[Dict[str, str]]]:
    """Extract capa MITRE ATT&CK capability matches.

    Returns:
        (capabilities, risk_score, capa_status_info)
        capa_status_info is None when capa succeeded, or a dict with
        'status'/'error'/'hint' keys when capa failed or was unavailable.
    """
    risk_score = 0
    capabilities: List[Dict[str, Any]] = []
    capa_status_info: Optional[Dict[str, str]] = None

    CAPA_SEVERITY_MAP = {
        "anti-analysis": "High", "collection": "High",
        "credential-access": "High", "defense-evasion": "High",
        "execution": "High", "impact": "High",
        "persistence": "High", "privilege-escalation": "High",
        "lateral-movement": "High",
        "communication": "Medium", "data-manipulation": "Medium",
        "discovery": "Medium", "c2": "High",
    }

    if 'capa_analysis' in state.pe_data:
        capa_analysis = state.pe_data['capa_analysis']
        if isinstance(capa_analysis.get('results'), dict):
            capa_rules = capa_analysis['results'].get('rules', {})
            for rule_name, rule_details in capa_rules.items():
                meta = rule_details.get('meta', {})
                namespace = meta.get('namespace', '').split('/')[0]
                severity = CAPA_SEVERITY_MAP.get(namespace, "Low")
                if severity in ["High", "Medium"]:
                    capabilities.append({
                        "capability": meta.get('name', rule_name),
                        "namespace": meta.get('namespace'),
                        "severity": severity,
                    })
                    if severity == "High":
                        risk_score += 2
                    else:
                        risk_score += 1

            capabilities.sort(key=lambda x: (x['severity'], x.get('capability', '')))
        else:
            # capa ran but failed — surface diagnostics
            capa_status_info = {
                "status": str(capa_analysis.get("status", "failed")),
            }
            if capa_analysis.get("error"):
                capa_status_info["error"] = str(capa_analysis["error"])
            if capa_analysis.get("hint"):
                capa_status_info["hint"] = str(capa_analysis["hint"])
    else:
        capa_status_info = {"status": "not_available"}

    return capabilities, risk_score, capa_status_info


# ===================================================================
#  Section 5 — Network IOC Extraction
# ===================================================================

_TRIAGE_IP_RE = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)")
_TRIAGE_URL_RE = re.compile(r'(?:https?|ftp)://[^\s\'"<>]{1,2000}', re.IGNORECASE)
_TRIAGE_DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]{1,63}\.){1,20}(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|su|onion|de|uk|fr|jp|br|au|ca|nl|kr|us|gov|edu|mil|co|me|in|es|it|pl|se|no|fi|cz|ch|at|be|pt|mx|ar|cl|za|tw|hk|sg|my|th|ph|vn|id|ke|ng|ly|gg|ir|kp|to|ws|nu|st|ac|cx)\b', re.IGNORECASE)
_TRIAGE_REGISTRY_RE = re.compile(r'(?:HKLM|HKCU|HKCR|HKU|HKCC|Software)\\[^\s\'"]+', re.IGNORECASE)


def _triage_network_iocs(indicator_limit: int, all_string_values: set) -> Tuple[Dict[str, Any], int]:
    """Extract IPs, URLs, domains, and registry paths from strings."""
    risk_score = 0

    # Iterate over strings individually instead of joining into one large blob.
    # This avoids a memory spike from the concatenated text and improves cache
    # locality since each string is small.
    found_ips: set = set()
    found_urls: set = set()
    found_domains: set = set()
    found_registry: set = set()

    from arkana.mcp._category_maps import is_benign_ip

    for s in all_string_values:
        for m in _TRIAGE_IP_RE.finditer(s):
            ip = m.group()
            if not is_benign_ip(ip):
                found_ips.add(ip)
        for m in _TRIAGE_URL_RE.finditer(s):
            found_urls.add(m.group())
        for m in _TRIAGE_DOMAIN_RE.finditer(s):
            found_domains.add(m.group().lower())
        for m in _TRIAGE_REGISTRY_RE.finditer(s):
            found_registry.add(m.group())

    if found_ips or found_urls or found_domains:
        risk_score += 3

    return {
        "ip_addresses": sorted(found_ips),
        "urls": sorted(found_urls),
        "domains": sorted(found_domains),
        "registry_paths": sorted(found_registry),
    }, risk_score


# ===================================================================
#  Section 6 — Section Anomalies
# ===================================================================

def _triage_section_anomalies(indicator_limit: int) -> Tuple[List[Dict[str, Any]], int]:
    """Detect W+X sections, size mismatches, and other anomalies."""
    risk_score = 0
    sections_data = state.pe_data.get('sections', [])
    anomalies: List[Dict[str, Any]] = []

    for sec in sections_data:
        if not isinstance(sec, dict):
            continue
        name = sec.get('name', '').strip()
        chars = str(sec.get('characteristics_str', sec.get('characteristics', '')))
        vsize = sec.get('virtual_size', sec.get('Misc_VirtualSize', 0))
        rsize = sec.get('raw_size', sec.get('SizeOfRawData', 0))

        if 'WRITE' in chars.upper() and 'EXECUTE' in chars.upper():
            anomalies.append({"section": name, "issue": "Write+Execute (W+X)", "severity": "HIGH"})
            risk_score += 2
        if isinstance(vsize, int) and isinstance(rsize, int) and vsize > 0 and rsize == 0:
            anomalies.append({"section": name, "issue": "Virtual size > 0 but raw size = 0 (runtime unpacking)", "severity": "MEDIUM"})
            risk_score += 1
        if isinstance(vsize, int) and isinstance(rsize, int) and rsize > 0 and vsize > rsize * 10:
            anomalies.append({"section": name, "issue": f"Virtual size ({vsize}) >> raw size ({rsize})", "severity": "MEDIUM"})
            risk_score += 1

    return anomalies, risk_score


# ===================================================================
#  Section 6a — Overlay / Appended Data Analysis (PE only)
# ===================================================================

def _triage_overlay_analysis(indicator_limit: int, file_size: int = 0) -> Tuple[Dict[str, Any], int]:
    """Analyse overlay / appended data and detect embedded signatures."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'pe':
        overlay_data = state.pe_data.get('overlay_data')
        if overlay_data and isinstance(overlay_data, dict):
            overlay_size = overlay_data.get('size', 0)
            overlay_offset = overlay_data.get('offset')
            overlay_info: Dict[str, Any] = {
                "present": True,
                "offset": overlay_offset,
                "size": overlay_size,
                "md5": overlay_data.get('md5'),
                "sha256": overlay_data.get('sha256'),
            }
            # Check if overlay is a large proportion of the file
            if file_size > 0 and overlay_size > 0:
                overlay_pct = round((overlay_size / file_size) * 100, 1)
                overlay_info["percent_of_file"] = overlay_pct
                if overlay_pct > 50:
                    overlay_info["note"] = "Overlay is >50% of file — likely contains appended data, resources, or embedded payload"
                    risk_score += 2

            # Check for embedded file signatures in the first 20 bytes (40 hex
            # chars) of the overlay.  This covers all common file magic sequences
            # while tolerating small preambles before the embedded file header.
            sample_hex = overlay_data.get('sample_hex', '')
            embedded_sigs: List[str] = []
            if sample_hex:
                overlay_prefix = sample_hex.lower()[:40]
                # MZ header
                if '4d5a' in overlay_prefix:
                    embedded_sigs.append("PE/MZ header detected at overlay start")
                    risk_score += 3
                # PK (ZIP) header
                if '504b0304' in overlay_prefix:
                    embedded_sigs.append("ZIP/PK archive detected at overlay start")
                # 7z header
                if '377abcaf271c' in overlay_prefix:
                    embedded_sigs.append("7-Zip archive detected at overlay start")
                # RAR header
                if '526172211a07' in overlay_prefix:
                    embedded_sigs.append("RAR archive detected at overlay start")
                # PDF header
                if '25504446' in overlay_prefix:
                    embedded_sigs.append("PDF document detected at overlay start")
            overlay_info["embedded_signatures"] = embedded_sigs
            return overlay_info, risk_score
        else:
            return {"present": False}, 0
    else:
        return {"note": f"Not applicable for {analysis_mode} mode"}, 0


# ===================================================================
#  Section 6b — Import Anomalies (ordinal-only imports, unusual DLLs)
# ===================================================================

def _triage_import_anomalies(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Detect ordinal-only imports and non-standard DLLs."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')
    imports_data = state.pe_data.get('imports', [])

    if analysis_mode == 'pe' and isinstance(imports_data, list):
        ordinal_only_imports: List[Dict[str, Any]] = []
        unusual_dll_imports: List[str] = []
        COMMON_DLLS = {
            'kernel32.dll', 'ntdll.dll', 'user32.dll', 'advapi32.dll', 'gdi32.dll',
            'ole32.dll', 'oleaut32.dll', 'shell32.dll', 'shlwapi.dll', 'msvcrt.dll',
            'ws2_32.dll', 'wininet.dll', 'crypt32.dll', 'comctl32.dll', 'comdlg32.dll',
            'rpcrt4.dll', 'secur32.dll', 'winhttp.dll', 'urlmon.dll', 'version.dll',
            'imagehlp.dll', 'psapi.dll', 'iphlpapi.dll', 'setupapi.dll', 'winspool.drv',
            'mscoree.dll', 'msvcp140.dll', 'vcruntime140.dll', 'ucrtbase.dll',
            'api-ms-win-crt-runtime-l1-1-0.dll', 'api-ms-win-crt-heap-l1-1-0.dll',
            'api-ms-win-crt-stdio-l1-1-0.dll', 'api-ms-win-crt-string-l1-1-0.dll',
            'api-ms-win-crt-math-l1-1-0.dll', 'api-ms-win-crt-locale-l1-1-0.dll',
        }

        for dll_entry in imports_data:
            if not isinstance(dll_entry, dict):
                continue
            dll_name = dll_entry.get('dll_name', '')
            dll_lower = dll_name.lower()
            # Check for unusual DLLs (not in the common set and not api-ms-win-*)
            if dll_lower and dll_lower not in COMMON_DLLS and not dll_lower.startswith('api-ms-win-'):
                unusual_dll_imports.append(dll_name)
            for sym in dll_entry.get('symbols', []):
                if isinstance(sym, dict):
                    name = sym.get('name', '')
                    ordinal = sym.get('ordinal')
                    if (not name or name.startswith('ord(')) and ordinal is not None:
                        ordinal_only_imports.append({"dll": dll_name, "ordinal": ordinal})

        import_anom: Dict[str, Any] = {}
        if ordinal_only_imports:
            import_anom["ordinal_only_imports"] = ordinal_only_imports
            import_anom["ordinal_only_count"] = len(ordinal_only_imports)
            if len(ordinal_only_imports) > 5:
                risk_score += 1  # Many ordinal-only imports can indicate evasion
        if unusual_dll_imports:
            import_anom["non_standard_dlls"] = sorted(set(unusual_dll_imports))
        return import_anom, risk_score
    else:
        note = f"Not applicable for {analysis_mode} mode" if analysis_mode != 'pe' else "No imports data"
        return {"note": note}, 0


# ===================================================================
#  Section 6c — Resource Anomalies (PE only)
# ===================================================================

def _triage_resource_anomalies(indicator_limit: int) -> Tuple[List[Dict[str, Any]], int]:
    """Detect nested PEs, large RCDATA payloads, and high-entropy resources."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'pe':
        res_anomalies: List[Dict[str, Any]] = []
        resources = state.pe_data.get('resources_summary', [])
        if isinstance(resources, list):
            for res in resources:
                if not isinstance(res, dict):
                    continue
                res_size = res.get('size', 0)
                res_type = res.get('type', '')
                # Suspiciously large resources
                if isinstance(res_size, int) and res_size > 500000:
                    res_anomalies.append({
                        "type": res_type,
                        "size": res_size,
                        "issue": f"Large resource ({res_size} bytes) — may contain embedded payload",
                        "severity": "MEDIUM",
                    })
                # RCDATA or custom type with large sizes are suspicious
                if res_type in ('RT_RCDATA', 'RCDATA', '10') and isinstance(res_size, int) and res_size > 50000:
                    res_anomalies.append({
                        "type": res_type,
                        "size": res_size,
                        "issue": "Large RCDATA resource — common vector for embedded payloads",
                        "severity": "HIGH",
                    })
                    risk_score += 1

        # Check if PE object has resource data we can scan for embedded PEs
        if state.pe_object and hasattr(state.pe_object, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for res_type_entry in state.pe_object.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(res_type_entry, 'directory') and res_type_entry.directory:
                        for res_id_entry in res_type_entry.directory.entries:
                            if hasattr(res_id_entry, 'directory') and res_id_entry.directory:
                                for res_lang_entry in res_id_entry.directory.entries:
                                    if hasattr(res_lang_entry, 'data') and hasattr(res_lang_entry.data, 'struct'):
                                        try:
                                            data_rva = res_lang_entry.data.struct.OffsetToData
                                            data_size = res_lang_entry.data.struct.Size
                                            res_bytes = state.pe_object.get_data(data_rva, min(data_size, 4))
                                            if len(res_bytes) >= 2 and res_bytes[:2] == b'MZ':
                                                type_id = getattr(res_type_entry, 'id', None)
                                                type_str = str(type_id) if type_id else 'unknown'
                                                res_anomalies.append({
                                                    "type": type_str,
                                                    "size": data_size,
                                                    "issue": "Embedded PE (MZ header) found inside resource",
                                                    "severity": "CRITICAL",
                                                })
                                                risk_score += 4
                                        except Exception:
                                            pass
            except Exception:
                pass

        return res_anomalies, risk_score
    else:
        return [], 0


# ===================================================================
#  Section 6d — YARA Match Integration
# ===================================================================

def _triage_yara_matches(indicator_limit: int) -> Tuple[List[Dict[str, Any]], int]:
    """Summarise YARA rule matches."""
    risk_score = 0
    yara_data = state.pe_data.get('yara_matches', [])

    if isinstance(yara_data, list) and yara_data:
        yara_summary: List[Dict[str, Any]] = []
        for match in yara_data:
            if isinstance(match, dict):
                yara_summary.append({
                    "rule": match.get('rule', match.get('name', 'unknown')),
                    "tags": match.get('tags', []),
                    "meta": match.get('meta', {}),
                })
                risk_score += 2  # Each YARA rule match adds risk
            elif isinstance(match, str):
                yara_summary.append({"rule": match})
                risk_score += 2
        return yara_summary, risk_score
    else:
        return [], 0


# ===================================================================
#  Section 6e — Header Anomalies & Corruption Detection
# ===================================================================

def _triage_header_anomalies(indicator_limit: int) -> Tuple[List[Dict[str, Any]], int]:
    """Detect header anomalies: pefile warnings, checksum, entry point issues."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')
    header_anomalies: List[Dict[str, Any]] = []

    if analysis_mode == 'pe':
        sections_data = state.pe_data.get('sections', [])

        # Check pefile warnings for corruption indicators
        pefile_warnings = state.pe_data.get('pefile_warnings', [])
        if isinstance(pefile_warnings, list) and pefile_warnings:
            for warn in pefile_warnings:
                header_anomalies.append({
                    "issue": str(warn),
                    "severity": "MEDIUM",
                    "source": "pefile_parser",
                })
            if len(pefile_warnings) > 3:
                risk_score += 1  # Many warnings indicate a malformed binary

        # Checksum verification
        checksum_info = state.pe_data.get('checksum_verification', {})
        if isinstance(checksum_info, dict):
            if checksum_info.get('valid') is False:
                header_anomalies.append({
                    "issue": f"PE checksum mismatch: header={checksum_info.get('header_checksum')}, computed={checksum_info.get('computed_checksum')}",
                    "severity": "LOW",
                    "source": "checksum",
                })
                # Mismatched checksums are common for unsigned binaries, low risk

        # Check for suspicious entry point
        nt_headers = state.pe_data.get('nt_headers', {})
        opt_header = nt_headers.get('optional_header', {})
        ep_rva = opt_header.get('AddressOfEntryPoint', opt_header.get('addressofentrypoint'))
        if isinstance(ep_rva, dict):
            ep_rva = ep_rva.get('Value', ep_rva.get('value'))
        if isinstance(ep_rva, int):
            # EP outside any section
            ep_in_section = False
            for sec in sections_data:
                if isinstance(sec, dict):
                    sec_va = sec.get('virtual_address', sec.get('VirtualAddress', 0))
                    sec_vs = sec.get('virtual_size', sec.get('Misc_VirtualSize', 0))
                    if isinstance(sec_va, int) and isinstance(sec_vs, int):
                        if sec_va <= ep_rva < sec_va + sec_vs:
                            ep_in_section = True
                            sec_name = sec.get('name', '').strip()
                            # EP not in .text or CODE section is unusual
                            if sec_name.lower() not in ('.text', 'code', '.code', ''):
                                header_anomalies.append({
                                    "issue": f"Entry point is in '{sec_name}' section (not .text/CODE)",
                                    "severity": "MEDIUM",
                                    "source": "entry_point",
                                })
                                risk_score += 1
                            break
            if not ep_in_section and ep_rva != 0:
                header_anomalies.append({
                    "issue": "Entry point address does not fall within any section",
                    "severity": "HIGH",
                    "source": "entry_point",
                })
                risk_score += 3

        # Section name anomalies (non-printable characters)
        for sec in sections_data:
            if isinstance(sec, dict):
                name = sec.get('name', '')
                if name and any(ord(c) < 32 or ord(c) > 126 for c in name.replace('\x00', '')):
                    header_anomalies.append({
                        "issue": f"Section '{name!r}' contains non-printable characters",
                        "severity": "MEDIUM",
                        "source": "section_names",
                    })
                    risk_score += 1
                    break  # Only report once

    return header_anomalies, risk_score


# ===================================================================
#  Section 6f — TLS Callback Detection (PE only)
# ===================================================================

def _triage_tls_callbacks(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Detect TLS callbacks (classic anti-analysis / unpacking technique)."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'pe':
        tls_data = state.pe_data.get('tls_info')
        if tls_data and isinstance(tls_data, dict):
            callbacks = tls_data.get('callbacks', [])
            if isinstance(callbacks, list) and len(callbacks) > 0:
                result = {
                    "present": True,
                    "callback_count": len(callbacks),
                    "callback_addresses": [cb.get('va', cb.get('rva', '?')) for cb in callbacks],
                    "warning": "TLS callbacks execute BEFORE the entry point — classic anti-debugging / unpacking technique",
                }
                risk_score += 5  # TLS callbacks are a strong malware/packer indicator
                return result, risk_score
            else:
                return {"present": True, "callback_count": 0, "note": "TLS directory present but no callbacks"}, 0
        else:
            return {"present": False}, 0
    else:
        return {}, 0


# ===================================================================
#  Section 6g — Security Mitigations (PE only — CFG/CET/XFG/DEP/ASLR)
# ===================================================================

def _triage_security_mitigations(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Check ASLR, DEP, CFG, CET, XFG, and other PE security flags."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'pe':
        mitigations: Dict[str, Any] = {}
        # DLL characteristics flags (ASLR, DEP, SEH, etc.)
        nt_hdr = state.pe_data.get('nt_headers', {})
        opt_hdr = nt_hdr.get('optional_header', {})
        dll_chars = opt_hdr.get('DllCharacteristics', opt_hdr.get('dll_characteristics'))
        if isinstance(dll_chars, dict):
            dll_chars = dll_chars.get('Value', dll_chars.get('value', 0))
        if isinstance(dll_chars, int):
            mitigations["aslr"] = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            mitigations["dep_nx"] = bool(dll_chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            mitigations["no_seh"] = bool(dll_chars & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH
            mitigations["high_entropy_aslr"] = bool(dll_chars & 0x0020)  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
            mitigations["force_integrity"] = bool(dll_chars & 0x0080)  # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
            mitigations["guard_cf"] = bool(dll_chars & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
            # No ASLR or DEP is suspicious for modern binaries
            if not mitigations["aslr"]:
                risk_score += 1
            if not mitigations["dep_nx"]:
                risk_score += 1

        # Load config guard flags (CFG/CET/XFG details)
        load_config = state.pe_data.get('load_config')
        if load_config and isinstance(load_config, dict):
            guard_flags = load_config.get('guard_flags_list', [])
            if isinstance(guard_flags, list):
                mitigations["cfg_instrumented"] = any('CF_INSTRUMENTED' in f for f in guard_flags)
                mitigations["xfg_enabled"] = any('XFG_ENABLED' in f for f in guard_flags)
                mitigations["cet_shadow_stack"] = any('CET_SHADOW_STACK' in f for f in guard_flags)
                mitigations["retpoline"] = any('RETPOLINE' in f for f in guard_flags)
                mitigations["security_cookie_unused"] = any('SECURITY_COOKIE_UNUSED' in f for f in guard_flags)
                if mitigations.get("security_cookie_unused"):
                    risk_score += 1  # Disabled stack cookie

        return mitigations, risk_score
    else:
        return {}, 0


# ===================================================================
#  Section 6h — Delay-Load Suspicious API Detection (PE only)
# ===================================================================

def _triage_delay_load_evasion(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Detect suspicious APIs hidden in delay-load imports."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'pe':
        delay_imports = state.pe_data.get('delay_load_imports', [])
        if isinstance(delay_imports, list) and delay_imports:
            delay_suspicious: List[Dict[str, str]] = []
            delay_total_funcs = 0
            for dll_entry in delay_imports:
                if not isinstance(dll_entry, dict):
                    continue
                dll_name = dll_entry.get('dll_name', dll_entry.get('name', 'Unknown'))
                for sym in dll_entry.get('symbols', []):
                    if isinstance(sym, dict):
                        delay_total_funcs += 1
                        func_name = sym.get('name', '')
                        if not func_name:
                            continue
                        for susp_name, severity in SUSPICIOUS_IMPORTS_DB.items():
                            if susp_name in func_name:
                                delay_suspicious.append({
                                    "function": func_name,
                                    "dll": dll_name,
                                    "risk": severity,
                                    "note": "Delay-loaded — only resolved at runtime, harder to detect statically",
                                })
                                if severity == "CRITICAL":
                                    risk_score += 3
                                elif severity == "HIGH":
                                    risk_score += 2
                                break
            return {
                "delay_load_dll_count": len(delay_imports),
                "delay_load_function_count": delay_total_funcs,
                "suspicious_delay_loaded_apis": delay_suspicious,
            }, risk_score
        else:
            return {"delay_load_dll_count": 0}, 0
    else:
        return {}, 0


# ===================================================================
#  Section 6i — Version Info Anomaly Detection (PE only)
# ===================================================================

def _triage_version_info(indicator_limit: int, sig_present: bool = False, sig_signer: Optional[str] = None) -> Tuple[Dict[str, Any], int]:
    """Detect filename mismatches and company name spoofing in version info."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'pe':
        ver_anomalies: List[Dict[str, str]] = []
        ver_data = state.pe_data.get('version_info', {})
        if isinstance(ver_data, dict):
            # Extract string table entries
            string_entries: Dict[str, str] = {}
            fi_blocks = ver_data.get('file_info_blocks', [])
            if isinstance(fi_blocks, list):
                for block in fi_blocks:
                    if isinstance(block, dict) and block.get('type') == 'StringFileInfo':
                        for st in block.get('string_tables', []):
                            if isinstance(st, dict):
                                string_entries.update(st.get('entries', {}))

            if string_entries:
                original_filename = string_entries.get('OriginalFilename', '')
                internal_name = string_entries.get('InternalName', '')
                company_name = string_entries.get('CompanyName', '')
                file_description = string_entries.get('FileDescription', '')

                # Check if original filename matches actual filename
                if original_filename and state.filepath:
                    actual_name = os.path.basename(state.filepath)
                    # Strip extension for comparison
                    orig_base = os.path.splitext(original_filename)[0].lower()
                    actual_base = os.path.splitext(actual_name)[0].lower()
                    if orig_base and actual_base and orig_base != actual_base:
                        ver_anomalies.append({
                            "issue": f"OriginalFilename '{original_filename}' does not match actual filename '{actual_name}'",
                            "severity": "MEDIUM",
                        })
                        risk_score += 1

                # Check for known spoofed company names in non-Microsoft binaries
                SPOOFED_COMPANIES = {'microsoft corporation', 'google llc', 'google inc',
                                     'apple inc', 'mozilla corporation', 'adobe systems'}
                if company_name and company_name.lower().strip() in SPOOFED_COMPANIES:
                    # Only flag if not signed by that company
                    if not sig_present or (sig_signer and company_name.lower() not in str(sig_signer).lower()):
                        ver_anomalies.append({
                            "issue": f"Claims company '{company_name}' but binary is not signed by them",
                            "severity": "HIGH",
                        })
                        risk_score += 3

                return {
                    "original_filename": original_filename or None,
                    "internal_name": internal_name or None,
                    "company_name": company_name or None,
                    "file_description": file_description or None,
                    "anomalies": ver_anomalies,
                }, risk_score
            else:
                return {"note": "No version string table present"}, 0
        else:
            return {"note": "No version info"}, 0
    else:
        return {}, 0


# ===================================================================
#  Section 6j — .NET Assembly Detection (PE only)
# ===================================================================

def _triage_dotnet_indicators(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Detect .NET assembly presence and extract flags."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'pe':
        com_desc = state.pe_data.get('com_descriptor')
        if com_desc and isinstance(com_desc, dict):
            flags_list = com_desc.get('flags_list', [])
            return {
                "is_dotnet": True,
                "flags": flags_list if isinstance(flags_list, list) else [],
                "il_only": any('ILONLY' in str(f) for f in flags_list) if isinstance(flags_list, list) else False,
                "mixed_mode": not any('ILONLY' in str(f) for f in flags_list) if isinstance(flags_list, list) else False,
                "note": "Use dotnet_analyze for full .NET metadata, types, methods, and user strings",
            }, risk_score
        else:
            return {"is_dotnet": False}, 0
    else:
        return {}, 0


# ===================================================================
#  Section 6k — Export Anomalies (PE only)
# ===================================================================

def _triage_export_anomalies(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Detect ordinal-only and forwarded exports."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'pe':
        exports_data = state.pe_data.get('exports', {})
        if isinstance(exports_data, dict) and exports_data.get('symbols'):
            export_syms = exports_data['symbols']
            ordinal_only_exports: List[Any] = []
            forwarded_exports: List[Dict[str, Any]] = []
            total_exports = len(export_syms)
            for exp in export_syms:
                if isinstance(exp, dict):
                    if not exp.get('name') and exp.get('ordinal') is not None:
                        ordinal_only_exports.append(exp.get('ordinal'))
                    if exp.get('forwarder'):
                        forwarded_exports.append({
                            "name": exp.get('name') or f"ord({exp.get('ordinal')})",
                            "forwards_to": exp.get('forwarder'),
                        })
            export_anom: Dict[str, Any] = {
                "total_exports": total_exports,
                "dll_name": exports_data.get('name'),
            }
            if ordinal_only_exports:
                export_anom["ordinal_only_count"] = len(ordinal_only_exports)
                export_anom["ordinal_only_values"] = ordinal_only_exports
                if len(ordinal_only_exports) > total_exports * 0.5 and total_exports > 5:
                    risk_score += 1  # Majority ordinal-only exports suggest intentional obfuscation
            if forwarded_exports:
                export_anom["forwarded_count"] = len(forwarded_exports)
                export_anom["forwarded_exports"] = forwarded_exports
            return export_anom, risk_score
        else:
            return {"total_exports": 0}, 0
    else:
        return {}, 0


# ===================================================================
#  Section 6l — ELF Security Features (ELF only)
# ===================================================================

def _triage_elf_security(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Check PIE, NX, RELRO, stack canaries, and stripped status (ELF only)."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'elf':
        elf_sec: Dict[str, Any] = {}
        try:
            if not (state.filepath and os.path.isfile(state.filepath)):
                return {"error": "No file available for ELF security check."}, 0

            if PYELFTOOLS_AVAILABLE:
                # Use pyelftools for accurate segment/section parsing
                with open(state.filepath, 'rb') as f:
                    elffile = ELFFile(f)
                    elf_sec["class"] = "64-bit" if elffile.elfclass == 64 else "32-bit"
                    elf_sec["endianness"] = "little-endian" if elffile.little_endian else "big-endian"

                    TYPE_MAP = {'ET_NONE': 'ET_NONE', 'ET_REL': 'ET_REL',
                                'ET_EXEC': 'ET_EXEC', 'ET_DYN': 'ET_DYN', 'ET_CORE': 'ET_CORE'}
                    e_type = elffile.header.e_type
                    elf_sec["type"] = TYPE_MAP.get(e_type, e_type)
                    elf_sec["is_pie"] = (e_type == 'ET_DYN')
                    if not elf_sec["is_pie"]:
                        risk_score += 1

                    # Check segments for RELRO, NX (stack executability)
                    has_gnu_relro = False
                    has_nx = False
                    for segment in elffile.iter_segments():
                        seg_type = segment.header.p_type
                        if seg_type == 'PT_GNU_RELRO':
                            has_gnu_relro = True
                        elif seg_type == 'PT_GNU_STACK':
                            # PF_X (0x1) flag means stack is executable (no NX)
                            has_nx = not bool(segment.header.p_flags & 0x1)

                    # Check for full vs partial RELRO by inspecting BIND_NOW
                    has_bind_now = False
                    if has_gnu_relro:
                        for segment in elffile.iter_segments():
                            if hasattr(segment, 'iter_tags'):
                                for tag in segment.iter_tags():
                                    if tag.entry.d_tag in ('DT_BIND_NOW', 'DT_FLAGS') and (
                                        tag.entry.d_tag == 'DT_BIND_NOW' or
                                        (tag.entry.d_tag == 'DT_FLAGS' and tag.entry.d_val & 0x8)
                                    ):
                                        has_bind_now = True
                                        break

                    elf_sec["has_gnu_relro"] = has_gnu_relro
                    elf_sec["relro_type"] = "Full RELRO" if (has_gnu_relro and has_bind_now) else (
                        "Partial RELRO" if has_gnu_relro else "No RELRO")
                    elf_sec["has_nx"] = has_nx

                    # Check for stack canary and fortify via dynamic symbols
                    has_canary = False
                    has_fortify = False
                    for section in elffile.iter_sections():
                        if isinstance(section, SymbolTableSection):
                            for symbol in section.iter_symbols():
                                name = symbol.name
                                if name == '__stack_chk_fail':
                                    has_canary = True
                                elif name in ('__fortify_fail', '__chk_fail'):
                                    has_fortify = True
                    elf_sec["has_stack_canary"] = has_canary
                    elf_sec["has_fortify"] = has_fortify

                    # Check stripped status by looking for .symtab section
                    elf_sec["stripped"] = elffile.get_section_by_name('.symtab') is None
                    if elf_sec["stripped"]:
                        elf_sec["note_stripped"] = "Symbol table stripped — harder to analyze"
            else:
                # Fallback: manual header parsing when pyelftools is unavailable
                with open(state.filepath, 'rb') as f:
                    elf_header = f.read(64)

                if len(elf_header) >= 20:
                    elf_sec["class"] = "64-bit" if elf_header[4] == 2 else "32-bit"
                    elf_sec["endianness"] = "little-endian" if elf_header[5] == 1 else "big-endian"
                    byte_order = '<' if elf_header[5] == 1 else '>'
                    e_type = struct.unpack_from(byte_order + 'H', elf_header, 16)[0]
                    TYPE_MAP = {0: 'ET_NONE', 1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE'}
                    elf_sec["type"] = TYPE_MAP.get(e_type, f'unknown({e_type})')
                    elf_sec["is_pie"] = (e_type == 3)
                    if not elf_sec["is_pie"]:
                        risk_score += 1

                # Use mmap for byte-search fallback (avoids loading full file into memory)
                if os.path.getsize(state.filepath) == 0:
                    elf_sec["note"] = "Empty file — skipped byte-search checks"
                    return elf_sec, risk_score
                with open(state.filepath, 'rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        elf_sec["has_stack_canary"] = mm.find(b'__stack_chk_fail') != -1
                        elf_sec["has_fortify"] = (mm.find(b'__fortify_fail') != -1 or
                                                  mm.find(b'__chk_fail') != -1)
                        elf_sec["stripped"] = mm.find(b'.symtab') == -1
                        if elf_sec["stripped"]:
                            elf_sec["note_stripped"] = "Symbol table stripped — harder to analyze"
                        elf_sec["has_gnu_relro"] = mm.find(b'GNU_RELRO') != -1
                        # GNU_STACK presence alone doesn't mean NX is enabled — it depends
                        # on the segment's PF_X flag. Without pyelftools we can't read the
                        # program header flags, so report as unknown rather than guessing.
                        has_gnu_stack = mm.find(b'GNU_STACK') != -1
                        elf_sec["has_nx"] = "unknown (heuristic)"
                        if not has_gnu_stack:
                            elf_sec["has_nx"] = False
                            elf_sec["note_nx"] = "No GNU_STACK segment — stack may be executable"
                        elf_sec["note"] = "pyelftools not available — results are heuristic-based"

        except Exception as e:
            elf_sec["error"] = f"ELF security check failed: {e}"
        return elf_sec, risk_score
    else:
        return {}, 0


# ===================================================================
#  Section 6m — Mach-O Security Features (Mach-O only)
# ===================================================================

def _triage_macho_security(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Check PIE, code signing, and entitlements (Mach-O only)."""
    risk_score = 0
    analysis_mode = state.pe_data.get('mode', 'pe')

    if analysis_mode == 'macho':
        macho_sec: Dict[str, Any] = {}
        try:
            if not (state.filepath and os.path.isfile(state.filepath)):
                return {"error": "No file available for Mach-O security check."}, 0

            with open(state.filepath, 'rb') as f:
                macho_header = f.read(32)

            if len(macho_header) >= 16:
                magic = struct.unpack_from('<I', macho_header, 0)[0]
                is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
                is_le = magic in (0xFEEDFACE, 0xFEEDFACF)
                macho_sec["bits"] = "64-bit" if is_64 else "32-bit"
                byte_order = '<' if is_le else '>'

                filetype = struct.unpack_from(byte_order + 'I', macho_header, 12)[0]
                FILETYPE_MAP = {1: 'MH_OBJECT', 2: 'MH_EXECUTE', 6: 'MH_DYLIB',
                                8: 'MH_BUNDLE', 9: 'MH_DYLIB_STUB', 11: 'MH_DSYM'}
                macho_sec["filetype"] = FILETYPE_MAP.get(filetype, f'unknown({filetype})')

                flags_offset = 24
                flags = struct.unpack_from(byte_order + 'I', macho_header, flags_offset)[0]
                macho_sec["is_pie"] = bool(flags & 0x200000)  # MH_PIE
                macho_sec["no_heap_execution"] = bool(flags & 0x1000000)  # MH_NO_HEAP_EXECUTION
                macho_sec["has_restrict"] = bool(flags & 0x00000080)  # MH_RESTRICT segment

            # M13-v10: Empty-file guard before mmap (matches ELF path)
            if os.path.getsize(state.filepath) == 0:
                macho_sec["note"] = "Empty file — skipped byte-search checks"
                return macho_sec, risk_score

            # Use mmap for byte-search checks (avoids loading full file into memory)
            with open(state.filepath, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    macho_sec["has_code_signature"] = (
                        mm.find(b'__LINKEDIT') != -1 and mm.find(b'\xfa\xde\x0c\xc0') != -1
                    )
                    macho_sec["has_entitlements"] = (
                        mm.find(b'</plist>') != -1 and mm.find(b'<key>') != -1
                    )

            if not macho_sec.get("is_pie", True):
                risk_score += 1

        except Exception as e:
            macho_sec["error"] = f"Mach-O security check failed: {e}"
        return macho_sec, risk_score
    else:
        return {}, 0


# ===================================================================
#  Section 7 — High-Value String Indicators
# ===================================================================

def _triage_high_value_strings(sifter_score_threshold: float, indicator_limit: int, all_string_values: set) -> Tuple[list, int]:
    """Extract ML-ranked high-value strings from analysis data."""
    risk_score = 0
    high_value_strings: list = []

    # Use sifter scores if available
    for source in [state.pe_data.get('basic_ascii_strings', [])]:
        if isinstance(source, list):
            for s in source:
                if isinstance(s, dict) and s.get('sifter_score', 0.0) >= sifter_score_threshold:
                    if s.get('category') or s.get('sifter_score', 0.0) >= 9.0:
                        high_value_strings.append(s)

    if 'floss_analysis' in state.pe_data and isinstance(state.pe_data['floss_analysis'], dict):
        floss_strings = state.pe_data['floss_analysis'].get('strings')
        if isinstance(floss_strings, dict):
            for str_list in floss_strings.values():
                if isinstance(str_list, list):
                    for s in str_list:
                        if isinstance(s, dict) and s.get('sifter_score', 0.0) >= sifter_score_threshold:
                            if s.get('category') or s.get('sifter_score', 0.0) >= 9.0:
                                high_value_strings.append(s)

    unique_indicators = {s.get('string', str(s)): s for s in high_value_strings if isinstance(s, dict)}
    sorted_indicators = sorted(
        unique_indicators.values(),
        key=lambda x: (-x.get('sifter_score', 0.0), x.get('string', '')),
    )

    # Contribute to risk score based on density of high-value indicators
    indicator_count = len(sorted_indicators)
    if indicator_count >= 10:
        risk_score += 3
    elif indicator_count >= 5:
        risk_score += 2
    elif indicator_count >= 1:
        risk_score += 1

    return sorted_indicators, risk_score


# ===================================================================
#  Section 8 — Compiler / Language Detection
# ===================================================================

# Known Go section names and string indicators
_GO_SECTION_NAMES = {'.gopclntab', '.go.buildinfo', '.go.itab', '.go.buildid', 'go.buildid'}
_GO_STRING_MARKERS = ('Go build', 'go.buildid', 'runtime.main', 'runtime.goexit',
                      'runtime/internal/', 'go.itab.', 'go.string.')
# Known Rust string indicators
_RUST_STRING_MARKERS = ('rustc/', '.rustc', 'rust_begin_unwind', 'rust_panic',
                        'core::panicking', 'std::panicking', 'alloc::raw_vec')


def _triage_compiler_language(all_string_values: set) -> Tuple[Dict[str, Any], int]:
    """Detect the source language / compiler toolchain from sections and strings."""
    risk_score = 0
    detected: Dict[str, Any] = {"detected_languages": []}

    sections_data = state.pe_data.get('sections') or []
    section_names: set = set()
    for sec in sections_data:
        if isinstance(sec, dict):
            name = sec.get('name', sec.get('name_str', '')).strip().lower()
            if name:
                section_names.add(name)

    # --- Go detection ---
    go_evidence: List[str] = []
    for sn in section_names:
        if sn in {n.lower() for n in _GO_SECTION_NAMES}:
            go_evidence.append(f"section '{sn}'")
    for marker in _GO_STRING_MARKERS:
        if any(marker in s for s in all_string_values):
            go_evidence.append(f"string '{marker}'")
            break  # one string match is enough
    if go_evidence:
        detected["detected_languages"].append("Go")
        detected["go_indicators"] = go_evidence

    # --- Rust detection ---
    rust_evidence: List[str] = []
    for sn in section_names:
        if sn == '.rustc':
            rust_evidence.append("section '.rustc'")
    for marker in _RUST_STRING_MARKERS:
        if any(marker in s for s in all_string_values):
            rust_evidence.append(f"string '{marker}'")
            break
    if rust_evidence:
        detected["detected_languages"].append("Rust")
        detected["rust_indicators"] = rust_evidence

    # --- .NET is already detected in dotnet_indicators, just cross-reference ---
    if state.pe_data.get('com_descriptor'):
        if ".NET" not in detected["detected_languages"]:
            detected["detected_languages"].append(".NET")

    # --- VB6 detection (MSVBVM60/50.DLL imports) ---
    # pe_data["imports"] is List[Dict] with keys: dll_name, struct, symbols
    imports_data = state.pe_data.get('imports', [])
    vb6_dll_names = set()
    vb6_import_names = set()
    for dll_entry in (imports_data if isinstance(imports_data, list) else []):
        if isinstance(dll_entry, dict):
            dll_name = dll_entry.get('dll_name', '').lower()
            if dll_name in ('msvbvm60.dll', 'msvbvm50.dll'):
                vb6_dll_names.add(dll_name)
                for sym in dll_entry.get('symbols', []):
                    if isinstance(sym, dict):
                        name = sym.get('name', '')
                        if name:
                            vb6_import_names.add(name)
    if vb6_dll_names:
        vb6_evidence = [f"imports {', '.join(sorted(vb6_dll_names))}"]
        if 'DllFunctionCall' in vb6_import_names:
            vb6_evidence.append("imports DllFunctionCall (dynamic API resolver)")
        detected["detected_languages"].append("Visual Basic 6")
        detected["vb6_indicators"] = vb6_evidence

    # --- Rich header compiler hints (Delphi, MSVC) ---
    # Rich header entries contain product_id_dec and build_number, not human-readable
    # names. Known product IDs: Delphi linker prod_ids are in the 0x00-0x04 range,
    # MSVC uses higher IDs. We detect by checking build_number patterns.
    rich_data = state.pe_data.get('rich_header')
    if rich_data and isinstance(rich_data, dict):
        entries = rich_data.get('decoded_values', rich_data.get('decoded_entries', []))
        for entry in (entries if isinstance(entries, list) else []):
            if isinstance(entry, dict):
                prod_id = entry.get('product_id_dec', 0)
                if isinstance(prod_id, int):
                    # Delphi/C++Builder uses product IDs 1-4
                    if prod_id in (1, 2, 3, 4) and 'Delphi' not in detected["detected_languages"]:
                        detected["detected_languages"].append("Delphi")
                    # MSVC linker/compiler product IDs >= 5 (various VS versions)
                    elif prod_id >= 5 and 'MSVC' not in detected["detected_languages"]:
                        detected["detected_languages"].append("MSVC")

    if not detected["detected_languages"]:
        detected["detected_languages"] = ["Unknown / native C/C++"]

    return detected, risk_score


# ===================================================================
#  Section 9 — VM/Sandbox Indicator Strings
# ===================================================================

# VM/sandbox indicator byte strings — reuses the same patterns as
# find_anti_debug_comprehensive in tools_angr_forensic.py, but scans
# raw PE data without requiring a CFG.
_VM_INDICATORS = [
    # --- VMware ---
    (b"VMwareVMware", "VMware", "CPUID brand string"),
    (b"vmware", "VMware", "Driver/service name"),
    (b"VMware Virtual", "VMware", "Hardware string"),
    (b"vmci.sys", "VMware", "VMCI driver"),
    (b"vmhgfs.sys", "VMware", "HGFS shared folders driver"),
    (b"vmmouse.sys", "VMware", "VM mouse driver"),
    (b"vmrawdsk.sys", "VMware", "Raw disk driver"),
    (b"vmusbmouse.sys", "VMware", "USB mouse driver"),
    (b"vmx86.sys", "VMware", "VMX driver"),
    (b"vmnet.sys", "VMware", "Network driver"),
    (b"VMTools", "VMware", "Guest tools service"),
    (b"vmtoolsd", "VMware", "Tools daemon"),
    (b"vmwaretray", "VMware", "System tray tool"),
    # --- VirtualBox ---
    (b"VBoxGuest", "VirtualBox", "Guest additions driver"),
    (b"VBoxMiniRdr", "VirtualBox", "Shared folders driver"),
    (b"VBoxSF", "VirtualBox", "Shared folders service"),
    (b"vboxservice", "VirtualBox", "Guest service"),
    (b"VBOX HARDDISK", "VirtualBox", "Disk identifier"),
    (b"VBoxMouse", "VirtualBox", "Mouse integration"),
    (b"VBoxVideo", "VirtualBox", "Video driver"),
    (b"VBoxTray", "VirtualBox", "Tray application"),
    (b"innotek GmbH", "VirtualBox", "BIOS vendor"),
    (b"VirtualBox", "VirtualBox", "Product name"),
    (b"vboxdrv", "VirtualBox", "Kernel driver"),
    # --- Hyper-V ---
    (b"Virtual HD", "Hyper-V", "Disk identifier"),
    (b"Microsoft Hv", "Hyper-V", "CPUID brand string"),
    (b"vmicheartbeat", "Hyper-V", "Heartbeat IC"),
    (b"vmicshutdown", "Hyper-V", "Shutdown IC"),
    (b"vmickvpexchange", "Hyper-V", "KVP exchange IC"),
    (b"vmbus", "Hyper-V", "VMBus driver"),
    (b"Hyper-V", "Hyper-V", "Product name"),
    (b"storvsc", "Hyper-V", "Storage VSC driver"),
    (b"netvsc", "Hyper-V", "Network VSC driver"),
    # --- QEMU/KVM ---
    (b"QEMU HARDDISK", "QEMU", "Disk identifier"),
    (b"QEMU DVD-ROM", "QEMU", "DVD identifier"),
    (b"KVMKVMKVM", "KVM", "CPUID brand string"),
    (b"BOCHS", "QEMU/Bochs", "BIOS vendor string"),
    (b"SeaBIOS", "QEMU", "BIOS firmware"),
    (b"virtio", "QEMU/KVM", "VirtIO driver string"),
    (b"qemu-ga", "QEMU", "Guest agent"),
    # --- Xen ---
    (b"Xen ", "Xen", "Hypervisor string"),
    (b"XenVMMXenVMM", "Xen", "CPUID brand string"),
    (b"xenbus", "Xen", "Xen bus driver"),
    # --- Parallels ---
    (b"prl_fs", "Parallels", "Shared folders driver"),
    (b"prl_tg", "Parallels", "Tools gate driver"),
    (b"Parallels", "Parallels", "Product name"),
    # --- Sandbox indicators ---
    (b"SbieDll", "Sandboxie", "Sandbox DLL"),
    (b"sbiedll", "Sandboxie", "Sandbox DLL"),
    (b"cuckoomon", "Cuckoo", "Cuckoo sandbox monitor"),
    (b"CWSandbox", "CWSandbox", "Sandbox indicator"),
    (b"JoeBox", "JoeSandbox", "Sandbox indicator"),
    # --- Analysis tool indicators ---
    (b"dbghelp", "Debugger", "Debug helper library"),
    (b"wireshark", "Wireshark", "Network analysis tool"),
    (b"procmon", "Procmon", "Process monitor"),
    (b"procexp", "Procexp", "Process explorer"),
    (b"ollydbg", "OllyDbg", "Debugger"),
    (b"x64dbg", "x64dbg", "Debugger"),
    (b"ImmunityDebugger", "Immunity", "Debugger"),
    (b"ida.exe", "IDA Pro", "Disassembler"),
    (b"Fiddler", "Fiddler", "HTTP proxy"),
    # --- Registry paths (VM-specific) ---
    (b"SOFTWARE\\VMware, Inc.\\VMware Tools", "VMware", "Registry: VMware Tools path"),
    (b"SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VirtualBox", "Registry: VBox GA path"),
    (b"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", "VirtualBox", "Registry: VBox service"),
    (b"SYSTEM\\CurrentControlSet\\Services\\VMTools", "VMware", "Registry: VMware service"),
    (b"HARDWARE\\ACPI\\DSDT\\VBOX__", "VirtualBox", "Registry: VBox ACPI table"),
    (b"HARDWARE\\ACPI\\FADT\\VBOX__", "VirtualBox", "Registry: VBox ACPI table"),
    (b"HARDWARE\\Description\\System\\SystemBiosVersion", "Generic", "Registry: BIOS version query"),
    # --- WMI query strings ---
    (b"Win32_ComputerSystem", "Generic", "WMI: computer system query"),
    (b"Win32_BIOS", "Generic", "WMI: BIOS info query"),
    (b"Win32_BaseBoard", "Generic", "WMI: baseboard info query"),
    (b"Win32_DiskDrive", "Generic", "WMI: disk drive query"),
    (b"Win32_NetworkAdapter", "Generic", "WMI: network adapter query"),
    (b"Win32_PhysicalMemory", "Generic", "WMI: physical memory query"),
    (b"MSAcpi_ThermalZoneTemperature", "Generic", "WMI: thermal zone (absent in VMs)"),
    # --- MAC OUI strings ---
    (b"00:0C:29", "VMware", "MAC OUI: VMware"),
    (b"00:50:56", "VMware", "MAC OUI: VMware"),
    (b"00-0C-29", "VMware", "MAC OUI: VMware (dash)"),
    (b"00-50-56", "VMware", "MAC OUI: VMware (dash)"),
    (b"08:00:27", "VirtualBox", "MAC OUI: VirtualBox"),
    (b"08-00-27", "VirtualBox", "MAC OUI: VirtualBox (dash)"),
    (b"00:15:5D", "Hyper-V", "MAC OUI: Hyper-V"),
    (b"00-15-5D", "Hyper-V", "MAC OUI: Hyper-V (dash)"),
    (b"52:54:00", "QEMU", "MAC OUI: QEMU"),
    (b"52-54-00", "QEMU", "MAC OUI: QEMU (dash)"),
]

# Pre-built case-insensitive lookup and compiled regex for single-pass scanning
_VM_IND_LOOKUP = {ind.lower(): (ind, target, detail)
                  for ind, target, detail in _VM_INDICATORS}
_VM_IND_PATTERN = re.compile(
    b'(' + b'|'.join(re.escape(ind) for ind in _VM_IND_LOOKUP) + b')',
    re.IGNORECASE,
)


def _triage_vm_indicator_strings(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Scan raw binary data for VM/sandbox/analysis-tool indicator strings.

    Uses the same comprehensive indicator list as ``find_anti_debug_comprehensive``
    but runs on raw PE data without requiring a CFG.  Single-pass regex scan.
    """
    risk_score = 0
    pe_obj = state.pe_object
    if not pe_obj or not hasattr(pe_obj, '__data__'):
        return {"vm_indicators": [], "count": 0, "has_vm_detection": False}, risk_score

    try:
        raw_data = pe_obj.__data__
    except (AttributeError, TypeError):
        return {"vm_indicators": [], "count": 0, "has_vm_detection": False}, risk_score

    indicators: List[Dict[str, str]] = []
    hypervisor_breakdown: Dict[str, List[str]] = {}
    seen: set = set()

    for m in _VM_IND_PATTERN.finditer(raw_data):
        matched_lower = m.group().lower()
        if matched_lower in seen:
            continue
        seen.add(matched_lower)
        ind_bytes, target, detail = _VM_IND_LOOKUP[matched_lower]
        indicator_str = ind_bytes.decode('ascii', 'replace')
        indicators.append({
            "indicator": indicator_str,
            "target": target,
            "detail": detail,
        })
        hypervisor_breakdown.setdefault(target, []).append(indicator_str)
        if len(indicators) >= indicator_limit:
            break

    # Risk contribution: 3 for 5+ unique VM indicators, 2 for 3+, 1 for any
    if len(indicators) >= 5:
        risk_score += 3
    elif len(indicators) >= 3:
        risk_score += 2
    elif indicators:
        risk_score += 1

    hypervisor_breakdown = {k: sorted(set(v)) for k, v in hypervisor_breakdown.items()}

    return {
        "vm_indicators": indicators[:indicator_limit],
        "count": len(indicators),
        "has_vm_detection": len(indicators) > 0,
        "hypervisor_breakdown": hypervisor_breakdown,
    }, risk_score


# ===================================================================
#  Section 10 — Anti-Debug Instruction Patterns
# ===================================================================

# Anti-debug/anti-analysis instruction byte patterns for x86/x64.
# Same patterns as find_anti_debug_comprehensive in tools_angr_forensic.py.
_ANTI_DEBUG_INSN_PATTERNS = [
    (b'\x0f\x31', "RDTSC", "timing_check", "medium",
     "Read timestamp counter — timing-based anti-debug/VM detection"),
    (b'\x0f\xa2', "CPUID", "vm_detection", "high",
     "CPUID — leaf 1 bit 31 = hypervisor, leaf 0x40000000 = vendor ID"),
    (b'\xcd\x2d', "INT 2Dh", "debugger_check", "high",
     "Debug service interrupt — execution differs under debugger"),
    (b'\x0f\x01\x0d', "SIDT", "vm_detection", "low",
     "Store IDT register — Red Pill VM detection (unreliable on modern CPUs)"),
]


def _triage_anti_debug_instructions(indicator_limit: int) -> Tuple[Dict[str, Any], int]:
    """Scan executable PE sections for anti-debug/anti-analysis instruction patterns.

    Searches for known byte sequences (RDTSC, CPUID, INT 2Dh, SIDT) in
    executable sections.  Fast raw-bytes scan — no disassembly or CFG needed.
    """
    risk_score = 0
    pe_obj = state.pe_object
    if not pe_obj:
        return {"anti_debug_instructions": [], "count": 0, "has_anti_debug_instructions": False}, risk_score

    try:
        sections = pe_obj.sections
    except (AttributeError, TypeError):
        return {"anti_debug_instructions": [], "count": 0, "has_anti_debug_instructions": False}, risk_score

    findings: List[Dict[str, Any]] = []
    image_base = getattr(pe_obj.OPTIONAL_HEADER, 'ImageBase', 0) if hasattr(pe_obj, 'OPTIONAL_HEADER') else 0

    for section in sections:
        try:
            chars = getattr(section, 'Characteristics', 0) or 0
            if not (chars & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
                continue

            sec_name = section.Name.rstrip(b'\x00').decode('ascii', 'replace')
            sec_rva = getattr(section, 'VirtualAddress', 0) or 0
            section_data = section.get_data()

            for pattern_bytes, mnemonic, category, severity, description in _ANTI_DEBUG_INSN_PATTERNS:
                addresses: List[str] = []
                offset = 0
                while offset <= len(section_data) - len(pattern_bytes):
                    pos = section_data.find(pattern_bytes, offset)
                    if pos == -1:
                        break
                    addresses.append(hex(image_base + sec_rva + pos))
                    offset = pos + len(pattern_bytes)
                    if len(addresses) >= 100:  # Cap per pattern per section
                        break

                if addresses:
                    findings.append({
                        "instruction": mnemonic,
                        "description": description,
                        "category": category,
                        "severity": severity,
                        "section": sec_name,
                        "count": len(addresses),
                        "addresses": addresses[:10],
                    })
        except Exception:
            continue

    # Risk contribution based on high-severity findings
    high_sev = sum(1 for f in findings if f["severity"] == "high")
    med_sev = sum(1 for f in findings if f["severity"] == "medium")
    if high_sev >= 2:
        risk_score += 3
    elif high_sev >= 1:
        risk_score += 2
    elif med_sev >= 1:
        risk_score += 1

    return {
        "anti_debug_instructions": findings[:indicator_limit],
        "count": len(findings),
        "has_anti_debug_instructions": len(findings) > 0,
    }, risk_score


# ===================================================================
#  Section 11 — Risk Score & Suggested Next Tools
# ===================================================================

def _triage_risk_and_suggestions(risk_score: int, analysis_mode: str, triage_report: Dict[str, Any]) -> Dict[str, Any]:
    """Compute risk level and suggest format-aware next analysis steps."""
    result: Dict[str, Any] = {}
    result["risk_score"] = risk_score

    if risk_score >= 15:
        result["risk_level"] = "CRITICAL"
    elif risk_score >= 8:
        result["risk_level"] = "HIGH"
    elif risk_score >= 4:
        result["risk_level"] = "MEDIUM"
    elif risk_score >= 1:
        result["risk_level"] = "LOW"
    else:
        result["risk_level"] = "BENIGN"

    # Context-aware, format-aware tool suggestions
    is_likely_packed = triage_report.get("packing_assessment", {}).get("likely_packed", False)
    network_iocs = triage_report.get("network_iocs", {})
    found_ips = network_iocs.get("ip_addresses", [])
    found_urls = network_iocs.get("urls", [])
    detected_langs = triage_report.get("compiler_language", {}).get("detected_languages", [])

    suggested: List[str] = []
    if analysis_mode == 'pe':
        if is_likely_packed:
            suggested.append("auto_unpack_pe — attempt automatic unpacking (uses Unipacker for UPX, ASPack, PEtite, FSG)")
            suggested.append("detect_packing — run angr-based multi-heuristic packing analysis")
            suggested.append("get_pe_data(key='peid_matches') — review packer signatures")
        else:
            if triage_report.get("capa_status"):
                suggested.append("get_capa_analysis_info — capa failed during triage, re-run or check setup")
            elif not triage_report["suspicious_capabilities"]:
                suggested.append("get_capa_analysis_info — run capa for capability detection")
            suggested.append("find_and_decode_encoded_strings — hunt for obfuscated IOCs")
        if not found_ips and not found_urls:
            suggested.append("search_floss_strings — search for network indicators with regex")
        if triage_report.get("overlay_analysis", {}).get("present"):
            suggested.append("scan_for_embedded_files — scan overlay for embedded binaries")
        if triage_report.get("resource_anomalies"):
            suggested.append("get_pe_data(key='resources_summary') — inspect suspicious resources")
        # Language-specific tool suggestions
        if "Go" in detected_langs:
            suggested.append("go_analyze — extract Go compiler version, packages, types, and build ID")
        if "Rust" in detected_langs:
            suggested.append("rust_analyze — extract Rust compiler version, dependencies, and toolchain")
            suggested.append("rust_demangle_symbols — demangle Rust symbol names for readability")
        if triage_report.get("dotnet_indicators", {}).get("is_dotnet") or ".NET" in detected_langs:
            suggested.append("dotnet_analyze — extract .NET types, methods, and user strings")
        if "Visual Basic 6" in detected_langs:
            suggested.append("vb6_analyze — extract VB6 project info, forms, modules, and Declare Function APIs")
        if triage_report.get("tls_callbacks", {}).get("present") and triage_report["tls_callbacks"].get("callback_count", 0) > 0:
            suggested.append("get_pe_data(key='tls_info') — inspect TLS callback addresses")
        has_vm = triage_report.get("vm_indicator_strings", {}).get("has_vm_detection", False)
        has_ad = triage_report.get("anti_debug_instructions", {}).get("has_anti_debug_instructions", False)
        if has_vm or has_ad:
            suggested.append("find_anti_debug_comprehensive — deep anti-analysis detection with CFG (expands on triage VM/anti-debug findings)")
        suggested.append("classify_binary_purpose — determine if GUI app, service, DLL, etc.")
    elif analysis_mode == 'elf':
        suggested.append("elf_analyze — full ELF header, section, and symbol analysis")
        suggested.append("elf_dwarf_info — extract debug symbols and source file names")
        if "Go" in detected_langs:
            suggested.append("go_analyze — extract Go compiler version, packages, types, and build ID")
        if "Rust" in detected_langs:
            suggested.append("rust_analyze — extract Rust compiler version, dependencies, and toolchain")
            suggested.append("rust_demangle_symbols — demangle Rust symbol names for readability")
        if triage_report.get("elf_security", {}).get("stripped"):
            suggested.append("decompile_function — use angr to decompile stripped functions")
        suggested.append("parse_binary_with_lief — cross-format binary analysis")
    elif analysis_mode == 'macho':
        suggested.append("macho_analyze — full Mach-O load commands, segments, and symbols")
        if "Go" in detected_langs:
            suggested.append("go_analyze — extract Go compiler version, packages, types, and build ID")
        if "Rust" in detected_langs:
            suggested.append("rust_analyze — extract Rust compiler version, dependencies, and toolchain")
        suggested.append("parse_binary_with_lief — cross-format binary analysis")
    elif analysis_mode == 'shellcode':
        suggested.append("emulate_shellcode_with_speakeasy — emulate with Windows API hooks")
        suggested.append("disassemble_raw_bytes — disassemble the shellcode")
    # Universal suggestions
    if risk_score >= 8:
        suggested.append("get_virustotal_report_for_loaded_file — check community reputation")
    suggested.append("compute_similarity_hashes — compute ssdeep/TLSH for sample clustering")
    result["suggested_next_tools"] = suggested

    return result


# ===================================================================
#  Auto-note helper — saves key triage findings for the analysis digest
# ===================================================================

def _auto_save_triage_notes(triage_report: Dict[str, Any],
                            full_suspicious_imports: Optional[List] = None) -> None:
    """Auto-create 'tool_result' notes from triage findings.

    Called after each triage run so that ``get_analysis_digest()`` always
    has meaningful data.  Skips if triage notes already exist to avoid
    duplicates on re-triage.

    ``full_suspicious_imports`` should be the pre-pagination list so that
    CRITICAL imports beyond the page limit are still captured in notes.

    Notes are persisted via the project overlay flush daemon — the cache
    wrapper v2 strips user state, so no explicit cache write is needed.
    """
    # Check if triage notes already exist (idempotent)
    existing = state.get_notes(category="tool_result")
    if any(n.get("content", "").startswith("Triage:") for n in existing):
        return

    risk_level = triage_report.get("risk_level", "UNKNOWN")
    risk_score = triage_report.get("risk_score", 0)

    # Build risk summary
    parts = [f"{risk_level} risk (score {risk_score})"]
    packing = triage_report.get("packing_assessment", {})
    if isinstance(packing, dict) and packing.get("likely_packed"):
        packer_names = packing.get("peid_matches", [])
        packer = packer_names[0] if packer_names else "unknown packer"
        parts.append(f"likely packed ({packer})")
    sig = triage_report.get("digital_signature", {})
    if isinstance(sig, dict):
        parts.append("signed" if sig.get("present") else "unsigned")

    # Use full pre-pagination list if available, otherwise fall back to report data
    sus = full_suspicious_imports if full_suspicious_imports is not None else triage_report.get("suspicious_imports", [])
    critical_imports = []
    if isinstance(sus, list):
        critical_imports = [
            imp.get("function", "?")
            for imp in sus
            if isinstance(imp, dict) and imp.get("risk") == "CRITICAL"
        ]
    if critical_imports:
        parts.append(f"{len(critical_imports)} CRITICAL imports")

    state.add_note(
        content=f"Triage: {', '.join(parts)}",
        category="tool_result",
        tool_name="get_triage_report",
    )

    # Note critical imports individually (up to 3)
    for func_name in critical_imports[:3]:
        state.add_note(
            content=f"CRITICAL import: {func_name}",
            category="tool_result",
            tool_name="get_triage_report",
        )

    # Note network IOCs if present
    net = triage_report.get("network_iocs", {})
    if isinstance(net, dict):
        ioc_parts = []
        for ioc_type in ("ip_addresses", "urls", "domains"):
            ioc_list = net.get(ioc_type, [])
            if isinstance(ioc_list, list) and ioc_list:
                ioc_parts.append(f"{len(ioc_list)} {ioc_type.replace('_', ' ')}")
        if ioc_parts:
            state.add_note(
                content=f"Network IOCs: {', '.join(ioc_parts)}",
                category="tool_result",
                tool_name="get_triage_report",
            )

    # Note VM/sandbox indicator findings
    vm_data = triage_report.get("vm_indicator_strings", {})
    if isinstance(vm_data, dict) and vm_data.get("has_vm_detection"):
        breakdown = vm_data.get("hypervisor_breakdown", {})
        targets = sorted(breakdown.keys()) if breakdown else []
        if targets:
            state.add_note(
                content=f"VM/sandbox detection: {vm_data.get('count', 0)} indicators targeting {', '.join(targets)}",
                category="tool_result",
                tool_name="get_triage_report",
            )

    # Note anti-debug instruction findings
    ad_data = triage_report.get("anti_debug_instructions", {})
    if isinstance(ad_data, dict) and ad_data.get("has_anti_debug_instructions"):
        instrs = ad_data.get("anti_debug_instructions", [])
        high_sev = [f["instruction"] for f in instrs if isinstance(f, dict) and f.get("severity") == "high"]
        if high_sev:
            state.add_note(
                content=f"Anti-debug instructions: {', '.join(sorted(set(high_sev)))} (high severity)",
                category="tool_result",
                tool_name="get_triage_report",
            )


# ===================================================================
#  Internal triage function (callable from enrichment without tool_decorator)
# ===================================================================

def _run_triage_internal(
    current_state,
    sifter_score_threshold: float = 8.0,
    indicator_limit: int = 50,
    progress_cb=None,
    indicator_offset: int = 0,
) -> Dict[str, Any]:
    """Run triage synchronously on the given state. No MCP/async overhead.

    ``progress_cb`` is an optional ``(percent, message)`` callback.
    Returns the full triage report dict and caches it on the state.
    """
    from arkana.state import set_current_state
    set_current_state(current_state)

    def _report(pct, msg=""):
        if progress_cb:
            progress_cb(pct, msg)

    risk_score = 0
    triage_report: Dict[str, Any] = {
        "file_info": {}, "timestamp_analysis": {}, "packing_assessment": {},
        "digital_signature": {}, "rich_header_summary": {}, "suspicious_imports": [],
        "import_anomalies": {}, "suspicious_capabilities": [], "network_iocs": {},
        "section_anomalies": [], "overlay_analysis": {}, "resource_anomalies": [],
        "yara_matches": [], "header_anomalies": [], "tls_callbacks": {},
        "security_mitigations": {}, "delay_load_risks": {}, "version_info_anomalies": {},
        "dotnet_indicators": {}, "export_anomalies": {}, "high_value_strings": [],
        "elf_security": {}, "macho_security": {}, "compiler_language": {},
        "vm_indicator_strings": {}, "anti_debug_instructions": {},
        "risk_score": 0, "risk_level": "UNKNOWN", "suggested_next_tools": [],
    }

    _report(2, "Collecting file info...")
    triage_report["file_info"] = _triage_file_info(indicator_limit)
    analysis_mode = triage_report["file_info"]["mode"]
    file_size = triage_report["file_info"]["file_size"]

    data, delta = _triage_timestamp_analysis(analysis_mode, indicator_limit)
    triage_report["timestamp_analysis"] = data
    risk_score += delta

    _report(8, "Assessing packing...")
    data, delta = _triage_packing_assessment(indicator_limit)
    triage_report["packing_assessment"] = data
    risk_score += delta

    data, delta = _triage_digital_signature(indicator_limit)
    triage_report["digital_signature"] = data
    risk_score += delta
    sig_present = data["present"]
    sig_signer = data["signer"]

    data, delta = _triage_rich_header(analysis_mode, indicator_limit)
    triage_report["rich_header_summary"] = data
    risk_score += delta

    # Helper to paginate a list field and add pagination metadata
    def _pf(items):
        return _paginate_field(items, indicator_offset, indicator_limit)

    _report(20, "Analyzing imports...")
    imports_result, delta = _triage_suspicious_imports(indicator_limit)
    _full_suspicious_imports = imports_result["suspicious_imports"]  # pre-pagination for notes
    page, pag = _pf(_full_suspicious_imports)
    triage_report["suspicious_imports"] = page
    triage_report["suspicious_imports_pagination"] = pag
    triage_report["suspicious_import_summary"] = imports_result["suspicious_import_summary"]
    risk_score += delta

    _report(28, "Checking capa capabilities...")
    capa_data, delta, capa_status_info = _triage_capa_capabilities(indicator_limit)
    page, pag = _pf(capa_data)
    triage_report["suspicious_capabilities"] = page
    triage_report["suspicious_capabilities_pagination"] = pag
    risk_score += delta
    if capa_status_info is not None:
        triage_report["capa_status"] = capa_status_info

    _report(35, "Extracting network IOCs...")
    all_string_values, strings_truncated = _collect_all_string_values()
    data, delta = _triage_network_iocs(indicator_limit, all_string_values)
    net_iocs: Dict[str, Any] = {}
    for key in ("ip_addresses", "urls", "domains", "registry_paths"):
        p, pg = _pf(data.get(key, []))
        net_iocs[key] = p
        net_iocs[f"{key}_pagination"] = pg
    triage_report["network_iocs"] = net_iocs
    risk_score += delta

    _report(42, "Checking sections & overlays...")
    sec_data, delta = _triage_section_anomalies(indicator_limit)
    page, pag = _pf(sec_data)
    triage_report["section_anomalies"] = page
    triage_report["section_anomalies_pagination"] = pag
    risk_score += delta

    data, delta = _triage_overlay_analysis(indicator_limit, file_size)
    triage_report["overlay_analysis"] = data
    risk_score += delta

    data, delta = _triage_import_anomalies(indicator_limit)
    # Paginate internal lists
    if "ordinal_only_imports" in data:
        p, pg = _pf(data["ordinal_only_imports"])
        data["ordinal_only_imports"] = p
        data["ordinal_only_imports_pagination"] = pg
    if "non_standard_dlls" in data:
        p, pg = _pf(data["non_standard_dlls"])
        data["non_standard_dlls"] = p
        data["non_standard_dlls_pagination"] = pg
    triage_report["import_anomalies"] = data
    risk_score += delta

    res_data, delta = _triage_resource_anomalies(indicator_limit)
    page, pag = _pf(res_data)
    triage_report["resource_anomalies"] = page
    triage_report["resource_anomalies_pagination"] = pag
    risk_score += delta

    _report(55, "Running YARA rules...")
    yara_data, delta = _triage_yara_matches(indicator_limit)
    page, pag = _pf(yara_data)
    triage_report["yara_matches"] = page
    triage_report["yara_matches_pagination"] = pag
    risk_score += delta

    hdr_data, delta = _triage_header_anomalies(indicator_limit)
    page, pag = _pf(hdr_data)
    triage_report["header_anomalies"] = page
    triage_report["header_anomalies_pagination"] = pag
    risk_score += delta

    _report(62, "Checking TLS & security mitigations...")
    data, delta = _triage_tls_callbacks(indicator_limit)
    triage_report["tls_callbacks"] = data
    risk_score += delta

    data, delta = _triage_security_mitigations(indicator_limit)
    triage_report["security_mitigations"] = data
    risk_score += delta

    data, delta = _triage_delay_load_evasion(indicator_limit)
    if "suspicious_delay_loaded_apis" in data:
        p, pg = _pf(data["suspicious_delay_loaded_apis"])
        data["suspicious_delay_loaded_apis"] = p
        data["suspicious_delay_loaded_apis_pagination"] = pg
    triage_report["delay_load_risks"] = data
    risk_score += delta

    data, delta = _triage_version_info(indicator_limit, sig_present, sig_signer)
    triage_report["version_info_anomalies"] = data
    risk_score += delta

    _report(72, "Checking .NET, exports & platform features...")
    data, delta = _triage_dotnet_indicators(indicator_limit)
    triage_report["dotnet_indicators"] = data
    risk_score += delta

    data, delta = _triage_export_anomalies(indicator_limit)
    if "ordinal_only_values" in data:
        p, pg = _pf(data["ordinal_only_values"])
        data["ordinal_only_values"] = p
        data["ordinal_only_values_pagination"] = pg
    if "forwarded_exports" in data:
        p, pg = _pf(data["forwarded_exports"])
        data["forwarded_exports"] = p
        data["forwarded_exports_pagination"] = pg
    triage_report["export_anomalies"] = data
    risk_score += delta

    data, delta = _triage_elf_security(indicator_limit)
    triage_report["elf_security"] = data
    risk_score += delta

    data, delta = _triage_macho_security(indicator_limit)
    triage_report["macho_security"] = data
    risk_score += delta

    _report(82, "Ranking high-value strings...")
    hvs_data, delta = _triage_high_value_strings(sifter_score_threshold, indicator_limit, all_string_values)
    page, pag = _pf(hvs_data)
    triage_report["high_value_strings"] = page
    triage_report["high_value_strings_pagination"] = pag
    risk_score += delta

    lang_data, delta = _triage_compiler_language(all_string_values)
    triage_report["compiler_language"] = lang_data
    risk_score += delta

    _report(86, "Scanning for VM/sandbox indicators...")
    vm_data, delta = _triage_vm_indicator_strings(indicator_limit)
    if vm_data.get("has_vm_detection"):
        triage_report["vm_indicator_strings"] = vm_data
    risk_score += delta

    anti_dbg_data, delta = _triage_anti_debug_instructions(indicator_limit)
    if anti_dbg_data.get("has_anti_debug_instructions"):
        triage_report["anti_debug_instructions"] = anti_dbg_data
    risk_score += delta

    if strings_truncated:
        triage_report["strings_truncated"] = True
        triage_report["strings_truncated_at"] = _MAX_TRIAGE_STRINGS

    _report(92, "Computing risk score & recommendations...")
    risk_data = _triage_risk_and_suggestions(risk_score, analysis_mode, triage_report)
    triage_report["risk_score"] = risk_data["risk_score"]
    triage_report["risk_level"] = risk_data["risk_level"]
    page, pag = _pf(risk_data["suggested_next_tools"])
    triage_report["suggested_next_tools"] = page
    triage_report["suggested_next_tools_pagination"] = pag

    # Packing assessment pagination
    packing = triage_report.get("packing_assessment", {})
    if isinstance(packing, dict):
        if "peid_matches" in packing:
            p, pg = _pf(packing["peid_matches"])
            packing["peid_matches"] = p
            packing["peid_matches_pagination"] = pg
        if "peid_ranked" in packing:
            p, pg = _pf(packing["peid_ranked"])
            packing["peid_ranked"] = p
            packing["peid_ranked_pagination"] = pg

    # Cache on state (pe_data persistence handled by _save_enrichment_cache)
    current_state._cached_triage = triage_report

    _auto_save_triage_notes(triage_report, full_suspicious_imports=_full_suspicious_imports)
    return triage_report


# ===================================================================
#  Public tool — Orchestrator
# ===================================================================

@tool_decorator
async def get_triage_report(
    ctx: Context,
    sifter_score_threshold: float = 8.0,
    indicator_limit: int = 50,
    indicator_offset: int = 0,
    compact: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: triage] START HERE after opening a file. Comprehensive automated triage
    of the loaded binary with risk scoring and format-aware next-tool recommendations.

    ---compact: START HERE — auto risk score, packing, imports, capa, IOCs | needs: file

    Analyses 27+ dimensions including entropy, packing, digital signatures,
    suspicious imports, capa capabilities, network IOCs, section anomalies,
    timestamps, Rich header, overlay data, resources, YARA, header corruption,
    TLS callbacks, security mitigations (CFG/CET/ASLR/DEP), delay-load evasion,
    version info spoofing, .NET indicators, export anomalies, VM/sandbox indicator
    strings, anti-debug instruction patterns, and platform-specific security
    features (ELF: PIE/NX/RELRO/canaries, Mach-O: code signing/PIE).

    Designed to give an AI analyst a complete first-look assessment without needing
    to call multiple individual tools. The response includes 'suggested_next_tools'
    with context-aware recommendations based on what the triage found.

    Args:
        ctx: The MCP Context object.
        sifter_score_threshold: (float) Min sifter score for high-value string indicators.
        indicator_limit: (int) Max items per category in the report (default 50).
        indicator_offset: (int) Start index for paginated lists (default 0).
        compact: (bool) If True, return only risk level, risk score, top findings,
            and suggested next tools (~2KB instead of ~20KB). Default False.

    Returns:
        A comprehensive triage dictionary with sections:
        - file_info: path, hashes, mode, file size
        - timestamp_analysis: compilation timestamp anomalies (PE)
        - packing_assessment: entropy, PEiD, import count analysis
        - digital_signature: signing status and signer info
        - rich_header_summary: build environment fingerprint (PE)
        - suspicious_imports: risk-categorized API imports
        - import_anomalies: ordinal-only imports, non-standard DLLs
        - suspicious_capabilities: capa MITRE ATT&CK matches
        - network_iocs: IPs, URLs, domains, registry paths
        - section_anomalies: W+X, size mismatches
        - overlay_analysis: appended data with embedded signature detection
        - resource_anomalies: nested PEs, large RCDATA payloads
        - yara_matches: matched YARA rules
        - header_anomalies: pefile warnings, checksum, entry point issues
        - tls_callbacks: TLS callback detection (anti-debug/unpacking)
        - security_mitigations: ASLR, DEP, CFG, CET, XFG status (PE)
        - delay_load_risks: suspicious APIs hidden in delay-load imports
        - version_info_anomalies: filename mismatch, company spoofing
        - dotnet_indicators: .NET assembly detection and flags
        - export_anomalies: ordinal-only and forwarded exports
        - high_value_strings: ML-ranked high-value strings
        - elf_security: PIE, NX, RELRO, stack canaries, stripped status (ELF)
        - macho_security: PIE, code signing, entitlements (Mach-O)
        - compiler_language: detected source language (Go, Rust, .NET, Delphi, MSVC)
        - vm_indicator_strings: VM/sandbox/analysis-tool indicator strings found in raw data (PE only, omitted if none)
        - anti_debug_instructions: anti-debug instruction byte patterns in executable sections (PE only, omitted if none)
        - risk_score / risk_level: cumulative risk assessment
        - suggested_next_tools: format-aware recommended next analysis steps
    """
    await ctx.info("Generating comprehensive triage report...")

    _check_pe_loaded("get_triage_report")

    # Return cached result if enrichment already ran triage
    if state._cached_triage and not compact:
        import copy
        triage_report = copy.deepcopy(state._cached_triage)
        triage_report["workflow_hints"] = _TRIAGE_WORKFLOW_HINTS
        # Re-apply pagination parameters to all paginated fields in the cached result
        _top_level_paginated = (
            "suspicious_imports", "suspicious_capabilities", "section_anomalies",
            "resource_anomalies", "yara_matches", "header_anomalies",
            "high_value_strings", "suggested_next_tools",
        )
        for field_key in _top_level_paginated:
            items = triage_report.get(field_key, [])
            if isinstance(items, list):
                page, pag_meta = _paginate_field(items, indicator_offset, indicator_limit)
                triage_report[field_key] = page
                triage_report[f"{field_key}_pagination"] = pag_meta
        # Re-paginate network_iocs sub-fields
        net_iocs = triage_report.get("network_iocs", {})
        for field_key in ("ip_addresses", "urls", "domains", "registry_paths"):
            items = net_iocs.get(field_key, [])
            if isinstance(items, list):
                page, pag_meta = _paginate_field(items, indicator_offset, indicator_limit)
                net_iocs[field_key] = page
                net_iocs[f"{field_key}_pagination"] = pag_meta
        # Re-paginate nested dict fields (export_anomalies, delay_load_risks, vm/anti-debug)
        for nested_key in ("export_anomalies", "delay_load_risks",
                           "vm_indicator_strings", "anti_debug_instructions"):
            nested = triage_report.get(nested_key, {})
            if isinstance(nested, dict):
                for sub_key, sub_val in list(nested.items()):
                    if isinstance(sub_val, list) and not sub_key.endswith("_pagination"):
                        page, pag_meta = _paginate_field(sub_val, indicator_offset, indicator_limit)
                        nested[sub_key] = page
                        nested[f"{sub_key}_pagination"] = pag_meta
        return await _check_mcp_response_size(ctx, triage_report, "get_triage_report", "the 'indicator_limit' parameter")

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _bridge_progress(pct, msg=""):
        bridge.report_progress(pct, 100)
        if msg:
            bridge.info(f"[triage] {msg}")

    from arkana.state import get_current_state as _gcs
    _current = _gcs()

    triage_report = await asyncio.to_thread(
        _run_triage_internal, _current,
        sifter_score_threshold, indicator_limit, _bridge_progress,
        indicator_offset,
    )

    if compact:
        # Build compact summary: risk info + top findings as one-liners
        findings = []
        # suspicious_imports is a list of dicts with 'function', 'dll', 'risk' keys
        sus = triage_report.get("suspicious_imports", [])
        if isinstance(sus, list):
            for imp in sus[:3]:
                if isinstance(imp, dict):
                    findings.append(
                        f"Suspicious import: {imp.get('function', '?')} "
                        f"({imp.get('dll', '?')}) — {imp.get('risk', '?')}"
                    )
        packing = triage_report.get("packing_assessment", {})
        if isinstance(packing, dict) and packing.get("likely_packed"):
            packer_names = packing.get("peid_matches", [])
            packer = packer_names[0] if packer_names else "unknown packer"
            findings.append(f"Likely packed ({packer})")
        net = triage_report.get("network_iocs", {})
        if isinstance(net, dict):
            for ioc_type in ("urls", "ip_addresses", "domains"):
                ioc_list = net.get(ioc_type, [])
                if isinstance(ioc_list, list) and ioc_list:
                    findings.append(f"{ioc_type}: {', '.join(str(x) for x in ioc_list[:3])}")
        # capa status — surface failures before capabilities
        capa_st = triage_report.get("capa_status")
        if isinstance(capa_st, dict):
            err = capa_st.get("error", "")
            findings.append(f"capa {capa_st.get('status', 'failed')}{': ' + err if err else ''}")
        # suspicious_capabilities is a list of dicts with 'capability', 'namespace', 'severity'
        caps = triage_report.get("suspicious_capabilities", [])
        if isinstance(caps, list):
            for cap in caps[:3]:
                if isinstance(cap, dict):
                    findings.append(f"Capability: {cap.get('capability', '?')} ({cap.get('namespace', '?')})")
        # VM/sandbox indicators
        vm = triage_report.get("vm_indicator_strings", {})
        if isinstance(vm, dict) and vm.get("has_vm_detection"):
            targets = sorted(vm.get("hypervisor_breakdown", {}).keys())
            findings.append(f"VM/sandbox indicators: {vm.get('count', 0)} strings ({', '.join(targets[:3])})")
        # Anti-debug instructions
        ad = triage_report.get("anti_debug_instructions", {})
        if isinstance(ad, dict) and ad.get("has_anti_debug_instructions"):
            instrs = [f["instruction"] for f in ad.get("anti_debug_instructions", []) if isinstance(f, dict)]
            findings.append(f"Anti-debug instructions: {', '.join(sorted(set(instrs)))}")
        # digital_signature uses key "present" (from _triage_digital_signature)
        sig = triage_report.get("digital_signature", {})
        if isinstance(sig, dict):
            if not sig.get("present"):
                findings.append("Not digitally signed")
        compact_report = {
            "risk_score": triage_report["risk_score"],
            "risk_level": triage_report["risk_level"],
            "file_info": triage_report.get("file_info", {}),
            "top_findings": findings[:8],
            "suggested_next_tools": triage_report.get("suggested_next_tools", []),
            "note": "Use get_triage_report(compact=False) for full details.",
            "workflow_hints": _TRIAGE_WORKFLOW_HINTS,
        }
        return await _check_mcp_response_size(ctx, compact_report, "get_triage_report")

    triage_report["workflow_hints"] = _TRIAGE_WORKFLOW_HINTS
    return await _check_mcp_response_size(ctx, triage_report, "get_triage_report", "the 'indicator_limit' parameter")
