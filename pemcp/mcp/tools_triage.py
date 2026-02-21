"""MCP tool for comprehensive automated binary triage."""
import math
import mmap
import os
import re
import struct
import datetime
import asyncio

from typing import Dict, Any, Optional, List, Tuple

from pemcp.config import (
    state, logger, Context, analysis_cache,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    STRINGSIFTER_AVAILABLE, YARA_AVAILABLE,
    PYELFTOOLS_AVAILABLE,
)
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size

if PYELFTOOLS_AVAILABLE:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection

if STRINGSIFTER_AVAILABLE:
    import stringsifter.lib.util as sifter_util
    import joblib


# ===================================================================
#  Suspicious Import Database (risk-categorized)
# ===================================================================

SUSPICIOUS_IMPORTS_DB = {
    # CRITICAL — Process injection / code execution
    "CreateRemoteThread": "CRITICAL", "NtCreateThreadEx": "CRITICAL",
    "RtlCreateUserThread": "CRITICAL", "WriteProcessMemory": "CRITICAL",
    "NtWriteVirtualMemory": "CRITICAL", "VirtualAllocEx": "CRITICAL",
    "NtAllocateVirtualMemory": "CRITICAL", "QueueUserAPC": "CRITICAL",
    "NtQueueApcThread": "CRITICAL", "SetWindowsHookEx": "CRITICAL",
    "NtMapViewOfSection": "CRITICAL", "NtUnmapViewOfSection": "CRITICAL",
    "ZwMapViewOfSection": "CRITICAL",
    # CRITICAL — Credential theft / privilege escalation
    "MiniDumpWriteDump": "CRITICAL", "LsaEnumerateLogonSessions": "CRITICAL",
    "AdjustTokenPrivileges": "CRITICAL", "ImpersonateLoggedOnUser": "CRITICAL",
    "OpenProcessToken": "CRITICAL", "DuplicateToken": "CRITICAL",
    "LdrLoadDll": "CRITICAL",
    # HIGH — Anti-analysis / evasion
    "IsDebuggerPresent": "HIGH", "CheckRemoteDebuggerPresent": "HIGH",
    "NtQueryInformationProcess": "HIGH", "OutputDebugString": "HIGH",
    "GetTickCount": "HIGH", "QueryPerformanceCounter": "HIGH",
    "NtSetInformationThread": "HIGH",
    # HIGH — Networking (C2 potential)
    "InternetOpen": "HIGH", "InternetConnect": "HIGH",
    "HttpOpenRequest": "HIGH", "HttpSendRequest": "HIGH",
    "URLDownloadToFile": "HIGH", "URLDownloadToCacheFile": "HIGH",
    "WinHttpOpen": "HIGH", "WinHttpConnect": "HIGH",
    # HIGH — Process/service manipulation
    "OpenProcess": "HIGH", "TerminateProcess": "HIGH",
    "CreateService": "HIGH", "StartService": "HIGH",
    "ShellExecute": "HIGH", "WinExec": "HIGH",
    "CreateProcess": "HIGH",
    # MEDIUM — Registry / persistence
    "RegSetValueEx": "MEDIUM", "RegCreateKeyEx": "MEDIUM",
    "RegDeleteKey": "MEDIUM", "RegDeleteValue": "MEDIUM",
    # MEDIUM — Crypto (ransomware indicators)
    "CryptEncrypt": "MEDIUM", "CryptDecrypt": "MEDIUM",
    "CryptAcquireContext": "MEDIUM", "BCryptEncrypt": "MEDIUM",
    "CryptDeriveKey": "MEDIUM", "CryptGenKey": "MEDIUM",
    # MEDIUM — File operations (dropper indicators)
    "CreateFileMapping": "MEDIUM", "MapViewOfFile": "MEDIUM",
    "VirtualProtect": "MEDIUM", "SetFileAttributes": "MEDIUM",
    # MEDIUM — Socket-level networking
    "WSAStartup": "MEDIUM", "connect": "MEDIUM",
    "send": "MEDIUM", "recv": "MEDIUM", "socket": "MEDIUM",
    "bind": "MEDIUM", "listen": "MEDIUM", "accept": "MEDIUM",
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

def _collect_all_string_values() -> set:
    """Gather all string values from floss analysis and basic ASCII strings."""
    all_string_values: set = set()

    if 'floss_analysis' in state.pe_data and isinstance(state.pe_data['floss_analysis'], dict):
        floss_strings = state.pe_data['floss_analysis'].get('strings')
        if isinstance(floss_strings, dict):
            for str_list in floss_strings.values():
                if isinstance(str_list, list):
                    for s in str_list:
                        if isinstance(s, dict):
                            all_string_values.add(s.get('string', ''))
                        elif isinstance(s, str):
                            all_string_values.add(s)

    basic_strings = state.pe_data.get('basic_ascii_strings')
    if isinstance(basic_strings, list):
        for s in basic_strings:
            if isinstance(s, dict):
                all_string_values.add(s.get('string', ''))
            elif isinstance(s, str):
                all_string_values.add(s)

    return all_string_values


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
    packer_names = [
        m.get('name', m.get('match', 'unknown')) if isinstance(m, dict) else str(m)
        for m in (ep_matches + heuristic_matches)
        if isinstance(m, (dict, str))
    ]
    if packer_names:
        risk_score += 4

    # Known packer section names
    PACKER_SECTION_NAMES = {'UPX0', 'UPX1', 'UPX2', '.aspack', '.adata', '.nsp0', '.nsp1',
                            '.perplex', '.themida', '.vmp0', '.vmp1', '.enigma1', '.petite'}
    suspicious_section_names: List[str] = []
    for sec in sections_data:
        if isinstance(sec, dict):
            name = sec.get('name', '').strip()
            if name in PACKER_SECTION_NAMES:
                suspicious_section_names.append(name)
                risk_score += 3

    is_likely_packed = (
        bool(packer_names)
        or len(high_entropy_sections) > 0
        or total_import_funcs < 10
        or bool(suspicious_section_names)
    )

    return {
        "likely_packed": is_likely_packed,
        "max_section_entropy": round(max_entropy, 3),
        "high_entropy_executable_sections": high_entropy_sections,
        "peid_matches": packer_names[:5],
        "total_import_functions": total_import_funcs,
        "minimal_imports": total_import_funcs < 10,
        "packer_section_names": suspicious_section_names,
    }, risk_score


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
        "suspicious_imports": found_imports[:indicator_limit],
        "suspicious_import_summary": {
            "critical": sum(1 for i in found_imports if i['risk'] == 'CRITICAL'),
            "high": sum(1 for i in found_imports if i['risk'] == 'HIGH'),
            "medium": sum(1 for i in found_imports if i['risk'] == 'MEDIUM'),
        },
    }, risk_score


# ===================================================================
#  Section 4 — Capa Capabilities (severity-mapped)
# ===================================================================

def _triage_capa_capabilities(indicator_limit: int) -> Tuple[List[Dict[str, Any]], int]:
    """Extract capa MITRE ATT&CK capability matches."""
    risk_score = 0
    capabilities: List[Dict[str, Any]] = []

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
            capabilities = capabilities[:indicator_limit]

    return capabilities, risk_score


# ===================================================================
#  Section 5 — Network IOC Extraction
# ===================================================================

def _triage_network_iocs(indicator_limit: int, all_string_values: set) -> Tuple[Dict[str, Any], int]:
    """Extract IPs, URLs, domains, and registry paths from strings."""
    risk_score = 0

    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    url_pattern = re.compile(r'(?:https?|ftp)://[^\s\'"<>]+', re.IGNORECASE)
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|su|onion)\b', re.IGNORECASE)
    registry_pattern = re.compile(r'(?:HKLM|HKCU|HKCR|HKU|HKCC|Software)\\[^\s\'"]+', re.IGNORECASE)

    # Iterate over strings individually instead of joining into one large blob.
    # This avoids a memory spike from the concatenated text and improves cache
    # locality since each string is small.
    found_ips: set = set()
    found_urls: set = set()
    found_domains: set = set()
    found_registry: set = set()

    for s in all_string_values:
        for m in ip_pattern.finditer(s):
            ip = m.group()
            octets = ip.split('.')
            if all(0 <= int(o) <= 255 for o in octets):
                first = int(octets[0])
                if first not in (0, 10, 127, 255) and not (first == 192 and int(octets[1]) == 168) and not (first == 172 and 16 <= int(octets[1]) <= 31):
                    found_ips.add(ip)
        for m in url_pattern.finditer(s):
            found_urls.add(m.group())
        for m in domain_pattern.finditer(s):
            found_domains.add(m.group().lower())
        for m in registry_pattern.finditer(s):
            found_registry.add(m.group())

    if found_ips or found_urls or found_domains:
        risk_score += 3

    return {
        "ip_addresses": sorted(found_ips)[:indicator_limit],
        "urls": sorted(found_urls)[:indicator_limit],
        "domains": sorted(found_domains)[:indicator_limit],
        "registry_paths": sorted(found_registry)[:indicator_limit],
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
        ent = sec.get('entropy', 0.0)

        if 'WRITE' in chars.upper() and 'EXECUTE' in chars.upper():
            anomalies.append({"section": name, "issue": "Write+Execute (W+X)", "severity": "HIGH"})
            risk_score += 2
        if isinstance(vsize, int) and isinstance(rsize, int) and vsize > 0 and rsize == 0:
            anomalies.append({"section": name, "issue": "Virtual size > 0 but raw size = 0 (runtime unpacking)", "severity": "MEDIUM"})
            risk_score += 1
        if isinstance(vsize, int) and isinstance(rsize, int) and rsize > 0 and vsize > rsize * 10:
            anomalies.append({"section": name, "issue": f"Virtual size ({vsize}) >> raw size ({rsize})", "severity": "MEDIUM"})
            risk_score += 1

    return anomalies[:indicator_limit], risk_score


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
            import_anom["ordinal_only_imports"] = ordinal_only_imports[:indicator_limit]
            import_anom["ordinal_only_count"] = len(ordinal_only_imports)
            if len(ordinal_only_imports) > 5:
                risk_score += 1  # Many ordinal-only imports can indicate evasion
        if unusual_dll_imports:
            import_anom["non_standard_dlls"] = sorted(set(unusual_dll_imports))[:indicator_limit]
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

        return res_anomalies[:indicator_limit], risk_score
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
        return yara_summary[:indicator_limit], risk_score
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
            for warn in pefile_warnings[:10]:
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
                        "issue": f"Section '{repr(name)}' contains non-printable characters",
                        "severity": "MEDIUM",
                        "source": "section_names",
                    })
                    risk_score += 1
                    break  # Only report once

    return header_anomalies[:indicator_limit], risk_score


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
                    "callback_addresses": [cb.get('va', cb.get('rva', '?')) for cb in callbacks[:10]],
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
                "suspicious_delay_loaded_apis": delay_suspicious[:indicator_limit],
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
            com_struct = com_desc.get('struct', {})
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
                export_anom["ordinal_only_values"] = ordinal_only_exports[:indicator_limit]
                if len(ordinal_only_exports) > total_exports * 0.5 and total_exports > 5:
                    risk_score += 1  # Majority ordinal-only exports suggest intentional obfuscation
            if forwarded_exports:
                export_anom["forwarded_count"] = len(forwarded_exports)
                export_anom["forwarded_exports"] = forwarded_exports[:indicator_limit]
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
                with open(state.filepath, 'rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        elf_sec["has_stack_canary"] = mm.find(b'__stack_chk_fail') != -1
                        elf_sec["has_fortify"] = (mm.find(b'__fortify_fail') != -1 or
                                                  mm.find(b'__chk_fail') != -1)
                        elf_sec["stripped"] = mm.find(b'.symtab') == -1
                        if elf_sec["stripped"]:
                            elf_sec["note_stripped"] = "Symbol table stripped — harder to analyze"
                        elf_sec["has_gnu_relro"] = mm.find(b'GNU_RELRO') != -1
                        elf_sec["has_nx"] = mm.find(b'GNU_STACK') != -1
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

    return sorted_indicators[:indicator_limit], risk_score


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
        detected["go_indicators"] = go_evidence[:5]

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
        detected["rust_indicators"] = rust_evidence[:5]

    # --- .NET is already detected in dotnet_indicators, just cross-reference ---
    if state.pe_data.get('com_descriptor'):
        if ".NET" not in detected["detected_languages"]:
            detected["detected_languages"].append(".NET")

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
                build_num = entry.get('build_number', 0)
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
#  Section 9 — Risk Score & Suggested Next Tools
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
            if not triage_report["suspicious_capabilities"]:
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
        if triage_report.get("tls_callbacks", {}).get("present") and triage_report["tls_callbacks"].get("callback_count", 0) > 0:
            suggested.append("get_pe_data(key='tls_info') — inspect TLS callback addresses")
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
    result["suggested_next_tools"] = suggested[:8]

    return result


# ===================================================================
#  Public tool — Orchestrator
# ===================================================================

@tool_decorator
async def get_triage_report(
    ctx: Context,
    sifter_score_threshold: float = 8.0,
    indicator_limit: int = 20,
    compact: bool = False,
) -> Dict[str, Any]:
    """
    Comprehensive automated triage of the loaded binary. Works across PE, ELF,
    Mach-O, and shellcode formats with format-specific analysis sections.

    Analyses 25+ dimensions including entropy, packing, digital signatures,
    suspicious imports, capa capabilities, network IOCs, section anomalies,
    timestamps, Rich header, overlay data, resources, YARA, header corruption,
    TLS callbacks, security mitigations (CFG/CET/ASLR/DEP), delay-load evasion,
    version info spoofing, .NET indicators, export anomalies, and platform-specific
    security features (ELF: PIE/NX/RELRO/canaries, Mach-O: code signing/PIE).

    Designed to give an AI analyst a complete first-look assessment without needing
    to call multiple individual tools.

    Args:
        ctx: The MCP Context object.
        sifter_score_threshold: (float) Min sifter score for high-value string indicators.
        indicator_limit: (int) Max items per category in the report.
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
        - risk_score / risk_level: cumulative risk assessment
        - suggested_next_tools: format-aware recommended next analysis steps
    """
    await ctx.info("Generating comprehensive triage report...")

    _check_pe_loaded("get_triage_report")

    risk_score = 0  # Cumulative risk score (higher = more suspicious)

    triage_report: Dict[str, Any] = {
        "file_info": {},
        "timestamp_analysis": {},
        "packing_assessment": {},
        "digital_signature": {},
        "rich_header_summary": {},
        "suspicious_imports": [],
        "import_anomalies": {},
        "suspicious_capabilities": [],
        "network_iocs": {},
        "section_anomalies": [],
        "overlay_analysis": {},
        "resource_anomalies": [],
        "yara_matches": [],
        "header_anomalies": [],
        "tls_callbacks": {},
        "security_mitigations": {},
        "delay_load_risks": {},
        "version_info_anomalies": {},
        "dotnet_indicators": {},
        "export_anomalies": {},
        "high_value_strings": [],
        "elf_security": {},
        "macho_security": {},
        "compiler_language": {},
        "risk_score": 0,
        "risk_level": "UNKNOWN",
        "suggested_next_tools": [],
    }

    # ---------------------------------------------------------------
    # 0. Basic file info
    # ---------------------------------------------------------------
    triage_report["file_info"] = _triage_file_info(indicator_limit)
    analysis_mode = triage_report["file_info"]["mode"]
    file_size = triage_report["file_info"]["file_size"]

    # ---------------------------------------------------------------
    # 0a. Timestamp Anomaly Detection
    # ---------------------------------------------------------------
    data, delta = _triage_timestamp_analysis(analysis_mode, indicator_limit)
    triage_report["timestamp_analysis"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 1. Packing Assessment
    # ---------------------------------------------------------------
    data, delta = _triage_packing_assessment(indicator_limit)
    triage_report["packing_assessment"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 2. Digital Signature Assessment
    # ---------------------------------------------------------------
    data, delta = _triage_digital_signature(indicator_limit)
    triage_report["digital_signature"] = data
    risk_score += delta
    sig_present = data["present"]
    sig_signer = data["signer"]

    # ---------------------------------------------------------------
    # 2a. Rich Header Summary
    # ---------------------------------------------------------------
    data, delta = _triage_rich_header(analysis_mode, indicator_limit)
    triage_report["rich_header_summary"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 3. Suspicious Imports
    # ---------------------------------------------------------------
    imports_result, delta = _triage_suspicious_imports(indicator_limit)
    triage_report["suspicious_imports"] = imports_result["suspicious_imports"]
    triage_report["suspicious_import_summary"] = imports_result["suspicious_import_summary"]
    risk_score += delta

    # ---------------------------------------------------------------
    # 4. Capa Capabilities
    # ---------------------------------------------------------------
    capa_data, delta = _triage_capa_capabilities(indicator_limit)
    triage_report["suspicious_capabilities"] = capa_data
    risk_score += delta

    # ---------------------------------------------------------------
    # 5. Network IOC Extraction
    # ---------------------------------------------------------------
    all_string_values = _collect_all_string_values()
    data, delta = _triage_network_iocs(indicator_limit, all_string_values)
    triage_report["network_iocs"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6. Section Anomalies
    # ---------------------------------------------------------------
    sec_data, delta = _triage_section_anomalies(indicator_limit)
    triage_report["section_anomalies"] = sec_data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6a. Overlay / Appended Data Analysis
    # ---------------------------------------------------------------
    data, delta = _triage_overlay_analysis(indicator_limit, file_size)
    triage_report["overlay_analysis"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6b. Import Anomalies
    # ---------------------------------------------------------------
    data, delta = _triage_import_anomalies(indicator_limit)
    triage_report["import_anomalies"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6c. Resource Anomalies
    # ---------------------------------------------------------------
    res_data, delta = _triage_resource_anomalies(indicator_limit)
    triage_report["resource_anomalies"] = res_data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6d. YARA Matches
    # ---------------------------------------------------------------
    yara_data, delta = _triage_yara_matches(indicator_limit)
    triage_report["yara_matches"] = yara_data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6e. Header Anomalies
    # ---------------------------------------------------------------
    hdr_data, delta = _triage_header_anomalies(indicator_limit)
    triage_report["header_anomalies"] = hdr_data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6f. TLS Callbacks
    # ---------------------------------------------------------------
    data, delta = _triage_tls_callbacks(indicator_limit)
    triage_report["tls_callbacks"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6g. Security Mitigations
    # ---------------------------------------------------------------
    data, delta = _triage_security_mitigations(indicator_limit)
    triage_report["security_mitigations"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6h. Delay-Load Suspicious API Detection
    # ---------------------------------------------------------------
    data, delta = _triage_delay_load_evasion(indicator_limit)
    triage_report["delay_load_risks"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6i. Version Info Anomaly Detection
    # ---------------------------------------------------------------
    data, delta = _triage_version_info(indicator_limit, sig_present, sig_signer)
    triage_report["version_info_anomalies"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6j. .NET Assembly Detection
    # ---------------------------------------------------------------
    data, delta = _triage_dotnet_indicators(indicator_limit)
    triage_report["dotnet_indicators"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6k. Export Anomalies
    # ---------------------------------------------------------------
    data, delta = _triage_export_anomalies(indicator_limit)
    triage_report["export_anomalies"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6l. ELF Security Features
    # ---------------------------------------------------------------
    data, delta = _triage_elf_security(indicator_limit)
    triage_report["elf_security"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 6m. Mach-O Security Features
    # ---------------------------------------------------------------
    data, delta = _triage_macho_security(indicator_limit)
    triage_report["macho_security"] = data
    risk_score += delta

    # ---------------------------------------------------------------
    # 7. High-Value String Indicators
    # ---------------------------------------------------------------
    hvs_data, delta = _triage_high_value_strings(sifter_score_threshold, indicator_limit, all_string_values)
    triage_report["high_value_strings"] = hvs_data
    risk_score += delta

    # ---------------------------------------------------------------
    # 8. Compiler / Language Detection
    # ---------------------------------------------------------------
    lang_data, delta = _triage_compiler_language(all_string_values)
    triage_report["compiler_language"] = lang_data
    risk_score += delta

    # ---------------------------------------------------------------
    # 9. Risk Score & Suggested Next Tools
    # ---------------------------------------------------------------
    risk_data = _triage_risk_and_suggestions(risk_score, analysis_mode, triage_report)
    triage_report["risk_score"] = risk_data["risk_score"]
    triage_report["risk_level"] = risk_data["risk_level"]
    triage_report["suggested_next_tools"] = risk_data["suggested_next_tools"]

    # Cache for use by get_analysis_digest and other progressive tools
    state._cached_triage = triage_report

    if compact:
        # Build compact summary: risk info + top findings as one-liners
        findings = []
        sus = triage_report.get("suspicious_imports", {})
        if isinstance(sus, dict):
            for imp in sus.get("items", [])[:3]:
                if isinstance(imp, dict):
                    findings.append(
                        f"Suspicious import: {imp.get('function', '?')} "
                        f"({imp.get('dll', '?')}) — {imp.get('severity', '?')}"
                    )
        packing = triage_report.get("packing_assessment", {})
        if isinstance(packing, dict) and packing.get("likely_packed"):
            packer = packing.get("packer_name", "unknown packer")
            findings.append(f"Likely packed ({packer})")
        net = triage_report.get("network_iocs", {})
        if isinstance(net, dict):
            for ioc_type in ("urls", "ip_addresses", "domains"):
                ioc_list = net.get(ioc_type, [])
                if isinstance(ioc_list, list) and ioc_list:
                    findings.append(f"{ioc_type}: {', '.join(str(x) for x in ioc_list[:3])}")
        caps = triage_report.get("suspicious_capabilities", {})
        if isinstance(caps, dict):
            for cap in caps.get("items", [])[:3]:
                if isinstance(cap, dict):
                    findings.append(f"Capability: {cap.get('rule', '?')} ({cap.get('namespace', '?')})")
        sig = triage_report.get("digital_signature", {})
        if isinstance(sig, dict):
            if not sig.get("embedded_signature_present"):
                findings.append("Not digitally signed")
        compact_report = {
            "risk_score": triage_report["risk_score"],
            "risk_level": triage_report["risk_level"],
            "file_info": triage_report.get("file_info", {}),
            "top_findings": findings[:8],
            "suggested_next_tools": triage_report.get("suggested_next_tools", []),
            "note": "Use get_triage_report(compact=False) for full details.",
        }
        return await _check_mcp_response_size(ctx, compact_report, "get_triage_report")

    return await _check_mcp_response_size(ctx, triage_report, "get_triage_report", "the 'indicator_limit' parameter")
