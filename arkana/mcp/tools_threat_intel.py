"""MCP tools for threat intelligence — MITRE ATT&CK mapping and Sigma rule generation."""
import asyncio
import datetime
import json
import re

from typing import Dict, Any, List, Optional

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._refinery_helpers import _write_output_and_register_artifact


# ===================================================================
#  ATT&CK tactic ordering (kill chain)
# ===================================================================

_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

_TACTIC_SHORT = {
    "reconnaissance": "Recon",
    "resource-development": "Resource Dev",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Priv Esc",
    "defense-evasion": "Def Evasion",
    "credential-access": "Cred Access",
    "discovery": "Discovery",
    "lateral-movement": "Lat Movement",
    "collection": "Collection",
    "command-and-control": "C2",
    "exfiltration": "Exfil",
    "impact": "Impact",
}

# Import-to-ATT&CK mapping for common suspicious APIs
_IMPORT_ATTACK_MAP = {
    # Execution
    "CreateProcess": ("T1106", "execution", "Native API"),
    "WinExec": ("T1106", "execution", "Native API"),
    "ShellExecute": ("T1106", "execution", "Native API"),
    # Process injection
    "WriteProcessMemory": ("T1055", "defense-evasion", "Process Injection"),
    "CreateRemoteThread": ("T1055", "defense-evasion", "Process Injection"),
    "VirtualAllocEx": ("T1055", "defense-evasion", "Process Injection"),
    "NtUnmapViewOfSection": ("T1055.012", "defense-evasion", "Process Hollowing"),
    "QueueUserAPC": ("T1055.004", "defense-evasion", "Asynchronous Procedure Call"),
    "SetWindowsHookEx": ("T1055.003", "defense-evasion", "Thread Execution Hijacking"),
    # Persistence
    "RegSetValue": ("T1547.001", "persistence", "Registry Run Keys"),
    "CreateService": ("T1543.003", "persistence", "Windows Service"),
    # Credential access
    "MiniDumpWriteDump": ("T1003.001", "credential-access", "LSASS Memory"),
    "LsaEnumerateLogonSessions": ("T1003", "credential-access", "OS Credential Dumping"),
    "OpenProcessToken": ("T1134", "privilege-escalation", "Access Token Manipulation"),
    # Discovery
    "GetComputerName": ("T1082", "discovery", "System Information Discovery"),
    "GetUserName": ("T1033", "discovery", "System Owner/User Discovery"),
    "NetShareEnum": ("T1135", "discovery", "Network Share Discovery"),
    "GetAdaptersInfo": ("T1016", "discovery", "System Network Configuration"),
    # Anti-analysis / Defense evasion
    "IsDebuggerPresent": ("T1622", "defense-evasion", "Debugger Evasion"),
    "CheckRemoteDebuggerPresent": ("T1622", "defense-evasion", "Debugger Evasion"),
    "NtQueryInformationProcess": ("T1622", "defense-evasion", "Debugger Evasion"),
    "VirtualProtect": ("T1055", "defense-evasion", "Process Injection"),
    # Networking / C2
    "InternetOpen": ("T1071", "command-and-control", "Application Layer Protocol"),
    "HttpSendRequest": ("T1071.001", "command-and-control", "Web Protocols"),
    "URLDownloadToFile": ("T1105", "command-and-control", "Ingress Tool Transfer"),
    "WSAStartup": ("T1095", "command-and-control", "Non-Application Layer Protocol"),
    # Collection
    "GetClipboardData": ("T1115", "collection", "Clipboard Data"),
    "GetAsyncKeyState": ("T1056.001", "collection", "Keylogging"),
    "SetWindowsHookExA": ("T1056.001", "collection", "Keylogging"),
    # Impact
    "CryptEncrypt": ("T1486", "impact", "Data Encrypted for Impact"),
}


# ===================================================================
#  Internal MITRE mapping (callable from enrichment)
# ===================================================================

def _map_mitre_internal(current_state) -> Dict[str, Any]:
    """Map findings to MITRE ATT&CK synchronously. No MCP overhead."""
    from arkana.state import set_current_state
    set_current_state(current_state)

    pe_data = current_state.pe_data or {}
    triage = getattr(current_state, '_cached_triage', None) or {}

    techniques: Dict[str, Dict[str, Any]] = {}

    # capa ATT&CK mappings
    capa_analysis = pe_data.get("capa_analysis", {})
    if isinstance(capa_analysis, dict):
        results = capa_analysis.get("results", {})
        if isinstance(results, dict):
            rules = results.get("rules", {})
            for rule_name, rule_details in rules.items():
                meta = rule_details.get("meta", {})
                attck_entries = meta.get("att&ck", [])
                if not isinstance(attck_entries, list):
                    attck_entries = [attck_entries]
                for entry in attck_entries:
                    tech_id = None
                    tactic = None
                    tech_name = None
                    if isinstance(entry, dict):
                        tech_id = entry.get("id", "")
                        tactic = entry.get("tactic", "").lower().replace(" ", "-")
                        tech_name = entry.get("technique", entry.get("name", ""))
                    elif isinstance(entry, str):
                        m = re.search(r'\[?(T\d{4}(?:\.\d{3})?)\]?', entry)
                        if m:
                            tech_id = m.group(1)
                        tech_name = re.sub(r'\s*\[T\d{4}(?:\.\d{3})?\]', '', entry).strip()
                    if tech_id:
                        if tech_id not in techniques:
                            techniques[tech_id] = {
                                "id": tech_id, "name": tech_name or tech_id,
                                "tactic": tactic or "", "sources": [], "confidence": 0,
                            }
                        techniques[tech_id]["sources"].append({
                            "type": "capa",
                            "rule": meta.get("name", rule_name),
                            "namespace": meta.get("namespace", ""),
                        })
                        techniques[tech_id]["confidence"] = max(techniques[tech_id]["confidence"], 80)

    # Import-based mapping
    imports_data = pe_data.get("imports", [])
    if isinstance(imports_data, list):
        for dll_entry in imports_data:
            if not isinstance(dll_entry, dict):
                continue
            for sym in dll_entry.get("symbols", []):
                func_name = (sym.get("name") or "") if isinstance(sym, dict) else str(sym)
                mapping = _IMPORT_ATTACK_MAP.get(func_name)
                if not mapping:
                    for suffix in ("A", "W", "Ex", "ExA", "ExW"):
                        if func_name.endswith(suffix):
                            mapping = _IMPORT_ATTACK_MAP.get(func_name[:-len(suffix)])
                            if mapping:
                                break
                if mapping:
                    tech_id, tactic, tech_name = mapping
                    if tech_id not in techniques:
                        techniques[tech_id] = {
                            "id": tech_id, "name": tech_name, "tactic": tactic,
                            "sources": [], "confidence": 0,
                        }
                    techniques[tech_id]["sources"].append({
                        "type": "import", "function": func_name, "dll": dll_entry.get("dll", ""),
                    })
                    techniques[tech_id]["confidence"] = max(techniques[tech_id]["confidence"], 50)

    # Triage behavioral indicators
    sus_caps = triage.get("suspicious_capabilities", [])
    if isinstance(sus_caps, list):
        for cap in sus_caps:
            if not isinstance(cap, dict):
                continue
            ns = cap.get("namespace", "").lower()
            if "anti-analysis" in ns:
                _add_tactic_technique(techniques, "T1622", "defense-evasion",
                                      "Debugger Evasion", "triage_capability", cap.get("capability", ""))
            elif "persistence" in ns:
                _add_tactic_technique(techniques, "T1547", "persistence",
                                      "Boot or Logon Autostart Execution", "triage_capability", cap.get("capability", ""))
            elif "c2" in ns or "communication" in ns:
                _add_tactic_technique(techniques, "T1071", "command-and-control",
                                      "Application Layer Protocol", "triage_capability", cap.get("capability", ""))

    tactic_coverage: Dict[str, List[str]] = {t: [] for t in _TACTIC_ORDER}
    for tech in techniques.values():
        tactic = tech.get("tactic", "")
        if tactic in tactic_coverage:
            tactic_coverage[tactic].append(tech["id"])

    sorted_techniques = sorted(techniques.values(), key=lambda t: (-t["confidence"], t["id"]))

    return {
        "technique_count": len(sorted_techniques),
        "techniques": sorted_techniques,
        "tactic_coverage": {
            t: {"short_name": _TACTIC_SHORT.get(t, t), "technique_count": len(ids), "techniques": ids}
            for t, ids in tactic_coverage.items() if ids
        },
        "tactics_covered": sum(1 for ids in tactic_coverage.values() if ids),
        "tactics_total": len(_TACTIC_ORDER),
    }


# ===================================================================
#  Tool 1: map_mitre_attack
# ===================================================================

@tool_decorator
async def map_mitre_attack(
    ctx: Context,
    include_navigator_layer: bool = False,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: utility] Aggregates all MITRE ATT&CK-relevant findings from the
    current analysis: capa results, import classification, behavioral indicators,
    and string matches. Maps them to specific techniques with confidence scores
    and shows coverage across tactics.

    When to use: After analysis is complete. Provides a structured ATT&CK
    overview for reporting. Optionally outputs an ATT&CK Navigator layer.

    Next steps: add_note() to record key techniques, generate_analysis_report()
    for final report, generate_yara_rule() for detection.

    Args:
        ctx: MCP Context.
        include_navigator_layer: If True, include ATT&CK Navigator JSON layer
            in the output. Default False.
        output_path: (Optional[str]) Save Navigator layer JSON to this path and register as artifact.
            Requires include_navigator_layer=True.
    """
    await ctx.info("Mapping findings to MITRE ATT&CK")
    _check_pe_loaded("map_mitre_attack")

    # Return cached result if enrichment already mapped MITRE
    if not include_navigator_layer and state._cached_mitre_mapping:
        return state._cached_mitre_mapping

    pe_data = state.pe_data or {}
    triage = getattr(state, '_cached_triage', None) or {}

    def _map():
        # technique_id -> {name, tactic, sources[], confidence}
        techniques: Dict[str, Dict[str, Any]] = {}

        # --- 1. capa ATT&CK mappings (highest confidence) ---
        capa_analysis = pe_data.get("capa_analysis", {})
        if isinstance(capa_analysis, dict):
            results = capa_analysis.get("results", {})
            if isinstance(results, dict):
                rules = results.get("rules", {})
                for rule_name, rule_details in rules.items():
                    meta = rule_details.get("meta", {})
                    attck_entries = meta.get("att&ck", [])
                    if not isinstance(attck_entries, list):
                        attck_entries = [attck_entries]

                    for entry in attck_entries:
                        tech_id = None
                        tactic = None
                        tech_name = None

                        if isinstance(entry, dict):
                            tech_id = entry.get("id", "")
                            tactic = entry.get("tactic", "").lower().replace(" ", "-")
                            tech_name = entry.get("technique", entry.get("name", ""))
                        elif isinstance(entry, str):
                            # Parse "Technique Name [T1234.001]" format
                            m = re.search(r'\[?(T\d{4}(?:\.\d{3})?)\]?', entry)
                            if m:
                                tech_id = m.group(1)
                            tech_name = re.sub(r'\s*\[T\d{4}(?:\.\d{3})?\]', '', entry).strip()

                        if tech_id:
                            if tech_id not in techniques:
                                techniques[tech_id] = {
                                    "id": tech_id,
                                    "name": tech_name or tech_id,
                                    "tactic": tactic or "",
                                    "sources": [],
                                    "confidence": 0,
                                }
                            techniques[tech_id]["sources"].append({
                                "type": "capa",
                                "rule": meta.get("name", rule_name),
                                "namespace": meta.get("namespace", ""),
                            })
                            techniques[tech_id]["confidence"] = max(
                                techniques[tech_id]["confidence"], 80
                            )

        # --- 2. Import-based ATT&CK mapping (medium confidence) ---
        imports_data = pe_data.get("imports", [])
        if isinstance(imports_data, list):
            for dll_entry in imports_data:
                if not isinstance(dll_entry, dict):
                    continue
                for sym in dll_entry.get("symbols", []):
                    func_name = (sym.get("name") or "") if isinstance(sym, dict) else str(sym)
                    # Check exact and prefix matches
                    mapping = _IMPORT_ATTACK_MAP.get(func_name)
                    if not mapping:
                        # Try stripping A/W suffix
                        for suffix in ("A", "W", "Ex", "ExA", "ExW"):
                            if func_name.endswith(suffix):
                                mapping = _IMPORT_ATTACK_MAP.get(func_name[:-len(suffix)])
                                if mapping:
                                    break

                    if mapping:
                        tech_id, tactic, tech_name = mapping
                        if tech_id not in techniques:
                            techniques[tech_id] = {
                                "id": tech_id,
                                "name": tech_name,
                                "tactic": tactic,
                                "sources": [],
                                "confidence": 0,
                            }
                        techniques[tech_id]["sources"].append({
                            "type": "import",
                            "function": func_name,
                            "dll": dll_entry.get("dll", ""),
                        })
                        techniques[tech_id]["confidence"] = max(
                            techniques[tech_id]["confidence"], 50
                        )

        # --- 3. Triage behavioral indicators (low-medium confidence) ---
        sus_caps = triage.get("suspicious_capabilities", [])
        if isinstance(sus_caps, list):
            for cap in sus_caps:
                if not isinstance(cap, dict):
                    continue
                ns = cap.get("namespace", "").lower()
                # Map capa namespaces to ATT&CK tactics
                if "anti-analysis" in ns:
                    _add_tactic_technique(techniques, "T1622", "defense-evasion",
                                          "Debugger Evasion", "triage_capability", cap.get("capability", ""))
                elif "persistence" in ns:
                    _add_tactic_technique(techniques, "T1547", "persistence",
                                          "Boot or Logon Autostart Execution", "triage_capability", cap.get("capability", ""))
                elif "c2" in ns or "communication" in ns:
                    _add_tactic_technique(techniques, "T1071", "command-and-control",
                                          "Application Layer Protocol", "triage_capability", cap.get("capability", ""))

        # Build tactic coverage summary
        tactic_coverage: Dict[str, List[str]] = {t: [] for t in _TACTIC_ORDER}
        for tech in techniques.values():
            tactic = tech.get("tactic", "")
            if tactic in tactic_coverage:
                tactic_coverage[tactic].append(tech["id"])

        # Sort techniques by confidence
        sorted_techniques = sorted(
            techniques.values(),
            key=lambda t: (-t["confidence"], t["id"]),
        )

        result = {
            "technique_count": len(sorted_techniques),
            "techniques": sorted_techniques,
            "tactic_coverage": {
                t: {
                    "short_name": _TACTIC_SHORT.get(t, t),
                    "technique_count": len(ids),
                    "techniques": ids,
                }
                for t, ids in tactic_coverage.items()
                if ids  # Only include tactics with coverage
            },
            "tactics_covered": sum(1 for ids in tactic_coverage.values() if ids),
            "tactics_total": len(_TACTIC_ORDER),
        }

        # Optionally build Navigator layer
        if include_navigator_layer:
            result["navigator_layer"] = _build_navigator_layer(sorted_techniques)

        return result

    analysis = await asyncio.to_thread(_map)

    if output_path and analysis.get("navigator_layer"):
        text_bytes = json.dumps(analysis["navigator_layer"], indent=2).encode("utf-8")
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, text_bytes, "map_mitre_attack",
            f"ATT&CK Navigator layer ({analysis.get('technique_count', 0)} techniques)",
        )
        analysis["artifact"] = artifact_meta

    return await _check_mcp_response_size(ctx, analysis, "map_mitre_attack")


def _add_tactic_technique(
    techniques: Dict, tech_id: str, tactic: str, name: str,
    source_type: str, source_detail: str,
):
    """Helper to add a technique mapping."""
    if tech_id not in techniques:
        techniques[tech_id] = {
            "id": tech_id,
            "name": name,
            "tactic": tactic,
            "sources": [],
            "confidence": 0,
        }
    techniques[tech_id]["sources"].append({
        "type": source_type,
        "detail": source_detail,
    })
    techniques[tech_id]["confidence"] = max(
        techniques[tech_id]["confidence"], 40
    )


def _build_navigator_layer(techniques: List[Dict]) -> Dict[str, Any]:
    """Build an ATT&CK Navigator JSON layer."""
    layer_techniques = []
    for tech in techniques:
        score = min(tech["confidence"], 100)
        entry = {
            "techniqueID": tech["id"],
            "score": score,
            "comment": f"Sources: {len(tech['sources'])}",
            "enabled": True,
        }
        if tech.get("tactic"):
            entry["tactic"] = tech["tactic"]
        layer_techniques.append(entry)

    return {
        "name": "Arkana Analysis",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"Auto-generated from Arkana analysis — {len(techniques)} techniques",
        "techniques": layer_techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
    }


# ===================================================================
#  Tool 2: generate_sigma_rule
# ===================================================================

@tool_decorator
async def generate_sigma_rule(
    ctx: Context,
    rule_type: str = "process_creation",
    include_network: bool = True,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: utility] Generates draft Sigma detection rules from analysis findings:
    process creation patterns, file paths, registry keys, and network indicators
    inferred from strings, imports, and triage data. Output is valid Sigma YAML.

    IMPORTANT: Generated rules are starting points requiring analyst review —
    not production-ready detections. Each rule includes a confidence annotation.

    When to use: After analysis to create initial detection signatures for
    the sample's behavior.

    Next steps: Review and refine generated rules, add_note() to record.

    Args:
        ctx: MCP Context.
        rule_type: Primary rule type: 'process_creation' (default), 'file_event',
            'registry', or 'all'.
        include_network: Include network-based detection rules. Default True.
        output_path: (Optional[str]) Save combined Sigma YAML to this path and register as artifact.
    """
    await ctx.info("Generating draft Sigma rules")
    _check_pe_loaded("generate_sigma_rule")

    pe_data = state.pe_data or {}
    triage = getattr(state, '_cached_triage', None) or {}
    hashes = pe_data.get("file_hashes", {})

    def _generate():
        rules: List[Dict[str, Any]] = []
        valid_types = {"process_creation", "file_event", "registry", "all"}
        if rule_type not in valid_types:
            return {"error": f"Invalid rule_type. Options: {', '.join(sorted(valid_types))}"}

        sha256 = hashes.get("sha256", "unknown")
        filename = state.filepath.split("/")[-1] if state.filepath else "unknown"
        date_str = datetime.date.today().isoformat()

        # --- Process creation rule ---
        if rule_type in ("process_creation", "all"):
            proc_rule = _generate_process_creation_rule(
                pe_data, triage, sha256, filename, date_str,
            )
            if proc_rule:
                rules.append(proc_rule)

        # --- File event rule ---
        if rule_type in ("file_event", "all"):
            file_rule = _generate_file_event_rule(
                pe_data, triage, sha256, filename, date_str,
            )
            if file_rule:
                rules.append(file_rule)

        # --- Registry rule ---
        if rule_type in ("registry", "all"):
            reg_rule = _generate_registry_rule(
                pe_data, triage, sha256, filename, date_str,
            )
            if reg_rule:
                rules.append(reg_rule)

        # --- Network rule ---
        if include_network:
            net_rule = _generate_network_rule(
                triage, sha256, filename, date_str,
            )
            if net_rule:
                rules.append(net_rule)

        # Build combined YAML output
        yaml_parts = []
        for rule in rules:
            yaml_parts.append(rule["yaml"])

        return {
            "rule_count": len(rules),
            "rules": rules,
            "combined_yaml": "\n---\n".join(yaml_parts) if yaml_parts else "",
            "disclaimer": "DRAFT rules — review and refine before production use",
        }

    result = await asyncio.to_thread(_generate)

    if output_path and result.get("combined_yaml"):
        text_bytes = result["combined_yaml"].encode("utf-8")
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, text_bytes, "generate_sigma_rule",
            f"Sigma rules ({result.get('rule_count', 0)} rules)",
        )
        result["artifact"] = artifact_meta

    return await _check_mcp_response_size(ctx, result, "generate_sigma_rule")


def _generate_process_creation_rule(
    pe_data: Dict, triage: Dict, sha256: str, filename: str, date_str: str,
) -> Optional[Dict[str, Any]]:
    """Generate a process creation Sigma rule."""
    detection_items = []
    confidence = "low"

    # Hash-based detection
    md5 = pe_data.get("file_hashes", {}).get("md5", "")
    if md5:
        detection_items.append(f"        Hashes|contains: '{md5}'")
        confidence = "medium"

    # Image name
    if filename and filename != "unknown":
        detection_items.append(f"        Image|endswith: '\\\\{filename}'")

    # Suspicious parent-child from imports
    imports_data = pe_data.get("imports", [])
    exec_apis = set()
    if isinstance(imports_data, list):
        for dll_entry in imports_data:
            if not isinstance(dll_entry, dict):
                continue
            for sym in dll_entry.get("symbols", []):
                name = (sym.get("name") or "") if isinstance(sym, dict) else str(sym)
                if name.lower().startswith(("createprocess", "winexec", "shellexecute")):
                    exec_apis.add(name)

    if not detection_items:
        return None

    selection = "\n".join(detection_items)
    yaml = f"""title: 'Suspicious Process - {filename} (DRAFT)'
id: arkana-proc-{sha256[:8]}
status: experimental
description: >
    DRAFT detection rule generated by Arkana for sample {sha256[:16]}...
    Confidence: {confidence}. Requires analyst review before deployment.
references:
    - 'Generated by Arkana generate_sigma_rule'
author: Arkana (auto-generated)
date: {date_str}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
{selection}
    condition: selection
falsepositives:
    - Legitimate software with same name or hash
level: medium
tags:
    - attack.execution"""

    return {
        "type": "process_creation",
        "confidence": confidence,
        "yaml": yaml,
    }


def _generate_file_event_rule(
    pe_data: Dict, triage: Dict, sha256: str, filename: str, date_str: str,
) -> Optional[Dict[str, Any]]:
    """Generate a file event Sigma rule."""
    # Look for file paths in strings/IOCs
    file_paths = []
    net_iocs = triage.get("network_iocs", {})
    if isinstance(net_iocs, dict):
        for path in net_iocs.get("file_paths", []):
            if isinstance(path, str) and len(path) > 5:
                file_paths.append(path)

    # Also check notes for file paths
    notes = state.get_notes()
    for note in notes:
        content = note.get("content", "")
        # Simple file path extraction
        for m in re.finditer(r'[A-Z]:\\[^\s"\'<>]{5,100}', content):
            path = m.group()
            if path not in file_paths:
                file_paths.append(path)

    if not file_paths and filename == "unknown":
        return None

    detection_items = []
    if filename and filename != "unknown":
        detection_items.append(f"        TargetFilename|endswith: '\\\\{filename}'")
    for path in file_paths[:3]:
        escaped = path.replace("\\", "\\\\")
        detection_items.append(f"        TargetFilename|contains: '{escaped}'")

    if not detection_items:
        return None

    selection = "\n".join(detection_items)
    yaml = f"""title: 'Suspicious File Drop - {filename} (DRAFT)'
id: arkana-file-{sha256[:8]}
status: experimental
description: >
    DRAFT file event detection for sample {sha256[:16]}...
    Confidence: low. Requires analyst review.
author: Arkana (auto-generated)
date: {date_str}
logsource:
    category: file_event
    product: windows
detection:
    selection:
{selection}
    condition: selection
falsepositives:
    - Legitimate file operations at these paths
level: low"""

    return {
        "type": "file_event",
        "confidence": "low",
        "yaml": yaml,
    }


def _generate_registry_rule(
    pe_data: Dict, triage: Dict, sha256: str, filename: str, date_str: str,
) -> Optional[Dict[str, Any]]:
    """Generate a registry event Sigma rule."""
    reg_keys = []
    net_iocs = triage.get("network_iocs", {})
    if isinstance(net_iocs, dict):
        for key in net_iocs.get("registry_keys", []):
            if isinstance(key, str):
                reg_keys.append(key)

    # Check for persistence-related imports
    has_reg_apis = False
    imports_data = pe_data.get("imports", [])
    if isinstance(imports_data, list):
        for dll_entry in imports_data:
            if not isinstance(dll_entry, dict):
                continue
            for sym in dll_entry.get("symbols", []):
                name = (sym.get("name") or "") if isinstance(sym, dict) else str(sym)
                if name.lower().startswith(("regsetvalue", "regcreatekey")):
                    has_reg_apis = True

    if not reg_keys and not has_reg_apis:
        return None

    detection_items = []
    # Common persistence keys
    if has_reg_apis:
        detection_items.append("        TargetObject|contains:")
        detection_items.append("            - '\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'")
        detection_items.append("            - '\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce'")
    for key in reg_keys[:3]:
        escaped = key.replace("\\", "\\\\")
        detection_items.append(f"        TargetObject|contains: '{escaped}'")

    if not detection_items:
        return None

    selection = "\n".join(detection_items)
    yaml = f"""title: 'Suspicious Registry Modification - {filename} (DRAFT)'
id: arkana-reg-{sha256[:8]}
status: experimental
description: >
    DRAFT registry detection for sample {sha256[:16]}...
    Confidence: low. Requires analyst review.
author: Arkana (auto-generated)
date: {date_str}
logsource:
    category: registry_set
    product: windows
detection:
    selection:
{selection}
    condition: selection
falsepositives:
    - Legitimate software using same registry keys
level: low
tags:
    - attack.persistence
    - attack.t1547.001"""

    return {
        "type": "registry",
        "confidence": "low",
        "yaml": yaml,
    }


def _generate_network_rule(
    triage: Dict, sha256: str, filename: str, date_str: str,
) -> Optional[Dict[str, Any]]:
    """Generate a network connection Sigma rule."""
    net_iocs = triage.get("network_iocs", {})
    if not isinstance(net_iocs, dict):
        return None

    ips = net_iocs.get("ip_addresses", [])
    domains = net_iocs.get("domains", [])

    if not ips and not domains:
        return None

    detection_items = []
    if ips:
        detection_items.append("        DestinationIp:")
        for ip in ips[:5]:
            if isinstance(ip, str):
                detection_items.append(f"            - '{ip}'")
    if domains:
        detection_items.append("        DestinationHostname|contains:")
        for domain in domains[:5]:
            if isinstance(domain, str):
                detection_items.append(f"            - '{domain}'")

    if not detection_items:
        return None

    confidence = "medium" if len(ips) + len(domains) >= 2 else "low"
    selection = "\n".join(detection_items)
    yaml = f"""title: 'Suspicious Network Connection - {filename} (DRAFT)'
id: arkana-net-{sha256[:8]}
status: experimental
description: >
    DRAFT network detection for sample {sha256[:16]}...
    IOCs: {len(ips)} IPs, {len(domains)} domains.
    Confidence: {confidence}. Requires analyst review.
author: Arkana (auto-generated)
date: {date_str}
logsource:
    category: network_connection
    product: windows
detection:
    selection:
{selection}
    condition: selection
falsepositives:
    - Legitimate connections to listed IPs/domains
level: medium
tags:
    - attack.command-and-control"""

    return {
        "type": "network",
        "confidence": confidence,
        "yaml": yaml,
    }
