"""MCP tools for Frida script generation — hooks, bypasses, and API tracing."""
import asyncio
import os

from typing import Dict, Any, Optional, List

from arkana.config import state, logger, Context
from arkana.constants import MAX_FRIDA_HOOK_TARGETS, MAX_FRIDA_TRACE_APIS, MAX_TOOL_LIMIT
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._frida_templates import (
    FRIDA_API_SIGNATURES,
    ANTI_DEBUG_BYPASSES,
    ANTI_DEBUG_APIS,
    generate_hook_js,
    generate_hook_for_address,
    generate_bypass_js,
    generate_trace_js,
    generate_stalker_coverage_js,
    generate_anti_vm_bypass_js,
    generate_injection_detector_js,
    generate_api_logger_js,
)


import re as _re

# Allowed characters for Frida target names (API names, module names).
# Prevents JS code injection via string literal breakout.
_SAFE_TARGET_RE = _re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.@#$:]*$')


def _sanitize_js_string(value: str) -> str:
    """Escape a string for safe interpolation into JS string literals."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")


def _validate_targets(targets: List[str]) -> List[str]:
    """Validate and sanitise hook target list."""
    if not targets:
        raise ValueError("targets list cannot be empty.")
    if len(targets) > MAX_FRIDA_HOOK_TARGETS:
        raise ValueError(f"Too many targets ({len(targets)}). Maximum is {MAX_FRIDA_HOOK_TARGETS}.")
    cleaned = []
    for t in targets:
        if not isinstance(t, str):
            raise ValueError(f"Invalid target type: {type(t).__name__}. Expected string.")
        t = t.strip()
        if not t:
            continue
        if len(t) > 256:
            raise ValueError(f"Target name too long ({len(t)} chars). Maximum is 256.")
        if not _SAFE_TARGET_RE.match(t) and not t.startswith("0x"):
            raise ValueError(f"Invalid target name: {t[:50]!r}. Must be alphanumeric/underscore (or hex address).")
        cleaned.append(t)
    if not cleaned:
        raise ValueError("No valid targets after validation.")
    return cleaned


def _save_script(output_path: Optional[str], script_text: str, tool_name: str) -> Optional[Dict[str, Any]]:
    """Optionally save script to disk and register as artifact."""
    if not output_path:
        return None
    resolved = os.path.realpath(output_path)
    state.check_path_allowed(resolved)
    script_bytes = script_text.encode("utf-8")
    from arkana.mcp._refinery_helpers import _write_output_and_register_artifact
    return _write_output_and_register_artifact(
        resolved, script_bytes, tool_name, f"Frida script ({tool_name})"
    )


def _collect_import_names(pe_data):
    """Extract (api_name, dll_name) tuples from pe_data imports.

    Handles the canonical format:
        [{"dll_name": "kernel32.dll", "symbols": [{"name": "CreateProcessA"}, ...]}]
    And a defensive dict-keyed-by-DLL fallback:
        {"kernel32.dll": [{"name": "CreateProcessA"}, ...]}
    """
    if not pe_data:
        return set()
    imports = pe_data.get("imports")
    if not imports:
        return set()
    result = set()
    if isinstance(imports, list):
        for entry in imports:
            if not isinstance(entry, dict):
                continue
            dll = entry.get("dll_name", "") or ""
            symbols = entry.get("symbols")
            if isinstance(symbols, list):
                for sym in symbols:
                    if isinstance(sym, dict):
                        name = sym.get("name", "")
                        if name:
                            result.add((name, dll))
                    elif isinstance(sym, str) and sym:
                        result.add((sym, dll))
    elif isinstance(imports, dict):
        for dll_name, dll_imports in imports.items():
            if isinstance(dll_imports, list):
                for imp in dll_imports:
                    if isinstance(imp, dict):
                        name = imp.get("name", "")
                        if name:
                            result.add((name, dll_name))
                    elif isinstance(imp, str) and imp:
                        result.add((imp, dll_name))
    return result


@tool_decorator
async def generate_frida_hook_script(
    ctx: Context,
    targets: List[str],
    include_backtrace: bool = True,
    include_args: bool = True,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Generate a Frida hook script for specified API functions or addresses.

    ---compact: generate Frida JS hook script for APIs/addresses | args + backtrace | needs: file

    Produces JavaScript code ready to run with Frida to intercept API calls,
    log arguments, return values, and optionally capture backtraces.

    When to use: When you want to dynamically instrument a binary to observe API usage
    at runtime. Useful for tracing C2 communication, crypto operations, or injection techniques.
    Next steps: Run the generated script with Frida, add_note() to record observations.

    Args:
        targets: List of API names (e.g. 'CreateRemoteThread') or hex addresses (e.g. '0x401000'). Max 50.
        include_backtrace: Include call stack backtrace in hook output. Default True.
        include_args: Include argument values in hook output. Default True.
        output_path: Optional file path to save the generated script.
    """
    targets = _validate_targets(targets)

    hook_parts = [
        '"use strict";',
        "",
        "// ============================================",
        "// Arkana Hook Script (Frida)",
        "// ============================================",
        "",
    ]

    hooked_apis = []
    hooked_addresses = []
    unknown_targets = []

    for target in targets:
        target_stripped = target.strip()
        if target_stripped.startswith("0x") or target_stripped.startswith("0X"):
            # Raw address hook
            hook_parts.append(generate_hook_for_address(target_stripped, include_backtrace))
            hook_parts.append("")
            hooked_addresses.append(target_stripped)
        elif target_stripped in FRIDA_API_SIGNATURES:
            # Known API with signature
            hook_parts.append(generate_hook_js(
                target_stripped,
                include_backtrace=include_backtrace,
                include_args=include_args,
            ))
            hook_parts.append("")
            hooked_apis.append(target_stripped)
        else:
            # Unknown API — generate generic hook
            hook_parts.append(generate_hook_js(
                target_stripped,
                include_backtrace=include_backtrace,
                include_args=False,
            ))
            hook_parts.append("")
            unknown_targets.append(target_stripped)

    total = len(hooked_apis) + len(hooked_addresses) + len(unknown_targets)
    hook_parts.append(f'console.log("[ARKANA] {total} hooks installed");')

    script_text = "\n".join(hook_parts)

    result: Dict[str, Any] = {
        "script": script_text,
        "hooked_apis": hooked_apis,
        "hooked_addresses": hooked_addresses,
        "unknown_targets": unknown_targets,
        "total_hooks": total,
        "usage": "frida -l <script.js> -p <PID>  OR  frida -l <script.js> -f <binary>",
    }

    artifact = _save_script(output_path, script_text, "generate_frida_hook_script")
    if artifact:
        result["saved_to"] = artifact.get("path", output_path)

    return await _check_mcp_response_size(ctx, result, "generate_frida_hook_script")


@tool_decorator
async def generate_frida_bypass_script(
    ctx: Context,
    auto_detect: bool = True,
    techniques: Optional[List[str]] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Generate a Frida script that bypasses anti-debug techniques.

    ---compact: generate Frida anti-debug bypass script | auto-detect from imports | needs: file

    Auto-detects anti-debug APIs from the binary's imports and triage data,
    then generates targeted bypass code for each detected technique.

    When to use: When the binary uses anti-debug techniques that prevent dynamic analysis.
    Run the generated script alongside the target to neutralise debug detection.
    Next steps: Run with Frida, then use generate_frida_hook_script() for further instrumentation.

    Args:
        auto_detect: Automatically detect anti-debug techniques from imports/triage. Default True.
        techniques: Manual list of technique names to bypass (overrides auto_detect).
            Available: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess,
            NtSetInformationThread, OutputDebugStringA, GetTickCount, QueryPerformanceCounter,
            NtClose, BlockInput, NtQuerySystemInformation.
        output_path: Optional file path to save the generated script.
    """
    detected_techniques = []

    if techniques:
        # Manual override
        for tech in techniques:
            if not isinstance(tech, str):
                continue
            tech = tech.strip()
            if tech in ANTI_DEBUG_BYPASSES:
                detected_techniques.append(tech)
        if not detected_techniques:
            available = ", ".join(sorted(ANTI_DEBUG_BYPASSES.keys()))
            return {
                "error": "None of the specified techniques have bypass templates.",
                "available_techniques": available,
            }
    elif auto_detect:
        # Detect from imports
        pe_data = state.pe_data or {}
        all_imports = _collect_import_names(pe_data)
        import_names = {name for name, _dll in all_imports}

        # Match against known anti-debug APIs
        for api in import_names:
            if api in ANTI_DEBUG_APIS and api in ANTI_DEBUG_BYPASSES:
                detected_techniques.append(api)

        # Also check triage data for anti-debug findings
        triage = getattr(state, "_cached_triage", None) or {}
        anti_debug = triage.get("anti_debug_techniques") or triage.get("anti_analysis") or []
        if isinstance(anti_debug, list):
            for tech_info in anti_debug:
                if isinstance(tech_info, dict):
                    api = tech_info.get("api") or tech_info.get("name", "")
                    if api in ANTI_DEBUG_BYPASSES and api not in detected_techniques:
                        detected_techniques.append(api)

        if not detected_techniques:
            return {
                "status": "no_anti_debug_detected",
                "message": "No anti-debug techniques detected in imports or triage data.",
                "hint": "Use techniques=['IsDebuggerPresent', ...] to manually specify bypasses.",
                "available_techniques": sorted(ANTI_DEBUG_BYPASSES.keys()),
            }

    # Sort for deterministic output
    detected_techniques.sort()
    script_text = generate_bypass_js(detected_techniques)

    result: Dict[str, Any] = {
        "script": script_text,
        "bypassed_techniques": detected_techniques,
        "total_bypasses": len(detected_techniques),
        "usage": "frida -l <script.js> -p <PID>  OR  frida -l <script.js> -f <binary>",
    }

    artifact = _save_script(output_path, script_text, "generate_frida_bypass_script")
    if artifact:
        result["saved_to"] = artifact.get("path", output_path)

    return await _check_mcp_response_size(ctx, result, "generate_frida_bypass_script")


@tool_decorator
async def generate_frida_trace_script(
    ctx: Context,
    categories: Optional[List[str]] = None,
    limit: int = 50,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Generate a Frida API tracing script based on the binary's imports.

    ---compact: generate Frida API trace script from imports | filter by category | needs: file

    Identifies suspicious/interesting APIs from the binary's import table and generates
    a comprehensive tracing script that logs all calls with arguments and return values.

    When to use: When you want a broad view of the binary's runtime API behaviour.
    Filter by category to focus on specific behaviours (networking, crypto, injection, etc.).
    Next steps: Run with Frida, then generate_frida_hook_script() for targeted hooks.

    Args:
        categories: Filter APIs by category. Options: process_injection, process_creation,
            memory, networking, file_io, registry, crypto, anti_debug, service, thread.
            Default: all categories.
        limit: Maximum number of APIs to include in the script (1-100000). Default 50.
        output_path: Optional file path to save the generated script.
    """
    _check_pe_loaded("generate_frida_trace_script")

    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    valid_categories = {
        "process_injection", "process_creation", "memory", "networking",
        "file_io", "registry", "crypto", "anti_debug", "service", "thread",
    }
    if categories:
        invalid = [c for c in categories if c not in valid_categories]
        if invalid:
            return {
                "error": f"Invalid categories: {invalid}",
                "valid_categories": sorted(valid_categories),
            }

    # Gather APIs from imports
    pe_data = state.pe_data or {}
    import_names = _collect_import_names(pe_data)

    # Match against signature database
    apis_to_trace: List[Dict[str, Any]] = []
    for api_name, sig_info in FRIDA_API_SIGNATURES.items():
        for imp_name, imp_dll in import_names:
            if imp_name == api_name:
                apis_to_trace.append({
                    "name": api_name,
                    "module": imp_dll if imp_dll else None,
                    "category": sig_info.get("category", "unknown"),
                })
                break

    # Also add imports that match CATEGORIZED_IMPORTS_DB but aren't in FRIDA_API_SIGNATURES
    try:
        from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB
        for imp_name, imp_dll in import_names:
            if imp_name in CATEGORIZED_IMPORTS_DB and imp_name not in FRIDA_API_SIGNATURES:
                risk, cat = CATEGORIZED_IMPORTS_DB[imp_name]
                apis_to_trace.append({
                    "name": imp_name,
                    "module": imp_dll if imp_dll else None,
                    "category": cat,
                })
    except ImportError:
        pass

    # Deduplicate by name
    seen = set()
    unique_apis = []
    for api in apis_to_trace:
        if api["name"] not in seen:
            seen.add(api["name"])
            unique_apis.append(api)

    # Apply category filter
    if categories:
        unique_apis = [a for a in unique_apis if a.get("category") in categories]

    # Apply limit
    unique_apis = unique_apis[:limit]

    if not unique_apis:
        return {
            "status": "no_matching_apis",
            "message": "No matching APIs found in the binary's imports.",
            "hint": "Try without category filter, or use generate_frida_hook_script() with specific targets.",
            "available_categories": sorted(valid_categories),
        }

    script_text = generate_trace_js(unique_apis, categories)

    # Group by category for summary
    by_category: Dict[str, List[str]] = {}
    for api in unique_apis:
        cat = api.get("category", "unknown")
        by_category.setdefault(cat, []).append(api["name"])

    result: Dict[str, Any] = {
        "script": script_text,
        "traced_apis": [a["name"] for a in unique_apis],
        "total_apis": len(unique_apis),
        "by_category": by_category,
        "usage": "frida -l <script.js> -p <PID>  OR  frida -l <script.js> -f <binary>",
    }

    artifact = _save_script(output_path, script_text, "generate_frida_trace_script")
    if artifact:
        result["saved_to"] = artifact.get("path", output_path)

    return await _check_mcp_response_size(ctx, result, "generate_frida_trace_script")


@tool_decorator
async def generate_frida_stalker_script(
    ctx: Context,
    script_type: str = "coverage",
    target_module: Optional[str] = None,
    apis: Optional[List[str]] = None,
    output_format: str = "drcov",
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Generate advanced Frida DBI scripts: Stalker coverage, anti-VM bypass, injection detection, or structured API logging.

    ---compact: generate Frida Stalker/anti-VM/injection/logger script | drcov or JSON output | needs: file

    Generates specialised Frida scripts for dynamic binary instrumentation scenarios
    beyond simple API hooking. Supports four script types:

    - **coverage**: Stalker-based basic-block coverage collection in drcov or JSON format.
      Compatible with Lighthouse, dragondance, and other coverage visualisation tools.
    - **anti_vm**: Bypasses common VM detection — registry keys, SMBIOS strings,
      process enumeration, and MAC address checks.
    - **injection_detector**: Monitors VirtualAllocEx/WriteProcessMemory/CreateRemoteThread/
      NtMapViewOfSection and detects the classic injection sequence.
    - **api_logger**: Structured JSON logging of specified APIs with full argument resolution.

    When to use: When you need DBI-level instrumentation beyond simple hooks — e.g. collecting
    code coverage for a fuzzer, bypassing VM-aware malware, or detecting injection behaviour.
    Next steps: Run with Frida, then add_note() to record findings.

    Args:
        script_type: Type of script to generate. One of: 'coverage', 'anti_vm',
            'injection_detector', 'api_logger'.
        target_module: Module name for Stalker coverage (e.g. 'sample.exe'). Default: main binary.
            Only used when script_type='coverage'.
        apis: List of API names for api_logger script type. Max 50.
            Only used when script_type='api_logger'.
        output_format: Output format for coverage scripts: 'drcov' or 'json'. Default 'drcov'.
            Only used when script_type='coverage'.
        output_path: Optional file path to save the generated script.
    """
    valid_types = {"coverage", "anti_vm", "injection_detector", "api_logger"}
    if script_type not in valid_types:
        return {
            "error": f"Invalid script_type: {script_type!r}",
            "valid_types": sorted(valid_types),
        }

    tool_name = "generate_frida_stalker_script"

    if script_type == "coverage":
        if output_format not in ("drcov", "json"):
            return {
                "error": f"Invalid output_format: {output_format!r}. Must be 'drcov' or 'json'.",
            }
        script_text = generate_stalker_coverage_js(
            target_module=target_module,
            output_format=output_format,
        )
        result: Dict[str, Any] = {
            "script": script_text,
            "script_type": "coverage",
            "target_module": target_module or "(main binary)",
            "output_format": output_format,
            "usage": "frida -l <script.js> -f <binary>  # then rpc.exports.dump() to collect",
        }

    elif script_type == "anti_vm":
        script_text = generate_anti_vm_bypass_js()
        result = {
            "script": script_text,
            "script_type": "anti_vm",
            "bypasses": [
                "RegOpenKeyExA/W (VM registry keys)",
                "GetSystemFirmwareTable (SMBIOS scrub)",
                "Process32FirstW/NextW (VM process hiding)",
                "GetAdaptersInfo (MAC prefix masking)",
            ],
            "usage": "frida -l <script.js> -f <binary>",
        }

    elif script_type == "injection_detector":
        script_text = generate_injection_detector_js()
        result = {
            "script": script_text,
            "script_type": "injection_detector",
            "monitored_apis": [
                "VirtualAllocEx", "WriteProcessMemory",
                "CreateRemoteThread", "NtMapViewOfSection",
            ],
            "sequence_detection": "VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread",
            "usage": "frida -l <script.js> -f <binary>  # alerts via send()",
        }

    elif script_type == "api_logger":
        if not apis:
            return {
                "error": "apis parameter is required for script_type='api_logger'.",
                "hint": "Provide a list of API names, e.g. apis=['CreateFileA', 'WriteFile']",
            }
        apis = _validate_targets(apis)
        script_text = generate_api_logger_js(
            apis=apis,
            include_args=True,
            include_backtrace=False,
        )
        known = [a for a in apis if a in FRIDA_API_SIGNATURES]
        unknown = [a for a in apis if a not in FRIDA_API_SIGNATURES]
        result = {
            "script": script_text,
            "script_type": "api_logger",
            "logged_apis": apis,
            "known_signatures": known,
            "generic_hooks": unknown,
            "total_apis": len(apis),
            "usage": "frida -l <script.js> -f <binary>  # JSON events via send()",
        }

    artifact = _save_script(output_path, script_text, tool_name)
    if artifact:
        result["saved_to"] = artifact.get("path", output_path)

    return await _check_mcp_response_size(ctx, result, tool_name)
