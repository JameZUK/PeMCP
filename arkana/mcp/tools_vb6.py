"""MCP tool for Visual Basic 6 binary analysis."""

import asyncio
import struct
from typing import Dict, Any, Optional, List

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._format_helpers import _get_filepath
from arkana.constants import MAX_TOOL_LIMIT
from arkana.parsers.vb6 import parse_vb6_header, is_vb6_binary


# Security-relevant VB6 external APIs to flag
_VB6_SECURITY_APIS = {
    # Dynamic API resolution
    "DllFunctionCall": ("CRITICAL", "Dynamic API resolver — can call any Windows API at runtime"),
    # Network access
    "URLDownloadToFile": ("HIGH", "Downloads file from URL"),
    "InternetOpen": ("HIGH", "Opens WinINet session"),
    "InternetConnect": ("HIGH", "Opens HTTP/FTP connection"),
    # Shell / execution
    "Shell": ("HIGH", "Launches external process"),
    "ShellExecute": ("HIGH", "Launches program or document"),
    "WinExec": ("HIGH", "Executes command"),
    "CreateProcess": ("HIGH", "Creates new process"),
    # Process injection
    "WriteProcessMemory": ("CRITICAL", "Writes to remote process memory"),
    "VirtualAllocEx": ("CRITICAL", "Allocates memory in remote process"),
    "CreateRemoteThread": ("CRITICAL", "Creates thread in remote process"),
    # File/registry
    "RegSetValueEx": ("MEDIUM", "Writes registry value"),
    "RegCreateKeyEx": ("MEDIUM", "Creates registry key"),
    "DeleteFile": ("MEDIUM", "Deletes a file"),
    "CopyFile": ("MEDIUM", "Copies a file"),
}


@tool_decorator
async def vb6_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    [Phase: triage] Analyse a Visual Basic 6 compiled PE: extract VB6 project
    metadata (name, GUID, language ID), form/module/class objects with method
    counts, and Declare Function external API declarations.

    ---compact: analyze VB6 PE — project metadata, forms/modules, Declare APIs | needs: file

    When to use: When get_triage_report() detects "Visual Basic 6" in
    compiler_language, or when MSVBVM60.DLL / MSVBVM50.DLL appears in imports.

    Next steps: get_focused_imports() to see which VB6 runtime APIs are flagged,
    decompile_function_with_angr() to inspect specific functions,
    search_floss_strings() to hunt for obfuscated strings.

    Args:
        file_path: Optional path to PE file. If None, uses the loaded file.
        limit: Max entries for objects and externals lists.
    """
    await ctx.info("Analysing VB6 binary metadata")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))

    if not state.pe_data:
        return {"error": "No PE file loaded. Use open_file() first."}

    target = _get_filepath(file_path)

    def _analyze() -> Dict[str, Any]:
        try:
            with open(target, "rb") as f:
                data = f.read()
        except (OSError, IOError) as exc:
            return {"error": f"Failed to read file: {exc}"}

        # Check for MSVBVM import — pe_data["imports"] is List[Dict]
        imports = state.pe_data.get("imports", [])
        vb_dlls = set()
        for dll_entry in imports:
            if isinstance(dll_entry, dict):
                dll_name = dll_entry.get("dll_name", "").lower()
                if dll_name in ("msvbvm60.dll", "msvbvm50.dll"):
                    vb_dlls.add(dll_name)

        if not vb_dlls:
            return {
                "error": "Not a VB6 binary — no MSVBVM60.DLL or MSVBVM50.DLL imports found.",
                "hint": "This tool is for Visual Basic 6 compiled executables only.",
            }

        # Get image base and sections from pe_object (pefile)
        pe = state.pe_object
        image_base = 0x400000
        sections = []
        if pe is not None:
            if hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
                image_base = getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0x400000)
            for sec in getattr(pe, 'sections', []):
                sections.append({
                    "virtual_address": sec.VirtualAddress,
                    "virtual_size": sec.Misc_VirtualSize,
                    "pointer_to_raw_data": sec.PointerToRawData,
                    "size_of_raw_data": sec.SizeOfRawData,
                })

        # Parse VB6 header
        vb_info = parse_vb6_header(data, image_base, sections)

        result: Dict[str, Any] = {
            "runtime_dlls": sorted(vb_dlls),
            "is_vb6": True,
        }

        # Project info
        project: Dict[str, Any] = {}
        if vb_info.get("project_name"):
            project["name"] = vb_info["project_name"]
        if vb_info.get("project_description"):
            project["description"] = vb_info["project_description"]
        if vb_info.get("project_exe_name"):
            project["exe_name"] = vb_info["project_exe_name"]
        if vb_info.get("guid"):
            project["guid"] = vb_info["guid"]
        if vb_info.get("language_id"):
            project["language_id"] = vb_info["language_id"]
        project["form_count"] = vb_info.get("form_count", 0)
        project["module_count"] = vb_info.get("module_count", 0)
        if project:
            result["project"] = project

        # Objects
        objects = vb_info.get("objects", [])
        if objects:
            result["object_count"] = len(objects)
            result["objects"] = objects[:limit]
            if len(objects) > limit:
                result["objects_truncated"] = True

        # Externals (Declare Function entries)
        externals = vb_info.get("externals", [])
        if externals:
            result["external_count"] = len(externals)
            result["externals"] = externals[:limit]
            if len(externals) > limit:
                result["externals_truncated"] = True

        # Security analysis of external declarations
        security_notes: List[str] = []
        flagged_apis: List[Dict[str, str]] = []

        # Check DllFunctionCall in imports (not externals)
        all_imports = set()
        for dll_entry in imports:
            if isinstance(dll_entry, dict):
                for sym in dll_entry.get("symbols", []):
                    if isinstance(sym, dict):
                        name = sym.get("name", "")
                        if name:
                            all_imports.add(name)

        if "DllFunctionCall" in all_imports:
            security_notes.append(
                "CRITICAL: DllFunctionCall imported — VB6 can resolve and call "
                "any Windows API dynamically at runtime, bypassing static import analysis"
            )

        # Scan externals for security-relevant APIs
        for ext in externals:
            func = ext.get("function", "")
            for api, (risk, desc) in _VB6_SECURITY_APIS.items():
                if api.lower() in func.lower():
                    flagged_apis.append({
                        "api": func,
                        "dll": ext.get("dll", ""),
                        "risk": risk,
                        "description": desc,
                    })

        if flagged_apis:
            result["flagged_apis"] = flagged_apis[:limit]
        if security_notes:
            result["security_notes"] = security_notes

        # Parse errors
        if vb_info.get("parse_errors"):
            result["parse_warnings"] = vb_info["parse_errors"]

        return result

    result = await asyncio.to_thread(_analyze)
    return await _check_mcp_response_size(ctx, result, "vb6_analyze", "the 'limit' parameter")
