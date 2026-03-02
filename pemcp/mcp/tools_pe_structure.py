"""MCP tools for deep PE structure analysis — relocations, SEH, and debug directories."""
import asyncio
import struct

from typing import Dict, Any, List, Optional

from pemcp.config import state, logger, Context, pefile
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size


# ===================================================================
#  Relocation type names (IMAGE_REL_BASED_*)
# ===================================================================

_RELOC_TYPE_NAMES = {
    0: "ABSOLUTE",      # Padding, no relocation
    1: "HIGH",
    2: "LOW",
    3: "HIGHLOW",       # Most common for x86
    4: "HIGHADJ",
    5: "MIPS_JMPADDR",  # Also ARM_MOV32
    6: "RESERVED",
    7: "MIPS_JMPADDR16",
    9: "IA64_IMM64",
    10: "DIR64",        # Most common for x64
}


# ===================================================================
#  Tool 1: analyze_relocations
# ===================================================================

@tool_decorator
async def analyze_relocations(
    ctx: Context,
    limit: int = 30,
) -> Dict[str, Any]:
    """
    [Phase: explore] Parses the BASE_RELOC directory to enumerate relocation blocks,
    types, and anomalies. Detects ASLR bypass indicators, relocations pointing
    outside sections, unusual type distributions, and empty/malformed blocks.

    When to use: When investigating packed binaries, position-independent shellcode,
    ASLR bypass techniques, or when triage flags missing or suspicious relocations.

    Next steps: If anomalies found → get_hex_dump() to inspect suspicious blocks,
    decompile_function_with_angr() on functions at anomalous addresses.
    Record findings with add_note().

    Args:
        ctx: MCP Context.
        limit: Max relocation blocks to return in detail. Default 30.
    """
    await ctx.info("Analyzing relocation table")
    _check_pe_loaded("analyze_relocations")

    pe = state.pe_object
    pe_data = state.pe_data or {}

    def _analyze():
        result: Dict[str, Any] = {}

        # Check if relocations exist
        if not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') or not pe.DIRECTORY_ENTRY_BASERELOC:
            # Check if reloc directory was stripped or empty
            nt = pe_data.get("nt_headers", {})
            oh = nt.get("optional_header", {}) if isinstance(nt, dict) else {}
            dll_chars = oh.get("dll_characteristics", 0)
            if isinstance(dll_chars, dict):
                dll_chars = dll_chars.get("Value", 0)
            aslr_enabled = bool(isinstance(dll_chars, int) and dll_chars & 0x0040)

            fh = nt.get("file_header", {}) if isinstance(nt, dict) else {}
            chars = fh.get("characteristics", fh.get("Characteristics", 0))
            if isinstance(chars, dict):
                chars = chars.get("Value", 0)
            relocs_stripped = bool(isinstance(chars, int) and chars & 0x0001)

            result["has_relocations"] = False
            result["relocs_stripped"] = relocs_stripped
            result["aslr_enabled"] = aslr_enabled
            anomalies = []
            if aslr_enabled and (relocs_stripped or not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC')):
                anomalies.append({
                    "type": "aslr_no_relocs",
                    "severity": "high",
                    "description": "ASLR flag set but relocations stripped/absent — binary cannot be relocated, possible ASLR bypass indicator",
                })
            result["anomalies"] = anomalies
            return result

        # Collect section ranges for bounds checking
        sections = []
        for sec in pe.sections:
            sections.append({
                "name": sec.Name.decode('utf-8', 'ignore').strip('\x00'),
                "va_start": sec.VirtualAddress,
                "va_end": sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData),
                "writable": bool(sec.Characteristics & 0x80000000),
                "executable": bool(sec.Characteristics & 0x20000000),
            })

        total_entries = 0
        type_counts: Dict[str, int] = {}
        blocks_detail: List[Dict[str, Any]] = []
        anomalies: List[Dict[str, Any]] = []
        blocks_with_anomalies = 0

        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            block_rva = base_reloc.struct.VirtualAddress
            block_size = base_reloc.struct.SizeOfBlock
            entries = getattr(base_reloc, 'entries', [])

            block_info: Dict[str, Any] = {
                "rva": hex(block_rva),
                "size": block_size,
                "entry_count": len(entries),
                "types": {},
            }

            block_anomalies: List[str] = []

            # Check block is within a section
            in_section = False
            for sec in sections:
                if sec["va_start"] <= block_rva < sec["va_end"]:
                    in_section = True
                    block_info["section"] = sec["name"]
                    break
            if not in_section and block_rva != 0:
                block_anomalies.append("Block RVA outside any section")

            # Check for empty blocks
            if len(entries) == 0 and block_size > 8:
                block_anomalies.append(f"Empty block with size {block_size}")

            # Analyze entries
            entry_types: Dict[str, int] = {}
            oob_count = 0
            for entry in entries:
                type_name = _RELOC_TYPE_NAMES.get(entry.type, f"UNKNOWN_{entry.type}")
                entry_types[type_name] = entry_types.get(type_name, 0) + 1
                type_counts[type_name] = type_counts.get(type_name, 0) + 1
                total_entries += 1

                # Check if entry points outside any section
                if entry.type != 0:  # Skip padding entries
                    entry_rva = entry.rva
                    in_any_section = False
                    for sec in sections:
                        if sec["va_start"] <= entry_rva < sec["va_end"]:
                            in_any_section = True
                            break
                    if not in_any_section:
                        oob_count += 1

            if oob_count > 0:
                block_anomalies.append(f"{oob_count} entries point outside any section")

            # Check for unusual types
            for t_name in entry_types:
                if t_name.startswith("UNKNOWN_"):
                    block_anomalies.append(f"Unknown relocation type: {t_name}")

            block_info["types"] = entry_types
            if block_anomalies:
                block_info["anomalies"] = block_anomalies
                blocks_with_anomalies += 1
                for a in block_anomalies:
                    anomalies.append({
                        "type": "block_anomaly",
                        "severity": "medium",
                        "block_rva": hex(block_rva),
                        "description": a,
                    })

            blocks_detail.append(block_info)

        # Check ASLR flag consistency
        nt = pe_data.get("nt_headers", {})
        oh = nt.get("optional_header", {}) if isinstance(nt, dict) else {}
        dll_chars = oh.get("dll_characteristics", 0)
        if isinstance(dll_chars, dict):
            dll_chars = dll_chars.get("Value", 0)
        aslr_enabled = bool(isinstance(dll_chars, int) and dll_chars & 0x0040)

        # Determine expected primary type
        machine = pe.FILE_HEADER.Machine
        is_64bit = machine in (
            pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_AMD64', 0x8664),
            pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_ARM64', 0xAA64),
            pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_IA64', 0x200),
        )
        expected_type = "DIR64" if is_64bit else "HIGHLOW"
        unexpected_types = {t for t in type_counts if t not in ("ABSOLUTE", expected_type)}
        if unexpected_types:
            anomalies.append({
                "type": "unexpected_reloc_types",
                "severity": "low",
                "description": f"Unexpected relocation types for {'x64' if is_64bit else 'x86'}: {', '.join(sorted(unexpected_types))}",
            })

        result = {
            "has_relocations": True,
            "aslr_enabled": aslr_enabled,
            "total_blocks": len(pe.DIRECTORY_ENTRY_BASERELOC),
            "total_entries": total_entries,
            "type_distribution": type_counts,
            "expected_primary_type": expected_type,
            "blocks_with_anomalies": blocks_with_anomalies,
            "anomalies": anomalies,
            "blocks": blocks_detail[:limit],
        }

        if len(pe.DIRECTORY_ENTRY_BASERELOC) > limit:
            result["truncated"] = True
            result["total_blocks_available"] = len(pe.DIRECTORY_ENTRY_BASERELOC)

        return result

    analysis = await asyncio.to_thread(_analyze)
    return await _check_mcp_response_size(ctx, analysis, "analyze_relocations")


# ===================================================================
#  Tool 2: analyze_seh_handlers
# ===================================================================

@tool_decorator
async def analyze_seh_handlers(
    ctx: Context,
    limit: int = 30,
) -> Dict[str, Any]:
    """
    [Phase: explore] Analyzes Structured Exception Handling (SEH) data:
    parses x64 RUNTIME_FUNCTION entries from the exception directory, enumerates
    SafeSEH table (x86), detects SEH-based anti-debug patterns, and flags
    suspicious handler addresses (outside image, in writable sections).

    When to use: When investigating anti-analysis techniques, exploit payloads
    that abuse SEH, or when triage flags unusual exception handling.

    Next steps: If suspicious handlers found → decompile_function_with_angr()
    on handler addresses, disassemble_at_address() to inspect unwind info.
    Record findings with add_note().

    Args:
        ctx: MCP Context.
        limit: Max entries to return. Default 30.
    """
    await ctx.info("Analyzing SEH handlers")
    _check_pe_loaded("analyze_seh_handlers")

    pe = state.pe_object
    pe_data = state.pe_data or {}

    def _analyze():
        machine = pe.FILE_HEADER.Machine
        is_x64 = machine == pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_AMD64', 0x8664)
        is_x86 = machine == pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_I386', 0x14C)

        result: Dict[str, Any] = {
            "architecture": "x64" if is_x64 else "x86" if is_x86 else f"other (0x{machine:x})",
        }

        # Collect section info for bounds checking
        image_size = pe.OPTIONAL_HEADER.SizeOfImage
        sections = []
        for sec in pe.sections:
            sections.append({
                "name": sec.Name.decode('utf-8', 'ignore').strip('\x00'),
                "va_start": sec.VirtualAddress,
                "va_end": sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData),
                "writable": bool(sec.Characteristics & 0x80000000),
                "executable": bool(sec.Characteristics & 0x20000000),
            })

        anomalies: List[Dict[str, Any]] = []

        if is_x64:
            # x64: Parse RUNTIME_FUNCTION entries from exception directory
            result.update(_analyze_x64_exception_dir(pe, sections, image_size, limit))
        elif is_x86:
            # x86: Check SafeSEH table and load config
            result.update(_analyze_x86_seh(pe, pe_data, sections, image_size, limit))
        else:
            result["note"] = "SEH analysis only supported for x86 and x64 binaries"
            return result

        # Common: check for SEH-related anti-debug imports
        seh_anti_debug_apis = {
            "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler",
            "RemoveVectoredExceptionHandler", "RtlAddFunctionTable",
            "RtlInstallFunctionTableCallback", "RtlAddGrowableFunctionTable",
            "NtSetInformationProcess",  # Can disable SEH-based debugging
        }
        imports_data = pe_data.get("imports", [])
        found_seh_apis: List[str] = []
        if isinstance(imports_data, list):
            for dll_entry in imports_data:
                if not isinstance(dll_entry, dict):
                    continue
                for sym in dll_entry.get("symbols", []):
                    name = sym.get("name", "") if isinstance(sym, dict) else str(sym)
                    if name in seh_anti_debug_apis:
                        found_seh_apis.append(name)

        if found_seh_apis:
            result["seh_related_imports"] = found_seh_apis
            if "SetUnhandledExceptionFilter" in found_seh_apis:
                anomalies.append({
                    "type": "seh_anti_debug",
                    "severity": "medium",
                    "description": "SetUnhandledExceptionFilter imported — commonly used for anti-debug via SEH",
                })
            if "AddVectoredExceptionHandler" in found_seh_apis:
                anomalies.append({
                    "type": "veh_usage",
                    "severity": "low",
                    "description": "AddVectoredExceptionHandler imported — VEH can intercept exceptions before SEH",
                })

        # Merge anomalies
        existing = result.get("anomalies", [])
        result["anomalies"] = existing + anomalies

        return result

    analysis = await asyncio.to_thread(_analyze)
    return await _check_mcp_response_size(ctx, analysis, "analyze_seh_handlers")


def _analyze_x64_exception_dir(
    pe: "pefile.PE",
    sections: List[Dict],
    image_size: int,
    limit: int,
) -> Dict[str, Any]:
    """Analyze x64 RUNTIME_FUNCTION entries."""
    result: Dict[str, Any] = {"seh_type": "x64_runtime_functions"}
    anomalies: List[Dict[str, Any]] = []

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION') or not pe.DIRECTORY_ENTRY_EXCEPTION:
        result["has_exception_dir"] = False
        result["anomalies"] = anomalies
        return result

    entries = pe.DIRECTORY_ENTRY_EXCEPTION
    result["has_exception_dir"] = True
    result["total_entries"] = len(entries)

    functions: List[Dict[str, Any]] = []
    oob_count = 0
    writable_count = 0

    for entry in entries:
        if not hasattr(entry, 'struct'):
            continue

        begin_addr = getattr(entry.struct, 'BeginAddress', None)
        end_addr = getattr(entry.struct, 'EndAddress', None)
        unwind_rva = getattr(entry.struct, 'UnwindInfoAddressRVA',
                             getattr(entry.struct, 'UnwindData', None))

        func_info: Dict[str, Any] = {
            "begin": hex(begin_addr) if begin_addr is not None else None,
            "end": hex(end_addr) if end_addr is not None else None,
            "unwind_rva": hex(unwind_rva) if unwind_rva is not None else None,
        }

        # Check bounds
        if begin_addr is not None and begin_addr >= image_size:
            oob_count += 1
            func_info["anomaly"] = "begin address outside image"

        if end_addr is not None and begin_addr is not None and end_addr < begin_addr:
            func_info["anomaly"] = "end address before begin address"

        # Check if handler is in writable section
        if begin_addr is not None:
            for sec in sections:
                if sec["va_start"] <= begin_addr < sec["va_end"]:
                    func_info["section"] = sec["name"]
                    if sec["writable"] and not sec["executable"]:
                        writable_count += 1
                        func_info["anomaly"] = "function in writable non-executable section"
                    break

        if len(functions) < limit:
            functions.append(func_info)

    if oob_count:
        anomalies.append({
            "type": "oob_handlers",
            "severity": "high",
            "description": f"{oob_count} RUNTIME_FUNCTION entries with addresses outside image bounds",
        })
    if writable_count:
        anomalies.append({
            "type": "writable_handlers",
            "severity": "high",
            "description": f"{writable_count} functions in writable sections — possible code injection target",
        })

    result["functions"] = functions
    result["anomalies"] = anomalies
    if len(entries) > limit:
        result["truncated"] = True

    return result


def _analyze_x86_seh(
    pe: "pefile.PE",
    pe_data: Dict,
    sections: List[Dict],
    image_size: int,
    limit: int,
) -> Dict[str, Any]:
    """Analyze x86 SEH / SafeSEH table."""
    result: Dict[str, Any] = {"seh_type": "x86_safeseh"}
    anomalies: List[Dict[str, Any]] = []

    # Check for SafeSEH in load config
    load_config = None
    if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
        load_config = pe.DIRECTORY_ENTRY_LOAD_CONFIG

    if load_config and hasattr(load_config, 'struct'):
        lc = load_config.struct
        se_table_va = getattr(lc, 'SEHandlerTable', 0)
        se_count = getattr(lc, 'SEHandlerCount', 0)

        result["safeseh_enabled"] = bool(se_table_va and se_count)
        result["handler_count"] = se_count

        if se_table_va and se_count:
            # Parse handler table
            handlers: List[Dict[str, Any]] = []
            try:
                table_rva = se_table_va - pe.OPTIONAL_HEADER.ImageBase
                for i in range(min(se_count, limit)):
                    offset = pe.get_offset_from_rva(table_rva + i * 4)
                    handler_rva = struct.unpack_from('<I', pe.__data__, offset)[0]
                    handler_info: Dict[str, Any] = {
                        "index": i,
                        "rva": hex(handler_rva),
                    }

                    # Check if handler is within image
                    if handler_rva >= image_size:
                        handler_info["anomaly"] = "handler outside image bounds"
                        anomalies.append({
                            "type": "oob_seh_handler",
                            "severity": "high",
                            "description": f"SafeSEH handler {i} at RVA {hex(handler_rva)} is outside image",
                        })

                    # Find which section contains the handler
                    for sec in sections:
                        if sec["va_start"] <= handler_rva < sec["va_end"]:
                            handler_info["section"] = sec["name"]
                            if sec["writable"]:
                                handler_info["anomaly"] = "handler in writable section"
                            break

                    handlers.append(handler_info)

                result["handlers"] = handlers
            except Exception as e:
                result["handler_parse_error"] = str(e)
        elif se_table_va == 0 and se_count == 0:
            # NO_SEH flag check
            nt = pe_data.get("nt_headers", {})
            oh = nt.get("optional_header", {}) if isinstance(nt, dict) else {}
            dll_chars = oh.get("dll_characteristics", 0)
            if isinstance(dll_chars, dict):
                dll_chars = dll_chars.get("Value", 0)
            no_seh = bool(isinstance(dll_chars, int) and dll_chars & 0x0400)
            result["no_seh_flag"] = no_seh
            if not no_seh:
                anomalies.append({
                    "type": "no_safeseh_no_flag",
                    "severity": "medium",
                    "description": "No SafeSEH table and NO_SEH flag not set — binary may be vulnerable to SEH overwrite",
                })
    else:
        result["safeseh_enabled"] = False
        result["load_config_present"] = False

    # Check exception directory for x86 (uncommon but possible)
    if hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION') and pe.DIRECTORY_ENTRY_EXCEPTION:
        result["has_exception_dir"] = True
        result["exception_entries"] = len(pe.DIRECTORY_ENTRY_EXCEPTION)
    else:
        result["has_exception_dir"] = False

    result["anomalies"] = anomalies
    return result


# ===================================================================
#  Tool 3: analyze_debug_directory
# ===================================================================

# Debug type constants (IMAGE_DEBUG_TYPE_*)
_DEBUG_TYPES = {
    0: "UNKNOWN",
    1: "COFF",
    2: "CODEVIEW",
    3: "FPO",
    4: "MISC",
    5: "EXCEPTION",
    6: "FIXUP",
    7: "OMAP_TO_SRC",
    8: "OMAP_FROM_SRC",
    9: "BORLAND",
    10: "RESERVED10",
    11: "CLSID",
    12: "VC_FEATURE",
    13: "POGO",
    14: "ILTCG",
    15: "MPX",
    16: "REPRO",
    19: "EX_DLLCHARACTERISTICS",
    20: "PERFMAP",
}

# Known Visual Studio product IDs for Rich header
_RICH_PRODUCT_IDS = {
    0x00: "Unknown/Imported",
    0x01: "Import0 (object)",
    0x04: "Linker (link.exe)",
    0x06: "Resource compiler (cvtres.exe)",
    0x0A: "C compiler (cl.exe)",
    0x0B: "C++ compiler (cl.exe)",
    0x0D: "MASM (ml.exe)",
    0x0E: "Linker (link.exe)",
    0x0F: "C/C++ compiler (cl.exe)",
    0x19: "Linker (link.exe)",
    0x40: ".NET compiler (csc.exe)",
    0x83: "Linker (VS2005)",
    0x84: "C/C++ compiler (VS2005)",
    0x91: "Linker (VS2008)",
    0x92: "C/C++ compiler (VS2008)",
    0x93: "MASM (VS2008)",
    0x9D: "Linker (VS2010)",
    0x9E: "C/C++ compiler (VS2010)",
    0xAA: "Linker (VS2012)",
    0xAB: "C/C++ compiler (VS2012)",
    0xC7: "Linker (VS2013)",
    0xC8: "C/C++ compiler (VS2013)",
    0xCB: "MASM (VS2013)",
    0xD9: "Linker (VS2015)",
    0xDA: "C/C++ compiler (VS2015)",
    0xDB: "MASM (VS2015)",
    0xFF: "Linker (VS2017+)",
    0x100: "C/C++ compiler (VS2017+)",
    0x101: "MASM (VS2017+)",
    0x104: "Linker (VS2019+)",
    0x105: "C/C++ compiler (VS2019+)",
}


@tool_decorator
async def analyze_debug_directory(
    ctx: Context,
) -> Dict[str, Any]:
    """
    [Phase: explore] Deep parsing of the debug directory: extracts PDB paths and
    GUIDs (CodeView NB10/RSDS), parses POGO sections, decodes Rich header build
    tool info, detects debug info anomalies (mismatched timestamps, suspicious PDB
    paths, timestamp tampering, compilation environment indicators).

    When to use: When investigating binary provenance, build environment, timestamp
    tampering, or when correlating samples via PDB paths / Rich header hashes.

    Next steps: If suspicious PDB paths found → search_floss_strings() for related
    strings. If timestamp anomalies → add_note() to record findings. Use
    compute_similarity_hashes() for Rich header-based sample correlation.

    Args:
        ctx: MCP Context.
    """
    await ctx.info("Analyzing debug directory and build info")
    _check_pe_loaded("analyze_debug_directory")

    pe = state.pe_object

    def _analyze():
        result: Dict[str, Any] = {}
        anomalies: List[Dict[str, Any]] = []

        # --- 1. Debug directory entries ---
        debug_entries: List[Dict[str, Any]] = []
        pdb_paths: List[str] = []
        pdb_guids: List[str] = []

        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                dbg_type = entry.struct.Type
                type_name = _DEBUG_TYPES.get(dbg_type, f"UNKNOWN_{dbg_type}")

                dbg_info: Dict[str, Any] = {
                    "type": type_name,
                    "type_value": dbg_type,
                    "timestamp": entry.struct.TimeDateStamp,
                    "major_version": entry.struct.MajorVersion,
                    "minor_version": entry.struct.MinorVersion,
                    "size_of_data": entry.struct.SizeOfData,
                    "address_of_raw_data": hex(entry.struct.AddressOfRawData),
                    "pointer_to_raw_data": hex(entry.struct.PointerToRawData),
                }

                # Parse CodeView info (PDB paths, GUIDs)
                if entry.entry and dbg_type == 2:  # CODEVIEW
                    cv = entry.entry
                    cv_sig = getattr(cv, 'CvSignature', getattr(cv, 'Signature', None))
                    if cv_sig is not None:
                        if isinstance(cv_sig, bytes):
                            dbg_info["cv_signature"] = cv_sig.decode('ascii', 'replace')
                        else:
                            dbg_info["cv_signature"] = hex(cv_sig) if isinstance(cv_sig, int) else str(cv_sig)

                    # RSDS format (most common, VS2005+)
                    if hasattr(cv, 'GUID_Data1'):
                        guid = f"{cv.GUID_Data1:08x}-{cv.GUID_Data2:04x}-{cv.GUID_Data3:04x}-"
                        guid += cv.GUID_Data4.hex()[:4] + "-" + cv.GUID_Data4.hex()[4:]
                        dbg_info["guid"] = guid
                        pdb_guids.append(guid)
                        dbg_info["age"] = getattr(cv, 'Age', None)

                    # PDB path
                    if hasattr(cv, 'PdbFileName'):
                        try:
                            pdb = cv.PdbFileName.decode('utf-8', 'ignore').rstrip('\x00')
                        except Exception:
                            pdb = str(cv.PdbFileName)
                        dbg_info["pdb_path"] = pdb
                        pdb_paths.append(pdb)

                        # Detect suspicious PDB paths
                        pdb_lower = pdb.lower()
                        if any(s in pdb_lower for s in [
                            "\\users\\", "c:\\users\\", "/home/",
                            "desktop", "documents",
                        ]):
                            anomalies.append({
                                "type": "pdb_user_path",
                                "severity": "low",
                                "description": f"PDB path contains user directory: {pdb}",
                            })
                        if pdb_lower.endswith(".dll") or pdb_lower.endswith(".exe"):
                            anomalies.append({
                                "type": "pdb_not_pdb",
                                "severity": "medium",
                                "description": f"PDB path has non-.pdb extension: {pdb}",
                            })
                        if len(pdb) > 200:
                            anomalies.append({
                                "type": "pdb_path_long",
                                "severity": "low",
                                "description": f"Unusually long PDB path ({len(pdb)} chars)",
                            })

                # Parse POGO (Profile-Guided Optimization) data
                elif dbg_type == 13:  # POGO
                    pogo_entries = _parse_pogo(pe, entry)
                    if pogo_entries:
                        dbg_info["pogo_entries"] = pogo_entries[:20]
                        dbg_info["pogo_count"] = len(pogo_entries)

                debug_entries.append(dbg_info)

        result["debug_entries"] = debug_entries
        result["debug_entry_count"] = len(debug_entries)
        result["pdb_paths"] = pdb_paths
        result["pdb_guids"] = pdb_guids

        # --- 2. Rich header analysis ---
        rich = _analyze_rich_header(pe)
        if rich:
            result["rich_header"] = rich

        # --- 3. Timestamp analysis ---
        pe_timestamp = pe.FILE_HEADER.TimeDateStamp
        result["pe_timestamp"] = pe_timestamp
        result["pe_timestamp_human"] = _timestamp_to_str(pe_timestamp)

        # Check for timestamp mismatches
        for dbg in debug_entries:
            dbg_ts = dbg.get("timestamp", 0)
            if dbg_ts and dbg_ts != pe_timestamp and dbg_ts != 0:
                anomalies.append({
                    "type": "timestamp_mismatch",
                    "severity": "medium",
                    "description": f"Debug directory timestamp ({_timestamp_to_str(dbg_ts)}) differs from PE header ({_timestamp_to_str(pe_timestamp)})",
                })

        # Check for zeroed or obviously fake timestamps
        if pe_timestamp == 0:
            anomalies.append({
                "type": "timestamp_zeroed",
                "severity": "medium",
                "description": "PE timestamp is zero — likely stripped or tampered",
            })
        elif pe_timestamp > 2000000000:  # After ~2033
            anomalies.append({
                "type": "timestamp_future",
                "severity": "medium",
                "description": f"PE timestamp is in the far future: {_timestamp_to_str(pe_timestamp)}",
            })
        elif pe_timestamp < 631152000:  # Before 1990
            anomalies.append({
                "type": "timestamp_ancient",
                "severity": "low",
                "description": f"PE timestamp is before 1990: {_timestamp_to_str(pe_timestamp)}",
            })

        # Rich header timestamp cross-check
        if rich and rich.get("newest_build"):
            newest = rich["newest_build"]
            if isinstance(newest, int) and newest > 0:
                # Rich header build numbers are VS build IDs, not timestamps,
                # but we can flag if Rich header is absent when debug is present
                pass

        result["anomalies"] = anomalies
        return result

    analysis = await asyncio.to_thread(_analyze)
    return await _check_mcp_response_size(ctx, analysis, "analyze_debug_directory")


def _parse_pogo(pe: "pefile.PE", debug_entry) -> List[Dict[str, Any]]:
    """Parse POGO (Profile-Guided Optimization) entries from debug data."""
    entries = []
    try:
        ptr = debug_entry.struct.PointerToRawData
        size = debug_entry.struct.SizeOfData
        if ptr == 0 or size == 0:
            return entries

        data = pe.__data__[ptr:ptr + size]
        if len(data) < 4:
            return entries

        # POGO signature: "LTCG" or "PGU\0" (first 4 bytes)
        offset = 4

        while offset + 12 <= len(data):
            rva = struct.unpack_from('<I', data, offset)[0]
            seg_size = struct.unpack_from('<I', data, offset + 4)[0]
            # Name is null-terminated ASCII
            name_start = offset + 8
            name_end = data.find(b'\x00', name_start)
            if name_end == -1 or name_end > ptr + size:
                break
            name = data[name_start:name_end].decode('ascii', 'replace')

            entries.append({
                "rva": hex(rva),
                "size": seg_size,
                "name": name,
            })

            # Align to 4 bytes
            offset = name_end + 1
            offset = (offset + 3) & ~3

            if len(entries) >= 100:
                break

    except Exception as e:
        logger.debug("POGO parse error: %s", e)

    return entries


def _analyze_rich_header(pe: "pefile.PE") -> Optional[Dict[str, Any]]:
    """Analyze Rich header for build tool information."""
    if not hasattr(pe, 'RICH_HEADER') or not pe.RICH_HEADER:
        return None

    raw_vals = list(pe.RICH_HEADER.values) if pe.RICH_HEADER.values else []
    tools: List[Dict[str, Any]] = []
    build_numbers: List[int] = []

    for i in range(0, len(raw_vals), 2):
        if i + 1 < len(raw_vals):
            comp_id = raw_vals[i]
            count = raw_vals[i + 1]
            prod_id = comp_id >> 16
            build_num = comp_id & 0xFFFF

            tool_name = _RICH_PRODUCT_IDS.get(prod_id, f"Unknown (0x{prod_id:x})")
            tools.append({
                "product_id": prod_id,
                "tool": tool_name,
                "build": build_num,
                "count": count,
            })
            build_numbers.append(build_num)

    return {
        "present": True,
        "tool_count": len(tools),
        "tools": tools,
        "key_hex": pe.RICH_HEADER.key.hex() if isinstance(pe.RICH_HEADER.key, bytes) else str(pe.RICH_HEADER.key),
        "checksum": hex(pe.RICH_HEADER.checksum) if pe.RICH_HEADER.checksum is not None else None,
        "newest_build": max(build_numbers) if build_numbers else None,
    }


def _timestamp_to_str(ts: int) -> str:
    """Convert a PE timestamp to human-readable string."""
    import datetime
    try:
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OSError, ValueError, OverflowError):
        return f"invalid ({ts})"
