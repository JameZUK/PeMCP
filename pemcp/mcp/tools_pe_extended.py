"""Extended PE analysis, deobfuscation, and forensic tools — gaps in existing library coverage."""
import binascii
import datetime
import re
import struct
import math
import asyncio
import zlib
import os

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context, pefile
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.mcp._progress_bridge import ProgressBridge
from pemcp.utils import shannon_entropy


# ===================================================================
#  PE STRUCTURE GAPS
# ===================================================================

@tool_decorator
async def get_section_permissions(ctx: Context, limit: int = 20) -> Dict[str, Any]:
    """
    [Phase: explore] Maps every section's permission flags (Read/Write/Execute)
    with anomaly detection. Flags sections with dangerous W+X (writable+executable).

    When to use: After triage reveals section anomalies, or when investigating
    packing, code injection, or self-modifying code.

    Next steps: If W+X sections found → get_hex_dump() to inspect content,
    decompile_function_with_angr() to analyze code in suspicious sections, or
    detect_packing() for packer analysis. Record findings with add_note().

    Args:
        limit: Max sections to return.
    """
    await ctx.info("Mapping section permissions")
    _check_pe_loaded("get_section_permissions")

    pe = state.pe_object
    sections = []
    anomalies = []

    for sec in pe.sections:
        chars = sec.Characteristics
        name = sec.Name.decode('utf-8', 'ignore').strip('\x00')
        readable = bool(chars & 0x40000000)
        writable = bool(chars & 0x80000000)
        executable = bool(chars & 0x20000000)
        contains_code = bool(chars & 0x00000020)
        contains_init_data = bool(chars & 0x00000040)
        contains_uninit_data = bool(chars & 0x00000080)

        perms = ("R" if readable else "-") + ("W" if writable else "-") + ("X" if executable else "-")

        entry = {
            "name": name,
            "virtual_address": hex(sec.VirtualAddress),
            "virtual_size": sec.Misc_VirtualSize,
            "raw_size": sec.SizeOfRawData,
            "permissions": perms,
            "characteristics_hex": hex(chars),
            "contains_code": contains_code,
            "contains_initialized_data": contains_init_data,
            "contains_uninitialized_data": contains_uninit_data,
        }

        # Anomaly detection
        if writable and executable:
            anomalies.append({"section": name, "issue": "W+X (writable and executable)", "severity": "high"})
        if sec.Misc_VirtualSize > 0 and sec.SizeOfRawData == 0:
            anomalies.append({"section": name, "issue": "Virtual size > 0 but raw size = 0 (likely unpacked at runtime)", "severity": "medium"})
        if sec.SizeOfRawData > 0 and sec.Misc_VirtualSize > sec.SizeOfRawData * 10:
            anomalies.append({"section": name, "issue": f"Virtual size ({sec.Misc_VirtualSize}) >> raw size ({sec.SizeOfRawData})", "severity": "medium"})

        sections.append(entry)

    return {
        "total_sections": len(sections),
        "sections": sections[:limit],
        "anomalies": anomalies,
    }


@tool_decorator
async def get_pe_metadata(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: explore] Returns extended PE metadata not covered by basic header tools:
    machine type, subsystem, OS version, linker version, ASLR/DEP/CFG flags, and
    entry point context.

    When to use: When you need detailed PE header info beyond what triage provides,
    e.g. to check security mitigations or identify the build environment.

    Next steps: If security flags are missing → get_load_config_details() for CFG
    details. If timestamp is suspicious → check get_triage_report() timestamp_analysis.
    """
    await ctx.info("Extracting extended PE metadata")
    _check_pe_loaded("get_pe_metadata")

    pe = state.pe_object
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER

    MACHINE_TYPES = {
        0x14c: "x86 (i386)", 0x8664: "x64 (AMD64)", 0x1c0: "ARM",
        0xaa64: "ARM64 (AArch64)", 0x200: "IA-64 (Itanium)",
    }
    SUBSYSTEM_TYPES = {
        1: "Native", 2: "Windows GUI", 3: "Windows Console",
        5: "OS/2 Console", 7: "POSIX Console", 9: "Windows CE GUI",
        10: "EFI Application", 11: "EFI Boot Service Driver",
        12: "EFI Runtime Driver", 14: "Xbox",
    }

    machine = MACHINE_TYPES.get(fh.Machine, f"Unknown (0x{fh.Machine:04x})")
    subsystem = SUBSYSTEM_TYPES.get(oh.Subsystem, f"Unknown ({oh.Subsystem})")

    dll_chars = oh.DllCharacteristics
    security_flags = {
        "ASLR": bool(dll_chars & 0x0040),
        "high_entropy_ASLR": bool(dll_chars & 0x0020),
        "DEP_NX": bool(dll_chars & 0x0100),
        "force_integrity": bool(dll_chars & 0x0080),
        "SEH_disabled": bool(dll_chars & 0x0400),
        "CFG_guard": bool(dll_chars & 0x4000),
        "terminal_server_aware": bool(dll_chars & 0x8000),
    }

    # Entry point section
    ep = oh.AddressOfEntryPoint
    ep_section = None
    for sec in pe.sections:
        sec_start = sec.VirtualAddress
        sec_end = sec_start + sec.Misc_VirtualSize
        if sec_start <= ep < sec_end:
            ep_section = sec.Name.decode('utf-8', 'ignore').strip('\x00')
            break

    # Timestamp analysis
    timestamp = fh.TimeDateStamp
    try:
        compile_time = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat()
    except Exception:
        logger.debug("get_pe_metadata: failed to parse compile timestamp %s", timestamp, exc_info=True)
        compile_time = "invalid"

    timestamp_suspicious = False
    if timestamp == 0 or timestamp > 2000000000:
        timestamp_suspicious = True

    # Checksum
    try:
        checksum_valid = pe.verify_checksum()
    except Exception:
        logger.debug("get_pe_metadata: failed to verify checksum", exc_info=True)
        checksum_valid = None

    return {
        "machine_type": machine,
        "subsystem": subsystem,
        "image_base": hex(oh.ImageBase),
        "entry_point_rva": hex(ep),
        "entry_point_section": ep_section,
        "os_version": f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}",
        "linker_version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
        "image_version": f"{oh.MajorImageVersion}.{oh.MinorImageVersion}",
        "compile_timestamp": compile_time,
        "compile_timestamp_raw": timestamp,
        "timestamp_suspicious": timestamp_suspicious,
        "checksum_valid": checksum_valid,
        "checksum_stored": hex(oh.CheckSum),
        "security_flags": security_flags,
        "dll_characteristics_hex": hex(dll_chars),
        "file_alignment": oh.FileAlignment,
        "section_alignment": oh.SectionAlignment,
        "size_of_image": oh.SizeOfImage,
        "number_of_sections": fh.NumberOfSections,
        "pointer_to_symbol_table": hex(fh.PointerToSymbolTable),
        "number_of_symbols": fh.NumberOfSymbols,
    }


@tool_decorator
async def extract_resources(ctx: Context, limit: int = 20) -> Dict[str, Any]:
    """
    [Phase: explore] Extracts PE resource data with types, sizes, language IDs,
    entropy, and the first 64 bytes of each resource payload (hex encoded).

    When to use: When triage flags resource anomalies, or when investigating
    droppers, installers, or binaries with embedded payloads in resources.

    Next steps: If high-entropy resources found → scan_for_embedded_files() to
    check for embedded executables, get_hex_dump() to inspect resource data.
    If RT_MANIFEST found → extract_manifest() for privilege/compatibility info.

    Args:
        limit: Max resources to return.
    """
    await ctx.info("Extracting PE resources")
    _check_pe_loaded("extract_resources")

    pe = state.pe_object
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return {"total_resources": 0, "resources": [], "note": "No resource directory found."}

    RESOURCE_TYPES = {
        1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
        5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT",
        9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE",
        12: "RT_GROUP_CURSOR", 14: "RT_GROUP_ICON", 16: "RT_VERSION",
        24: "RT_MANIFEST",
    }

    resources = []

    def _walk_resources(entries, type_name="", depth=0):
        for entry in entries:
            name = type_name
            if entry.id is not None:
                if depth == 0:
                    name = RESOURCE_TYPES.get(entry.id, f"Type_{entry.id}")
                else:
                    name = f"{type_name}/{entry.id}"
            elif entry.name:
                name = f"{type_name}/{entry.name}" if type_name else str(entry.name)

            if hasattr(entry, 'directory') and depth < 10:
                _walk_resources(entry.directory.entries, name, depth + 1)
            elif hasattr(entry, 'data'):
                data_rva = entry.data.struct.OffsetToData
                data_size = entry.data.struct.Size
                try:
                    data = pe.get_data(data_rva, min(data_size, 1024))
                    preview = data[:64].hex()
                    entropy = shannon_entropy(data)
                except Exception:
                    logger.debug("extract_resources: failed to read resource data at RVA %s", hex(data_rva), exc_info=True)
                    preview = ""
                    entropy = 0.0

                resources.append({
                    "type": name,
                    "rva": hex(data_rva),
                    "size": data_size,
                    "entropy": round(entropy, 3),
                    "preview_hex": preview,
                    "language_id": getattr(entry, 'id', None) if depth >= 2 else None,
                })

                if len(resources) >= limit:
                    return

    _walk_resources(pe.DIRECTORY_ENTRY_RESOURCE.entries)

    return {
        "total_resources": len(resources),
        "resources": resources[:limit],
    }


@tool_decorator
async def extract_manifest(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: explore] Extracts the embedded application manifest (RT_MANIFEST resource).
    Manifests reveal requested privileges (e.g. requireAdministrator), COM registrations,
    and OS compatibility info.

    When to use: When investigating privilege escalation, UAC bypass, or to
    understand the binary's declared capabilities and compatibility settings.

    Next steps: If elevated privileges requested → decompile_function_with_angr()
    at entry point to understand what requires elevation. Record with add_note().
    """
    await ctx.info("Extracting manifest")
    _check_pe_loaded("extract_manifest")

    pe = state.pe_object
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return {"error": "No resource directory found."}

    RT_MANIFEST = 24
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == RT_MANIFEST:
            for sub in entry.directory.entries:
                for lang in sub.directory.entries:
                    data_rva = lang.data.struct.OffsetToData
                    data_size = lang.data.struct.Size
                    try:
                        data = pe.get_data(data_rva, data_size)
                        manifest_text = data.decode('utf-8', 'ignore')
                        # Parse for interesting fields
                        result = {"manifest_xml": manifest_text}
                        if "requestedExecutionLevel" in manifest_text:
                            level_match = re.search(r'level="([^"]+)"', manifest_text)
                            if level_match:
                                result["requested_execution_level"] = level_match.group(1)
                        return result
                    except Exception as e:
                        return {"error": f"Failed to extract manifest: {e}"}

    return {"note": "No RT_MANIFEST resource found."}


@tool_decorator
async def get_load_config_details(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: explore] Parses the Load Configuration directory in detail: Control Flow
    Guard (CFG), security cookie, SafeSEH handlers, and guard flags.

    When to use: When assessing exploit mitigations, or when triage shows CFG/CET
    flags are set and you want to understand the specific protections enabled.

    Next steps: If CFG is absent → binary may be vulnerable to control-flow hijacking.
    Use get_pe_metadata() to cross-reference with ASLR/DEP status.
    """
    await ctx.info("Parsing Load Config directory")
    _check_pe_loaded("get_load_config_details")

    pe = state.pe_object
    if not hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
        return {"note": "No Load Config directory found."}

    lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    result = {}

    # Map available fields
    fields = [
        ('Size', 'size'), ('TimeDateStamp', 'timestamp'),
        ('SecurityCookie', 'security_cookie'),
        ('SEHandlerTable', 'seh_handler_table'), ('SEHandlerCount', 'seh_handler_count'),
        ('GuardCFCheckFunctionPointer', 'guard_cf_check_function_pointer'),
        ('GuardCFDispatchFunctionPointer', 'guard_cf_dispatch_function_pointer'),
        ('GuardCFFunctionTable', 'guard_cf_function_table'),
        ('GuardCFFunctionCount', 'guard_cf_function_count'),
        ('GuardFlags', 'guard_flags'),
    ]

    for pe_name, out_name in fields:
        val = getattr(lc, pe_name, None)
        if val is not None:
            result[out_name] = hex(val) if isinstance(val, int) and val > 0xFFFF else val

    # Interpret Guard Flags
    guard_flags = getattr(lc, 'GuardFlags', 0) or 0
    result["guard_flags_decoded"] = {
        "CF_INSTRUMENTED": bool(guard_flags & 0x00000100),
        "CFW_INSTRUMENTED": bool(guard_flags & 0x00000200),
        "CF_FUNCTION_TABLE_PRESENT": bool(guard_flags & 0x00000400),
        "SECURITY_COOKIE_UNUSED": bool(guard_flags & 0x00000800),
        "PROTECT_DELAYLOAD_IAT": bool(guard_flags & 0x00001000),
        "DELAYLOAD_IAT_IN_ITS_OWN_SECTION": bool(guard_flags & 0x00002000),
        "CF_EXPORT_SUPPRESSION_INFO_PRESENT": bool(guard_flags & 0x00004000),
        "CF_ENABLE_EXPORT_SUPPRESSION": bool(guard_flags & 0x00008000),
        "CF_LONGJUMP_TABLE_PRESENT": bool(guard_flags & 0x00010000),
        "EH_CONTINUATION_TABLE_PRESENT": bool(guard_flags & 0x00400000),
    }

    return result


# ===================================================================
#  STRING ANALYSIS GAPS
# ===================================================================

@tool_decorator
async def extract_wide_strings(
    ctx: Context,
    min_length: int = 4,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: explore] Extracts UTF-16LE (wide) strings from the binary. Essential
    for Windows GUI applications and .NET binaries where strings are wchar_t*.

    When to use: When FLOSS static strings miss expected strings (common with GUI
    apps), or when triage shows .NET/Delphi/GUI classification and you need string
    analysis. Complements get_floss_analysis_info() which focuses on ASCII.

    Next steps: Review strings for IOCs → add_note() to record findings.
    Use search_for_specific_strings() to search for specific patterns found here.

    Args:
        min_length: Minimum string length in characters.
        limit: Max strings to return.
    """
    await ctx.info(f"Extracting wide (UTF-16LE) strings, min_length={min_length}")
    _check_pe_loaded("extract_wide_strings")

    pe = state.pe_object
    file_data = pe.__data__

    def _extract():
        strings = []
        i = 0
        while i < len(file_data) - 1:
            # Read UTF-16LE pairs
            current_string = ""
            start_offset = i
            while i < len(file_data) - 1:
                lo = file_data[i]
                hi = file_data[i + 1]
                if hi == 0 and 0x20 <= lo <= 0x7e:
                    current_string += chr(lo)
                    i += 2
                else:
                    break
            if len(current_string) >= min_length:
                strings.append({
                    "offset": hex(start_offset),
                    "string": current_string,
                    "length": len(current_string),
                    "encoding": "UTF-16LE",
                })
            else:
                i += 2  # skip one wide char

            if len(strings) >= limit:
                break

        return strings

    result_strings = await asyncio.to_thread(_extract)

    return {
        "total_found": len(result_strings),
        "min_length": min_length,
        "strings": result_strings[:limit],
    }


@tool_decorator
async def detect_format_strings(ctx: Context, limit: int = 20) -> Dict[str, Any]:
    """
    [Phase: explore] Scans for printf/scanf-style format specifiers (%s, %x, %d,
    %n, etc.) in strings. The dangerous %n specifier can indicate format string
    vulnerabilities.

    When to use: When investigating vulnerability research or exploit development.
    Especially useful for binaries handling user input with printf-family functions.

    Next steps: If dangerous %n found → decompile_function_with_angr() at the
    containing function to verify exploitability. Record with add_note().

    Args:
        limit: Max findings to return.
    """
    await ctx.info("Scanning for format string patterns")
    _check_pe_loaded("detect_format_strings")

    pe = state.pe_object
    file_data = pe.__data__

    # Extract ASCII strings first
    fmt_pattern = re.compile(r'%[-+0 #]*\d*\.?\d*[diouxXeEfFgGaAcspn%]')
    dangerous_pattern = re.compile(r'%[-+0 #]*\d*\.?\d*n')

    def _scan():
        findings = []
        # Simple ASCII string extraction
        current = ""
        start = 0
        for i, b in enumerate(file_data):
            if 0x20 <= b <= 0x7e:
                if not current:
                    start = i
                current += chr(b)
            else:
                if len(current) >= 4 and fmt_pattern.search(current):
                    has_dangerous = bool(dangerous_pattern.search(current))
                    findings.append({
                        "offset": hex(start),
                        "string": current[:200],
                        "format_specifiers": fmt_pattern.findall(current),
                        "has_dangerous_n": has_dangerous,
                        "severity": "high" if has_dangerous else "info",
                    })
                current = ""
                if len(findings) >= limit:
                    break
        return findings

    findings = await asyncio.to_thread(_scan)
    dangerous_count = sum(1 for f in findings if f["has_dangerous_n"])

    result = {
        "total_format_strings": len(findings),
        "dangerous_n_count": dangerous_count,
        "findings": findings[:limit],
    }

    # Warn when binary is likely packed — format specifier matches in
    # compressed data are almost always false positives.
    likely_packed = (state.pe_data or {}).get("triage", {}).get(
        "packing_assessment", {}
    ).get("likely_packed", False)
    if not likely_packed:
        # Lightweight fallback: check if PE sections have very high entropy
        try:
            for sec in pe.sections:
                if sec.get_entropy() > 7.0 and sec.SizeOfRawData > 1024:
                    likely_packed = True
                    break
        except Exception:
            logger.debug("detect_format_strings: failed to check section entropy for packing", exc_info=True)
    if likely_packed:
        result["warning"] = (
            "Binary appears packed or compressed. Format specifier matches "
            "in compressed data are likely false positives. Consider unpacking "
            "first with auto_unpack_pe() or try_all_unpackers()."
        )

    return result


@tool_decorator
async def detect_compression_headers(ctx: Context, limit: int = 30) -> Dict[str, Any]:
    """
    [Phase: explore] Scans the binary for embedded compression/archive magic bytes:
    zlib, gzip, LZMA, ZIP, RAR, 7z, bzip2, cab, and XZ.

    When to use: When investigating droppers, packers, or binaries with overlay data.
    Triage overlay_analysis or high resource entropy suggests embedded archives.

    Next steps: If archives found → scan_for_embedded_files() to extract them,
    get_hex_dump(start_offset=<offset>) to inspect compressed data. For packed
    binaries → auto_unpack_pe() or detect_packing().

    Args:
        limit: Max findings to return.
    """
    await ctx.info("Scanning for compression/archive headers")
    _check_pe_loaded("detect_compression_headers")

    pe = state.pe_object
    file_data = pe.__data__

    SIGNATURES = [
        (b'\x78\x01', "zlib (low compression)"),
        (b'\x78\x5e', "zlib (default compression)"),
        (b'\x78\x9c', "zlib (best compression)"),
        (b'\x78\xda', "zlib (best compression alt)"),
        (b'\x1f\x8b', "gzip"),
        (b'\x5d\x00\x00', "LZMA"),
        (b'PK\x03\x04', "ZIP archive"),
        (b'PK\x05\x06', "ZIP (empty archive)"),
        (b'Rar!\x1a\x07', "RAR archive"),
        (b'7z\xbc\xaf\x27\x1c', "7-Zip archive"),
        (b'BZh', "bzip2"),
        (b'MSCF', "Microsoft CAB"),
        (b'\xfd7zXZ\x00', "XZ archive"),
        (b'\x04\x22\x4d\x18', "LZ4"),
        (b'\x28\xb5\x2f\xfd', "Zstandard"),
    ]

    def _scan():
        findings = []
        for magic, desc in SIGNATURES:
            offset = 0
            while True:
                idx = file_data.find(magic, offset)
                if idx == -1:
                    break
                # Determine which section
                section_name = None
                try:
                    sec = pe.get_section_by_offset(idx)
                    if sec:
                        section_name = sec.Name.decode('utf-8', 'ignore').strip('\x00')
                except Exception:
                    logger.debug("detect_compression_headers: failed to resolve section at offset %s", hex(idx), exc_info=True)

                findings.append({
                    "offset": hex(idx),
                    "type": desc,
                    "magic_hex": magic.hex(),
                    "section": section_name,
                    "context_hex": file_data[idx:idx+32].hex(),
                })
                offset = idx + len(magic)

                if len(findings) >= limit:
                    break
            if len(findings) >= limit:
                break

        return findings

    findings = await asyncio.to_thread(_scan)

    return {
        "total_found": len(findings),
        "findings": findings[:limit],
    }


# ===================================================================
#  DEOBFUSCATION GAPS
# ===================================================================

@tool_decorator
async def deobfuscate_xor_multi_byte(
    ctx: Context,
    data_hex: str,
    key_hex: str,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Decrypts data using a multi-byte XOR key (repeating key cipher).

    When to use: After identifying XOR-encrypted data via detect_crypto_constants(),
    string analysis, or decompilation. Use brute_force_simple_crypto() first if
    the key is unknown.

    Next steps: If decrypted data looks like a PE → open_file() to analyze it.
    If it contains strings/URLs → add_note() to record IOCs.

    Args:
        data_hex: Hex-encoded encrypted data.
        key_hex: Hex-encoded XOR key (e.g. 'deadbeef' for a 4-byte key).
    """
    await ctx.info(f"Multi-byte XOR: data={len(data_hex)//2} bytes, key={key_hex}")
    try:
        data = bytes.fromhex(data_hex)
        key = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("Invalid hex string for data or key.")

    if len(key) == 0:
        raise ValueError("Key must not be empty.")

    decrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    dec_hex = decrypted.hex()
    try:
        dec_text = decrypted.decode('utf-8', 'ignore')
    except Exception:
        logger.debug("deobfuscate_xor_multi_byte: UTF-8 decode failed, falling back to latin-1", exc_info=True)
        dec_text = decrypted.decode('latin-1', 'ignore')

    printable_ratio = sum(1 for c in dec_text if ' ' <= c <= '~' or c in '\n\r\t') / max(len(dec_text), 1)

    return {
        "decrypted_hex": dec_hex,
        "decrypted_text": dec_text[:2000],
        "printable_ratio": round(printable_ratio, 3),
        "key_length": len(key),
        "data_length": len(data),
    }


@tool_decorator
async def detect_crypto_constants(ctx: Context, limit: int = 20) -> Dict[str, Any]:
    """
    [Phase: explore] Scans for known cryptographic constants (AES S-box, DES, SHA,
    RC4, etc.) to identify crypto algorithm usage without symbolic execution.

    When to use: When investigating ransomware, C2 encryption, credential theft,
    or any binary suspected of using custom cryptography.

    Next steps: Use get_cross_reference_map(target_address=<offset>) to find code
    referencing the crypto constants, then decompile_function_with_angr() to
    understand the encryption logic. Record findings with add_note().

    Args:
        limit: Max findings to return.
    """
    await ctx.info("Scanning for cryptographic constants")
    _check_pe_loaded("detect_crypto_constants")

    pe = state.pe_object
    file_data = pe.__data__

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    # Well-known crypto constants (first N bytes of each)
    CRYPTO_SIGS = [
        (bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]), "AES S-box"),
        (bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38]), "AES inverse S-box"),
        (bytes([0xd7, 0x6a, 0xa4, 0x78]), "SHA-256 initial hash (H0)"),
        (bytes([0x67, 0x45, 0x23, 0x01]), "MD5/SHA-1 init (little-endian)"),
        (bytes([0x01, 0x23, 0x45, 0x67]), "MD5/SHA-1 init (big-endian)"),
        (bytes([0x6a, 0x09, 0xe6, 0x67]), "SHA-256 init (big-endian H0)"),
        (bytes([0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8]), "SHA-512 initial hash"),
        (bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]), "Identity permutation (RC4 init?)"),
        (bytes([0x30, 0x2C, 0x61, 0x2E, 0x69, 0x68, 0x00, 0x71]), "Blowfish P-array fragment"),
        (bytes([0x3a, 0x39, 0xce, 0x37, 0xd3, 0xfa, 0xf5, 0xcf]), "DES initial permutation fragment"),
    ]

    def _scan():
        findings = []
        total_sigs = len(CRYPTO_SIGS)
        for sig_idx, (sig_bytes, name) in enumerate(CRYPTO_SIGS):
            if sig_idx % 3 == 0:
                pct = 5 + int((sig_idx / total_sigs) * 80)
                bridge.report_progress(pct, 100)
                bridge.info(f"Scanning for {name}...")
            offset = 0
            while True:
                idx = file_data.find(sig_bytes, offset)
                if idx == -1:
                    break
                section_name = None
                try:
                    sec = pe.get_section_by_offset(idx)
                    if sec:
                        section_name = sec.Name.decode('utf-8', 'ignore').strip('\x00')
                except Exception:
                    logger.debug("detect_crypto_constants: failed to resolve section at offset %s", hex(idx), exc_info=True)
                findings.append({
                    "offset": hex(idx),
                    "algorithm": name,
                    "matched_bytes": len(sig_bytes),
                    "section": section_name,
                })
                offset = idx + len(sig_bytes)
                if len(findings) >= limit:
                    break
            if len(findings) >= limit:
                break
        return findings

    findings = await asyncio.to_thread(_scan)

    return {
        "total_found": len(findings),
        "findings": findings[:limit],
    }


@tool_decorator
async def analyze_entropy_by_offset(
    ctx: Context,
    window_size: int = 256,
    step: int = 256,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    [Phase: explore] Computes sliding-window Shannon entropy across the binary to
    locate encrypted, compressed, or packed regions.

    When to use: When investigating packing or embedded encrypted payloads. Triage
    packing_assessment provides a summary; this gives offset-level granularity.

    Next steps: High-entropy regions (>7.0) → get_hex_dump() to inspect content,
    detect_compression_headers() to check for known archive formats, or
    detect_packing() for packer analysis.

    Args:
        window_size: Size of entropy calculation window in bytes.
        step: Step size between windows.
        limit: Max data points to return.
    """
    await ctx.info(f"Computing entropy curve (window={window_size}, step={step})")
    _check_pe_loaded("analyze_entropy_by_offset")

    pe = state.pe_object
    file_data = pe.__data__

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _compute():
        points = []
        total_windows = max(1, (len(file_data) - window_size) // step)

        bridge.report_progress(5, 100)
        bridge.info("Computing entropy windows...")

        for offset in range(0, len(file_data) - window_size, step):
            window = file_data[offset:offset + window_size]
            entropy = shannon_entropy(window)
            points.append({
                "offset": hex(offset),
                "entropy": round(entropy, 4),
            })
            if len(points) % max(1, total_windows // 10) == 0:
                pct = 5 + int((len(points) / min(total_windows, limit)) * 80)
                bridge.report_progress(min(pct, 85), 100)
            if len(points) >= limit:
                break

        bridge.report_progress(88, 100)
        bridge.info("Identifying high-entropy regions...")

        # Find high-entropy regions (>7.0)
        high_regions = [p for p in points if p["entropy"] > 7.0]
        avg_entropy = sum(p["entropy"] for p in points) / max(len(points), 1)

        return points, high_regions, avg_entropy

    points, high_regions, avg = await asyncio.to_thread(_compute)

    return {
        "total_windows": len(points),
        "average_entropy": round(avg, 4),
        "high_entropy_regions_count": len(high_regions),
        "high_entropy_regions": high_regions[:50],
        "entropy_curve": points[:limit],
    }


@tool_decorator
async def scan_for_api_hashes(
    ctx: Context,
    hash_algorithm: str = "ror13",
    seed: Optional[int] = None,
    case_handling: Optional[str] = None,
    family_hint: Optional[str] = None,
    include_extended_db: bool = False,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: explore] Scans for known API name hashes used by shellcode and malware
    to hide imports via dynamic resolution (e.g. ror13, djb2, crc32, fnv1a).

    When to use: When triage shows very few imports (suggesting dynamic resolution),
    or when analyzing shellcode. Common in malware that avoids static import tables.

    Next steps: If API hashes resolved → decompile_function_with_angr() at those
    offsets to see how APIs are called. Use get_hex_dump() to inspect surrounding
    shellcode. Record findings with add_note().

    Args:
        hash_algorithm: Algorithm ('ror13', 'djb2', 'crc32', 'fnv1a'). Default 'ror13'.
        seed: Custom seed/initial value for the hash algorithm. None uses the standard
            default (e.g. 5381 for djb2, 0 for ror13). Use for malware variants that
            modify the seed (e.g. AdaptixC2 uses djb2 with seed=1572).
        case_handling: Transform API names before hashing: 'lower', 'upper', or None.
        family_hint: Malware family name (e.g. 'AdaptixC2 Beacon'). Reads algorithm,
            seed, and case handling from malware_signatures.yaml knowledge base.
            Also adds any known_hashes from the KB to the lookup table.
        include_extended_db: If True, use the full ~10K API export list (slower but
            more comprehensive). Default False uses the curated ~800 name list.
        limit: Max resolved hashes to return.
    """
    from pemcp.mcp._helpers_api_hashes import (
        get_all_api_names, compute_hash, build_hash_lookup,
        HASH_ALGORITHMS,
    )

    # If family_hint is provided, read algorithm/seed/case from the KB
    kb_known_hashes = {}
    family_match_info = None
    if family_hint:
        try:
            from pemcp.mcp.tools_malware_identify import _get_families
            for fam in _get_families():
                if fam.get("family", "").lower() == family_hint.lower():
                    api_hash_meta = fam.get("api_hash") or {}
                    if isinstance(api_hash_meta, dict):
                        kb_algo = api_hash_meta.get("algorithm", "").replace("_modified", "")
                        if kb_algo and hash_algorithm == "ror13":
                            hash_algorithm = kb_algo
                        if seed is None and "seed" in api_hash_meta:
                            seed = api_hash_meta["seed"]
                        if case_handling is None:
                            case_sensitive = api_hash_meta.get("case_sensitive", True)
                            if not case_sensitive:
                                case_handling = "lower"
                        # Grab known_hashes for direct lookup
                        known = api_hash_meta.get("known_hashes") or {}
                        if isinstance(known, dict):
                            kb_known_hashes = {v: k for k, v in known.items()}
                    family_match_info = fam.get("family")
                    break
        except Exception:
            logger.debug("scan_for_api_hashes: KB lookup failed for '%s'", family_hint, exc_info=True)

    if hash_algorithm not in HASH_ALGORITHMS:
        raise ValueError(
            f"Unknown hash algorithm '{hash_algorithm}'. "
            f"Supported: {', '.join(sorted(HASH_ALGORITHMS))}"
        )

    await ctx.info(f"Scanning for API hashes ({hash_algorithm}"
                   f"{f', seed={seed}' if seed is not None else ''}"
                   f"{f', case={case_handling}' if case_handling else ''})")
    _check_pe_loaded("scan_for_api_hashes")

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _scan():
        # Build lookup table from bundled API DB
        api_names = get_all_api_names(include_extended=include_extended_db)
        hash_to_api = build_hash_lookup(api_names, hash_algorithm,
                                        seed=seed, case_handling=case_handling)

        # Merge KB known_hashes (these are pre-computed, no need to hash)
        hash_to_api.update(kb_known_hashes)

        pe = state.pe_object
        file_data = pe.__data__
        matches = []
        total_dwords = max(1, (len(file_data) - 3) // 4)

        bridge.report_progress(5, 100)
        bridge.info(f"Scanning {total_dwords} dwords against {len(hash_to_api)} API hashes...")

        # Scan for 4-byte aligned values matching known hashes
        for i in range(0, len(file_data) - 3, 4):
            if (i // 4) % max(1, total_dwords // 10) == 0:
                pct = 5 + int(((i // 4) / total_dwords) * 85)
                bridge.report_progress(min(pct, 90), 100)
            val = struct.unpack_from('<I', file_data, i)[0]
            if val in hash_to_api:
                section_name = None
                try:
                    sec = pe.get_section_by_offset(i)
                    if sec:
                        section_name = sec.Name.decode('utf-8', 'ignore').strip('\x00')
                except Exception:
                    logger.debug("scan_for_api_hashes: failed to resolve section at offset %s", hex(i), exc_info=True)

                entry = {
                    "offset": hex(i),
                    "hash_value": hex(val),
                    "resolved_api": hash_to_api[val],
                    "algorithm": hash_algorithm,
                    "section": section_name,
                }

                # Check if this hash appears in any KB family's known_hashes
                if val in kb_known_hashes:
                    entry["kb_match"] = True
                    if family_match_info:
                        entry["family_match"] = family_match_info

                matches.append(entry)
                if len(matches) >= limit:
                    break

        # KB cross-reference: check if found hashes match any family
        if matches and not family_hint:
            bridge.info("Cross-referencing with malware KB...")
            try:
                from pemcp.mcp.tools_malware_identify import _get_families
                found_hashes = {int(m["hash_value"], 16) for m in matches}
                for fam in _get_families():
                    api_hash_meta = fam.get("api_hash") or {}
                    if not isinstance(api_hash_meta, dict):
                        continue
                    known = api_hash_meta.get("known_hashes") or {}
                    if not isinstance(known, dict):
                        continue
                    kb_vals = set(known.values())
                    overlap = found_hashes & kb_vals
                    if overlap:
                        for m in matches:
                            if int(m["hash_value"], 16) in overlap:
                                m["family_match"] = fam.get("family", "unknown")
            except Exception:
                logger.debug("scan_for_api_hashes: KB cross-reference failed", exc_info=True)

        return matches

    matches = await asyncio.to_thread(_scan)

    result = {
        "algorithm": hash_algorithm,
        "seed": seed,
        "case_handling": case_handling,
        "api_db_size": "extended (~10K)" if include_extended_db else "curated (~800)",
        "total_resolved": len(matches),
        "matches": matches[:limit],
    }
    if family_hint:
        result["family_hint"] = family_hint
        result["family_resolved"] = family_match_info

    return result


@tool_decorator
async def get_import_hash_analysis(ctx: Context, compact: bool = False) -> Dict[str, Any]:
    """
    [Phase: explore] Computes import-based similarity hashes (imphash) and categorizes
    imports by function: networking, crypto, process manipulation, file I/O, registry,
    anti-debug, privilege escalation, service control, and code injection.

    When to use: After triage to understand the binary's API usage patterns and for
    sample clustering. The imphash can identify malware families sharing code.

    Next steps: Use compute_similarity_hashes() for fuzzy hashing (ssdeep/TLSH).
    If suspicious categories found → get_focused_imports() for detailed import
    analysis, decompile_function_with_angr() to analyze usage of flagged APIs.
    """
    await ctx.info("Computing import hash analysis")
    _check_pe_loaded("get_import_hash_analysis")

    pe = state.pe_object

    # Compute imphash
    try:
        imphash = pe.get_imphash()
    except Exception:
        logger.debug("get_import_hash_analysis: failed to compute imphash", exc_info=True)
        imphash = None

    # Categorize imports
    CATEGORIES = {
        "networking": {"WSA", "socket", "connect", "send", "recv", "Internet", "Http", "Url", "WinHttp", "Winsock"},
        "crypto": {"Crypt", "BCrypt", "NCrypt", "CertOpen", "CertFind"},
        "process": {"CreateProcess", "OpenProcess", "TerminateProcess", "CreateThread", "CreateRemoteThread",
                    "WriteProcessMemory", "ReadProcessMemory", "VirtualAlloc", "VirtualProtect", "NtCreate"},
        "file_io": {"CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CopyFile", "MoveFile", "FindFirst"},
        "registry": {"RegOpen", "RegSet", "RegQuery", "RegCreate", "RegDelete", "RegEnum"},
        "anti_debug": {"IsDebuggerPresent", "CheckRemoteDebugger", "NtQueryInformation", "GetTickCount",
                       "QueryPerformance", "OutputDebugString"},
        "privilege": {"AdjustTokenPriv", "OpenProcessToken", "LookupPrivilege", "ImpersonateLoggedOn"},
        "service": {"CreateService", "OpenService", "StartService", "ChangeServiceConfig"},
        "injection": {"NtMapViewOfSection", "RtlCreateUserThread", "QueueUserAPC", "NtUnmapViewOfSection"},
    }

    import_categories: Dict[str, List[str]] = {cat: [] for cat in CATEGORIES}
    total_imports = 0

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                total_imports += 1
                if imp.name:
                    name = imp.name.decode('utf-8', 'ignore')
                    for cat, keywords in CATEGORIES.items():
                        if any(kw in name for kw in keywords):
                            import_categories[cat].append(name)

    # Remove empty categories
    import_categories = {k: v for k, v in import_categories.items() if v}

    if compact:
        return {
            "imphash": imphash,
            "total_imports": total_imports,
            "category_counts": {k: len(v) for k, v in import_categories.items()},
        }

    return {
        "imphash": imphash,
        "total_imports": total_imports,
        "categorized_imports": import_categories,
        "category_counts": {k: len(v) for k, v in import_categories.items()},
    }
