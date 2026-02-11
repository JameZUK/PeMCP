"""Extended PE analysis, deobfuscation, and forensic tools — gaps in existing library coverage."""
import re
import struct
import math
import asyncio
import zlib
import os

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context, pefile
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size


# ===================================================================
#  PE STRUCTURE GAPS
# ===================================================================

@tool_decorator
async def get_section_permissions(ctx: Context, limit: int = 50) -> Dict[str, Any]:
    """
    Maps every section's permission flags (Read/Write/Execute) with anomaly detection.
    Flags sections with dangerous combinations like Write+Execute (W+X).

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
    Returns extended PE metadata not covered by basic header tools: machine type,
    subsystem, OS version, linker version, ASLR/DEP/CFG flags, and entry point context.
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
    import datetime
    timestamp = fh.TimeDateStamp
    try:
        compile_time = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat()
    except Exception:
        compile_time = "invalid"

    timestamp_suspicious = False
    if timestamp == 0 or timestamp > 2000000000:
        timestamp_suspicious = True

    # Checksum
    try:
        checksum_valid = pe.verify_checksum()
    except Exception:
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
async def extract_resources(ctx: Context, limit: int = 50) -> Dict[str, Any]:
    """
    Extracts PE resource data with types, sizes, language IDs, entropy,
    and the first 64 bytes of each resource payload (hex encoded).

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

            if hasattr(entry, 'directory'):
                _walk_resources(entry.directory.entries, name, depth + 1)
            elif hasattr(entry, 'data'):
                data_rva = entry.data.struct.OffsetToData
                data_size = entry.data.struct.Size
                try:
                    data = pe.get_data(data_rva, min(data_size, 1024))
                    preview = data[:64].hex()
                    # Compute entropy
                    entropy = 0.0
                    if len(data) > 0:
                        byte_counts = [0] * 256
                        for b in data:
                            byte_counts[b] += 1
                        for count in byte_counts:
                            if count > 0:
                                p = count / len(data)
                                entropy -= p * math.log2(p)
                except Exception:
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
    Extracts and returns the embedded application manifest (RT_MANIFEST resource).
    Manifests reveal requested privileges, COM registrations, and compatibility info.
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
                            import re as re_mod
                            level_match = re_mod.search(r'level="([^"]+)"', manifest_text)
                            if level_match:
                                result["requested_execution_level"] = level_match.group(1)
                        return result
                    except Exception as e:
                        return {"error": f"Failed to extract manifest: {e}"}

    return {"note": "No RT_MANIFEST resource found."}


@tool_decorator
async def get_load_config_details(ctx: Context) -> Dict[str, Any]:
    """
    Parses the Load Configuration directory in detail: Control Flow Guard (CFG),
    security cookie, SafeSEH handlers, and guard flags.
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
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Extracts UTF-16LE (wide) strings from the binary. Essential for Windows
    GUI applications and .NET binaries where strings are stored as wchar_t*.

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
async def detect_format_strings(ctx: Context, limit: int = 50) -> Dict[str, Any]:
    """
    Scans for printf/scanf-style format specifiers (%s, %x, %d, %n, etc.)
    in strings. The dangerous %n specifier can indicate format string vulnerabilities.

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

    return {
        "total_format_strings": len(findings),
        "dangerous_n_count": dangerous_count,
        "findings": findings[:limit],
    }


@tool_decorator
async def detect_compression_headers(ctx: Context, limit: int = 30) -> Dict[str, Any]:
    """
    Scans the binary for embedded compression/archive magic bytes:
    zlib, gzip, LZMA, ZIP, RAR, 7z, bzip2, cab, and XZ.

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
                    pass

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
    Decrypts data using a multi-byte XOR key (repeating key cipher).

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
async def bruteforce_xor_key(
    ctx: Context,
    data_hex: str,
    max_key_length: int = 4,
    known_plaintext: Optional[str] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """
    Brute-forces XOR key for encrypted data. Optionally uses known plaintext
    to derive the key directly.

    Args:
        data_hex: Hex-encoded encrypted data.
        max_key_length: Max key length to try (1-8 bytes). Default 4.
        known_plaintext: If you know what part of the plaintext looks like, provide it to derive the key.
        limit: Max results to return (sorted by printable ratio).
    """
    await ctx.info(f"XOR brute-force: max_key_len={max_key_length}")
    try:
        data = bytes.fromhex(data_hex)
    except ValueError:
        raise ValueError("Invalid hex string.")

    max_key_length = min(max_key_length, 8)

    def _bruteforce():
        results = []

        # If known plaintext provided, derive key directly
        if known_plaintext:
            pt = known_plaintext.encode('ascii', 'ignore')
            if len(pt) > 0:
                derived_key = bytes([data[i] ^ pt[i % len(pt)] for i in range(min(len(data), len(pt)))])
                # Try the derived key
                decrypted = bytes([data[i] ^ derived_key[i % len(derived_key)] for i in range(len(data))])
                dec_text = decrypted.decode('utf-8', 'ignore')
                printable = sum(1 for c in dec_text if ' ' <= c <= '~' or c in '\n\r\t') / max(len(dec_text), 1)
                results.append({
                    "key_hex": derived_key.hex(),
                    "key_length": len(derived_key),
                    "printable_ratio": round(printable, 3),
                    "preview": dec_text[:200],
                    "method": "known_plaintext",
                })
                return results

        # Single-byte brute force
        for key_byte in range(256):
            decrypted = bytes([b ^ key_byte for b in data])
            dec_text = decrypted.decode('latin-1', 'ignore')
            printable = sum(1 for c in dec_text if ' ' <= c <= '~' or c in '\n\r\t') / max(len(dec_text), 1)
            if printable > 0.7:
                results.append({
                    "key_hex": f"{key_byte:02x}",
                    "key_length": 1,
                    "printable_ratio": round(printable, 3),
                    "preview": dec_text[:200],
                    "method": "bruteforce",
                })

        # Multi-byte: use index-of-coincidence heuristic for key length detection
        if max_key_length > 1 and len(data) >= 16:
            for kl in range(2, max_key_length + 1):
                # For each key byte position, find the most common XOR result
                key = bytearray(kl)
                for pos in range(kl):
                    freq = [0] * 256
                    for i in range(pos, len(data), kl):
                        freq[data[i]] += 1
                    # Assume most common byte XORs to space (0x20) or null (0x00)
                    most_common = freq.index(max(freq))
                    key[pos] = most_common ^ 0x00  # Try null assumption

                decrypted = bytes([data[i] ^ key[i % kl] for i in range(len(data))])
                dec_text = decrypted.decode('latin-1', 'ignore')
                printable = sum(1 for c in dec_text if ' ' <= c <= '~' or c in '\n\r\t') / max(len(dec_text), 1)
                if printable > 0.6:
                    results.append({
                        "key_hex": bytes(key).hex(),
                        "key_length": kl,
                        "printable_ratio": round(printable, 3),
                        "preview": dec_text[:200],
                        "method": "frequency_analysis",
                    })

        results.sort(key=lambda r: r["printable_ratio"], reverse=True)
        return results

    results = await asyncio.to_thread(_bruteforce)

    return {
        "total_candidates": len(results),
        "results": results[:limit],
    }


@tool_decorator
async def detect_crypto_constants(ctx: Context, limit: int = 50) -> Dict[str, Any]:
    """
    Scans for known cryptographic constants (AES S-box, DES, SHA, RC4, etc.)
    to identify crypto algorithm usage without symbolic execution.

    Args:
        limit: Max findings to return.
    """
    await ctx.info("Scanning for cryptographic constants")
    _check_pe_loaded("detect_crypto_constants")

    pe = state.pe_object
    file_data = pe.__data__

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
        for sig_bytes, name in CRYPTO_SIGS:
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
                    pass
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
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Computes sliding-window Shannon entropy across the binary to locate
    encrypted/compressed/packed regions.

    Args:
        window_size: Size of entropy calculation window in bytes.
        step: Step size between windows.
        limit: Max data points to return.
    """
    await ctx.info(f"Computing entropy curve (window={window_size}, step={step})")
    _check_pe_loaded("analyze_entropy_by_offset")

    pe = state.pe_object
    file_data = pe.__data__

    def _compute():
        points = []
        for offset in range(0, len(file_data) - window_size, step):
            window = file_data[offset:offset + window_size]
            byte_counts = [0] * 256
            for b in window:
                byte_counts[b] += 1
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    p = count / window_size
                    entropy -= p * math.log2(p)
            points.append({
                "offset": hex(offset),
                "entropy": round(entropy, 4),
            })
            if len(points) >= limit:
                break

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
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Scans for known API name hashes used by shellcode/malware to hide imports.
    Supports common hashing algorithms: ror13 (rotate-right-13), djb2, crc32.

    Args:
        hash_algorithm: Algorithm to check ('ror13', 'djb2', 'crc32'). Default 'ror13'.
        limit: Max resolved hashes to return.
    """
    await ctx.info(f"Scanning for API hashes ({hash_algorithm})")
    _check_pe_loaded("scan_for_api_hashes")

    # Common Windows API names
    COMMON_APIS = [
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc",
        "VirtualProtect", "CreateThread", "CreateRemoteThread", "WriteProcessMemory",
        "ReadProcessMemory", "OpenProcess", "VirtualAllocEx", "NtAllocateVirtualMemory",
        "WinExec", "CreateProcessA", "CreateProcessW", "ShellExecuteA",
        "URLDownloadToFileA", "InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
        "WSAStartup", "connect", "send", "recv", "socket",
        "RegOpenKeyExA", "RegSetValueExA", "CreateFileA", "WriteFile", "ReadFile",
        "GetModuleHandleA", "GetModuleHandleW", "ExitProcess", "TerminateProcess",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetTickCount",
        "Sleep", "GetSystemTime", "GetComputerNameA", "GetUserNameA",
        "CryptAcquireContextA", "CryptEncrypt", "CryptDecrypt",
    ]

    def _ror13_hash(name):
        h = 0
        for c in name:
            h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
            h = (h + ord(c)) & 0xFFFFFFFF
        return h

    def _djb2_hash(name):
        h = 5381
        for c in name:
            h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
        return h

    def _crc32_hash(name):
        import binascii
        return binascii.crc32(name.encode('ascii')) & 0xFFFFFFFF

    hash_funcs = {
        "ror13": _ror13_hash,
        "djb2": _djb2_hash,
        "crc32": _crc32_hash,
    }

    if hash_algorithm not in hash_funcs:
        raise ValueError(f"Unknown hash algorithm. Supported: {', '.join(hash_funcs.keys())}")

    hash_func = hash_funcs[hash_algorithm]

    def _scan():
        # Build lookup table
        hash_to_api = {}
        for api in COMMON_APIS:
            h = hash_func(api)
            hash_to_api[h] = api

        pe = state.pe_object
        file_data = pe.__data__
        matches = []

        # Scan for 4-byte aligned values matching known hashes
        for i in range(0, len(file_data) - 3, 4):
            val = struct.unpack_from('<I', file_data, i)[0]
            if val in hash_to_api:
                section_name = None
                try:
                    sec = pe.get_section_by_offset(i)
                    if sec:
                        section_name = sec.Name.decode('utf-8', 'ignore').strip('\x00')
                except Exception:
                    pass
                matches.append({
                    "offset": hex(i),
                    "hash_value": hex(val),
                    "resolved_api": hash_to_api[val],
                    "algorithm": hash_algorithm,
                    "section": section_name,
                })
                if len(matches) >= limit:
                    break

        return matches

    matches = await asyncio.to_thread(_scan)

    return {
        "algorithm": hash_algorithm,
        "total_resolved": len(matches),
        "matches": matches[:limit],
    }


@tool_decorator
async def get_import_hash_analysis(ctx: Context) -> Dict[str, Any]:
    """
    Computes multiple import-based similarity hashes: imphash (MD5 of import table),
    and provides import categorization by DLL function (networking, crypto, process, file I/O, etc.).
    """
    await ctx.info("Computing import hash analysis")
    _check_pe_loaded("get_import_hash_analysis")

    pe = state.pe_object

    # Compute imphash
    try:
        imphash = pe.get_imphash()
    except Exception:
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

    return {
        "imphash": imphash,
        "total_imports": total_imports,
        "categorized_imports": import_categories,
        "category_counts": {k: len(v) for k, v in import_categories.items()},
    }
