"""MCP tools for payload extraction — steganography, custom containers, and config extraction.

Detects data hidden after image EOF markers, parses common malware container
formats, and automatically extracts C2 configurations using heuristics.
"""
import asyncio
import math
import re
import struct

from typing import Dict, Any, List, Optional

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.mcp._refinery_helpers import _get_data_from_hex_or_file, _bytes_to_hex, _safe_decode


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            ent -= p * math.log2(p)
    return ent


# ===================================================================
#  Image EOF markers
# ===================================================================

_IMAGE_MARKERS = {
    "PNG": {
        "header": b"\x89PNG\r\n\x1a\n",
        "eof": b"\x00\x00\x00\x00IEND\xaeB`\x82",
        "eof_len": 12,
    },
    "JPEG": {
        "header": b"\xff\xd8\xff",
        "eof": b"\xff\xd9",
        "eof_len": 2,
    },
    "GIF": {
        "header": b"GIF8",
        "eof": b"\x3b",  # GIF trailer
        "eof_len": 1,
    },
}


# ===================================================================
#  Tool 1: extract_steganography
# ===================================================================

@tool_decorator
async def extract_steganography(
    ctx: Context,
    data_hex: Optional[str] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Detects and extracts data hidden after image EOF markers
    (PNG IEND, JPEG FFD9, GIF trailer). Also detects BMP size mismatches and
    PE overlay data.

    When to use: When analyzing files that contain embedded images, or when
    file size is larger than expected. I.e., if binwalk or scan_for_embedded_files()
    found image files inside the binary.

    Next steps: If extracted data has high entropy → brute_force_simple_crypto().
    If it starts with MZ/PK → open_file() or refinery_extract(operation='archive').
    Record findings with add_note().

    Args:
        ctx: MCP Context.
        data_hex: Optional hex data to scan. If None, uses loaded file.
        limit: Max hidden payloads to extract. Default 10.
    """
    await ctx.info("Scanning for steganographic payloads (EOF marker analysis)")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Data too large (max 100MB).")

    def _scan():
        findings = []

        # --- Image EOF marker detection ---
        for fmt_name, markers in _IMAGE_MARKERS.items():
            header = markers["header"]
            eof = markers["eof"]
            eof_len = markers["eof_len"]

            # Find all instances of this image format
            offset = 0
            while offset < len(data):
                img_start = data.find(header, offset)
                if img_start == -1:
                    break

                # Find the EOF marker after the header
                eof_search_start = img_start + len(header)
                eof_pos = data.find(eof, eof_search_start)
                if eof_pos == -1:
                    offset = img_start + 1
                    continue

                payload_start = eof_pos + eof_len
                image_size = payload_start - img_start

                # Check if there's data after the EOF marker
                if payload_start < len(data):
                    trailing = data[payload_start:]
                    # Only report if there's meaningful trailing data (>8 bytes)
                    if len(trailing) > 8:
                        trailing_entropy = _shannon_entropy(trailing[:4096])
                        trailing_preview = trailing[:64]

                        findings.append({
                            "type": f"{fmt_name}_appended_data",
                            "image_format": fmt_name,
                            "image_offset": hex(img_start),
                            "image_size": image_size,
                            "eof_marker_offset": hex(eof_pos),
                            "payload_offset": hex(payload_start),
                            "payload_size": len(trailing),
                            "payload_entropy": round(trailing_entropy, 2),
                            "payload_preview_hex": trailing_preview.hex(),
                            "payload_magic": _identify_magic(trailing[:16]),
                        })

                offset = payload_start if payload_start > img_start else img_start + 1
                if len(findings) >= limit:
                    break
            if len(findings) >= limit:
                break

        # --- BMP size mismatch detection ---
        bmp_offset = 0
        while bmp_offset < len(data) - 14:
            bmp_start = data.find(b"BM", bmp_offset)
            if bmp_start == -1:
                break
            if bmp_start + 6 <= len(data):
                declared_size = struct.unpack_from("<I", data, bmp_start + 2)[0]
                actual_available = len(data) - bmp_start
                if 14 < declared_size < actual_available and (actual_available - declared_size) > 64:
                    hidden_start = bmp_start + declared_size
                    hidden_data = data[hidden_start:]
                    findings.append({
                        "type": "BMP_size_mismatch",
                        "image_format": "BMP",
                        "image_offset": hex(bmp_start),
                        "declared_size": declared_size,
                        "actual_available": actual_available,
                        "payload_offset": hex(hidden_start),
                        "payload_size": len(hidden_data),
                        "payload_entropy": round(_shannon_entropy(hidden_data[:4096]), 2),
                        "payload_preview_hex": hidden_data[:64].hex(),
                        "payload_magic": _identify_magic(hidden_data[:16]),
                    })
            bmp_offset = bmp_start + 1
            if len(findings) >= limit:
                break

        # --- PE overlay detection ---
        if data[:2] == b"MZ" and data_hex is None:
            try:
                pe = state.pe_object
                if pe and hasattr(pe, 'get_overlay_data_start_offset'):
                    overlay_start = pe.get_overlay_data_start_offset()
                    if overlay_start and overlay_start < len(data):
                        overlay = data[overlay_start:]
                        if len(overlay) > 64:
                            findings.append({
                                "type": "PE_overlay",
                                "image_format": "PE",
                                "payload_offset": hex(overlay_start),
                                "payload_size": len(overlay),
                                "payload_entropy": round(_shannon_entropy(overlay[:4096]), 2),
                                "payload_preview_hex": overlay[:64].hex(),
                                "payload_magic": _identify_magic(overlay[:16]),
                            })
            except Exception:
                pass

        return findings

    findings = await asyncio.to_thread(_scan)

    return await _check_mcp_response_size(ctx, {
        "findings": findings,
        "count": len(findings),
        "data_size": len(data),
        "next_steps": _suggest_next_steps(findings),
    }, "extract_steganography")


def _identify_magic(data: bytes) -> Optional[str]:
    """Identify file type from magic bytes."""
    if len(data) < 2:
        return None
    if data[:2] == b"MZ":
        return "PE executable"
    if data[:2] == b"PK":
        return "ZIP archive"
    if data[:4] == b"\x7fELF":
        return "ELF executable"
    if data[:3] == b"\x1f\x8b\x08":
        return "GZIP compressed"
    if data[:4] == b"Rar!":
        return "RAR archive"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG image"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG image"
    if data[:4] == b"GIF8":
        return "GIF image"
    if data[:5] == b"%PDF-":
        return "PDF document"
    return None


def _suggest_next_steps(findings: list) -> List[str]:
    """Generate next-step suggestions based on findings."""
    if not findings:
        return ["No hidden data found. Try analyze_entropy_by_offset() for encrypted regions."]
    steps = []
    for f in findings[:3]:
        magic = f.get("payload_magic")
        offset = f.get("payload_offset", "?")
        if magic == "PE executable":
            steps.append(f"get_hex_dump(start_offset={offset}, length=512) then open_file() to analyze extracted PE")
        elif magic and "archive" in magic.lower():
            steps.append(f"refinery_extract(operation='archive') on data at offset {offset}")
        elif f.get("payload_entropy", 0) > 7.0:
            steps.append(f"brute_force_simple_crypto() on data at offset {offset} (high entropy suggests encryption)")
        else:
            steps.append(f"get_hex_dump(start_offset={offset}, length=256) to inspect payload")
    return steps


# ===================================================================
#  Tool 2: parse_custom_container
# ===================================================================

@tool_decorator
async def parse_custom_container(
    ctx: Context,
    data_hex: str,
    delimiter: Optional[str] = None,
    structure: str = "delimiter_size_payload",
    size_width: int = 4,
    size_endian: str = "little",
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Parses binary data following common malware container patterns:
    delimiter + size + payload, size + payload, or repeated fixed-size chunks.

    When to use: When you've identified a custom binary format in hex dump
    (e.g., a magic string followed by size fields and encrypted blobs).

    Next steps: For each extracted chunk → brute_force_simple_crypto() if encrypted,
    or get_hex_dump() for further inspection.

    Args:
        ctx: MCP Context.
        data_hex: Hex-encoded container data.
        delimiter: Optional delimiter bytes (hex). If None, auto-detect.
        structure: Container structure: 'delimiter_size_payload', 'size_payload', 'fixed_chunks'.
        size_width: Byte width of size field (1, 2, 4, or 8). Default 4.
        size_endian: Endianness of size field: 'little' or 'big'. Default 'little'.
        limit: Max chunks to extract. Default 20.
    """
    await ctx.info(f"Parsing custom container (structure={structure})")

    try:
        data = bytes.fromhex(data_hex.replace(" ", "").replace("0x", ""))
    except ValueError as e:
        raise ValueError(f"Invalid data_hex: {e}")

    if size_width not in (1, 2, 4, 8):
        raise ValueError("size_width must be 1, 2, 4, or 8")
    endian = "<" if size_endian == "little" else ">"
    size_fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}[size_width]

    delim_bytes = None
    if delimiter:
        try:
            delim_bytes = bytes.fromhex(delimiter.replace(" ", "").replace("0x", ""))
        except ValueError as e:
            raise ValueError(f"Invalid delimiter hex: {e}")

    def _parse():
        chunks = []
        offset = 0

        if structure == "delimiter_size_payload":
            if delim_bytes is None:
                return _auto_detect_delimiter(data, size_width, endian + size_fmt, limit)

            while offset < len(data) - len(delim_bytes) - size_width:
                idx = data.find(delim_bytes, offset)
                if idx == -1:
                    break
                size_offset = idx + len(delim_bytes)
                if size_offset + size_width > len(data):
                    break
                chunk_size = struct.unpack_from(endian + size_fmt, data, size_offset)[0]
                payload_start = size_offset + size_width
                if chunk_size == 0 or chunk_size > len(data) - payload_start:
                    offset = idx + 1
                    continue
                payload = data[payload_start:payload_start + chunk_size]
                chunks.append({
                    "index": len(chunks),
                    "delimiter_offset": hex(idx),
                    "payload_offset": hex(payload_start),
                    "size": chunk_size,
                    "entropy": round(_shannon_entropy(payload), 2),
                    "preview_hex": payload[:64].hex(),
                    "magic": _identify_magic(payload[:16]),
                })
                offset = payload_start + chunk_size
                if len(chunks) >= limit:
                    break

        elif structure == "size_payload":
            while offset + size_width <= len(data):
                chunk_size = struct.unpack_from(endian + size_fmt, data, offset)[0]
                payload_start = offset + size_width
                if chunk_size == 0 or chunk_size > len(data) - payload_start:
                    break
                payload = data[payload_start:payload_start + chunk_size]
                chunks.append({
                    "index": len(chunks),
                    "size_offset": hex(offset),
                    "payload_offset": hex(payload_start),
                    "size": chunk_size,
                    "entropy": round(_shannon_entropy(payload), 2),
                    "preview_hex": payload[:64].hex(),
                    "magic": _identify_magic(payload[:16]),
                })
                offset = payload_start + chunk_size
                if len(chunks) >= limit:
                    break

        elif structure == "fixed_chunks":
            # Auto-detect chunk size from repeating patterns
            chunk_size = _detect_fixed_chunk_size(data)
            if chunk_size:
                for i in range(0, len(data) - chunk_size + 1, chunk_size):
                    payload = data[i:i + chunk_size]
                    chunks.append({
                        "index": len(chunks),
                        "offset": hex(i),
                        "size": chunk_size,
                        "entropy": round(_shannon_entropy(payload), 2),
                        "preview_hex": payload[:64].hex(),
                    })
                    if len(chunks) >= limit:
                        break

        return chunks

    chunks = await asyncio.to_thread(_parse)

    return await _check_mcp_response_size(ctx, {
        "chunks": chunks,
        "count": len(chunks),
        "data_size": len(data),
        "structure": structure,
    }, "parse_custom_container")


def _auto_detect_delimiter(data: bytes, size_width: int, size_fmt: str, limit: int) -> list:
    """Try to auto-detect delimiter by finding repeated short byte patterns."""
    chunks = []
    # Look for 2-8 byte sequences that repeat and are followed by valid sizes
    for dlen in range(2, 9):
        candidate = data[:dlen]
        if not candidate or len(set(candidate)) < 2:
            continue
        positions = []
        offset = 0
        while True:
            idx = data.find(candidate, offset)
            if idx == -1:
                break
            positions.append(idx)
            offset = idx + 1
            if len(positions) > 100:
                break
        if len(positions) >= 3:
            # Check if sizes after delimiters are valid
            valid_count = 0
            for pos in positions:
                size_off = pos + dlen
                if size_off + size_width <= len(data):
                    try:
                        sz = struct.unpack_from(size_fmt, data, size_off)[0]
                        if 0 < sz < len(data):
                            valid_count += 1
                    except struct.error:
                        pass
            if valid_count >= len(positions) * 0.5:
                # This delimiter looks valid — extract chunks
                for pos in positions[:limit]:
                    size_off = pos + dlen
                    if size_off + size_width > len(data):
                        break
                    sz = struct.unpack_from(size_fmt, data, size_off)[0]
                    pay_start = size_off + size_width
                    if sz > 0 and pay_start + sz <= len(data):
                        payload = data[pay_start:pay_start + sz]
                        chunks.append({
                            "index": len(chunks),
                            "auto_delimiter": candidate.hex(),
                            "delimiter_offset": hex(pos),
                            "payload_offset": hex(pay_start),
                            "size": sz,
                            "entropy": round(_shannon_entropy(payload), 2),
                            "preview_hex": payload[:64].hex(),
                        })
                if chunks:
                    break
    return chunks


def _detect_fixed_chunk_size(data: bytes) -> Optional[int]:
    """Detect fixed chunk size from repeating entropy patterns."""
    if len(data) < 64:
        return None
    # Try common chunk sizes
    for size in [16, 32, 64, 128, 256, 512, 1024]:
        if len(data) < size * 3:
            continue
        # Check if entropy is consistent across chunks
        entropies = []
        for i in range(0, min(len(data), size * 10), size):
            chunk = data[i:i + size]
            if len(chunk) == size:
                entropies.append(_shannon_entropy(chunk))
        if len(entropies) >= 3:
            avg = sum(entropies) / len(entropies)
            variance = sum((e - avg) ** 2 for e in entropies) / len(entropies)
            if variance < 1.0:  # Consistent entropy across chunks
                return size
    return None


# ===================================================================
#  Tool 3: extract_config_automated
# ===================================================================

# Regex patterns for C2 config extraction
_IP_PATTERN = re.compile(rb"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)")
_URL_PATTERN = re.compile(rb"https?://[^\x00-\x1f\x7f-\x9f \"'<>]{4,200}")
_DOMAIN_PATTERN = re.compile(rb"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|info|biz|cc|pw|top|onion|bit)\b")
_REGISTRY_KEY_PATTERN = re.compile(rb"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\x00-\x1f]{4,200}")
_FILE_PATH_PATTERN = re.compile(rb"(?:[A-Z]:\\|\\\\)[^\x00-\x1f\"<>|]{4,200}")
_PORT_PATTERN = re.compile(rb":(\d{2,5})\b")
_BASE64_BLOB_PATTERN = re.compile(rb"(?:[A-Za-z0-9+/]{20,}={0,2})")
_MUTEX_PATTERN = re.compile(rb"(?:Global\\|Local\\)[^\x00-\x1f]{4,100}")


@tool_decorator
async def extract_config_automated(
    ctx: Context,
    data_hex: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: explore] Automatically extracts potential C2 configuration data
    from the binary using regex patterns and heuristics. Finds IPs, URLs,
    domains, registry keys, file paths, mutexes, and base64-encoded config blobs.

    When to use: After triage shows networking or persistence capabilities,
    or when looking for C2 infrastructure indicators.

    Next steps: Use get_iocs_structured() to export findings in STIX format.
    Verify IOCs with get_virustotal_report_for_loaded_file().

    Args:
        ctx: MCP Context.
        data_hex: Optional hex data to scan. If None, uses loaded file.
        limit: Max items per category. Default 20.
    """
    await ctx.info("Extracting automated config (C2, keys, domains)")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Data too large (max 100MB).")

    def _extract():
        config: Dict[str, List] = {
            "ip_addresses": [],
            "urls": [],
            "domains": [],
            "registry_keys": [],
            "file_paths": [],
            "mutexes": [],
            "base64_blobs": [],
            "ports": [],
        }

        # Private IP exclusion for reducing noise
        _PRIVATE_PREFIXES = (b"10.", b"127.", b"192.168.", b"0.0.", b"255.")

        for match in _IP_PATTERN.finditer(data):
            ip = match.group(0)
            if not any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
                entry = {"value": ip.decode("ascii", "replace"), "offset": hex(match.start())}
                if entry not in config["ip_addresses"]:
                    config["ip_addresses"].append(entry)
                    if len(config["ip_addresses"]) >= limit:
                        break

        for match in _URL_PATTERN.finditer(data):
            url = _safe_decode(match.group(0))
            entry = {"value": url, "offset": hex(match.start())}
            if entry not in config["urls"]:
                config["urls"].append(entry)
                if len(config["urls"]) >= limit:
                    break

        for match in _DOMAIN_PATTERN.finditer(data):
            domain = match.group(0).decode("ascii", "replace").lower()
            # Filter out version-like strings
            if not re.match(r"^\d+\.\d+\.\d+", domain):
                entry = {"value": domain, "offset": hex(match.start())}
                if entry not in config["domains"]:
                    config["domains"].append(entry)
                    if len(config["domains"]) >= limit:
                        break

        for match in _REGISTRY_KEY_PATTERN.finditer(data):
            entry = {"value": _safe_decode(match.group(0)), "offset": hex(match.start())}
            config["registry_keys"].append(entry)
            if len(config["registry_keys"]) >= limit:
                break

        for match in _FILE_PATH_PATTERN.finditer(data):
            entry = {"value": _safe_decode(match.group(0)), "offset": hex(match.start())}
            config["file_paths"].append(entry)
            if len(config["file_paths"]) >= limit:
                break

        for match in _MUTEX_PATTERN.finditer(data):
            entry = {"value": _safe_decode(match.group(0)), "offset": hex(match.start())}
            config["mutexes"].append(entry)
            if len(config["mutexes"]) >= limit:
                break

        # Base64 blobs (only long ones that might be configs)
        for match in _BASE64_BLOB_PATTERN.finditer(data):
            blob = match.group(0)
            if len(blob) >= 40:  # At least ~30 bytes decoded
                entry = {
                    "value": blob.decode("ascii", "replace")[:200],
                    "offset": hex(match.start()),
                    "encoded_length": len(blob),
                }
                config["base64_blobs"].append(entry)
                if len(config["base64_blobs"]) >= limit:
                    break

        return config

    config = await asyncio.to_thread(_extract)

    # Count total IOCs
    total = sum(len(v) for v in config.values())

    # Auto-note significant findings
    auto_noted = 0
    for category in ["ip_addresses", "urls", "domains"]:
        for item in config.get(category, [])[:5]:
            try:
                state.add_note(
                    content=f"[auto-config] {category}: {item['value']}",
                    category="tool_result",
                    tool_name="extract_config_automated",
                )
                auto_noted += 1
            except Exception:
                pass

    result: Dict[str, Any] = {
        "config": config,
        "total_indicators": total,
        "data_size": len(data),
    }
    if auto_noted:
        result["auto_noted"] = f"{auto_noted} IOC(s) auto-saved as notes."
    if total > 0:
        result["next_steps"] = [
            "get_iocs_structured(format='json') — export all IOCs in structured format",
            "get_virustotal_report_for_loaded_file() — check file reputation",
            "add_note() — record significant C2 indicators",
        ]
    else:
        result["next_steps"] = [
            "Try brute_force_simple_crypto() if data appears encrypted",
            "Check FLOSS strings: search_floss_strings(query='http')",
        ]

    return await _check_mcp_response_size(ctx, result, "extract_config_automated")
