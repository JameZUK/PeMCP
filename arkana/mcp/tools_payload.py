"""MCP tools for payload extraction — steganography, custom containers, and config extraction.

Detects data hidden after image EOF markers, parses common malware container
formats, and automatically extracts C2 configurations using heuristics.
"""
import asyncio
import re
import struct

from typing import Dict, Any, List, Optional, Tuple

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._progress_bridge import ProgressBridge
from arkana.mcp._refinery_helpers import (
    _get_data_from_hex_or_file, _bytes_to_hex, _safe_decode,
    _write_output_and_register_artifact,
)


# L: Use shared implementation from arkana.utils instead of duplicate
from arkana.utils import shannon_entropy as _shannon_entropy


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
    output_path: Optional[str] = None,
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
        output_path: (Optional[str]) Directory to save extracted payloads. Each payload is saved
            with a descriptive name and registered as an artifact.
    """
    await ctx.info("Scanning for steganographic payloads (EOF marker analysis)")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Data too large (max 100MB).")

    save_data = bool(output_path)

    def _scan():
        findings = []
        raw_items: Optional[List[bytes]] = [] if save_data else None

        def _add_finding(entry, payload_bytes):
            findings.append(entry)
            if raw_items is not None:
                raw_items.append(payload_bytes)

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

                        _add_finding({
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
                        }, trailing)

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
                    _add_finding({
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
                    }, hidden_data)
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
                            _add_finding({
                                "type": "PE_overlay",
                                "image_format": "PE",
                                "payload_offset": hex(overlay_start),
                                "payload_size": len(overlay),
                                "payload_entropy": round(_shannon_entropy(overlay[:4096]), 2),
                                "payload_preview_hex": overlay[:64].hex(),
                                "payload_magic": _identify_magic(overlay[:16]),
                            }, overlay)
            except Exception:
                pass

        return findings, raw_items

    findings, raw_items = await asyncio.to_thread(_scan)

    response: Dict[str, Any] = {
        "findings": findings,
        "count": len(findings),
        "data_size": len(data),
        "next_steps": _suggest_next_steps(findings),
    }

    if output_path and raw_items:
        import os
        from pathlib import Path
        state.check_path_allowed(str(Path(output_path).resolve()))
        os.makedirs(output_path, exist_ok=True)
        artifacts: List[Dict[str, Any]] = []
        for i, raw in enumerate(raw_items):
            name = f"payload_{i}_{findings[i].get('type', 'unknown')}.bin"
            item_path = os.path.join(output_path, name)
            artifact_meta = await asyncio.to_thread(
                _write_output_and_register_artifact,
                item_path, raw, "extract_steganography",
                f"Steganographic payload: {findings[i].get('type', 'unknown')} ({len(raw)} bytes)",
            )
            artifacts.append(artifact_meta)
        response["artifacts"] = artifacts

    return await _check_mcp_response_size(ctx, response, "extract_steganography")


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
    output_path: Optional[str] = None,
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
        output_path: (Optional[str]) Directory to save extracted chunks. Each chunk is saved
            as chunk_N.bin and registered as an artifact.
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

    save_data = bool(output_path)

    def _parse():
        chunks = []
        raw_items: Optional[List[bytes]] = [] if save_data else None
        offset = 0

        def _add_chunk(entry, payload_bytes):
            chunks.append(entry)
            if raw_items is not None:
                raw_items.append(payload_bytes)

        if structure == "delimiter_size_payload":
            if delim_bytes is None:
                auto_chunks = _auto_detect_delimiter(data, size_width, endian + size_fmt, limit)
                return auto_chunks, None

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
                _add_chunk({
                    "index": len(chunks),
                    "delimiter_offset": hex(idx),
                    "payload_offset": hex(payload_start),
                    "size": chunk_size,
                    "entropy": round(_shannon_entropy(payload), 2),
                    "preview_hex": payload[:64].hex(),
                    "magic": _identify_magic(payload[:16]),
                }, payload)
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
                _add_chunk({
                    "index": len(chunks),
                    "size_offset": hex(offset),
                    "payload_offset": hex(payload_start),
                    "size": chunk_size,
                    "entropy": round(_shannon_entropy(payload), 2),
                    "preview_hex": payload[:64].hex(),
                    "magic": _identify_magic(payload[:16]),
                }, payload)
                offset = payload_start + chunk_size
                if len(chunks) >= limit:
                    break

        elif structure == "fixed_chunks":
            # Auto-detect chunk size from repeating patterns
            chunk_size = _detect_fixed_chunk_size(data)
            if chunk_size:
                for i in range(0, len(data) - chunk_size + 1, chunk_size):
                    payload = data[i:i + chunk_size]
                    _add_chunk({
                        "index": len(chunks),
                        "offset": hex(i),
                        "size": chunk_size,
                        "entropy": round(_shannon_entropy(payload), 2),
                        "preview_hex": payload[:64].hex(),
                    }, payload)
                    if len(chunks) >= limit:
                        break

        return chunks, raw_items

    chunks, raw_items = await asyncio.to_thread(_parse)

    response: Dict[str, Any] = {
        "chunks": chunks,
        "count": len(chunks),
        "data_size": len(data),
        "structure": structure,
    }

    if output_path and raw_items:
        import os
        from pathlib import Path
        state.check_path_allowed(str(Path(output_path).resolve()))
        os.makedirs(output_path, exist_ok=True)
        artifacts: List[Dict[str, Any]] = []
        for i, raw in enumerate(raw_items):
            name = f"chunk_{i}.bin"
            item_path = os.path.join(output_path, name)
            artifact_meta = await asyncio.to_thread(
                _write_output_and_register_artifact,
                item_path, raw, "parse_custom_container",
                f"Container chunk {i} ({len(raw)} bytes)",
            )
            artifacts.append(artifact_meta)
        response["artifacts"] = artifacts

    return await _check_mcp_response_size(ctx, response, "parse_custom_container")


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
#  Encrypted config scanner (signature-driven)
# ===================================================================

def _scan_encrypted_configs(data: bytes, bridge: ProgressBridge) -> List[Dict[str, Any]]:
    """Scan for encrypted config blocks using malware_signatures.yaml metadata.

    For families with ``config.encryption: xor_single_byte``, searches for runs
    of repeated key bytes (the encrypted zero-padding pattern), XOR-decrypts
    candidate blocks, and validates against known markers.

    Returns a list of detected config blocks with family hint, key, offset,
    and decrypted content preview.
    """
    from pathlib import Path
    import yaml

    sigs_path = Path(__file__).resolve().parent.parent / "data" / "malware_signatures.yaml"
    if not sigs_path.exists():
        return []

    try:
        with open(sigs_path, "r") as f:
            kb = yaml.safe_load(f)
    except Exception:
        return []

    families = kb.get("families", [])
    results: List[Dict[str, Any]] = []

    # If PE is loaded, try .data section first for faster scanning
    data_section_range = None
    if state.pe_object:
        try:
            for sec in state.pe_object.sections:
                name = sec.Name.decode("utf-8", "ignore").rstrip("\x00")
                if name == ".data":
                    offset = sec.PointerToRawData
                    size = sec.SizeOfRawData
                    data_section_range = (offset, offset + size)
                    break
        except Exception:
            pass

    for family in families:
        config_meta = family.get("config")
        if not isinstance(config_meta, dict):
            continue
        if config_meta.get("encryption") != "xor_single_byte":
            continue

        family_name = family.get("family", "unknown")
        constants = family.get("constants") or {}
        if not isinstance(constants, dict):
            continue

        config_size = constants.get("config_size")
        if not config_size or not isinstance(config_size, int):
            continue

        # Collect candidate XOR keys from constants (xor_key_*)
        candidate_keys: List[int] = []
        for k, v in constants.items():
            if k.startswith("xor_key_") and isinstance(v, int) and 0 < v < 256:
                candidate_keys.append(v)
        if not candidate_keys:
            continue

        # Parse config_start_marker from hex string
        marker_hex = constants.get("config_start_marker", "")
        marker_bytes = b""
        if isinstance(marker_hex, str) and marker_hex.strip():
            try:
                marker_bytes = bytes.fromhex(marker_hex.replace(" ", ""))
            except ValueError:
                pass

        # Determine scan regions — prioritize .data section if available
        scan_regions: List[bytes] = []
        if data_section_range:
            sec_start, sec_end = data_section_range
            scan_regions.append(data[sec_start:sec_end])
        scan_regions.append(data)  # Fallback to full file

        for key in candidate_keys:
            for region in scan_regions:
                # Search for runs of repeated key bytes (encrypted null padding)
                # A config block XOR'd with single-byte key will have runs of that
                # key byte wherever the plaintext was null.
                min_run = 16  # At least 16 consecutive key bytes
                needle = bytes([key]) * min_run
                search_start = 0
                while search_start < len(region) - config_size:
                    pos = region.find(needle, search_start)
                    if pos == -1:
                        break

                    # Align to start of config block — scan backwards from the
                    # run to find where the key-byte pattern begins
                    block_start = pos
                    while block_start > 0 and region[block_start - 1] == key:
                        block_start -= 1
                    # Ensure we have enough data for a full config block
                    if block_start + config_size > len(region):
                        search_start = pos + min_run
                        continue

                    candidate = region[block_start:block_start + config_size]
                    decrypted = bytes(b ^ key for b in candidate)

                    # Validate: check for marker in the first 16 bytes
                    valid = False
                    if marker_bytes and marker_bytes in decrypted[:16]:
                        valid = True
                    elif not marker_bytes:
                        # No marker defined — check if decrypted looks structured
                        # (low entropy first 32 bytes with some non-null content)
                        first32 = decrypted[:32]
                        non_null = sum(1 for b in first32 if b != 0)
                        if 4 <= non_null <= 28:
                            valid = True

                    if valid:
                        # Calculate the absolute offset in the original data
                        if data_section_range and region is not data:
                            abs_offset = block_start
                        elif data_section_range and region is scan_regions[0]:
                            abs_offset = data_section_range[0] + block_start
                        else:
                            abs_offset = block_start

                        # ASCII preview: printable chars, dots for non-printable
                        preview_bytes = decrypted[:128]
                        ascii_preview = "".join(
                            chr(b) if 32 <= b < 127 else "." for b in preview_bytes
                        )

                        results.append({
                            "family_hint": family_name,
                            "xor_key": key,
                            "xor_key_hex": f"0x{key:02x}",
                            "config_offset": abs_offset,
                            "config_offset_hex": f"0x{abs_offset:x}",
                            "config_size": config_size,
                            "decrypted_hex": decrypted.hex(),
                            "decrypted_preview": ascii_preview,
                        })
                        # Found a valid config for this key — stop scanning this region
                        break

                    search_start = pos + min_run

                if results and results[-1].get("xor_key") == key:
                    break  # Found config with this key, skip remaining regions

    return results


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
    output_path: Optional[str] = None,
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
        output_path: (Optional[str]) Save extracted config as JSON to this path and register as artifact.
    """
    await ctx.info("Extracting automated config (C2, keys, domains)")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Data too large (max 100MB).")

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _extract():
        bridge.report_progress(5, 100)
        bridge.info("Scanning for IPs, URLs, domains...")

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

        bridge.report_progress(35, 100)
        bridge.info("Scanning for registry keys, paths, mutexes...")

        for match in _REGISTRY_KEY_PATTERN.finditer(data):
            entry = {"value": _safe_decode(match.group(0)), "offset": hex(match.start())}
            config["registry_keys"].append(entry)
            if len(config["registry_keys"]) >= limit:
                break

        for match in _FILE_PATH_PATTERN.finditer(data):
            raw = match.group(0)
            # Skip paths with non-printable bytes (0x80-0xFF) — false
            # positives from packed/encrypted data.
            if any(b > 0x7E for b in raw):
                continue
            entry = {"value": _safe_decode(raw), "offset": hex(match.start())}
            config["file_paths"].append(entry)
            if len(config["file_paths"]) >= limit:
                break

        for match in _MUTEX_PATTERN.finditer(data):
            entry = {"value": _safe_decode(match.group(0)), "offset": hex(match.start())}
            config["mutexes"].append(entry)
            if len(config["mutexes"]) >= limit:
                break

        bridge.report_progress(60, 100)
        bridge.info("Scanning for Base64 config blobs...")

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

        bridge.report_progress(75, 100)
        bridge.info("Scanning for encrypted configs using known family signatures...")

        encrypted_configs = _scan_encrypted_configs(data, bridge)

        bridge.report_progress(95, 100)
        bridge.info("Finalizing config extraction...")

        return config, encrypted_configs

    config, encrypted_configs = await asyncio.to_thread(_extract)

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
    if encrypted_configs:
        result["encrypted_configs"] = encrypted_configs
        for ec in encrypted_configs:
            try:
                state.add_note(
                    content=(
                        f"[auto-config] Encrypted config detected: "
                        f"{ec['family_hint']} (XOR key {ec['xor_key_hex']}, "
                        f"offset {ec['config_offset_hex']}, {ec['config_size']} bytes)"
                    ),
                    category="tool_result",
                    tool_name="extract_config_automated",
                )
                auto_noted += 1
            except Exception:
                pass
    if auto_noted:
        result["auto_noted"] = f"{auto_noted} IOC(s) auto-saved as notes."
    if total > 0 or encrypted_configs:
        next_steps = [
            "get_iocs_structured(format='json') — export all IOCs in structured format",
            "get_virustotal_report_for_loaded_file() — check file reputation",
            "add_note() — record significant C2 indicators",
        ]
        if encrypted_configs:
            next_steps.insert(0,
                "Use get_hex_dump() or refinery_xor() on decrypted config to parse TLV/field structures"
            )
        result["next_steps"] = next_steps
    else:
        result["next_steps"] = [
            "Try brute_force_simple_crypto() if data appears encrypted",
            "Check FLOSS strings: search_floss_strings(query='http')",
        ]

    # Warn when binary is likely packed — regex matches in compressed data
    # produce garbage like X:\¬8§Ã*.
    likely_packed = (state.pe_data or {}).get("triage", {}).get(
        "packing_assessment", {}
    ).get("likely_packed", False)
    if not likely_packed and state.pe_object:
        try:
            for sec in state.pe_object.sections:
                if sec.get_entropy() > 7.0 and sec.SizeOfRawData > 1024:
                    likely_packed = True
                    break
        except Exception:
            pass
    if likely_packed:
        result["warning"] = (
            "Binary appears packed or compressed. Config matches extracted from "
            "compressed data are likely false positives (garbage paths, random byte "
            "sequences). Consider unpacking first with auto_unpack_pe() or "
            "try_all_unpackers()."
        )

    if output_path:
        import os, json
        state.check_path_allowed(os.path.realpath(output_path))
        config_output = {"config": config, "total_indicators": total}
        if encrypted_configs:
            config_output["encrypted_configs"] = encrypted_configs
        text_bytes = json.dumps(config_output, indent=2).encode("utf-8")
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, text_bytes, "extract_config_automated",
            f"Extracted config ({total} indicators)",
        )
        result["artifact"] = artifact_meta

    return await _check_mcp_response_size(ctx, result, "extract_config_automated")


# ===================================================================
#  Tool 4: extract_config_for_family — KB-driven config extraction
# ===================================================================

def _rc4_decrypt(data: bytes, key: bytes) -> bytes:
    """RC4 decryption (KSA + PRGA)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray(len(data))
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result[n] = data[n] ^ S[(S[i] + S[j]) % 256]
    return bytes(result)


def _parse_cstrings(data: bytes, max_count: int = 50) -> list:
    """Extract null-terminated strings sequentially from data."""
    strings = []
    offset = 0
    while offset < len(data) and len(strings) < max_count:
        null_pos = data.find(b"\x00", offset)
        if null_pos == -1:
            s = data[offset:].decode("ascii", errors="replace")
            if s:
                strings.append(s)
            break
        s = data[offset:null_pos].decode("ascii", errors="replace")
        strings.append(s)
        offset = null_pos + 1
    return strings


# --- Family-specific extractor dispatch table ---

def _read_lpstring(data: bytes, pos: int) -> Tuple[str, int]:
    """Read a length-prefixed null-terminated string: uint32_le length | chars | null."""
    if pos + 4 > len(data):
        return ("", pos)
    strlen = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    if strlen < 1 or pos + strlen > len(data):
        return ("", pos)
    raw = data[pos:pos + strlen]
    # Strip trailing null if present (the null is included in strlen)
    if raw and raw[-1:] == b"\x00":
        raw = raw[:-1]
    pos += strlen
    return (raw.decode("ascii", errors="replace"), pos)


def _extract_adaptixc2_beacon(file_data: bytes, section_data: bytes,
                               section_offset: int, family_meta: dict) -> Optional[Dict[str, Any]]:
    """Extract AdaptixC2 Beacon config: size(4B LE) | ciphertext | rc4_key(16B).

    Decrypted config format (length-prefixed strings):
      [4B header][1B ssl][4B server_count]
      per server: [4B strlen][string+null][4B port]
      [lpstring method][lpstring uri][lpstring parameter]
      [lpstring user_agent][lpstring http_headers]
      [4B sleep][4B jitter][4B download_chunk][4B pad][4B retry][4B pad]
    """
    config_meta = family_meta.get("config", {})
    key_length = config_meta.get("key_length", 16)

    # Scan the section for size-prefixed blobs that look like encrypted configs
    for offset in range(0, min(len(section_data) - 24, 256)):
        size_val = struct.unpack_from("<I", section_data, offset)[0]
        if size_val < 10 or size_val > 4096:
            continue
        total_blob = 4 + size_val + key_length
        if offset + total_blob > len(section_data):
            continue

        ciphertext = section_data[offset + 4:offset + 4 + size_val]
        key = section_data[offset + 4 + size_val:offset + total_blob]

        # Validate: key should have reasonable entropy (not all zeros/same byte)
        if len(set(key)) < 3:
            continue

        plaintext = _rc4_decrypt(ciphertext, key)
        if len(plaintext) < 20:
            continue

        # Validate: byte 4 should be ssl flag (0 or 1), bytes 5-8 a small server count
        ssl_byte = plaintext[4]
        if ssl_byte > 1:
            continue
        server_count = struct.unpack_from("<I", plaintext, 5)[0]
        if server_count < 1 or server_count > 50:
            continue

        # Parse fields
        fields = {}
        pos = 0
        try:
            fields["config_header"] = plaintext[:4].hex()
            pos = 4
            fields["ssl"] = plaintext[pos]
            pos += 1
            fields["server_count"] = struct.unpack_from("<I", plaintext, pos)[0]
            pos += 4

            # Parse servers: each is lpstring(addr) + uint32(port)
            servers = []
            for _ in range(fields["server_count"]):
                addr, pos = _read_lpstring(plaintext, pos)
                if pos + 4 > len(plaintext):
                    break
                port = struct.unpack_from("<I", plaintext, pos)[0]
                pos += 4
                servers.append(f"{addr}:{port}")
            fields["servers"] = ";".join(servers)

            # Parse remaining length-prefixed strings
            for field_name in ["http_method", "uri_path", "parameter",
                               "user_agent", "http_headers"]:
                val, pos = _read_lpstring(plaintext, pos)
                fields[field_name] = val

            # Parse trailing integers
            for field_name in ["sleep", "jitter", "download_chunk_size",
                               "_pad1", "retry_count", "_pad2"]:
                if pos + 4 > len(plaintext):
                    break
                fields[field_name] = struct.unpack_from("<I", plaintext, pos)[0]
                pos += 4

            # Remove padding fields from output
            fields.pop("_pad1", None)
            fields.pop("_pad2", None)
        except Exception:
            pass  # Return whatever we managed to parse

        # Extract IOCs
        iocs = []
        if fields.get("servers"):
            for server in fields["servers"].split(";"):
                server = server.strip()
                if server:
                    iocs.append({"type": "server", "value": server})
        if fields.get("uri_path"):
            iocs.append({"type": "uri_path", "value": fields["uri_path"]})
        if fields.get("user_agent"):
            iocs.append({"type": "user_agent", "value": fields["user_agent"]})

        abs_offset = section_offset + offset
        return {
            "family": "AdaptixC2 Beacon",
            "config_offset": hex(abs_offset),
            "config_size": total_blob,
            "encryption": "rc4",
            "key_hex": key.hex(),
            "key_offset": hex(abs_offset + 4 + size_val),
            "decrypted_size": len(plaintext),
            "decrypted_hex": plaintext.hex(),
            "fields": fields,
            "iocs": iocs,
            "bytes_parsed": pos,
        }

    return None


def _extract_generic_rc4_size_prefixed(file_data: bytes, section_data: bytes,
                                        section_offset: int, family_meta: dict) -> Optional[Dict[str, Any]]:
    """Generic extractor for: size(4B LE) | ciphertext | key(NB) in a section."""
    config_meta = family_meta.get("config", {})
    key_length = config_meta.get("key_length", 16)
    family_name = family_meta.get("family", "unknown")

    for offset in range(0, min(len(section_data) - 24, 512)):
        size_val = struct.unpack_from("<I", section_data, offset)[0]
        if size_val < 8 or size_val > 8192:
            continue
        total_blob = 4 + size_val + key_length
        if offset + total_blob > len(section_data):
            continue

        ciphertext = section_data[offset + 4:offset + 4 + size_val]
        key = section_data[offset + 4 + size_val:offset + total_blob]

        if len(set(key)) < 3:
            continue

        plaintext = _rc4_decrypt(ciphertext, key)

        # Basic validation: should contain some printable content
        printable_count = sum(1 for b in plaintext if 32 <= b < 127)
        if printable_count < len(plaintext) * 0.15:
            continue

        abs_offset = section_offset + offset
        # Extract any null-terminated strings as potential config values
        strings = _parse_cstrings(plaintext, max_count=20)
        strings = [s for s in strings if len(s) >= 2]

        return {
            "family": family_name,
            "config_offset": hex(abs_offset),
            "config_size": total_blob,
            "encryption": "rc4",
            "key_hex": key.hex(),
            "key_offset": hex(abs_offset + 4 + size_val),
            "decrypted_size": len(plaintext),
            "decrypted_hex": plaintext.hex(),
            "decrypted_text": plaintext.decode("ascii", errors="replace")[:500],
            "extracted_strings": strings[:20],
        }

    return None


def _extract_xor_single_byte(file_data: bytes, section_data: bytes,
                               section_offset: int, family_meta: dict) -> Optional[Dict[str, Any]]:
    """Generic extractor for single-byte XOR encrypted configs."""
    constants = family_meta.get("constants") or {}
    family_name = family_meta.get("family", "unknown")

    config_size = constants.get("config_size")
    if not isinstance(config_size, int) or config_size < 8:
        return None

    candidate_keys = []
    for k, v in constants.items():
        if k.startswith("xor_key_") and isinstance(v, int) and 0 < v < 256:
            candidate_keys.append(v)
    if not candidate_keys:
        return None

    for key in candidate_keys:
        needle = bytes([key]) * 16
        pos = section_data.find(needle)
        while pos != -1:
            # Align to block start
            block_start = pos
            while block_start > 0 and section_data[block_start - 1] == key:
                block_start -= 1
            if block_start + config_size > len(section_data):
                pos = section_data.find(needle, pos + 16)
                continue

            candidate = section_data[block_start:block_start + config_size]
            decrypted = bytes(b ^ key for b in candidate)

            # Validate
            first32 = decrypted[:32]
            non_null = sum(1 for b in first32 if b != 0)
            if 4 <= non_null <= 28:
                abs_offset = section_offset + block_start
                strings = _parse_cstrings(decrypted, max_count=20)
                strings = [s for s in strings if len(s) >= 2]

                return {
                    "family": family_name,
                    "config_offset": hex(abs_offset),
                    "config_size": config_size,
                    "encryption": "xor_single_byte",
                    "xor_key": key,
                    "xor_key_hex": f"0x{key:02x}",
                    "decrypted_size": len(decrypted),
                    "decrypted_hex": decrypted.hex(),
                    "decrypted_text": decrypted.decode("ascii", errors="replace")[:500],
                    "extracted_strings": strings[:20],
                }

            pos = section_data.find(needle, pos + 16)

    return None


# Dispatch table: family name (lowercase) → extractor function
_FAMILY_EXTRACTORS = {
    "adaptixc2 beacon": _extract_adaptixc2_beacon,
}


@tool_decorator
async def extract_config_for_family(
    ctx: Context,
    family: str,
    section_hint: Optional[str] = None,
    offset_hint: Optional[str] = None,
    auto_note: bool = True,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Extracts malware configuration using family-specific
    recipes from the knowledge base. Locates the encrypted config blob, extracts
    the key, decrypts, and parses the fields automatically.

    When to use: After identify_malware_family() returns a confirmed family, use
    this to extract the full C2 config in a single call. Falls back to generic
    extraction if no family-specific extractor exists.

    Next steps: Review extracted IOCs with get_iocs_structured(). Use add_note()
    to record key findings. Cross-reference servers with get_virustotal_report().

    Args:
        family: Malware family name (e.g. 'AdaptixC2 Beacon'). Must match a
            family in malware_signatures.yaml.
        section_hint: Override the section to scan (e.g. '.rdata', '.data').
            If None, uses the section from the KB entry.
        offset_hint: Start scanning at this file offset (e.g. '0x1000').
        auto_note: If True, automatically save extracted IOCs as notes.
        output_path: (Optional[str]) Save extracted config as JSON to this path and register as artifact.
    """
    await ctx.info(f"Extracting config for family: {family}")
    _check_pe_loaded("extract_config_for_family")

    # Load KB entry
    from arkana.mcp.tools_malware_identify import _get_families
    family_meta = None
    for fam in _get_families():
        if fam.get("family", "").lower() == family.lower():
            family_meta = fam
            break

    if not family_meta:
        return {
            "error": f"Unknown family '{family}'. Use list_malware_signatures() to see available families.",
        }

    config_meta = family_meta.get("config") or {}
    if not isinstance(config_meta, dict):
        return {
            "error": f"No config extraction info for '{family}' in the knowledge base.",
            "family": family,
        }

    pe = state.pe_object
    file_data = pe.__data__

    # Determine which section to scan
    target_section = section_hint
    if not target_section:
        loc = config_meta.get("location") or {}
        if isinstance(loc, dict):
            target_section = loc.get("section")

    # Get section data
    section_data = file_data
    section_offset = 0
    if target_section and pe.sections:
        for sec in pe.sections:
            sec_name = sec.Name.decode("utf-8", "ignore").rstrip("\x00")
            if sec_name == target_section:
                section_offset = sec.PointerToRawData
                section_size = sec.SizeOfRawData
                section_data = file_data[section_offset:section_offset + section_size]
                break

    if offset_hint:
        from arkana.mcp._input_helpers import _parse_int_param
        hint_offset = _parse_int_param(offset_hint, "offset_hint")
        if hint_offset >= section_offset:
            rel_offset = hint_offset - section_offset
            section_data = section_data[rel_offset:]
            section_offset = hint_offset

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _extract():
        bridge.info(f"Scanning {target_section or 'full binary'} ({len(section_data)} bytes)...")
        bridge.report_progress(10, 100)

        # Try family-specific extractor first
        family_key = family.lower()
        if family_key in _FAMILY_EXTRACTORS:
            bridge.info(f"Using {family} specific extractor...")
            bridge.report_progress(30, 100)
            result = _FAMILY_EXTRACTORS[family_key](file_data, section_data,
                                                     section_offset, family_meta)
            if result:
                bridge.report_progress(90, 100)
                return result

        # Fall back to generic extraction based on encryption type
        encryption = config_meta.get("encryption", "")
        bridge.info(f"Trying generic {encryption} extraction...")
        bridge.report_progress(50, 100)

        if encryption == "rc4":
            result = _extract_generic_rc4_size_prefixed(
                file_data, section_data, section_offset, family_meta)
            if result:
                bridge.report_progress(90, 100)
                return result

        if encryption == "xor_single_byte":
            result = _extract_xor_single_byte(
                file_data, section_data, section_offset, family_meta)
            if result:
                bridge.report_progress(90, 100)
                return result

        bridge.report_progress(90, 100)
        return None

    result = await asyncio.to_thread(_extract)

    if result is None:
        return {
            "status": "not_found",
            "family": family,
            "section_scanned": target_section or "full binary",
            "encryption_type": config_meta.get("encryption", "unknown"),
            "hint": (
                "Config blob not found in the expected location. Try: "
                "1) Different section_hint (e.g. '.data', '.rdata', '.rsrc'). "
                "2) get_hex_dump() to manually inspect candidate regions. "
                "3) analyze_entropy_by_offset() to find encrypted regions."
            ),
        }

    result["status"] = "extracted"
    result["section_scanned"] = target_section or "full binary"

    # Auto-note IOCs
    if auto_note and result.get("iocs"):
        for ioc in result["iocs"][:10]:
            try:
                state.add_note(
                    content=f"[{family}] {ioc['type']}: {ioc['value']}",
                    category="ioc",
                )
            except Exception:
                pass
    if auto_note and result.get("fields"):
        try:
            fields_summary = ", ".join(
                f"{k}={v}" for k, v in list(result["fields"].items())[:8]
            )
            state.add_note(
                content=f"[{family}] Config extracted: {fields_summary}",
                category="tool_result",
            )
        except Exception:
            pass

    if output_path and result.get("status") == "extracted":
        import os, json
        state.check_path_allowed(os.path.realpath(output_path))
        text_bytes = json.dumps(result, indent=2, default=str).encode("utf-8")
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, text_bytes, "extract_config_for_family",
            f"Config for {family}",
        )
        result["artifact"] = artifact_meta

    return await _check_mcp_response_size(ctx, result, "extract_config_for_family")
