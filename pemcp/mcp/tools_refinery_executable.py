"""MCP tools powered by Binary Refinery for low-level executable analysis.

Covers section/segment extraction, virtual address reading, native
disassembly (x86/x64/ARM), CIL disassembly, entropy visualization,
steganography detection, and image analysis.
"""
import asyncio
import hashlib

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.mcp._refinery_helpers import (
    _require_refinery, _safe_decode, _bytes_to_hex, _hex_to_bytes,
    _get_file_data, _MAX_INPUT_SIZE_LARGE as _MAX_INPUT_SIZE,
)


# ===================================================================
#  1. SECTION / SEGMENT EXTRACTION
# ===================================================================

@tool_decorator
async def refinery_extract_sections(
    ctx: Context,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Extract individual sections/segments from PE, ELF, or Mach-O binaries using Binary Refinery.

    Works across all major executable formats. Each extracted section includes
    its name, virtual address, raw size, and entropy. This is format-agnostic
    unlike pefile-based section extraction.

    See also: get_section_permissions() for PE-specific section analysis with anomaly detection,
    analyze_entropy_by_offset() for PE-specific entropy analysis.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max sections to extract. Default 50.

    Returns:
        Dictionary with extracted section metadata and content previews.
    """
    _require_refinery("refinery_extract_sections")
    _check_pe_loaded("refinery_extract_sections")

    data = _get_file_data()
    await ctx.info(f"Extracting sections from binary ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.exe.vsect import vsect
        import math
        from collections import Counter

        results = []
        for chunk in data | vsect():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('name', 'vaddr', 'offset', 'type', 'flags', 'path'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])

            # Compute entropy
            if raw:
                length = len(raw)
                entropy = 0.0
                for count in Counter(raw).values():
                    p = count / length
                    entropy -= p * math.log2(p)
                entry["entropy"] = round(entropy, 4)

            entry["preview_hex"] = raw[:64].hex()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "sections_found": len(results),
        "results": results,
    }, "refinery_extract_sections")


# ===================================================================
#  2. VIRTUAL ADDRESS READ
# ===================================================================

@tool_decorator
async def refinery_virtual_read(
    ctx: Context,
    address: str,
    size: int = 256,
) -> Dict[str, Any]:
    """
    Read data at a virtual address from the loaded binary using Binary Refinery.

    Reads raw bytes at a specified virtual memory address from a PE/ELF/MachO
    binary. The address is resolved from the binary's section layout.

    Args:
        ctx: The MCP Context object.
        address: (str) Virtual address as hex string (e.g. '0x00401000').
        size: (int) Number of bytes to read. Default 256.

    Returns:
        Dictionary with data at the specified virtual address.
    """
    _require_refinery("refinery_virtual_read")
    _check_pe_loaded("refinery_virtual_read")

    data = _get_file_data()
    addr = int(address, 16) if isinstance(address, str) else address

    await ctx.info(f"Reading {size} bytes at VA {hex(addr)}...")

    def _run():
        from refinery.units.formats.exe.vsnip import vsnip
        return data | vsnip(slice(addr, addr + size)) | bytes

    result = await asyncio.to_thread(_run)
    return {
        "address": hex(addr),
        "requested_size": size,
        "actual_size": len(result),
        "hex": _bytes_to_hex(result),
        "text": _safe_decode(result)[:1000],
    }


# ===================================================================
#  3. FILE OFFSET TO VIRTUAL ADDRESS
# ===================================================================

@tool_decorator
async def refinery_file_to_virtual(
    ctx: Context,
    offset: str,
) -> Dict[str, Any]:
    """
    Convert a file offset to a virtual address using Binary Refinery.

    Maps a raw file offset to its corresponding virtual address in the
    loaded binary's memory layout. Useful for cross-referencing between
    static analysis (file offsets) and dynamic analysis (virtual addresses).

    Args:
        ctx: The MCP Context object.
        offset: (str) File offset as hex string (e.g. '0x400').

    Returns:
        Dictionary with the corresponding virtual address.
    """
    _require_refinery("refinery_file_to_virtual")
    _check_pe_loaded("refinery_file_to_virtual")

    data = _get_file_data()
    off = int(offset, 16) if isinstance(offset, str) else offset

    await ctx.info(f"Converting file offset {hex(off)} to virtual address...")

    def _run():
        import pefile
        pe = pefile.PE(data=data)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        # Search sections for the one containing this file offset
        for section in pe.sections:
            sec_start = section.PointerToRawData
            sec_end = sec_start + section.SizeOfRawData
            if sec_start <= off < sec_end:
                rva = section.VirtualAddress + (off - sec_start)
                va = image_base + rva
                return {
                    "file_offset": hex(off),
                    "virtual_address": hex(va),
                    "rva": hex(rva),
                    "image_base": hex(image_base),
                    "section": section.Name.rstrip(b'\x00').decode("utf-8", errors="replace"),
                }
        # Offset is in headers (before first section)
        return {
            "file_offset": hex(off),
            "virtual_address": hex(image_base + off),
            "rva": hex(off),
            "image_base": hex(image_base),
            "section": "(header)",
        }

    result = await asyncio.to_thread(_run)
    return result


# ===================================================================
#  4. NATIVE DISASSEMBLY (x86/x64/ARM)
# ===================================================================

@tool_decorator
async def refinery_disassemble(
    ctx: Context,
    data_hex: Optional[str] = None,
    count: int = 50,
) -> Dict[str, Any]:
    """
    Disassemble binary code (x86, x64, ARM) using Binary Refinery.

    Uses Capstone disassembly engine under the hood. Can disassemble raw
    shellcode or code from the loaded binary. Auto-detects architecture
    from PE/ELF headers when possible.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Raw code as hex. If None, uses loaded file entry point.
        count: (int) Max instructions to disassemble. Default 50.

    Returns:
        Dictionary with disassembly listing.
    """
    _require_refinery("refinery_disassemble")

    if data_hex:
        cleaned = data_hex.replace(" ", "").replace("0x", "").replace("\\x", "")
        data = bytes.fromhex(cleaned)
    else:
        _check_pe_loaded("refinery_disassemble")
        data = _get_file_data()

    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]

    await ctx.info(f"Disassembling {len(data)} bytes...")

    def _run():
        from refinery.units.sinks.asm import asm
        result = data | asm(count=count) | bytes
        return result

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "disassembly": _safe_decode(result)[:8000],
    }, "refinery_disassemble")


# ===================================================================
#  5. .NET CIL DISASSEMBLY (DNASM)
# ===================================================================

@tool_decorator
async def refinery_disassemble_cil(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Disassemble .NET CIL/MSIL bytecode to readable assembly using Binary Refinery's dnasm sink.

    Produces formatted CIL disassembly output with instruction offsets,
    opcodes, and operands. Different from refinery_dotnet_disassemble
    (dnopc) which extracts per-method; this produces a full listing.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) .NET assembly as hex. If None, uses loaded file.

    Returns:
        Dictionary with CIL disassembly text.
    """
    _require_refinery("refinery_disassemble_cil")

    if data_hex:
        cleaned = data_hex.replace(" ", "").replace("0x", "").replace("\\x", "")
        data = bytes.fromhex(cleaned)
    else:
        _check_pe_loaded("refinery_disassemble_cil")
        data = _get_file_data()

    await ctx.info("Disassembling .NET CIL bytecode...")

    def _run():
        from refinery.units.sinks.dnasm import dnasm
        return data | dnasm() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "disassembly": _safe_decode(result)[:8000],
    }, "refinery_disassemble_cil")


# ===================================================================
#  6. ENTROPY MAP
# ===================================================================

@tool_decorator
async def refinery_entropy_map(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate an entropy distribution map of binary data using Binary Refinery.

    Produces a visual entropy map showing byte distribution and entropy
    per region. High-entropy regions suggest encrypted or compressed data.
    Low-entropy regions suggest padding, null bytes, or structured data.

    See also: analyze_entropy_by_offset() for PE-specific section-by-section entropy analysis.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.

    Returns:
        Dictionary with entropy map visualization.
    """
    _require_refinery("refinery_entropy_map")

    if data_hex:
        cleaned = data_hex.replace(" ", "").replace("0x", "").replace("\\x", "")
        data = bytes.fromhex(cleaned)
    else:
        data = _get_file_data()

    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]

    await ctx.info(f"Generating entropy map for {len(data)} bytes...")

    def _run():
        import os
        from refinery.units.sinks.iemap import iemap
        # iemap uses refinery's get_terminal_size() which checks the
        # REFINERY_TERM_SIZE env var first, then falls back to
        # os.get_terminal_size().  In headless/async contexts (no TTY),
        # the fallback returns 0, causing "computed terminal width 0 is
        # too small for heatmap".  Set REFINERY_TERM_SIZE as a workaround.
        old_val = os.environ.get("REFINERY_TERM_SIZE")
        try:
            os.environ["REFINERY_TERM_SIZE"] = "120"
            return data | iemap() | bytes
        finally:
            if old_val is None:
                os.environ.pop("REFINERY_TERM_SIZE", None)
            else:
                os.environ["REFINERY_TERM_SIZE"] = old_val

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "entropy_map": _safe_decode(result)[:8000],
    }, "refinery_entropy_map")


# ===================================================================
#  7. STEGANOGRAPHY
# ===================================================================

@tool_decorator
async def refinery_stego_extract(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract hidden data from images using Binary Refinery's steganography unit.

    Attempts to extract data hidden in image pixels using common steganographic
    techniques (LSB embedding in RGBA channels). Supports PNG and BMP images.
    Malware campaigns sometimes use image steganography to hide payloads.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Image data as hex. If None, uses loaded file.

    Returns:
        Dictionary with extracted hidden data.
    """
    _require_refinery("refinery_stego_extract")

    if data_hex:
        cleaned = data_hex.replace(" ", "").replace("0x", "").replace("\\x", "")
        data = bytes.fromhex(cleaned)
    else:
        data = _get_file_data()

    await ctx.info(f"Extracting steganographic data from image ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.stego import stego
        results = []
        for chunk in data | stego():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "preview_hex": raw[:128].hex(),
            }
            if raw[:2] == b'MZ':
                entry["detected_type"] = "PE executable"
            elif raw[:4] == b'PK\x03\x04':
                entry["detected_type"] = "ZIP archive"
            results.append(entry)
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "items_found": len(results),
        "results": results,
    }, "refinery_stego_extract")
