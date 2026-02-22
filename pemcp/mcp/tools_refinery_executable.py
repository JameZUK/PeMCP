"""MCP tools powered by Binary Refinery for low-level executable analysis.

Covers section/segment extraction from PE/ELF/Mach-O, virtual address data
reads, native disassembly, .NET CIL disassembly, entropy visualization,
and image steganography extraction.
"""
import asyncio
import hashlib
import os

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context, REFINERY_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.mcp._format_helpers import _check_lib

_MAX_OUTPUT_ITEMS = 200


def _require_refinery(tool_name: str):
    _check_lib("binary-refinery", REFINERY_AVAILABLE, tool_name, pip_name="binary-refinery")


def _safe_decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def _bytes_to_hex(data: bytes, max_len: int = 4096) -> str:
    if len(data) > max_len:
        return data[:max_len].hex() + f"...[truncated, {len(data)} bytes total]"
    return data.hex()


def _get_file_data() -> bytes:
    if not state.pe_object:
        raise RuntimeError("No file is loaded. Use open_file() first.")
    raw = getattr(state.pe_object, "__data__", None)
    if raw is None:
        raw = getattr(state.pe_object, "get_data", lambda: None)()
    if raw is None and state.filepath and os.path.isfile(state.filepath):
        with open(state.filepath, "rb") as f:
            raw = f.read()
    if raw is None:
        raise RuntimeError("Cannot access raw file data.")
    return bytes(raw)


def _get_data_from_hex_or_file(data_hex: Optional[str]) -> bytes:
    if data_hex:
        cleaned = data_hex.replace(" ", "").replace("0x", "").replace("\\x", "")
        return bytes.fromhex(cleaned)
    return _get_file_data()


# ===================================================================
#  1. SECTION/SEGMENT EXTRACTION
# ===================================================================

@tool_decorator
async def refinery_extract_sections(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract all sections/segments from a PE, ELF, or Mach-O binary using Binary Refinery.

    Returns each section as a separate item with name, virtual address,
    size, entropy, and raw data hash. Works across all major executable formats.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Binary data as hex. If None, uses loaded file.

    Returns:
        Dictionary with extracted sections and their metadata.
    """
    _require_refinery("refinery_extract_sections")

    data = _get_data_from_hex_or_file(data_hex)
    await ctx.info(f"Extracting sections from binary ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.exe.vsect import vsect
        import math
        results = []
        for chunk in data | vsect():
            raw = bytes(chunk)
            # Compute entropy
            if raw:
                from collections import Counter
                counts = Counter(raw)
                length = len(raw)
                entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
            else:
                entropy = 0.0

            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "entropy": round(entropy, 3),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('name', 'vaddr', 'offset', 'type', 'flags'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            entry["preview_hex"] = raw[:64].hex()
            results.append(entry)
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "sections_found": len(results),
        "results": results,
    }, "refinery_extract_sections")


# ===================================================================
#  2. VIRTUAL ADDRESS DATA READ
# ===================================================================

@tool_decorator
async def refinery_virtual_read(
    ctx: Context,
    address: str,
    size: int = 256,
) -> Dict[str, Any]:
    """
    Read data at a virtual address from the loaded binary using Binary Refinery.

    Resolves a virtual address (VA) in the binary and extracts the raw data
    at that location. Works with PE, ELF, and Mach-O formats.

    Args:
        ctx: The MCP Context object.
        address: (str) Virtual address as hex string (e.g. '0x401000').
        size: (int) Number of bytes to read. Default 256.

    Returns:
        Dictionary with data at the specified virtual address.
    """
    _require_refinery("refinery_virtual_read")
    _check_pe_loaded("refinery_virtual_read")

    data = _get_file_data()
    addr_int = int(address, 0)
    await ctx.info(f"Reading {size} bytes at VA {hex(addr_int)}...")

    def _run():
        from refinery.units.formats.exe.vsnip import vsnip
        return data | vsnip(addr_int, size) | bytes

    result = await asyncio.to_thread(_run)
    return {
        "virtual_address": hex(addr_int),
        "requested_size": size,
        "actual_size": len(result),
        "data_hex": _bytes_to_hex(result),
        "data_text": _safe_decode(result)[:500],
    }


# ===================================================================
#  3. VIRTUAL ADDRESS RESOLUTION
# ===================================================================

@tool_decorator
async def refinery_resolve_address(
    ctx: Context,
    offset: str,
) -> Dict[str, Any]:
    """
    Convert a file offset to a virtual address (or vice versa) using Binary Refinery.

    Useful for correlating file offsets with runtime addresses when analyzing
    disassembly output or debugging information.

    Args:
        ctx: The MCP Context object.
        offset: (str) File offset or virtual address as hex (e.g. '0x1000').

    Returns:
        Dictionary with resolved address information.
    """
    _require_refinery("refinery_resolve_address")
    _check_pe_loaded("refinery_resolve_address")

    data = _get_file_data()
    offset_int = int(offset, 0)
    await ctx.info(f"Resolving address {hex(offset_int)}...")

    def _run():
        from refinery.units.formats.exe.vaddr import vaddr
        return data | vaddr(offset_int) | bytes

    result = await asyncio.to_thread(_run)
    return {
        "input_offset": hex(offset_int),
        "result_size": len(result),
        "result_text": _safe_decode(result)[:500],
    }


# ===================================================================
#  4. NATIVE DISASSEMBLY
# ===================================================================

@tool_decorator
async def refinery_disassemble(
    ctx: Context,
    data_hex: Optional[str] = None,
    architecture: str = "x86",
    count: int = 100,
) -> Dict[str, Any]:
    """
    Disassemble binary code using Binary Refinery's asm sink (Capstone backend).

    Supports x86, x86_64, ARM, ARM64, MIPS, and PowerPC architectures.
    Returns human-readable assembly listing.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Machine code as hex. If None, uses loaded file data.
        architecture: (str) Architecture: 'x86', 'x64', 'arm', 'arm64', 'mips', 'ppc'. Default 'x86'.
        count: (int) Max instructions to disassemble. Default 100.

    Returns:
        Dictionary with disassembly listing.
    """
    _require_refinery("refinery_disassemble")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > 1024 * 1024:
        data = data[:1024 * 1024]  # Cap at 1MB

    await ctx.info(f"Disassembling {len(data)} bytes ({architecture})...")

    def _run():
        from refinery.units.sinks.asm import asm
        # The asm unit auto-detects from PE headers if possible
        result = data | asm(count=count) | bytes
        return result

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "architecture": architecture,
        "input_size": len(data),
        "output_size": len(result),
        "disassembly": _safe_decode(result)[:8000],
    }, "refinery_disassemble")


# ===================================================================
#  5. .NET CIL DISASSEMBLY (VISUAL)
# ===================================================================

@tool_decorator
async def refinery_dotnet_disasm_visual(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Produce a visual .NET CIL/MSIL disassembly listing using Binary Refinery.

    Uses the dnasm sink unit to produce a formatted, syntax-highlighted
    disassembly of .NET Intermediate Language instructions. More visual
    than the raw dnopc output.

    Args:
        ctx: The MCP Context object.

    Returns:
        Dictionary with formatted CIL disassembly.
    """
    _require_refinery("refinery_dotnet_disasm_visual")
    _check_pe_loaded("refinery_dotnet_disasm_visual")

    data = _get_file_data()
    await ctx.info("Generating visual .NET CIL disassembly...")

    def _run():
        from refinery.units.sinks.dnasm import dnasm
        return data | dnasm() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "output_size": len(result),
        "disassembly": _safe_decode(result)[:8000],
    }, "refinery_dotnet_disasm_visual")


# ===================================================================
#  6. ENTROPY VISUALIZATION
# ===================================================================

@tool_decorator
async def refinery_entropy_map(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a byte distribution / entropy heat map using Binary Refinery.

    Produces a visual entropy map showing the distribution of byte values
    across the binary. High-entropy regions suggest encryption, compression,
    or random data. Low-entropy regions suggest code or structured data.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Binary data as hex. If None, uses loaded file.

    Returns:
        Dictionary with entropy map visualization.
    """
    _require_refinery("refinery_entropy_map")

    data = _get_data_from_hex_or_file(data_hex)
    await ctx.info(f"Generating entropy map for {len(data)} bytes...")

    def _run():
        from refinery.units.sinks.iemap import iemap
        return data | iemap() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "entropy_map": _safe_decode(result)[:8000],
    }, "refinery_entropy_map")


# ===================================================================
#  7. IMAGE STEGANOGRAPHY
# ===================================================================

@tool_decorator
async def refinery_stego_extract(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract steganographically hidden data from images using Binary Refinery.

    Extracts data hidden in the least significant bits (LSB) of RGBA
    image channels. Supports PNG and BMP images commonly used in
    steganographic malware delivery.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Image data as hex. If None, uses loaded file.

    Returns:
        Dictionary with extracted hidden data.
    """
    _require_refinery("refinery_stego_extract")

    data = _get_data_from_hex_or_file(data_hex)
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
