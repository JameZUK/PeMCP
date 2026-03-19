"""MCP tools powered by Binary Refinery for low-level executable analysis.

Provides section/segment extraction, virtual address operations, native
disassembly (x86/x64/ARM), CIL disassembly, entropy visualization, and
steganography detection through a single dispatched tool.
"""
import asyncio
import hashlib
import threading

from typing import Dict, Any, Optional

from arkana.config import state, logger, Context
from arkana.constants import MAX_TOOL_LIMIT
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._refinery_helpers import (
    _require_refinery, _safe_decode, _bytes_to_hex, _hex_to_bytes,
    _get_file_data, _MAX_INPUT_SIZE_LARGE as _MAX_INPUT_SIZE,
)

_entropy_lock = threading.Lock()


@tool_decorator
async def refinery_executable(
    ctx: Context,
    operation: str,
    data_hex: Optional[str] = None,
    address: Optional[str] = None,
    offset: Optional[str] = None,
    size: int = 256,
    count: int = 50,
    limit: int = 20,
) -> Dict[str, Any]:
    """Low-level executable analysis via Binary Refinery.

    Operations:
    - 'sections': Extract sections/segments from PE, ELF, or Mach-O binaries.
    - 'virtual_read': Read data at a virtual address (requires address param).
    - 'file_to_virtual': Convert file offset to virtual address (requires offset param).
    - 'disassemble': Disassemble native code (x86/x64/ARM) using Capstone.
    - 'disassemble_cil': Disassemble .NET CIL/MSIL bytecode (dnasm sink).
    - 'entropy_map': Generate entropy distribution heatmap of binary data.
    - 'stego': Extract hidden data from images via LSB steganography.

    Args:
        ctx: MCP Context.
        operation: (str) One of the operations listed above.
        data_hex: (Optional[str]) Raw data as hex. If None, uses loaded file.
        address: (Optional[str]) Virtual address as hex (for virtual_read, e.g. '0x00401000').
        offset: (Optional[str]) File offset as hex (for file_to_virtual, e.g. '0x400').
        size: (int) Bytes to read for virtual_read. Default 256.
        count: (int) Max instructions for disassemble. Default 50.
        limit: (int) Max items for sections/stego. Default 20.

    Returns:
        Dictionary with operation-specific results.
    """
    _require_refinery("refinery_executable")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))

    op = operation.lower()

    _SUPPORTED = [
        "sections", "virtual_read", "file_to_virtual",
        "disassemble", "disassemble_cil", "entropy_map", "stego",
    ]
    if op not in _SUPPORTED:
        return {"error": f"Unknown operation '{operation}'.", "supported": sorted(_SUPPORTED)}

    # ── sections: requires loaded PE ────────────────────────────────
    if op == "sections":
        _check_pe_loaded("refinery_executable")
        data = _get_file_data()
        await ctx.info(f"Extracting sections from binary ({len(data)} bytes)...")

        def _run_sections():
            from refinery.units.formats.exe.vsect import vsect
            from arkana.utils import shannon_entropy  # M5-v9: use shared implementation

            results = []
            for chunk in data | vsect():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("name", "vaddr", "offset", "type", "flags", "path"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                if raw:
                    entry["entropy"] = round(shannon_entropy(raw), 4)
                entry["preview_hex"] = raw[:64].hex()
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_sections)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "filepath": state.filepath,
            "sections_found": len(results),
            "results": results,
        }, "refinery_executable")

    # ── virtual_read: read bytes at VA ──────────────────────────────
    if op == "virtual_read":
        _check_pe_loaded("refinery_executable")
        data = _get_file_data()
        if not address:
            return {"error": "virtual_read requires the 'address' parameter (hex or decimal, e.g. '0x00401000' or '4194304')."}
        addr = int(address, 0) if isinstance(address, str) else address
        await ctx.info(f"Reading {size} bytes at VA {hex(addr)}...")

        def _run_vread():
            from refinery.units.formats.exe.vsnip import vsnip
            # vsnip extracts the full virtual segment containing the range;
            # we must slice the result to the requested size ourselves.
            raw = data | vsnip(slice(addr, addr + size)) | bytes
            return raw[:size] if len(raw) > size else raw

        result = await asyncio.to_thread(_run_vread)
        return {
            "operation": op,
            "address": hex(addr),
            "requested_size": size,
            "actual_size": len(result),
            "hex": _bytes_to_hex(result),
            "text": _safe_decode(result, max_len=1000),
        }

    # ── file_to_virtual: offset → VA conversion ────────────────────
    if op == "file_to_virtual":
        _check_pe_loaded("refinery_executable")
        data = _get_file_data()
        if not offset:
            return {"error": "file_to_virtual requires the 'offset' parameter (hex or decimal, e.g. '0x400' or '1024')."}
        off = int(offset, 0) if isinstance(offset, str) else offset
        await ctx.info(f"Converting file offset {hex(off)} to virtual address...")

        def _run_f2v():
            # Note: state.pe_object could be used instead, but a fresh parse
            # provides isolation from concurrent state changes in the thread.
            import pefile
            pe = pefile.PE(data=data)
            try:  # L7-v9: ensure PE object is closed
                image_base = pe.OPTIONAL_HEADER.ImageBase
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
                            "section": section.Name.rstrip(b"\x00").decode("utf-8", errors="replace"),
                        }
                return {
                    "file_offset": hex(off),
                    "virtual_address": hex(image_base + off),
                    "rva": hex(off),
                    "image_base": hex(image_base),
                    "section": "(header)",
                }
            finally:
                pe.close()

        result = await asyncio.to_thread(_run_f2v)
        result["operation"] = op
        return result

    # ── disassemble: native code (x86/x64/ARM) ─────────────────────
    if op == "disassemble":
        if data_hex:
            cleaned = data_hex.replace(" ", "").replace("\\x", "")
            if cleaned.startswith(("0x", "0X")):
                cleaned = cleaned[2:]
            data = bytes.fromhex(cleaned)
        elif address:
            # Read bytes at the specified virtual address
            _check_pe_loaded("refinery_executable")
            full_data = _get_file_data()
            addr = int(address, 0) if isinstance(address, str) else address
            await ctx.info(f"Reading {size} bytes at VA {hex(addr)} for disassembly...")

            def _vsnip():
                from refinery.units.formats.exe.vsnip import vsnip
                return full_data | vsnip(slice(addr, addr + size)) | bytes

            data = await asyncio.to_thread(_vsnip)
            if not data:
                return {"error": f"No data found at virtual address {hex(addr)}. Check the address is valid."}
        else:
            _check_pe_loaded("refinery_executable")
            data = _get_file_data()
        if len(data) > _MAX_INPUT_SIZE:
            data = data[:_MAX_INPUT_SIZE]
        await ctx.info(f"Disassembling {len(data)} bytes...")

        def _run_disasm():
            from refinery.units.sinks.asm import asm
            # Detect PE bitness for correct disassembly mode
            # refinery asm expects mode as string: 'x32' or 'x64'
            mode = None
            pe_obj = state.pe_object
            if pe_obj and hasattr(pe_obj, 'FILE_HEADER'):
                machine = pe_obj.FILE_HEADER.Machine
                # 0x8664 = AMD64, 0xAA64 = ARM64
                if machine in (0x8664, 0xAA64):
                    mode = 'x64'
                # 0x14C = i386, 0x1C0 = ARM
                elif machine in (0x14C, 0x1C0):
                    mode = 'x32'
            if mode:
                return data | asm(count=count, mode=mode) | bytes
            return data | asm(count=count) | bytes

        result = await asyncio.to_thread(_run_disasm)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "input_size": len(data),
            "disassembly": _safe_decode(result, max_len=8000),
        }, "refinery_executable")

    # ── disassemble_cil: .NET CIL/MSIL bytecode ────────────────────
    if op == "disassemble_cil":
        if data_hex:
            _MAX_HEX_INPUT_LEN_CIL = 2_000_000  # 2M hex chars = 1MB decoded
            if len(data_hex) > _MAX_HEX_INPUT_LEN_CIL:
                raise ValueError(
                    f"Hex input too large ({len(data_hex):,} chars, "
                    f"limit {_MAX_HEX_INPUT_LEN_CIL:,})."
                )
            cleaned = data_hex.replace(" ", "").replace("\\x", "")
            if cleaned.startswith(("0x", "0X")):
                cleaned = cleaned[2:]
            data = bytes.fromhex(cleaned)
        else:
            _check_pe_loaded("refinery_executable")
            data = _get_file_data()
        await ctx.info("Disassembling .NET CIL bytecode...")

        def _run_cil():
            from refinery.units.sinks.dnasm import dnasm
            return data | dnasm() | bytes

        result = await asyncio.to_thread(_run_cil)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "input_size": len(data),
            "output_size": len(result),
            "disassembly": _safe_decode(result, max_len=8000),
        }, "refinery_executable")

    # ── entropy_map: entropy heatmap ────────────────────────────────
    if op == "entropy_map":
        if data_hex:
            _MAX_HEX_INPUT_LEN_ENT = 2_000_000  # 2M hex chars = 1MB decoded
            if len(data_hex) > _MAX_HEX_INPUT_LEN_ENT:
                raise ValueError(
                    f"Hex input too large ({len(data_hex):,} chars, "
                    f"limit {_MAX_HEX_INPUT_LEN_ENT:,})."
                )
            cleaned = data_hex.replace(" ", "").replace("\\x", "")
            if cleaned.startswith(("0x", "0X")):
                cleaned = cleaned[2:]
            data = bytes.fromhex(cleaned)
        else:
            data = _get_file_data()
        if len(data) > _MAX_INPUT_SIZE:
            data = data[:_MAX_INPUT_SIZE]
        await ctx.info(f"Generating entropy map for {len(data)} bytes...")

        def _run_entropy():
            import math
            # Compute actual numeric entropy per block instead of using
            # iemap (which produces ANSI terminal art, not numeric data).
            block_count = min(256, max(1, len(data) // 256))
            block_size = max(1, len(data) // block_count)
            blocks = []
            for i in range(block_count):
                start = i * block_size
                end = min(start + block_size, len(data))
                chunk = data[start:end]
                if not chunk:
                    break
                # Shannon entropy
                freq = [0] * 256
                for b in chunk:
                    freq[b] += 1
                length = len(chunk)
                entropy = 0.0
                for count in freq:
                    if count > 0:
                        p = count / length
                        entropy -= p * math.log2(p)
                blocks.append({
                    "offset": hex(start),
                    "size": len(chunk),
                    "entropy": round(entropy, 3),
                })
            # Overall entropy
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            length = len(data)
            overall = 0.0
            for count in freq:
                if count > 0:
                    p = count / length
                    overall -= p * math.log2(p)
            return {
                "overall_entropy": round(overall, 3),
                "block_count": len(blocks),
                "block_size": block_size,
                "blocks": blocks,
            }

        result = await asyncio.to_thread(_run_entropy)
        result["operation"] = op
        result["input_size"] = len(data)
        return await _check_mcp_response_size(ctx, result, "refinery_executable")

    # ── stego: steganography extraction ─────────────────────────────
    # op == "stego"
    if data_hex:
        _MAX_HEX_INPUT_LEN = 2_000_000  # 2M hex chars = 1MB decoded
        if len(data_hex) > _MAX_HEX_INPUT_LEN:
            raise ValueError(
                f"Hex input too large ({len(data_hex):,} chars, "
                f"limit {_MAX_HEX_INPUT_LEN:,})."
            )
        cleaned = data_hex.replace(" ", "").replace("\\x", "")
        if cleaned.startswith(("0x", "0X")):
            cleaned = cleaned[2:]
        data = bytes.fromhex(cleaned)
    else:
        data = _get_file_data()
    await ctx.info(f"Extracting steganographic data from image ({len(data)} bytes)...")

    def _run_stego():
        from refinery.units.formats.stego import stego
        results = []
        for chunk in data | stego():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "preview_hex": raw[:128].hex(),
            }
            if raw[:2] == b"MZ":
                entry["detected_type"] = "PE executable"
            elif raw[:4] == b"PK\x03\x04":
                entry["detected_type"] = "ZIP archive"
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run_stego)
    return await _check_mcp_response_size(ctx, {
        "operation": op,
        "input_size": len(data),
        "items_found": len(results),
        "results": results,
    }, "refinery_executable")
