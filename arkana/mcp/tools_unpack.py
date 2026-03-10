"""MCP tools for PE unpacking — multi-method unpacking, PE reconstruction, and OEP detection.

Orchestrates available unpacking methods (Unipacker, Binary Refinery, Speakeasy)
and provides PE header reconstruction and Original Entry Point heuristics.
"""
import asyncio
import math
import os
import struct

from typing import Dict, Any, List, Optional

from arkana.config import (
    state, logger, Context,
    LIEF_AVAILABLE,
    _check_speakeasy_available, _check_unipacker_available,
    REFINERY_AVAILABLE,
)
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._input_helpers import _parse_int_param
from arkana.mcp._progress_bridge import ProgressBridge
from arkana.mcp._refinery_helpers import _write_output_and_register_artifact


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
#  Tool 1: try_all_unpackers
# ===================================================================

@tool_decorator
async def try_all_unpackers(
    ctx: Context,
    timeout_seconds: int = 120,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Orchestrates multiple unpacking methods on the loaded PE
    file and returns the best result. Tries methods in order of reliability:
    1. Unipacker (generic PE unpacking)
    2. Binary Refinery PE reconstruction (pefix, peoverlay)
    3. PE overlay extraction

    When to use: When detect_packing() or triage confirms the binary is packed
    and you need the unpacked payload for analysis.

    Next steps: If unpacking succeeds → open_file() to analyze the unpacked PE.
    If all methods fail → try manual unpacking with emulate_binary_with_qiling()
    and qiling_dump_memory().

    Args:
        ctx: MCP Context.
        timeout_seconds: Max time per unpacking method. Default 120.
    """
    await ctx.info("Trying all available unpacking methods")
    _check_pe_loaded("try_all_unpackers")

    results = []
    best_result = None

    # --- Method 1: Unipacker ---
    await ctx.report_progress(5, 100)
    if _check_unipacker_available():
        await ctx.info("Trying Unipacker...")
        try:
            from arkana.config import _UNIPACKER_VENV_PYTHON, _UNIPACKER_RUNNER
            import json as _json
            proc = await asyncio.create_subprocess_exec(
                str(_UNIPACKER_VENV_PYTHON), str(_UNIPACKER_RUNNER),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            base, ext = os.path.splitext(state.filepath)
            output_path = f"{base}_unpacked{ext or '.exe'}"
            cmd = _json.dumps({
                "action": "unpack_pe",
                "filepath": state.filepath,
                "output_path": output_path,
                "timeout_seconds": timeout_seconds,
            }).encode()
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=cmd),
                timeout=timeout_seconds + 30,
            )
            if proc.returncode == 0:
                data = _json.loads(stdout.decode())
                if "output_path" in data:
                    results.append({
                        "method": "unipacker",
                        "status": "success",
                        "output_path": data["output_path"],
                        "details": data,
                    })
                else:
                    results.append({
                        "method": "unipacker",
                        "status": "no_output",
                        "error": data.get("error", "Process succeeded but produced no output file"),
                        "details": data,
                    })
            else:
                results.append({
                    "method": "unipacker",
                    "status": "failed",
                    "error": stderr.decode(errors="replace")[:300],
                })
        except asyncio.TimeoutError:
            results.append({"method": "unipacker", "status": "timeout"})
        except Exception as e:
            results.append({"method": "unipacker", "status": "error", "error": str(e)[:200]})
    else:
        results.append({"method": "unipacker", "status": "not_available"})

    # --- Method 2: Binary Refinery PE reconstruction ---
    await ctx.report_progress(35, 100)
    if REFINERY_AVAILABLE:
        await ctx.info("Trying Binary Refinery PE reconstruction...")
        try:
            def _try_refinery_pe():
                raw = state.pe_object.__data__

                # Try pefix (PE repair/reconstruction) — available in binary-refinery
                try:
                    from refinery.units.formats.pe.pefix import pefix
                    reconstructed = bytes(raw | pefix())
                    if len(reconstructed) > 0 and reconstructed[:2] == b"MZ":
                        return {"data_hex": reconstructed[:4096].hex(), "size": len(reconstructed), "method_detail": "pefix"}
                except ImportError:
                    pass
                except Exception:
                    pass

                # Try overlay extraction
                try:
                    from refinery.units.formats.pe.peoverlay import peoverlay
                    for chunk in raw | peoverlay():
                        overlay = bytes(chunk)
                        if len(overlay) > 64:
                            return {"data_hex": overlay[:4096].hex(), "size": len(overlay), "method_detail": "peoverlay"}
                except ImportError:
                    pass
                except Exception:
                    pass
                return None

            refinery_result = await asyncio.to_thread(_try_refinery_pe)
            if refinery_result:
                results.append({
                    "method": "refinery_pe",
                    "status": "success",
                    "details": refinery_result,
                })
            else:
                results.append({"method": "refinery_pe", "status": "no_output"})
        except Exception as e:
            results.append({"method": "refinery_pe", "status": "error", "error": str(e)[:200]})
    else:
        results.append({"method": "refinery_pe", "status": "not_available"})

    # --- Method 3: PE overlay extraction ---
    await ctx.info("Checking PE overlay...")
    try:
        pe = state.pe_object
        overlay_start = pe.get_overlay_data_start_offset()
        if overlay_start and overlay_start < len(pe.__data__):
            overlay = pe.__data__[overlay_start:]
            if len(overlay) > 64:
                results.append({
                    "method": "pe_overlay",
                    "status": "success",
                    "details": {
                        "offset": hex(overlay_start),
                        "size": len(overlay),
                        "entropy": round(_shannon_entropy(overlay[:4096]), 2),
                        "magic": overlay[:4].hex(),
                        "preview_hex": overlay[:128].hex(),
                    },
                })
            else:
                results.append({"method": "pe_overlay", "status": "overlay_too_small"})
        else:
            results.append({"method": "pe_overlay", "status": "no_overlay"})
    except Exception as e:
        results.append({"method": "pe_overlay", "status": "error", "error": str(e)[:200]})

    # Select best result
    for r in results:
        if r["status"] == "success":
            best_result = r
            break

    return await _check_mcp_response_size(ctx, {
        "results": results,
        "best_method": best_result["method"] if best_result else None,
        "best_result": best_result,
        "methods_tried": len(results),
        "next_steps": _unpack_next_steps(best_result),
    }, "try_all_unpackers")


def _unpack_next_steps(best: Optional[Dict]) -> List[str]:
    if best and best.get("status") == "success":
        if "output_path" in best.get("details", {}):
            return [f"open_file(filepath='{best['details']['output_path']}') — analyze unpacked binary"]
        return [
            "get_hex_dump() on the extracted data to inspect it",
            "If data starts with MZ: save and open_file() for analysis",
        ]
    return [
        "Manual unpacking may be needed. Try:",
        "  emulate_binary_with_qiling() → qiling_dump_memory() at suspected OEP",
        "  find_oep_heuristic() to locate Original Entry Point",
    ]


# ===================================================================
#  Tool 2: reconstruct_pe_from_dump
# ===================================================================

@tool_decorator
async def reconstruct_pe_from_dump(
    ctx: Context,
    data_hex: str,
    base_address: Optional[str] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Reconstructs a valid PE from a memory dump by fixing
    headers using LIEF. Realigns sections, fixes SizeOfImage/SizeOfHeaders,
    and optionally adjusts base address.

    When to use: After dumping memory from emulation (Qiling, Speakeasy) and
    getting a PE with corrupted headers.

    Next steps: open_file() on the reconstructed PE for full analysis.

    Args:
        ctx: MCP Context.
        data_hex: Hex-encoded PE memory dump.
        base_address: Optional base address for relocation (e.g. '0x10000000').
        output_path: (Optional[str]) Save reconstructed PE to this path and register as artifact.
    """
    await ctx.info("Reconstructing PE from memory dump")

    if not LIEF_AVAILABLE:
        raise RuntimeError(
            "LIEF library is required for PE reconstruction. Install with: pip install lief"
        )

    try:
        data = bytes.fromhex(data_hex.replace(" ", "").replace("0x", ""))
    except ValueError as e:
        raise ValueError(f"Invalid data_hex: {e}")

    if len(data) < 64:
        raise ValueError("Data too small to be a PE file (min 64 bytes).")
    if data[:2] != b"MZ":
        raise ValueError("Data does not start with MZ header. Not a PE dump.")
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Data too large (max 100MB).")

    base_addr = None
    if base_address:
        base_addr = _parse_int_param(base_address, "base_address")

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _reconstruct():
        import lief

        bridge.report_progress(5, 100)
        bridge.info("Parsing PE dump with LIEF...")
        pe = lief.parse(data)
        if pe is None:
            return {"error": "LIEF failed to parse the PE dump."}

        issues_fixed = []

        bridge.report_progress(20, 100)
        bridge.info("Fixing PE headers...")

        # Fix base address
        if base_addr is not None:
            pe.optional_header.imagebase = base_addr
            issues_fixed.append(f"Set ImageBase to {hex(base_addr)}")

        # Fix section alignment
        section_alignment = pe.optional_header.section_alignment
        file_alignment = pe.optional_header.file_alignment
        if file_alignment == 0:
            pe.optional_header.file_alignment = 0x200
            issues_fixed.append("Fixed FileAlignment to 0x200")
        if section_alignment == 0:
            pe.optional_header.section_alignment = 0x1000
            issues_fixed.append("Fixed SectionAlignment to 0x1000")

        bridge.report_progress(40, 100)
        bridge.info("Recalculating SizeOfImage...")

        # Recalculate SizeOfImage
        max_va = 0
        for section in pe.sections:
            end = section.virtual_address + section.virtual_size
            if end > max_va:
                max_va = end
        aligned_size = ((max_va + section_alignment - 1) // section_alignment) * section_alignment
        if pe.optional_header.sizeof_image != aligned_size:
            pe.optional_header.sizeof_image = aligned_size
            issues_fixed.append(f"Fixed SizeOfImage to {hex(aligned_size)}")

        # Fix SizeOfHeaders
        expected_headers = pe.optional_header.sizeof_headers
        if expected_headers == 0 or expected_headers > 0x10000:
            pe.optional_header.sizeof_headers = 0x400
            issues_fixed.append("Fixed SizeOfHeaders to 0x400")

        bridge.report_progress(60, 100)
        bridge.info("Rebuilding PE...")

        # Build the fixed PE
        builder = lief.PE.Builder(pe)
        builder.build()
        fixed_data = bytes(builder.get_build())

        bridge.report_progress(90, 100)
        bridge.info("Formatting results...")

        result_dict = {
            "fixed_pe_hex": fixed_data[:8192].hex(),
            "fixed_pe_size": len(fixed_data),
            "issues_fixed": issues_fixed,
            "sections": [
                {
                    "name": s.name,
                    "virtual_address": hex(s.virtual_address),
                    "virtual_size": s.virtual_size,
                    "raw_size": s.sizeof_raw_data,
                }
                for s in pe.sections
            ],
            "entry_point": hex(pe.optional_header.addressof_entrypoint),
        }
        if output_path:
            result_dict["_fixed_data"] = fixed_data
        return result_dict

    result = await asyncio.to_thread(_reconstruct)

    if "error" in result:
        return result

    fixed_data = result.pop("_fixed_data", None)
    if output_path and fixed_data:
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, fixed_data, "reconstruct_pe_from_dump",
            "Reconstructed PE",
        )
        result["artifact"] = artifact_meta

    result["next_steps"] = [
        "open_file() on the reconstructed PE for full analysis",
        "Check entry_point — if it looks wrong, use find_oep_heuristic()",
    ]

    return await _check_mcp_response_size(ctx, result, "reconstruct_pe_from_dump")


# ===================================================================
#  Tool 3: find_oep_heuristic
# ===================================================================

@tool_decorator
async def find_oep_heuristic(
    ctx: Context,
    limit: int = 10,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Detects the Original Entry Point (OEP) of a packed binary
    using multiple heuristics: tail-jump detection, section-hop analysis, known
    packer patterns, and entropy transition points.

    When to use: After detect_packing() confirms the binary is packed and you
    need to find where the unpacked code starts executing.

    Next steps: Use get_hex_dump(start_offset=<oep>) to inspect the OEP region.
    Set breakpoints in emulation at OEP candidates to dump unpacked code.

    Args:
        ctx: MCP Context.
        limit: Max OEP candidates to return. Default 10.
    """
    await ctx.info("Detecting Original Entry Point (OEP) using heuristics")
    _check_pe_loaded("find_oep_heuristic")

    pe = state.pe_object
    file_data = pe.__data__

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _detect():
        candidates = []
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase

        bridge.report_progress(5, 100)
        bridge.info("Checking known packer signatures...")

        # --- 1. Known packer signatures ---
        _PACKER_SIGS = [
            (b"UPX0", "UPX", "Look for tail JMP after UPX1 section"),
            (b"UPX1", "UPX", "OEP usually at first JMP after decompression"),
            (b".aspack", "ASPack", "OEP at JMP to .text section"),
            (b"PEC2", "PECompact", "OEP after PECompact stub"),
            (b".petite", "Petite", "OEP after Petite unpacking"),
            (b"MEW", "MEW", "OEP after MEW decompression"),
        ]
        for sig, packer, hint in _PACKER_SIGS:
            if sig in file_data:
                candidates.append({
                    "method": "packer_signature",
                    "packer": packer,
                    "hint": hint,
                    "confidence": 0.7,
                })

        bridge.report_progress(15, 100)
        bridge.info("Scanning for tail jumps...")

        # --- 2. Tail-jump detection ---
        # Look for JMP instructions at the end of the entry section
        # that jump to a different section (common in packers)
        try:
            entry_section = None
            for sec in pe.sections:
                if sec.VirtualAddress <= entry_point < sec.VirtualAddress + sec.Misc_VirtualSize:
                    entry_section = sec
                    break

            if entry_section:
                sec_data = entry_section.get_data()
                sec_va = entry_section.VirtualAddress

                # Scan last 256 bytes of entry section for far JMPs
                scan_start = max(0, len(sec_data) - 256)
                for i in range(scan_start, len(sec_data) - 5):
                    # E9 xx xx xx xx = JMP rel32
                    if sec_data[i] == 0xE9:
                        offset = struct.unpack_from("<i", sec_data, i + 1)[0]
                        target_rva = sec_va + i + 5 + offset
                        # Check if target is in a different section
                        for other_sec in pe.sections:
                            if other_sec != entry_section:
                                if other_sec.VirtualAddress <= target_rva < other_sec.VirtualAddress + other_sec.Misc_VirtualSize:
                                    candidates.append({
                                        "method": "tail_jump",
                                        "oep_rva": hex(target_rva),
                                        "oep_va": hex(image_base + target_rva),
                                        "jump_from_rva": hex(sec_va + i),
                                        "target_section": other_sec.Name.decode('utf-8', 'ignore').strip('\x00'),
                                        "confidence": 0.8,
                                    })
                                    break

                    # FF 25 xx xx xx xx = JMP [abs] (indirect)
                    if i + 5 < len(sec_data) and sec_data[i] == 0xFF and sec_data[i + 1] == 0x25:
                        candidates.append({
                            "method": "indirect_jump",
                            "location_rva": hex(sec_va + i),
                            "confidence": 0.5,
                        })
        except Exception as e:
            logger.debug("Tail-jump detection failed: %s", e)

        bridge.report_progress(35, 100)
        bridge.info("Analyzing entropy transitions...")

        # --- 3. Entropy transition detection ---
        # Find the boundary where entropy drops (packed code → unpacked code)
        try:
            window = 512
            entropies = []
            for i in range(0, len(file_data) - window, window):
                ent = _shannon_entropy(file_data[i:i + window])
                entropies.append((i, ent))

            # Find significant entropy drops
            for i in range(1, len(entropies)):
                offset_prev, ent_prev = entropies[i - 1]
                offset_curr, ent_curr = entropies[i]
                # High entropy → low entropy transition
                if ent_prev > 7.0 and ent_curr < 5.0:
                    # Convert file offset to RVA
                    try:
                        rva = pe.get_rva_from_offset(offset_curr)
                        candidates.append({
                            "method": "entropy_transition",
                            "oep_rva": hex(rva),
                            "oep_va": hex(image_base + rva),
                            "file_offset": hex(offset_curr),
                            "entropy_before": round(ent_prev, 2),
                            "entropy_after": round(ent_curr, 2),
                            "confidence": 0.6,
                        })
                    except Exception:
                        candidates.append({
                            "method": "entropy_transition",
                            "file_offset": hex(offset_curr),
                            "entropy_before": round(ent_prev, 2),
                            "entropy_after": round(ent_curr, 2),
                            "confidence": 0.5,
                        })
        except Exception as e:
            logger.debug("Entropy transition detection failed: %s", e)

        bridge.report_progress(65, 100)
        bridge.info("Analyzing executable sections...")

        # --- 4. Section with executable flag + low entropy ---
        try:
            for sec in pe.sections:
                is_exec = bool(sec.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
                if is_exec:
                    sec_data = sec.get_data()
                    ent = _shannon_entropy(sec_data)
                    if ent < 6.5:  # Likely contains code, not packed
                        candidates.append({
                            "method": "executable_low_entropy_section",
                            "section": sec.Name.decode('utf-8', 'ignore').strip('\x00'),
                            "section_rva": hex(sec.VirtualAddress),
                            "entropy": round(ent, 2),
                            "oep_rva": hex(sec.VirtualAddress),
                            "oep_va": hex(image_base + sec.VirtualAddress),
                            "confidence": 0.4,
                        })
        except Exception as e:
            logger.debug("Section analysis failed: %s", e)

        bridge.report_progress(85, 100)
        bridge.info("Ranking OEP candidates...")

        # Sort by confidence
        candidates.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return candidates[:limit]

    candidates = await asyncio.to_thread(_detect)

    return await _check_mcp_response_size(ctx, {
        "candidates": candidates,
        "count": len(candidates),
        "current_entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "current_entry_va": hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "next_steps": [
            "get_hex_dump(start_offset=<oep_rva>) — inspect OEP region",
            "emulate_binary_with_qiling() with breakpoint at OEP",
            "decompile_function_with_angr(address=<oep_va>) — analyze OEP code",
        ] if candidates else [
            "Try emulate_binary_with_qiling() and dump at different stages",
            "Use run_speakeasy_emulation() for behavioral analysis",
        ],
    }, "find_oep_heuristic")
