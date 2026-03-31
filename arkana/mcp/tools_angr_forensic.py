"""MCP tools for angr-based forensic and advanced binary analysis."""
import datetime
import pickle
import re
import threading
import time
import uuid
import asyncio
import os
from typing import Dict, Any, Optional, List

from collections import deque

from arkana.config import state, logger, Context, ANGR_AVAILABLE, ANGR_ANALYSIS_TIMEOUT, ANGR_SHORT_TIMEOUT
from arkana.constants import (
    MAX_TOOL_LIMIT,
    CFF_MIN_BLOCKS, CFF_DISPATCHER_IN_DEGREE_THRESHOLD, CFF_BACK_EDGE_RATIO_THRESHOLD,
    OPAQUE_PREDICATE_SOLVER_TIMEOUT, MAX_OPAQUE_PREDICATE_BLOCKS,
    OBFUSCATION_DETECTION_TIMEOUT,
    MAX_CFF_SCAN_FUNCTIONS, MAX_OPAQUE_SCAN_FUNCTIONS,
)
from arkana.mcp.server import tool_decorator, _check_angr_ready, _check_pe_loaded, _check_mcp_response_size
from arkana.background import _update_progress, _run_background_task_wrapper, _log_task_exception, _register_background_task
from arkana.mcp._progress_bridge import ProgressBridge
from arkana.mcp._angr_helpers import _ensure_project_and_cfg, _parse_addr, _resolve_function_address, _raise_on_error_dict
from arkana.mcp._input_helpers import _paginate_field
from arkana.mcp._rename_helpers import get_display_name
from arkana.utils import shannon_entropy

if ANGR_AVAILABLE:
    import angr
    import networkx as nx


# ---- BinDiff ---------------------------------------------------

@tool_decorator
async def diff_binaries(
    ctx: Context,
    file_path_b: str,
    limit: int = 20,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Compares the loaded binary against another to find matching,
    differing, and unmatched functions. For patch diffing and variant analysis.

    ---compact: binary diff two files | match, differ, unmatched functions | needs: angr+CFG

    When to use: When comparing malware variants, analyzing patches, or identifying
    code reuse across samples.

    Next steps: decompile_function_with_angr() on differing functions to understand
    what changed. Record findings with add_note().

    Args:
        file_path_b: Path to the second binary to compare against.
        limit: Max entries per category (identical, differing, unmatched).
        run_in_background: Run as background task (default True).
    """
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    _check_angr_ready("diff_binaries")
    abs_path_b = os.path.realpath(file_path_b)
    state.check_path_allowed(abs_path_b)
    if not os.path.isfile(abs_path_b):
        return {"error": f"File not found: {file_path_b}"}

    def _diff(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()
        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Loading second binary...", bridge=_progress_bridge)

        try:
            proj_b = angr.Project(abs_path_b, auto_load_libs=False)
        except Exception as e:
            return {"error": f"Failed to load second binary: {e}"}

        # M-3: Wrap in try/finally to ensure proj_b is cleaned up even if
        # CFG generation or BinDiff fails.
        cfg_b = None
        diff = None
        try:
            if task_id_for_progress:
                _update_progress(task_id_for_progress, 20, "Building CFG for second binary...", bridge=_progress_bridge)

            try:
                cfg_b = proj_b.analyses.CFGFast(normalize=True)
            except Exception as e:
                return {"error": f"CFG generation failed for second binary: {e}"}

            if task_id_for_progress:
                _update_progress(task_id_for_progress, 50, "Running BinDiff analysis...", bridge=_progress_bridge)

            try:
                # BinDiff internally calls get_any_node() which lives on
                # the CFGModel, not on the raw CFGFast analysis object.
                diff = state.angr_project.analyses.BinDiff(
                    proj_b, cfg_a=state.angr_cfg.model, cfg_b=cfg_b.model,
                )
            except (pickle.PicklingError, TypeError) as e:
                if "pickle" in str(e).lower() or "_CDataBase" in str(e):
                    # cffi objects can't be pickled — fall back to basic
                    # function-level comparison by name/size.
                    if task_id_for_progress:
                        _update_progress(task_id_for_progress, 70,
                                         "BinDiff pickle error — falling back to name-based comparison...",
                                         bridge=_progress_bridge)
                    funcs_a = {f.name: f for f in state.angr_cfg.functions.values()
                               if not f.is_simprocedure and not f.is_syscall}
                    funcs_b = {f.name: f for f in cfg_b.functions.values()
                               if not f.is_simprocedure and not f.is_syscall}
                    names_a = set(funcs_a.keys())
                    names_b = set(funcs_b.keys())
                    common = names_a & names_b
                    identical = [{"a": hex(funcs_a[n].addr), "b": hex(funcs_b[n].addr),
                                  "name": n} for n in sorted(common)[:limit]]
                    unmatched_a = [{"address": hex(funcs_a[n].addr), "name": n}
                                   for n in sorted(names_a - names_b)[:limit]]
                    unmatched_b = [{"address": hex(funcs_b[n].addr), "name": n}
                                   for n in sorted(names_b - names_a)[:limit]]
                    return {
                        "file_a": str(state.filepath),
                        "file_b": str(file_path_b),
                        "method": "name_based_fallback",
                        "note": "BinDiff failed due to cffi serialization error. "
                                "Results are based on function name matching only.",
                        "identical_count": len(identical),
                        "differing_count": 0,
                        "unmatched_a_count": len(unmatched_a),
                        "unmatched_b_count": len(unmatched_b),
                        "identical_functions": identical,
                        "differing_functions": [],
                        "unmatched_in_a": unmatched_a,
                        "unmatched_in_b": unmatched_b,
                    }
                return {"error": f"BinDiff failed: {type(e).__name__}: {e}"}
            except Exception as e:
                return {"error": f"BinDiff failed: {type(e).__name__}: {e}"}

            if task_id_for_progress:
                _update_progress(task_id_for_progress, 90, "Formatting results...", bridge=_progress_bridge)

            identical = []
            differing = []
            unmatched_a = []
            unmatched_b = []
            _diff_warnings = []

            def _addr(x):
                """Extract address — handles both function objects and raw ints."""
                return hex(x.addr) if hasattr(x, 'addr') else hex(x)

            def _name(x):
                """Extract name — handles both function objects and raw ints."""
                return str(x.name) if hasattr(x, 'name') else f"sub_{x:x}"

            try:
                for fa, fb in list(getattr(diff, 'identical_functions', []))[:limit]:
                    identical.append({"a": _addr(fa), "b": _addr(fb), "name": _name(fa)})
            except Exception as e:
                logger.warning("BinDiff: failed to extract identical_functions: %s", e)
                _diff_warnings.append(f"identical_functions extraction failed: {e}")
            try:
                for fa, fb in list(getattr(diff, 'differing_functions', []))[:limit]:
                    differing.append({"a": _addr(fa), "b": _addr(fb), "name_a": _name(fa), "name_b": _name(fb)})
            except Exception as e:
                logger.warning("BinDiff: failed to extract differing_functions: %s", e)
                _diff_warnings.append(f"differing_functions extraction failed: {e}")
            try:
                for f in list(getattr(diff, 'unmatched_from_a', getattr(diff, 'unmatched_a', [])))[:limit]:
                    unmatched_a.append({"address": _addr(f), "name": _name(f)})
            except Exception as e:
                logger.warning("BinDiff: failed to extract unmatched_from_a: %s", e)
                _diff_warnings.append(f"unmatched_from_a extraction failed: {e}")
            try:
                for f in list(getattr(diff, 'unmatched_from_b', getattr(diff, 'unmatched_b', [])))[:limit]:
                    unmatched_b.append({"address": _addr(f), "name": _name(f)})
            except Exception as e:
                logger.warning("BinDiff: failed to extract unmatched_from_b: %s", e)
                _diff_warnings.append(f"unmatched_from_b extraction failed: {e}")

            # Force all values to plain Python types — avoids CFFI
            # _CDataBase pickle errors when the result is stored in the
            # task registry and later serialised for the MCP response.
            result = {
                "file_a": str(state.filepath),
                "file_b": str(file_path_b),
                "identical_count": len(identical),
                "differing_count": len(differing),
                "unmatched_a_count": len(unmatched_a),
                "unmatched_b_count": len(unmatched_b),
                "identical_functions": identical,
                "differing_functions": differing,
                "unmatched_in_a": unmatched_a,
                "unmatched_in_b": unmatched_b,
            }
            if _diff_warnings:
                result["warnings"] = _diff_warnings

            return result
        finally:
            # Explicitly delete angr objects to release CFFI references
            # before this dict crosses the thread boundary.
            try:
                if hasattr(proj_b, 'close'):
                    proj_b.close()
            except Exception:
                pass
            del diff, cfg_b, proj_b

    if run_in_background:
        task_id = str(uuid.uuid4())
        _cancel = _register_background_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing BinDiff...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "diff_binaries",
        })
        task = asyncio.create_task(_run_background_task_wrapper(
            task_id, _diff, ctx=ctx, cancel_event=_cancel, timeout=600))
        task.add_done_callback(_log_task_exception(task_id))
        return {"status": "queued", "task_id": task_id, "message": "BinDiff queued."}

    await ctx.info("Running BinDiff")
    result = await asyncio.to_thread(_diff)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "diff_binaries", "the 'limit' parameter")


# ---- Self-Modifying Code Detection ----------------------------

@tool_decorator
async def detect_self_modifying_code(
    ctx: Context,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Detects instructions that write to executable memory —
    self-modifying code common in packers, crypters, and obfuscated malware.

    ---compact: detect writes to executable memory | packers, crypters | needs: angr+CFG

    When to use: When detect_packing() or triage suggests the binary is packed
    or obfuscated, or when section analysis shows W+X permissions.

    Next steps: get_hex_dump() at detected addresses, decompile_function_with_angr()
    to understand the unpacking routine, or auto_unpack_pe() for automated unpacking.
    """
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info("Scanning for self-modifying code")
    _check_angr_ready("detect_self_modifying_code")
    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _detect():
        _ensure_project_and_cfg()
        bridge.report_progress(5, 100)
        bridge.info("Gathering executable section ranges...")

        # Gather executable section ranges
        exec_ranges = []
        loader = state.angr_project.loader
        for obj in loader.all_objects:
            try:
                for seg in obj.segments:
                    if seg.is_executable:
                        exec_ranges.append((seg.min_addr, seg.max_addr))
            except Exception as e:
                logger.debug("Skipped object during exec range gathering: %s", e)

        def _addr_in_exec(addr_val):
            for lo, hi in exec_ranges:
                if lo <= addr_val <= hi:
                    return True
            return False

        findings = []
        bridge.report_progress(15, 100)
        bridge.info("Scanning functions for writes to executable memory...")

        # Scan all functions for memory writes to executable regions
        total_funcs = len(state.angr_cfg.functions)
        scanned = 0
        for _addr, func in state.angr_cfg.functions.items():
            if func.is_simprocedure or func.is_syscall:
                scanned += 1
                continue
            for block in func.blocks:
                try:
                    vex = block.vex
                except (pickle.PicklingError, TypeError, Exception) as e:
                    # VEX lifting can trigger cffi pickle errors intermittently
                    logger.debug("Skipped block %#x VEX lift: %s", block.addr, e)
                    continue
                try:
                    for stmt in vex.statements:
                        # Look for Store (memory write) statements
                        if stmt.tag == 'Ist_Store':
                            # If the store target is a constant address in an exec section
                            if hasattr(stmt, 'addr') and hasattr(stmt.addr, 'con'):
                                store_target = stmt.addr.con.value
                                if _addr_in_exec(store_target):
                                    findings.append({
                                        "function": func.name,
                                        "function_address": hex(func.addr),
                                        "instruction_block": hex(block.addr),
                                        "writes_to": hex(store_target),
                                        "type": "direct_write_to_executable",
                                    })
                except Exception as e:
                    logger.debug("Skipped block %#x during SMC scan: %s", block.addr, e)
                    continue

            scanned += 1
            if scanned % 50 == 0 and total_funcs > 0:
                pct = 15 + int((scanned / total_funcs) * 70)
                bridge.report_progress(min(pct, 85), 100)
                bridge.info(f"Scanned {scanned}/{total_funcs} functions...")

            if len(findings) >= limit:
                break

        bridge.report_progress(88, 100)
        bridge.info("Checking dedicated SMC analysis...")
        # Also try the dedicated analysis if available
        try:
            smc = state.angr_project.analyses.SelfModifyingCodeAnalysis()
            if hasattr(smc, 'result') and smc.result:
                for item in smc.result[:limit]:
                    findings.append({"analysis_result": str(item)})
        except (AttributeError, Exception):
            pass

        return {
            "total_findings": len(findings),
            "self_modifying_regions": findings[:limit],
            "executable_ranges": [{"start": hex(lo), "end": hex(hi)} for lo, hi in exec_ranges],
        }

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_detect), timeout=ANGR_ANALYSIS_TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError(f"detect_self_modifying_code timed out after {ANGR_ANALYSIS_TIMEOUT} seconds.")
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "detect_self_modifying_code", "the 'limit' parameter")


# ---- Code Cave Detection --------------------------------------

@tool_decorator
async def find_code_caves(
    ctx: Context,
    min_size: int = 16,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Finds unused/padding regions (code caves) in executable sections.
    Useful for detecting injected code or finding safe patching locations.

    ---compact: find code caves in executable sections | injection sites, patch locations | needs: angr+CFG

    When to use: When investigating code injection, looking for places to insert
    patches, or verifying binary integrity.

    Next steps: disassemble_at_address() at cave locations to check for hidden code,
    or patch_binary_memory() to insert patches in identified caves.

    Args:
        min_size: Minimum cave size in bytes (default 16).
        limit: Max caves to return.
    """
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    min_size = max(1, min(min_size, 1_000_000))
    await ctx.info("Scanning for code caves")
    _check_angr_ready("find_code_caves")
    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _find_caves():
        _ensure_project_and_cfg()
        bridge.report_progress(5, 100)
        bridge.info("Trying built-in cave analysis...")

        # Try the built-in analysis first
        try:
            cave_analysis = state.angr_project.analyses.CodeCaveAnalysis()
            caves = []
            for cave in list(cave_analysis.caves)[:limit]:
                if cave.size >= min_size:
                    caves.append({
                        "address": hex(cave.addr),
                        "size": cave.size,
                    })
            return {
                "total_caves": len(caves),
                "min_size_filter": min_size,
                "caves": caves[:limit],
            }
        except (AttributeError, Exception):
            pass

        # Fallback: manual scan for null-byte regions in executable sections
        bridge.report_progress(20, 100)
        bridge.info("Scanning sections for null-byte regions...")
        loader = state.angr_project.loader
        caves = []

        for obj in loader.all_objects:
            if obj.binary is None:
                continue
            for section in getattr(obj, 'sections', []):
                if not getattr(section, 'is_executable', False):
                    continue

                start = section.min_addr
                size = section.memsize
                if size <= 0:
                    continue

                try:
                    data = loader.memory.load(start, size)
                except Exception as e:
                    logger.debug("Skipped section during code cave scan (memory load failed): %s", e)
                    continue

                # Scan for runs of null/INT3 bytes using regex for efficiency
                import re as _re
                pattern = _re.compile(rb'[\x00\xcc]{' + str(min_size).encode() + rb',}')
                for m in pattern.finditer(data):
                    caves.append({
                        "address": hex(start + m.start()),
                        "size": m.end() - m.start(),
                        "fill_byte": "0x00/0xCC",
                        "section": getattr(section, 'name', 'unknown'),
                    })

                if len(caves) >= limit:
                    break

        caves.sort(key=lambda c: c["size"], reverse=True)
        bridge.report_progress(95, 100)
        bridge.info("Formatting results...")

        return {
            "total_caves": len(caves),
            "min_size_filter": min_size,
            "caves": caves[:limit],
        }

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_find_caves), timeout=ANGR_ANALYSIS_TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError(f"find_code_caves timed out after {ANGR_ANALYSIS_TIMEOUT} seconds.")
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "find_code_caves", "the 'limit' parameter")


# ---- Packing Detection ----------------------------------------

@tool_decorator
async def detect_packing(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: explore] Uses angr heuristics to detect packing or obfuscation.
    Complements PEiD/triage with entropy, import count, and section analysis.

    ---compact: detect packing via entropy, imports, section analysis | needs: angr

    When to use: After triage packing_assessment for a second opinion, or when
    triage entropy is borderline and you need more detailed analysis.

    Next steps: If packed → auto_unpack_pe() for automated unpacking,
    detect_self_modifying_code() to find the unpacking routine,
    or analyze_entropy_by_offset() for region-level entropy detail.
    """
    await ctx.info("Detecting packing/obfuscation")
    _check_angr_ready("detect_packing", require_cfg=False)
    _bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    # Cap per-section entropy load to avoid OOM on large sections
    _MAX_ENTROPY_SECTION_BYTES = 10 * 1024 * 1024  # 10 MB

    def _detect():
        if state.angr_project is None:
            return {"error": "No angr project loaded. Open a file first."}
        loader = state.angr_project.loader

        indicators = []
        score = 0

        _bridge.report_progress(10, 100)
        _bridge.info("Computing section entropy...")
        # 1. Section entropy analysis
        for section in getattr(loader.main_object, 'sections', []):
            try:
                load_size = min(section.memsize, _MAX_ENTROPY_SECTION_BYTES)
                data = loader.memory.load(section.min_addr, load_size)
                if len(data) > 0:
                    entropy = shannon_entropy(data)

                    section_name = getattr(section, 'name', 'unknown')
                    is_exec = getattr(section, 'is_executable', False)

                    if entropy > 7.0 and is_exec:
                        indicators.append({
                            "type": "high_entropy_executable",
                            "section": section_name,
                            "entropy": round(entropy, 3),
                            "severity": "high",
                        })
                        score += 3
                    elif entropy > 6.5:
                        indicators.append({
                            "type": "elevated_entropy",
                            "section": section_name,
                            "entropy": round(entropy, 3),
                            "severity": "medium",
                        })
                        score += 1
            except Exception as e:
                logger.debug("Skipped section during packing entropy scan: %s", e)
                continue

        _bridge.report_progress(35, 100)
        _bridge.info("Analyzing import table...")
        # 2. Import table analysis
        try:
            imports = loader.main_object.imports
            import_count = len(imports) if imports else 0
            if import_count < 5:
                indicators.append({
                    "type": "very_few_imports",
                    "count": import_count,
                    "severity": "high",
                    "note": "Packed binaries often have minimal imports.",
                })
                score += 2
        except Exception as e:
            logger.debug("Skipped import table analysis during packing detection: %s", e)
            pass

        _bridge.report_progress(50, 100)
        _bridge.info("Checking section names...")
        # 3. Section name anomalies
        known_packer_sections = {'UPX0', 'UPX1', 'UPX2', '.aspack', '.adata', '.nsp0', '.nsp1', '.perplex', '.themida'}
        for section in getattr(loader.main_object, 'sections', []):
            name = getattr(section, 'name', '')
            if name in known_packer_sections:
                indicators.append({
                    "type": "known_packer_section",
                    "section": name,
                    "severity": "high",
                })
                score += 3

        _bridge.report_progress(65, 100)
        _bridge.info("Checking entry point...")
        # 4. Entry point outside first section
        try:
            entry = state.angr_project.entry
            sections = list(getattr(loader.main_object, 'sections', []))
            if sections:
                first_section = sections[0]
                if entry < first_section.min_addr or entry > first_section.max_addr:
                    indicators.append({
                        "type": "entry_point_anomaly",
                        "entry": hex(entry),
                        "first_section_range": f"{hex(first_section.min_addr)}-{hex(first_section.max_addr)}",
                        "severity": "medium",
                    })
                    score += 1
        except Exception as e:
            logger.debug("Skipped entry point anomaly check during packing detection: %s", e)
            pass

        _bridge.report_progress(80, 100)
        _bridge.info("Running angr packing detector...")
        # 5. Try angr's built-in PackingDetector
        try:
            pd = state.angr_project.analyses.PackingDetector()
            if hasattr(pd, 'result') and pd.result:
                indicators.append({
                    "type": "angr_packing_detector",
                    "result": str(pd.result),
                    "severity": "high",
                })
                score += 3
        except (AttributeError, Exception):
            pass

        verdict = "not_packed"
        if score >= 5:
            verdict = "likely_packed"
        elif score >= 2:
            verdict = "possibly_packed"

        return {
            "verdict": verdict,
            "confidence_score": score,
            "indicators": indicators,
        }

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_detect), timeout=ANGR_ANALYSIS_TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError(f"detect_packing timed out after {ANGR_ANALYSIS_TIMEOUT} seconds.")
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "detect_packing")


# ---- Patch-to-Disk -------------------------------------------

@tool_decorator
async def save_patched_binary(
    ctx: Context,
    output_path: str,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Saves the in-memory binary state (including patches from
    patch_binary_memory()) to a new file on disk.

    ---compact: save patched binary to disk | needs: angr

    When to use: After applying patches via patch_binary_memory() and you want
    to save the modified binary for further analysis or testing.

    Next steps: open_file(output_path) to analyze the patched binary,
    or diff_binaries() to compare original vs patched.

    Args:
        output_path: File path to write the patched binary to.
    """
    await ctx.info(f"Saving patched binary to {output_path}")
    # save_patched_binary only needs the angr project loader, not the CFG.
    _check_angr_ready("save_patched_binary", require_cfg=False)

    # Validate output path against sandbox
    state.check_path_allowed(os.path.realpath(output_path))

    def _save():
        if state.angr_project is None:
            return {"error": "No angr project loaded. Open a file first."}

        # Re-validate path inside thread to reduce TOCTOU window
        state.check_path_allowed(os.path.realpath(output_path))

        proj = state.angr_project
        loader = proj.loader

        try:
            # Read the original binary
            with open(state.filepath, 'rb') as f:
                original_data = bytearray(f.read())

            # Apply all in-memory patches by comparing loader memory to original
            main_obj = loader.main_object
            patches_applied = 0

            for section in getattr(main_obj, 'sections', []):
                sec_vaddr = section.min_addr
                sec_size = section.memsize

                try:
                    mem_data = loader.memory.load(sec_vaddr, sec_size)
                except Exception as e:
                    logger.debug("Skipped section during binary patching (memory load failed): %s", e)
                    continue

                # Map VA to file offset — CLE section attribute names vary
                # by backend (PE vs ELF vs Mach-O).
                file_offset = getattr(section, 'offset', None)
                if file_offset is None:
                    # ELF uses sh_offset for section file offset
                    file_offset = getattr(section, 'sh_offset', None)
                if file_offset is None:
                    # Mach-O uses fileoff for segment file offset
                    file_offset = getattr(section, 'fileoff', None)
                if file_offset is None:
                    # Compute from VA and mapped base as last resort
                    try:
                        file_offset = sec_vaddr - main_obj.mapped_base
                    except Exception as e:
                        logger.debug("Skipped section during binary patching (offset calc failed): %s", e)
                        continue
                if file_offset is None or file_offset < 0:
                    continue

                for i in range(min(len(mem_data), len(original_data) - file_offset)):
                    if file_offset + i < len(original_data) and mem_data[i] != original_data[file_offset + i]:
                        original_data[file_offset + i] = mem_data[i]
                        patches_applied += 1

            # Ensure output directory exists
            out_dir = os.path.dirname(output_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            with open(output_path, 'wb') as f:
                f.write(original_data)

            file_size = os.path.getsize(output_path)

            return {
                "status": "success",
                "output_path": output_path,
                "file_size": file_size,
                "bytes_patched": patches_applied,
            }

        except Exception as e:
            return {"error": f"Failed to save patched binary: {e}"}

    result = await asyncio.to_thread(_save)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "save_patched_binary")


# ---- Symbolic Input Configuration ------------------------------

@tool_decorator
async def find_path_with_custom_input(
    ctx: Context,
    target_address: str,
    avoid_address: Optional[str] = None,
    symbolic_registers: Optional[List[str]] = None,
    symbolic_memory_ranges: Optional[List[str]] = None,
    concrete_memory: Optional[Dict[str, str]] = None,
    max_steps: int = 2000,
    use_dfs: bool = True,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Symbolic execution with configurable symbolic inputs —
    registers, memory ranges, and concrete pre-fills. Not limited to stdin.

    ---compact: symbolic execution with custom register/memory inputs | needs: angr+CFG

    When to use: When find_path_to_address() (stdin-only) is insufficient and
    you need to control specific registers or memory as symbolic inputs.

    Next steps: emulate_function_execution() to test with found values,
    add_note() to record the path constraint solution.

    Args:
        target_address: Hex address to reach.
        avoid_address: Optional hex address to avoid.
        symbolic_registers: List of register names to make symbolic (e.g. ['eax', 'ebx']).
        symbolic_memory_ranges: List of 'addr:size' strings — addr is hex or decimal (e.g. ['0x404000:64'] or ['4210688:64']).
        concrete_memory: Dict of 'addr' -> 'hex_bytes' to pre-fill memory — addr keys are hex or decimal.
        max_steps: Max execution steps.
        run_in_background: Run as background task.
    """
    _check_angr_ready("find_path_with_custom_input")
    target = _parse_addr(target_address)
    avoid = _parse_addr(avoid_address, "avoid_address") if avoid_address else None
    max_steps = max(1, min(max_steps, 100_000))

    _partial_custom = {}  # shared state for on_timeout callback

    def _solve(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()
        proj = state.angr_project

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Building initial state...", bridge=_progress_bridge)

        add_options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
        entry_state = proj.factory.entry_state(add_options=add_options)

        # Apply symbolic registers
        if symbolic_registers:
            for reg_name in symbolic_registers:
                try:
                    sym_var = entry_state.solver.BVS(f"sym_{reg_name}", proj.arch.bits)
                    setattr(entry_state.regs, reg_name, sym_var)
                except Exception as e:
                    logger.debug("Skipped symbolic register '%s': %s", reg_name, e)
                    pass

        # Apply symbolic memory ranges
        _MAX_SYMBOLIC_MEM_SIZE = 4096  # M-7: cap per-range size to prevent memory exhaustion
        if symbolic_memory_ranges:
            for spec in symbolic_memory_ranges:
                try:
                    parts = spec.split(":")
                    mem_addr = int(parts[0], 0)
                    mem_size = int(parts[1])
                    if mem_size < 1 or mem_size > _MAX_SYMBOLIC_MEM_SIZE:
                        raise ValueError(
                            f"Symbolic memory size must be 1-{_MAX_SYMBOLIC_MEM_SIZE} bytes, got {mem_size}"
                        )
                    sym_mem = entry_state.solver.BVS(f"sym_mem_{hex(mem_addr)}", mem_size * 8)
                    entry_state.memory.store(mem_addr, sym_mem)
                except Exception as e:
                    logger.debug("Skipped symbolic memory range '%s': %s", spec, e)
                    continue

        # Apply concrete memory values
        if concrete_memory:
            for addr_hex, data_hex in concrete_memory.items():
                try:
                    mem_addr = int(addr_hex, 0)
                    data = bytes.fromhex(data_hex)
                    entry_state.memory.store(mem_addr, data)
                except Exception as e:
                    logger.debug("Skipped concrete memory at '%s': %s", addr_hex, e)
                    continue

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 15, "Starting symbolic exploration...", bridge=_progress_bridge)

        simgr = proj.factory.simulation_manager(entry_state)
        if use_dfs:
            simgr.use_technique(angr.exploration_techniques.DFS())
        simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=max_steps))
        simgr.use_technique(angr.exploration_techniques.Explorer(find=target, avoid=avoid))

        steps = 0
        while len(simgr.active) > 0 and len(simgr.found) == 0 and steps < max_steps:
            if len(simgr.active) > 30:
                simgr.split(from_stash='active', to_stash='deferred', limit=30)
            # Cap deferred stash to prevent unbounded state accumulation
            deferred = getattr(simgr, 'deferred', None)
            if deferred is not None and len(deferred) > 500:
                simgr.drop(stash='deferred', filter_func=lambda s: True)
            simgr.step()
            steps += 1
            _partial_custom['steps'] = steps
            _partial_custom['active'] = len(simgr.active)
            if task_id_for_progress and steps % 20 == 0:
                percent = min(95, int((steps / max_steps) * 100))
                _update_progress(task_id_for_progress, percent, f"Step {steps}, active: {len(simgr.active)}", bridge=_progress_bridge)

        if simgr.found:
            found_state = simgr.found[0]
            results = {"status": "success", "steps_taken": steps}

            # Dump stdin if available
            try:
                stdin_data = found_state.posix.dumps(0)
                if stdin_data:
                    results["stdin_hex"] = stdin_data.hex()
                    results["stdin_ascii"] = stdin_data.decode('utf-8', 'ignore')
            except Exception as e:
                logger.debug("Skipped stdin dump from found state: %s", e)
                pass

            # Resolve symbolic registers
            if symbolic_registers:
                reg_solutions = {}
                for reg_name in symbolic_registers:
                    try:
                        val = found_state.solver.eval(getattr(found_state.regs, reg_name))
                        reg_solutions[reg_name] = hex(val)
                    except Exception:
                        reg_solutions[reg_name] = "unsolvable"
                results["register_solutions"] = reg_solutions

            # Resolve symbolic memory
            if symbolic_memory_ranges:
                mem_solutions = {}
                for spec in symbolic_memory_ranges:
                    try:
                        parts = spec.split(":")
                        mem_addr = int(parts[0], 0)
                        mem_size = int(parts[1])
                        data = found_state.solver.eval(
                            found_state.memory.load(mem_addr, mem_size), cast_to=bytes
                        )
                        mem_solutions[hex(mem_addr)] = data.hex()
                    except Exception:
                        mem_solutions[spec] = "unsolvable"
                results["memory_solutions"] = mem_solutions

            return results

        return {"status": "failure", "steps_taken": steps, "message": f"No path found after {steps} steps."}

    def _on_timeout_custom():
        return {
            "steps_completed": _partial_custom.get('steps', 0),
            "active_states": _partial_custom.get('active', 0),
            "message": f"Timed out after {_partial_custom.get('steps', 0)} steps. No path found.",
            "hint": "Try: smaller max_steps, add avoid addresses, or decompile first.",
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        _cancel = _register_background_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing custom solver...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "find_path_with_custom_input",
        })
        task = asyncio.create_task(_run_background_task_wrapper(
            task_id, _solve, ctx=ctx, cancel_event=_cancel,
            timeout=600, on_timeout=_on_timeout_custom))
        task.add_done_callback(_log_task_exception(task_id))
        return {"status": "queued", "task_id": task_id, "message": "Custom symbolic execution queued."}

    await ctx.info(f"Solving path to {target_address} with custom inputs")
    result = await asyncio.to_thread(_solve)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "find_path_with_custom_input")


# ---- SimInspect Watchpoints -----------------------------------

@tool_decorator
async def emulate_with_watchpoints(
    ctx: Context,
    function_address: str,
    watch_mem_writes: Optional[List[str]] = None,
    watch_mem_reads: Optional[List[str]] = None,
    watch_registers: Optional[List[str]] = None,
    args_hex: Optional[List[str]] = None,
    max_steps: int = 1000,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Emulates a function with watchpoints that log memory
    reads/writes and register accesses at specific addresses.

    ---compact: emulate with memory/register watchpoints | trace data access | needs: angr+CFG

    When to use: When you need to trace how specific memory locations or registers
    are accessed during execution — useful for understanding config decryption,
    key derivation, or data exfiltration routines.

    Next steps: auto_note_function() to record behavioral findings, add_note()
    for specific watchpoint observations.

    Args:
        function_address: Hex address of the function to emulate.
        watch_mem_writes: List of hex or decimal addresses to watch for memory writes.
        watch_mem_reads: List of hex or decimal addresses to watch for memory reads.
        watch_registers: List of register names to watch for writes.
        args_hex: Hex or decimal arguments to pass to the function.
        max_steps: Max emulation steps.
        run_in_background: Run as background task.
    """
    _check_angr_ready("emulate_with_watchpoints")
    target = _parse_addr(function_address)
    max_steps = max(1, min(max_steps, 100_000))
    if args_hex is None:
        args_hex = []
    args = [_parse_addr(a, "argument") for a in args_hex]

    _partial_wp = {}  # shared state for on_timeout callback

    def _emulate(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()
        proj = state.angr_project

        events = []  # Collected watchpoint hits
        _MAX_WATCHPOINT_EVENTS = 50_000  # OOM safety cap
        _partial_wp['events'] = events  # reference to the live list

        add_options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
        call_state = proj.factory.call_state(target, *args, add_options=add_options)

        # Install memory write watchpoints
        watch_write_addrs = set()
        if watch_mem_writes:
            for addr_hex in watch_mem_writes:
                watch_write_addrs.add(_parse_addr(addr_hex, "watch_mem_writes address"))

            def _on_mem_write(sim_state):
                try:
                    if len(events) >= _MAX_WATCHPOINT_EVENTS:
                        return
                    write_addr = sim_state.solver.eval(sim_state.inspect.mem_write_address)
                    if not watch_write_addrs or write_addr in watch_write_addrs:
                        length = sim_state.inspect.mem_write_length
                        val = sim_state.inspect.mem_write_expr
                        val_str = hex(sim_state.solver.eval(val)) if val is not None and not val.symbolic else "symbolic"
                        events.append({
                            "type": "mem_write",
                            "address": hex(write_addr),
                            "value": val_str,
                            "length": length,
                            "pc": hex(sim_state.addr),
                        })
                except Exception as e:
                    logger.debug("Skipped mem_write watchpoint event: %s", e)
                    pass

            call_state.inspect.b('mem_write', action=_on_mem_write)

        # Install memory read watchpoints
        watch_read_addrs = set()
        if watch_mem_reads:
            for addr_hex in watch_mem_reads:
                watch_read_addrs.add(_parse_addr(addr_hex, "watch_mem_reads address"))

            def _on_mem_read(sim_state):
                try:
                    if len(events) >= _MAX_WATCHPOINT_EVENTS:
                        return
                    read_addr = sim_state.solver.eval(sim_state.inspect.mem_read_address)
                    if not watch_read_addrs or read_addr in watch_read_addrs:
                        events.append({
                            "type": "mem_read",
                            "address": hex(read_addr),
                            "length": sim_state.inspect.mem_read_length,
                            "pc": hex(sim_state.addr),
                        })
                except Exception as e:
                    logger.debug("Skipped mem_read watchpoint event: %s", e)
                    pass

            call_state.inspect.b('mem_read', action=_on_mem_read)

        # Install register write watchpoints
        if watch_registers:
            reg_offsets = {}
            for reg_name in watch_registers:
                try:
                    off = proj.arch.registers.get(reg_name)
                    if off is not None:
                        reg_offsets[off[0]] = reg_name
                except Exception as e:
                    logger.debug("Skipped register offset lookup for '%s': %s", reg_name, e)
                    pass

            def _on_reg_write(sim_state):
                try:
                    if len(events) >= _MAX_WATCHPOINT_EVENTS:
                        return
                    offset = sim_state.inspect.reg_write_offset
                    if hasattr(offset, 'ast'):
                        offset = sim_state.solver.eval(offset)
                    if offset in reg_offsets:
                        val = sim_state.inspect.reg_write_expr
                        val_str = hex(sim_state.solver.eval(val)) if val is not None and not val.symbolic else "symbolic"
                        events.append({
                            "type": "reg_write",
                            "register": reg_offsets[offset],
                            "value": val_str,
                            "pc": hex(sim_state.addr),
                        })
                except Exception as e:
                    logger.debug("Skipped reg_write watchpoint event: %s", e)
                    pass

            call_state.inspect.b('reg_write', action=_on_reg_write)

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 10, "Emulating with watchpoints...", bridge=_progress_bridge)

        simgr = proj.factory.simulation_manager(call_state)
        steps_taken = 0
        while steps_taken < max_steps:
            if not simgr.active:
                break
            try:
                simgr.step()
            except Exception as e:
                return {
                    "status": "errored",
                    "steps_taken": steps_taken,
                    "error": str(e)[:200],
                    "total_events": len(events),
                    "events": events[:500],
                }
            steps_taken += 1
            _partial_wp['steps'] = steps_taken
            if task_id_for_progress and steps_taken % 20 == 0:
                percent = min(95, int((steps_taken / max_steps) * 100))
                _update_progress(task_id_for_progress, percent, f"Step {steps_taken}, events: {len(events)}", bridge=_progress_bridge)

        status = "completed"
        error_details = None
        if simgr.deadended:
            status = "function_returned"
        elif simgr.errored:
            status = "errored"
            try:
                error_details = str(simgr.errored[0].error)
            except Exception:
                error_details = f"{len(simgr.errored)} errored state(s)"
        elif simgr.active:
            status = "max_steps_reached"

        result = {
            "status": status,
            "steps_taken": steps_taken,
            "total_events": len(events),
            "events": events[:500],  # cap to prevent huge responses
        }
        if error_details:
            result["error"] = error_details
        return result

    def _on_timeout_wp():
        events = _partial_wp.get('events', [])
        return {
            "steps_taken": _partial_wp.get('steps', 0),
            "total_events": len(events),
            "events": events[:500],
            "message": f"Timed out but {len(events)} watchpoint events were captured.",
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        _cancel = _register_background_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing watchpoint emulation...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "emulate_with_watchpoints",
        })
        task = asyncio.create_task(_run_background_task_wrapper(
            task_id, _emulate, ctx=ctx, cancel_event=_cancel,
            timeout=300, on_timeout=_on_timeout_wp))
        task.add_done_callback(_log_task_exception(task_id))
        return {"status": "queued", "task_id": task_id, "message": "Watchpoint emulation queued."}

    await ctx.info(f"Emulating {function_address} with watchpoints")
    result = await asyncio.to_thread(_emulate)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "emulate_with_watchpoints")


# ---- Class Identification (C++) --------------------------------

@tool_decorator
async def identify_cpp_classes(
    ctx: Context,
    limit: int = 20,
    method_limit: int = 20,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Identifies C++ class hierarchies by analysing vtables.
    Returns classes with vtable addresses, virtual methods, and inheritance.

    ---compact: identify C++ classes via vtable analysis | inheritance, virtual methods | needs: angr+CFG

    When to use: When analyzing C++ binaries — helps understand object-oriented
    structure, identify polymorphic dispatch, and find virtual function targets.

    Next steps: decompile_function_with_angr() at virtual method addresses,
    get_function_xrefs() to trace vtable usage.

    Args:
        limit: Max classes to return.
        method_limit: Max methods per class to return (default 20).
        run_in_background: Run as background task.
    """
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    method_limit = max(1, min(method_limit, MAX_TOOL_LIMIT))
    _check_angr_ready("identify_cpp_classes")

    def _identify(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 10, "Scanning for vtables...", bridge=_progress_bridge)

        # Try the built-in ClassIdentifier first
        try:
            ci = state.angr_project.analyses.ClassIdentifier()
            classes = []
            for cls in list(getattr(ci, 'classes', []))[:limit]:
                entry = {
                    "name": getattr(cls, 'name', 'unknown'),
                    "vtable_address": hex(cls.vtable_addr) if hasattr(cls, 'vtable_addr') else None,
                }
                if hasattr(cls, 'methods'):
                    all_methods = [hex(m) if isinstance(m, int) else str(m) for m in cls.methods]
                    entry["methods"] = all_methods[:method_limit]
                    entry["method_count"] = len(all_methods)
                    entry["methods_has_more"] = len(all_methods) > method_limit
                if hasattr(cls, 'parents'):
                    entry["parents"] = [str(p) for p in cls.parents]
                classes.append(entry)
            return {
                "total_classes": len(classes),
                "classes": classes,
            }
        except (AttributeError, Exception):
            pass

        # Fallback: manual vtable heuristic scan
        if task_id_for_progress:
            _update_progress(task_id_for_progress, 30, "Using heuristic vtable scanner...", bridge=_progress_bridge)

        loader = state.angr_project.loader
        vtables = []

        # Build a set of addresses that belong to external/import stubs
        # (PLT entries, IAT thunks, SimProcedures).  Any pointer table
        # consisting solely of these is an IAT, not a vtable.
        extern_addrs = set()
        for addr, func in state.angr_cfg.functions.items():
            if func.is_simprocedure or func.is_plt or getattr(func, 'is_extern', False):
                extern_addrs.add(addr)

        # Identify IAT / import-related address ranges to skip entirely.
        # On PE binaries the IAT lives in .idata or .rdata at known offsets.
        iat_ranges = set()
        try:
            main_obj = loader.main_object
            # CLE's PE backend exposes the import directory
            if hasattr(main_obj, 'imports'):
                for _sym_name, sym in main_obj.imports.items():
                    if hasattr(sym, 'rebased_addr'):
                        iat_ranges.add(sym.rebased_addr)
        except Exception as e:
            logger.debug("Skipped IAT range extraction during vtable scan: %s", e)
            pass

        # Look for arrays of function pointers in data sections
        func_addrs = set(state.angr_cfg.functions.keys())
        for section in getattr(loader.main_object, 'sections', []):
            if getattr(section, 'is_executable', False):
                continue  # Skip code sections, vtables are in data

            # Skip sections that are commonly import-related
            sec_name = getattr(section, 'name', '').lower().strip('\x00')
            if sec_name in ('.idata', '.didat'):
                continue

            try:
                data = loader.memory.load(section.min_addr, min(section.memsize, 65536))
            except Exception as e:
                logger.debug("Skipped section during vtable scan (memory load failed): %s", e)
                continue

            ptr_size = state.angr_project.arch.bytes
            i = 0
            while i < len(data) - ptr_size * 2:
                # Read consecutive pointers
                consecutive_funcs = 0
                extern_count = 0
                start_offset = i
                while i < len(data) - ptr_size:
                    if ptr_size == 4:
                        ptr_val = int.from_bytes(data[i:i+4], byteorder='little')
                    else:
                        ptr_val = int.from_bytes(data[i:i+8], byteorder='little')

                    if ptr_val in func_addrs:
                        consecutive_funcs += 1
                        if ptr_val in extern_addrs:
                            extern_count += 1
                        i += ptr_size
                    else:
                        break

                if consecutive_funcs >= 2:
                    # Skip tables where ALL entries point to external/import
                    # stubs — these are IAT entries, not C++ vtables.
                    if extern_count == consecutive_funcs:
                        i += ptr_size  # advance past this IAT block
                        continue

                    # Also skip if the starting address is a known IAT slot
                    vtable_addr = section.min_addr + start_offset
                    if vtable_addr in iat_ranges:
                        i += ptr_size
                        continue

                    methods = []
                    for j in range(consecutive_funcs):
                        off = start_offset + j * ptr_size
                        if ptr_size == 4:
                            ptr_val = int.from_bytes(data[off:off+4], byteorder='little')
                        else:
                            ptr_val = int.from_bytes(data[off:off+8], byteorder='little')
                        fname = state.angr_cfg.functions[ptr_val].name if ptr_val in state.angr_cfg.functions else hex(ptr_val)
                        methods.append(fname)

                    vtables.append({
                        "vtable_address": hex(vtable_addr),
                        "consecutive_pointers": consecutive_funcs,
                        "methods": methods[:method_limit],
                        "method_count": len(methods),
                        "methods_has_more": len(methods) > method_limit,
                        "section": getattr(section, 'name', 'unknown'),
                    })

                    if len(vtables) >= limit:
                        break
                else:
                    i += ptr_size

            if len(vtables) >= limit:
                break

        vtables.sort(key=lambda v: v["method_count"], reverse=True)

        return {
            "method": "heuristic_vtable_scan",
            "total_vtables_found": len(vtables),
            "vtables": vtables[:limit],
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        _cancel = _register_background_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing class identification...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "identify_cpp_classes",
        })
        task = asyncio.create_task(_run_background_task_wrapper(
            task_id, _identify, ctx=ctx, cancel_event=_cancel, timeout=300))
        task.add_done_callback(_log_task_exception(task_id))
        return {"status": "queued", "task_id": task_id, "message": "Class identification queued."}

    await ctx.info("Identifying C++ classes")
    result = await asyncio.to_thread(_identify)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "identify_cpp_classes", "the 'limit' parameter")


# ---- Full Call Graph Export ------------------------------------

@tool_decorator
async def get_call_graph(
    ctx: Context,
    root_address: Optional[str] = None,
    max_depth: int = 0,
    limit: int = 20,
    compact: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: explore] Exports the full inter-procedural call graph, or a subgraph
    rooted at a specific function with optional depth limiting.

    ---compact: export inter-procedural call graph | optional root + depth limit | needs: angr+CFG

    When to use: When you need to understand the global function call structure
    or trace call chains from a specific entry point.

    Next steps: decompile_function_with_angr() on key nodes, or
    get_cross_reference_map() for a more detailed per-function view.

    Args:
        root_address: Optional; if set, return only the subgraph reachable from this function.
        max_depth: If >0 with root_address, limit traversal depth.
        limit: Max edges to return.
    """
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info("Exporting call graph")
    _check_angr_ready("get_call_graph")
    root = _parse_addr(root_address, "root_address") if root_address else None
    _cg_bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _extract():
        _ensure_project_and_cfg()
        _cg_bridge.report_progress(10, 100)
        _cg_bridge.info("Building call graph...")
        callgraph = state.angr_cfg.functions.callgraph

        if root is not None:
            if root not in callgraph:
                return {"error": f"Function {hex(root)} not found in call graph."}

            if max_depth > 0:
                # BFS with depth limit
                visited = set()
                queue = deque([(root, 0)])
                edges = []
                while queue:
                    node, depth = queue.popleft()
                    if node in visited or depth > max_depth:
                        continue
                    visited.add(node)
                    for succ in callgraph.successors(node):
                        src_name = state.angr_cfg.functions[node].name if node in state.angr_cfg.functions else hex(node)
                        dst_name = state.angr_cfg.functions[succ].name if succ in state.angr_cfg.functions else hex(succ)
                        edges.append({"src": hex(node), "src_name": src_name, "dst": hex(succ), "dst_name": dst_name})
                        if succ not in visited:
                            queue.append((succ, depth + 1))
                        if len(edges) >= limit:
                            break
                    if len(edges) >= limit:
                        break
                return {
                    "root": hex(root),
                    "max_depth": max_depth,
                    "nodes_visited": len(visited),
                    "total_edges": len(edges),
                    "edges": edges,
                }
            else:
                # Bounded BFS instead of unbounded nx.descendants
                _MAX_SLICE_NODES = 10_000
                descendants = set()
                _queue = deque([root])
                while _queue and len(descendants) < _MAX_SLICE_NODES:
                    _node = _queue.popleft()
                    if _node in descendants:
                        continue
                    descendants.add(_node)
                    _queue.extend(callgraph.successors(_node))
                subgraph = callgraph.subgraph(descendants)
                edges = []
                for src, dst in list(subgraph.edges())[:limit]:
                    src_name = state.angr_cfg.functions[src].name if src in state.angr_cfg.functions else hex(src)
                    dst_name = state.angr_cfg.functions[dst].name if dst in state.angr_cfg.functions else hex(dst)
                    edges.append({"src": hex(src), "src_name": src_name, "dst": hex(dst), "dst_name": dst_name})
                return {
                    "root": hex(root),
                    "total_nodes": len(subgraph.nodes()),
                    "total_edges": len(subgraph.edges()),
                    "edges": edges,
                }

        # Full call graph
        _cg_bridge.report_progress(50, 100)
        _cg_bridge.info("Extracting full call graph...")
        nodes = []
        for addr in list(callgraph.nodes())[:limit]:
            name = state.angr_cfg.functions[addr].name if addr in state.angr_cfg.functions else hex(addr)
            in_deg = callgraph.in_degree(addr)
            out_deg = callgraph.out_degree(addr)
            nodes.append({"address": hex(addr), "name": name, "callers": in_deg, "callees": out_deg})

        nodes.sort(key=lambda n: n["callees"], reverse=True)

        if compact:
            # Compact: summary stats + top 10 hub functions only
            return {
                "total_functions": len(callgraph.nodes()),
                "total_call_edges": len(callgraph.edges()),
                "top_hubs": [{"address": n["address"], "name": n["name"], "callees": n["callees"]} for n in nodes[:10]],
            }

        edges = []
        for src, dst in list(callgraph.edges())[:limit]:
            src_name = state.angr_cfg.functions[src].name if src in state.angr_cfg.functions else hex(src)
            dst_name = state.angr_cfg.functions[dst].name if dst in state.angr_cfg.functions else hex(dst)
            edges.append({"src": hex(src), "src_name": src_name, "dst": hex(dst), "dst_name": dst_name})

        return {
            "total_functions": len(callgraph.nodes()),
            "total_call_edges": len(callgraph.edges()),
            "nodes": nodes[:limit],
            "edges": edges,
        }

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_extract), timeout=ANGR_ANALYSIS_TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError(f"get_call_graph timed out after {ANGR_ANALYSIS_TIMEOUT} seconds.")
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_call_graph", "the 'limit' parameter")


# ===================================================================
#  find_anti_debug_comprehensive
# ===================================================================

@tool_decorator
async def find_anti_debug_comprehensive(
    ctx: Context,
    compact: bool = False,
    limit: int = 60,
) -> Dict[str, Any]:
    """
    [Phase: explore] Comprehensive anti-analysis technique detection — covers
    anti-debugging, anti-VM, and sandbox evasion. Checks for specific API
    patterns, timing checks, TLS callbacks, PEB access, VM indicator strings,
    and known evasion techniques.

    ---compact: detect anti-debug, anti-VM, sandbox evasion | APIs, strings, instructions | needs: angr+CFG

    When to use: After triage when anti-debug/anti-VM imports are flagged and
    you need a detailed inventory of evasion techniques. Also useful for packed
    samples where anti-analysis prevents dynamic analysis.

    Next steps: decompile_function_with_angr() on functions containing anti-analysis
    to understand the specific implementation and potential bypasses.

    Args:
        ctx: The MCP Context object.
        compact: (bool) If True, return a grouped summary instead of per-occurrence
            technique listings. Saves context budget when you only need an overview.
    """
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info("Scanning for anti-debug and anti-analysis techniques")
    _check_angr_ready("find_anti_debug_comprehensive")
    _ad_bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _scan():
        _ensure_project_and_cfg()
        _ad_bridge.report_progress(5, 100)
        _ad_bridge.info("Loading anti-debug API database...")

        techniques = []
        functions_with_antidbg = []

        # Known anti-debug/anti-analysis APIs
        ANTI_DEBUG_APIS = {
            "IsDebuggerPresent": {"category": "debugger_check", "severity": "high",
                                  "description": "Checks PEB.BeingDebugged flag"},
            "CheckRemoteDebuggerPresent": {"category": "debugger_check", "severity": "high",
                                           "description": "Checks if a remote debugger is attached"},
            "NtQueryInformationProcess": {"category": "debugger_check", "severity": "high",
                                          "description": "Can query ProcessDebugPort, ProcessDebugObjectHandle"},
            "NtQuerySystemInformation": {"category": "system_check", "severity": "medium",
                                         "description": "Can detect VMs and debuggers via system info classes"},
            "OutputDebugStringA": {"category": "debugger_check", "severity": "medium",
                                   "description": "Error-based debugger detection technique"},
            "OutputDebugStringW": {"category": "debugger_check", "severity": "medium",
                                   "description": "Error-based debugger detection (wide)"},
            "GetTickCount": {"category": "timing_check", "severity": "medium",
                             "description": "Timing-based anti-debug (detects single-step)"},
            "GetTickCount64": {"category": "timing_check", "severity": "medium",
                               "description": "64-bit timing-based anti-debug"},
            "QueryPerformanceCounter": {"category": "timing_check", "severity": "medium",
                                        "description": "High-resolution timing check"},
            "QueryPerformanceFrequency": {"category": "timing_check", "severity": "low",
                                           "description": "Often paired with QueryPerformanceCounter"},
            "GetSystemTime": {"category": "timing_check", "severity": "low",
                              "description": "System time-based timing check"},
            "NtQueryVirtualMemory": {"category": "memory_check", "severity": "medium",
                                     "description": "Can detect breakpoints in memory"},
            "VirtualProtect": {"category": "memory_manipulation", "severity": "low",
                               "description": "Can be used to detect/remove breakpoints"},
            "SetUnhandledExceptionFilter": {"category": "exception_handler", "severity": "medium",
                                            "description": "SEH-based anti-debug technique"},
            "RtlAddVectoredExceptionHandler": {"category": "exception_handler", "severity": "medium",
                                                "description": "VEH-based anti-debug technique"},
            "NtSetInformationThread": {"category": "thread_hiding", "severity": "high",
                                       "description": "ThreadHideFromDebugger — hides thread from debugger"},
            "NtClose": {"category": "exception_based", "severity": "medium",
                        "description": "Closing invalid handle causes exception under debugger"},
            "CloseHandle": {"category": "exception_based", "severity": "low",
                            "description": "CloseHandle with invalid handle — exception under debugger"},
            "FindWindowA": {"category": "window_check", "severity": "medium",
                            "description": "Searches for debugger windows (OllyDbg, x64dbg, etc.)"},
            "FindWindowW": {"category": "window_check", "severity": "medium",
                            "description": "Wide string variant of debugger window search"},
            "CreateToolhelp32Snapshot": {"category": "process_check", "severity": "medium",
                                         "description": "Process enumeration — can detect analysis tools"},
            "Process32First": {"category": "process_check", "severity": "low",
                               "description": "Process enumeration helper"},
            "Process32Next": {"category": "process_check", "severity": "low",
                              "description": "Process enumeration helper"},
            "GetModuleHandleA": {"category": "module_check", "severity": "low",
                                  "description": "Can check for loaded analysis DLLs"},
            # --- Anti-VM / Sandbox detection ---
            "GetSystemFirmwareTable": {"category": "vm_detection", "severity": "high",
                                       "description": "Reads SMBIOS/ACPI tables — detects VMware, VBox, Hyper-V"},
            "EnumSystemFirmwareTables": {"category": "vm_detection", "severity": "high",
                                          "description": "Enumerates firmware tables for VM artifacts"},
            "EnumServicesStatusExA": {"category": "vm_detection", "severity": "medium",
                                      "description": "Enumerates services — detects VM guest tools"},
            "EnumServicesStatusExW": {"category": "vm_detection", "severity": "medium",
                                      "description": "Enumerates services (wide) — detects VM guest tools"},
            "GetAdaptersAddresses": {"category": "vm_detection", "severity": "medium",
                                     "description": "Checks MAC address OUI for VM vendors"},
            "GetAdaptersInfo": {"category": "vm_detection", "severity": "medium",
                                "description": "Checks network adapters for VM artifacts"},
            "SetupDiGetDeviceRegistryPropertyA": {"category": "vm_detection", "severity": "medium",
                                                   "description": "Queries device properties for VM hardware strings"},
            "SetupDiGetDeviceRegistryPropertyW": {"category": "vm_detection", "severity": "medium",
                                                   "description": "Queries device properties (wide) for VM hardware strings"},
            "WMIQuery": {"category": "vm_detection", "severity": "medium",
                         "description": "WMI queries can detect VM vendor strings"},
            "SleepEx": {"category": "sandbox_evasion", "severity": "medium",
                        "description": "Extended sleep — evades sandbox time limits"},
            "WaitForSingleObject": {"category": "sandbox_evasion", "severity": "low",
                                    "description": "Can be used for timing-based sandbox evasion"},
            "GetCursorPos": {"category": "sandbox_evasion", "severity": "medium",
                             "description": "Checks for mouse movement — detects automated sandboxes"},
            "GetLastInputInfo": {"category": "sandbox_evasion", "severity": "medium",
                                 "description": "Checks time since last user input — sandbox detection"},
            "GetSystemMetrics": {"category": "sandbox_evasion", "severity": "low",
                                 "description": "Checks screen resolution — small screens indicate sandbox"},
            "GlobalMemoryStatusEx": {"category": "vm_detection", "severity": "medium",
                                     "description": "Checks total RAM — low RAM indicates VM"},
            "GetDiskFreeSpaceExA": {"category": "vm_detection", "severity": "medium",
                                    "description": "Checks disk space — small disks indicate VM/sandbox"},
            "GetDiskFreeSpaceExW": {"category": "vm_detection", "severity": "medium",
                                    "description": "Checks disk space (wide) — small disks indicate VM/sandbox"},
            "RegOpenKeyExA": {"category": "vm_detection", "severity": "medium",
                              "description": "Registry key check — can probe VM-specific registry paths"},
            "RegOpenKeyExW": {"category": "vm_detection", "severity": "medium",
                              "description": "Registry key check (wide) — VM registry path probing"},
            "DeviceIoControl": {"category": "vm_detection", "severity": "medium",
                                "description": "Device IOCTL — can probe virtual hardware controllers"},
            "NtDelayExecution": {"category": "sandbox_evasion", "severity": "medium",
                                 "description": "NT native sleep — evades sandbox time limits"},
            "Sleep": {"category": "sandbox_evasion", "severity": "low",
                      "description": "Sleep call — can delay past sandbox execution timeout"},
            "GetProcessHeap": {"category": "debugger_check", "severity": "medium",
                               "description": "Heap flags check — ForceFlags/Flags differ under debugger"},
            "NtQueryObject": {"category": "debugger_check", "severity": "high",
                              "description": "Can query DebugObject type count to detect debuggers"},
            "GetVolumeInformationA": {"category": "vm_detection", "severity": "medium",
                                      "description": "Volume serial number check — detects cloned VMs"},
            "GetVolumeInformationW": {"category": "vm_detection", "severity": "medium",
                                      "description": "Volume serial number check (wide) — VM detection"},
        }

        callgraph = state.angr_cfg.functions.callgraph
        _ad_bridge.report_progress(15, 100)
        _ad_bridge.info("Scanning functions for anti-debug API calls...")

        total_funcs = len(state.angr_cfg.functions)
        scanned = 0
        for addr, func in state.angr_cfg.functions.items():
            func_anti_apis = []
            try:
                for callee_addr in callgraph.successors(addr):
                    if callee_addr in state.angr_cfg.functions:
                        callee_name = state.angr_cfg.functions[callee_addr].name
                        for api_name, info in ANTI_DEBUG_APIS.items():
                            if api_name.lower() in callee_name.lower():
                                func_anti_apis.append({
                                    "api": api_name,
                                    "category": info["category"],
                                    "severity": info["severity"],
                                    "description": info["description"],
                                })
            except Exception as e:
                logger.debug("Skipped function during anti-debug scan: %s", e)
                continue

            scanned += 1
            if scanned % 50 == 0 and total_funcs > 0:
                pct = 15 + int((scanned / total_funcs) * 60)
                _ad_bridge.report_progress(min(pct, 75), 100)
                _ad_bridge.info(f"Scanned {scanned}/{total_funcs} functions...")

            if func_anti_apis:
                functions_with_antidbg.append({
                    "address": hex(addr),
                    "name": func.name,
                    "techniques": func_anti_apis,
                })
                for api_info in func_anti_apis:
                    techniques.append({
                        "technique": api_info["api"],
                        "category": api_info["category"],
                        "severity": api_info["severity"],
                        "function": hex(addr),
                        "function_name": func.name,
                    })

        _ad_bridge.report_progress(80, 100)
        _ad_bridge.info("Checking TLS callbacks...")
        # Check TLS callbacks (often used for anti-debug)
        tls_callbacks = []
        if state.pe_data:
            tls_info = state.pe_data.get("tls_info", {})
            if isinstance(tls_info, dict):
                callbacks = tls_info.get("callbacks", [])
                if callbacks:
                    tls_callbacks = callbacks
                    techniques.append({
                        "technique": "TLS_Callbacks",
                        "category": "early_execution",
                        "severity": "high",
                        "function": str(callbacks),
                        "function_name": "TLS callback(s)",
                    })

        # Check for anti-VM strings in binary data
        _ad_bridge.report_progress(85, 100)
        _ad_bridge.info("Scanning for anti-VM indicator strings...")
        vm_strings_found = []
        if state.pe_object and hasattr(state.pe_object, '__data__'):
            file_data = state.pe_object.__data__
            # Known VM/sandbox indicator strings (case-insensitive search)
            _VM_INDICATORS = [
                # --- VMware ---
                (b"VMwareVMware", "VMware", "CPUID brand string"),
                (b"vmware", "VMware", "Driver/service name"),
                (b"VMware Virtual", "VMware", "Hardware string"),
                (b"vmci.sys", "VMware", "VMCI driver"),
                (b"vmhgfs.sys", "VMware", "HGFS shared folders driver"),
                (b"vmmouse.sys", "VMware", "VM mouse driver"),
                (b"vmrawdsk.sys", "VMware", "Raw disk driver"),
                (b"vmusbmouse.sys", "VMware", "USB mouse driver"),
                (b"vmx86.sys", "VMware", "VMX driver"),
                (b"vmnet.sys", "VMware", "Network driver"),
                (b"VMTools", "VMware", "Guest tools service"),
                (b"vmtoolsd", "VMware", "Tools daemon"),
                (b"vmwaretray", "VMware", "System tray tool"),
                # --- VirtualBox ---
                (b"VBoxGuest", "VirtualBox", "Guest additions driver"),
                (b"VBoxMiniRdr", "VirtualBox", "Shared folders driver"),
                (b"VBoxSF", "VirtualBox", "Shared folders service"),
                (b"vboxservice", "VirtualBox", "Guest service"),
                (b"VBOX HARDDISK", "VirtualBox", "Disk identifier"),
                (b"VBoxMouse", "VirtualBox", "Mouse integration"),
                (b"VBoxVideo", "VirtualBox", "Video driver"),
                (b"VBoxTray", "VirtualBox", "Tray application"),
                (b"innotek GmbH", "VirtualBox", "BIOS vendor"),
                (b"VirtualBox", "VirtualBox", "Product name"),
                (b"vboxdrv", "VirtualBox", "Kernel driver"),
                # --- Hyper-V ---
                (b"Virtual HD", "Hyper-V", "Disk identifier"),
                (b"Microsoft Hv", "Hyper-V", "CPUID brand string"),
                (b"vmicheartbeat", "Hyper-V", "Heartbeat IC"),
                (b"vmicshutdown", "Hyper-V", "Shutdown IC"),
                (b"vmickvpexchange", "Hyper-V", "KVP exchange IC"),
                (b"vmbus", "Hyper-V", "VMBus driver"),
                (b"Hyper-V", "Hyper-V", "Product name"),
                (b"storvsc", "Hyper-V", "Storage VSC driver"),
                (b"netvsc", "Hyper-V", "Network VSC driver"),
                # --- QEMU/KVM ---
                (b"QEMU HARDDISK", "QEMU", "Disk identifier"),
                (b"QEMU DVD-ROM", "QEMU", "DVD identifier"),
                (b"KVMKVMKVM", "KVM", "CPUID brand string"),
                (b"BOCHS", "QEMU/Bochs", "BIOS vendor string"),
                (b"SeaBIOS", "QEMU", "BIOS firmware"),
                (b"virtio", "QEMU/KVM", "VirtIO driver string"),
                (b"qemu-ga", "QEMU", "Guest agent"),
                # --- Xen ---
                (b"Xen ", "Xen", "Hypervisor string"),
                (b"XenVMMXenVMM", "Xen", "CPUID brand string"),
                (b"xenbus", "Xen", "Xen bus driver"),
                # --- Parallels ---
                (b"prl_fs", "Parallels", "Shared folders driver"),
                (b"prl_tg", "Parallels", "Tools gate driver"),
                (b"Parallels", "Parallels", "Product name"),
                # --- Sandbox indicators ---
                (b"SbieDll", "Sandboxie", "Sandbox DLL"),
                (b"sbiedll", "Sandboxie", "Sandbox DLL"),
                (b"cuckoomon", "Cuckoo", "Cuckoo sandbox monitor"),
                (b"CWSandbox", "CWSandbox", "Sandbox indicator"),
                (b"JoeBox", "JoeSandbox", "Sandbox indicator"),
                # --- Analysis tool indicators ---
                (b"dbghelp", "Debugger", "Debug helper library"),
                (b"wireshark", "Wireshark", "Network analysis tool"),
                (b"procmon", "Procmon", "Process monitor"),
                (b"procexp", "Procexp", "Process explorer"),
                (b"ollydbg", "OllyDbg", "Debugger"),
                (b"x64dbg", "x64dbg", "Debugger"),
                (b"ImmunityDebugger", "Immunity", "Debugger"),
                (b"ida.exe", "IDA Pro", "Disassembler"),
                (b"Fiddler", "Fiddler", "HTTP proxy"),
                # --- Registry paths (VM-specific) ---
                (b"SOFTWARE\\VMware, Inc.\\VMware Tools", "VMware", "Registry: VMware Tools path"),
                (b"SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VirtualBox", "Registry: VBox GA path"),
                (b"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", "VirtualBox", "Registry: VBox service"),
                (b"SYSTEM\\CurrentControlSet\\Services\\VMTools", "VMware", "Registry: VMware service"),
                (b"HARDWARE\\ACPI\\DSDT\\VBOX__", "VirtualBox", "Registry: VBox ACPI table"),
                (b"HARDWARE\\ACPI\\FADT\\VBOX__", "VirtualBox", "Registry: VBox ACPI table"),
                (b"HARDWARE\\Description\\System\\SystemBiosVersion", "Generic", "Registry: BIOS version query"),
                # --- WMI query strings ---
                (b"Win32_ComputerSystem", "Generic", "WMI: computer system query"),
                (b"Win32_BIOS", "Generic", "WMI: BIOS info query"),
                (b"Win32_BaseBoard", "Generic", "WMI: baseboard info query"),
                (b"Win32_DiskDrive", "Generic", "WMI: disk drive query"),
                (b"Win32_NetworkAdapter", "Generic", "WMI: network adapter query"),
                (b"Win32_PhysicalMemory", "Generic", "WMI: physical memory query"),
                (b"MSAcpi_ThermalZoneTemperature", "Generic", "WMI: thermal zone (absent in VMs)"),
                # --- MAC OUI strings ---
                (b"00:0C:29", "VMware", "MAC OUI: VMware"),
                (b"00:50:56", "VMware", "MAC OUI: VMware"),
                (b"00-0C-29", "VMware", "MAC OUI: VMware (dash)"),
                (b"00-50-56", "VMware", "MAC OUI: VMware (dash)"),
                (b"08:00:27", "VirtualBox", "MAC OUI: VirtualBox"),
                (b"08-00-27", "VirtualBox", "MAC OUI: VirtualBox (dash)"),
                (b"00:15:5D", "Hyper-V", "MAC OUI: Hyper-V"),
                (b"00-15-5D", "Hyper-V", "MAC OUI: Hyper-V (dash)"),
                (b"52:54:00", "QEMU", "MAC OUI: QEMU"),
                (b"52-54-00", "QEMU", "MAC OUI: QEMU (dash)"),
            ]
            # Build a single case-insensitive regex from all indicator strings
            # and scan the binary in one pass — avoids creating a full lowercase
            # copy of file_data and running N individual `in` checks.
            _ind_lookup = {ind.lower(): (ind, target, detail) for ind, target, detail in _VM_INDICATORS}
            _vm_pattern = re.compile(
                b'(' + b'|'.join(re.escape(ind) for ind in _ind_lookup) + b')',
                re.IGNORECASE,
            )
            seen_indicators = set()
            for m in _vm_pattern.finditer(file_data):
                matched_lower = m.group().lower()
                if matched_lower in seen_indicators:
                    continue
                seen_indicators.add(matched_lower)
                indicator, target, detail = _ind_lookup[matched_lower]
                vm_strings_found.append({
                    "indicator": indicator.decode('ascii', 'replace'),
                    "target": target,
                    "detail": detail,
                })
                techniques.append({
                    "technique": f"VM_String_{target}",
                    "category": "vm_detection",
                    "severity": "medium",
                    "function": "string_scan",
                    "function_name": f"Contains '{indicator.decode('ascii', 'replace')}' ({detail})",
                })

        # Scan executable sections for anti-analysis instructions
        _ad_bridge.report_progress(90, 100)
        _ad_bridge.info("Scanning for anti-analysis instructions...")
        instruction_findings = []
        if state.pe_object:
            image_base = getattr(state.pe_object.OPTIONAL_HEADER, 'ImageBase', 0)
            _INSN_PATTERNS = [
                (b'\x0f\x31', "RDTSC", "timing_check", "medium",
                 "Read timestamp counter — timing-based anti-debug/VM detection"),
                (b'\x0f\xa2', "CPUID", "vm_detection", "high",
                 "CPUID — leaf 1 bit 31 = hypervisor, leaf 0x40000000 = vendor ID"),
                (b'\xcd\x2d', "INT 2Dh", "debugger_check", "high",
                 "Debug service interrupt — execution differs under debugger"),
                (b'\x0f\x01\x0d', "SIDT", "vm_detection", "low",
                 "Store IDT register — Red Pill VM detection (unreliable on modern CPUs)"),
            ]
            for section in state.pe_object.sections:
                try:
                    chars = getattr(section, 'Characteristics', 0) or 0
                    if not (chars & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
                        continue
                    data = section.get_data()
                    sec_rva = section.VirtualAddress
                    sec_name = section.Name.rstrip(b'\x00').decode('ascii', 'replace')

                    for pattern, name, category, severity, desc in _INSN_PATTERNS:
                        addrs = []
                        pos = 0
                        while pos <= len(data) - len(pattern):
                            pos = data.find(pattern, pos)
                            if pos == -1:
                                break
                            addrs.append(hex(image_base + sec_rva + pos))
                            pos += len(pattern)
                        if addrs:
                            instruction_findings.append({
                                "instruction": name,
                                "count": len(addrs),
                                "addresses": addrs[:10],
                                "section": sec_name,
                                "category": category,
                                "severity": severity,
                                "description": desc,
                            })
                except Exception as e:
                    logger.debug("Error scanning section for instructions: %s", e)
                    continue

        # Add instruction findings to techniques list
        for finding in instruction_findings:
            techniques.append({
                "technique": finding["instruction"],
                "category": finding["category"],
                "severity": finding["severity"],
                "function": finding["addresses"][0] if finding["addresses"] else "unknown",
                "function_name": f"{finding['instruction']} x{finding['count']} in {finding['section']}",
            })

        # Build hypervisor breakdown from VM findings
        hypervisor_breakdown = {}
        for vs in vm_strings_found:
            target = vs["target"]
            hypervisor_breakdown.setdefault(target, []).append(vs["indicator"])
        hypervisor_breakdown = {k: sorted(set(v)) for k, v in hypervisor_breakdown.items()}

        # Categorize findings
        categories = {}
        for t in techniques:
            cat = t["category"]
            categories.setdefault(cat, []).append(t["technique"])
        categories = {k: list(set(v)) for k, v in categories.items()}

        severity_counts = {"high": 0, "medium": 0, "low": 0}
        for t in techniques:
            severity_counts[t["severity"]] = severity_counts.get(t["severity"], 0) + 1

        if compact:
            # Rank functions by how many anti-debug techniques they use
            top_funcs = sorted(
                functions_with_antidbg,
                key=lambda f: len(f.get("techniques", [])),
                reverse=True,
            )[:5]
            top_funcs_compact = [
                {"addr": f["address"], "name": f["name"], "technique_count": len(f.get("techniques", []))}
                for f in top_funcs
            ]
            return {
                "total_techniques_found": len(techniques),
                "severity_summary": severity_counts,
                "categories": categories,
                "top_functions": top_funcs_compact,
                "has_tls_callbacks": bool(tls_callbacks),
                "has_vm_strings": bool(vm_strings_found),
                "hypervisor_breakdown": hypervisor_breakdown,
                "instruction_findings_count": len(instruction_findings),
                "note": "Use find_anti_debug_comprehensive(compact=False) for per-occurrence technique details.",
            }

        funcs_page, funcs_pag = _paginate_field(functions_with_antidbg, 0, limit)
        vm_page, vm_pag = _paginate_field(vm_strings_found, 0, limit)
        instr_page, instr_pag = _paginate_field(instruction_findings, 0, limit)
        tech_page, tech_pag = _paginate_field(techniques, 0, limit)
        return {
            "total_techniques_found": len(techniques),
            "severity_summary": severity_counts,
            "categories": categories,
            "hypervisor_breakdown": hypervisor_breakdown,
            "functions_with_anti_debug": funcs_page,
            "functions_with_anti_debug_pagination": funcs_pag,
            "tls_callbacks": tls_callbacks,
            "vm_indicator_strings": vm_page,
            "vm_indicator_strings_pagination": vm_pag,
            "instruction_findings": instr_page,
            "instruction_findings_pagination": instr_pag,
            "techniques": tech_page,
            "techniques_pagination": tech_pag,
        }

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_scan), timeout=ANGR_SHORT_TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError(f"find_anti_debug_comprehensive timed out after {ANGR_SHORT_TIMEOUT} seconds.")
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "find_anti_debug_comprehensive")


# =====================================================================
#  Control Flow Flattening Detection
# =====================================================================

def _analyze_function_for_cff(func_obj, cfg):
    """Analyse a single function for CFF obfuscation patterns.

    Returns a finding dict if CFF-like patterns are detected, else None.
    """
    try:
        graph = func_obj.graph
        if graph is None:
            return None

        blocks = list(graph.nodes())
        num_blocks = len(blocks)
        if num_blocks < CFF_MIN_BLOCKS:
            return None

        # Compute in-degree for all blocks
        in_degrees = {}
        for block in blocks:
            in_degrees[block] = graph.in_degree(block)

        # Find dispatcher candidate: block with highest in-degree
        dispatcher = max(blocks, key=lambda b: in_degrees.get(b, 0))
        dispatcher_in_degree = in_degrees.get(dispatcher, 0)

        if dispatcher_in_degree < CFF_DISPATCHER_IN_DEGREE_THRESHOLD:
            return None

        # Count blocks with edge back to dispatcher (back-edge ratio)
        back_edge_count = 0
        for block in blocks:
            if block == dispatcher:
                continue
            if graph.has_edge(block, dispatcher):
                back_edge_count += 1

        # Exclude dispatcher itself from ratio denominator
        other_blocks = num_blocks - 1
        back_edge_ratio = back_edge_count / other_blocks if other_blocks > 0 else 0.0

        # Check dispatcher VEX IR for comparison-based switch (state variable pattern)
        state_var_detected = False
        try:
            dispatcher_addr = dispatcher.addr if hasattr(dispatcher, 'addr') else dispatcher
            project, _ = state.get_angr_snapshot()
            if project:
                irsb = project.factory.block(dispatcher_addr).vex
                for stmt in irsb.statements:
                    if hasattr(stmt, 'tag') and stmt.tag == 'Ist_Exit':
                        # Has conditional exit — typical of dispatcher
                        state_var_detected = True
                        break
        except Exception:
            pass

        # Block size standard deviation among non-dispatcher blocks (uniformity signal)
        block_sizes = []
        for block in blocks:
            if block == dispatcher:
                continue
            try:
                baddr = block.addr if hasattr(block, 'addr') else block
                b = func_obj._project.factory.block(baddr) if hasattr(func_obj, '_project') else None
                if b:
                    block_sizes.append(b.size)
            except Exception:
                pass

        size_uniformity_score = 0
        if len(block_sizes) >= 3:
            mean_size = sum(block_sizes) / len(block_sizes)
            variance = sum((s - mean_size) ** 2 for s in block_sizes) / len(block_sizes)
            std_dev = variance ** 0.5
            # Low std_dev relative to mean = uniform sizes (CFF signal)
            if mean_size > 0:
                cv = std_dev / mean_size  # coefficient of variation
                if cv < 0.3:
                    size_uniformity_score = 20
                elif cv < 0.6:
                    size_uniformity_score = 10
                elif cv < 1.0:
                    size_uniformity_score = 5

        # Score: in_degree_anomaly(0-30) + back_edge_ratio(0-30) + state_var(0-20) + uniformity(0-20)
        # In-degree anomaly: how much dispatcher stands out
        avg_in_degree = sum(in_degrees.values()) / len(in_degrees) if in_degrees else 1
        in_degree_ratio = dispatcher_in_degree / avg_in_degree if avg_in_degree > 0 else 0
        in_degree_score = min(30, int(in_degree_ratio * 5))

        back_edge_score = min(30, int(back_edge_ratio * 50))

        state_var_score = 20 if state_var_detected else 0

        confidence = min(100, in_degree_score + back_edge_score + state_var_score + size_uniformity_score)

        addr_hex = hex(func_obj.addr)
        return {
            "function_address": addr_hex,
            "function_name": get_display_name(addr_hex, func_obj.name),
            "confidence": confidence,
            "dispatcher_address": hex(dispatcher.addr) if hasattr(dispatcher, 'addr') else "unknown",
            "dispatcher_in_degree": dispatcher_in_degree,
            "back_edge_ratio": round(back_edge_ratio, 3),
            "total_blocks": num_blocks,
            "state_variable_detected": state_var_detected,
        }
    except Exception as exc:
        logger.debug("CFF analysis failed for func %s: %s", hex(func_obj.addr), exc)
        return None


def _sync_detect_cff(target_addr, min_confidence, limit):
    """Synchronous CFF detection worker."""
    _ensure_project_and_cfg()
    _, cfg = state.get_angr_snapshot()
    if not cfg:
        return {"error": "No CFG available.", "findings": []}

    findings = []
    scanned = 0

    if target_addr is not None:
        # Scan single function
        if target_addr in cfg.functions:
            func_obj = cfg.functions[target_addr]
            result = _analyze_function_for_cff(func_obj, cfg)
            if result and result["confidence"] >= min_confidence:
                findings.append(result)
            scanned = 1
        else:
            return {"error": f"Function at {hex(target_addr)} not found in CFG.", "findings": []}
    else:
        # Scan all functions
        for _addr_int, func_obj in cfg.functions.items():
            if scanned >= MAX_CFF_SCAN_FUNCTIONS:
                break
            if getattr(func_obj, 'is_simprocedure', False) or getattr(func_obj, 'is_syscall', False):
                continue
            scanned += 1
            result = _analyze_function_for_cff(func_obj, cfg)
            if result and result["confidence"] >= min_confidence:
                findings.append(result)
                if len(findings) >= limit:
                    break

    # Sort by confidence descending
    findings.sort(key=lambda f: f["confidence"], reverse=True)

    return {
        "findings": findings[:limit],
        "total_findings": len(findings),
        "functions_scanned": scanned,
    }


@tool_decorator
async def detect_control_flow_flattening(
    ctx: Context,
    function_address: Optional[str] = None,
    min_confidence: int = 40,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: explore] Detect control flow flattening (CFF) obfuscation in functions.

    CFF transforms structured control flow into a dispatcher-driven switch loop.
    This tool detects the pattern by analysing dispatcher block in-degree,
    back-edge ratios, state variable comparisons, and block size uniformity.

    ---compact: detect control flow flattening obfuscation | confidence scoring | needs: angr+CFG

    Returns a confidence score (0-100) per function. Higher scores indicate
    stronger CFF signals.

    When to use: When triage or manual inspection suggests obfuscated control
    flow. Run on specific functions or scan all functions to identify CFF-protected
    code regions.

    Next steps: decompile_function_with_angr() on flagged functions,
    detect_opaque_predicates() for complementary obfuscation detection,
    get_function_cfg() to visualise the flattened control flow.

    Args:
        ctx: The MCP Context object.
        function_address: Analyse a specific function (hex address). Default: scan all.
        min_confidence: Minimum confidence threshold (0-100). Default 40.
        limit: Maximum findings to return (1-100000). Default 20.
    """
    _check_angr_ready("detect_control_flow_flattening")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    min_confidence = max(0, min(min_confidence, 100))

    target_addr = None
    if function_address:
        target_addr = _parse_addr(function_address, "function_address")

    await ctx.info("Scanning for control flow flattening patterns...")

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_sync_detect_cff, target_addr, min_confidence, limit),
            timeout=OBFUSCATION_DETECTION_TIMEOUT,
        )
    except asyncio.TimeoutError:
        raise RuntimeError(
            f"detect_control_flow_flattening timed out after {OBFUSCATION_DETECTION_TIMEOUT}s."
        )

    return await _check_mcp_response_size(ctx, result, "detect_control_flow_flattening")


# =====================================================================
#  Opaque Predicate Detection
# =====================================================================

def _analyze_block_for_opaque(project, block_addr, func_addr):
    """Check if a block contains an opaque predicate using Z3 constraint solving.

    Returns a finding dict if an opaque predicate is detected, else None.
    """
    try:
        block = project.factory.block(block_addr)
        irsb = block.vex

        # Find conditional exits
        for stmt in irsb.statements:
            if not (hasattr(stmt, 'tag') and stmt.tag == 'Ist_Exit'):
                continue

            # Create a blank state at block address
            blank_state = project.factory.blank_state(
                addr=block_addr,
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                },
            )

            # Get guard condition
            guard = stmt.guard
            if guard is None:
                continue

            try:
                if hasattr(guard, 'tmp'):
                    # Lift the block and get the guard expression
                    simgr = project.factory.simulation_manager(blank_state)
                    simgr.step(num_inst=block.instructions)
                    if simgr.active:
                        # The guard determines the taken branch
                        if hasattr(stmt, 'dst') and hasattr(stmt.dst, 'con'):
                            target = stmt.dst.con.value
                        else:
                            continue

                        # Check if fallthrough is satisfiable
                        # Both branches being satisfiable = normal predicate
                        # Only one branch satisfiable = opaque predicate
                        # This is a simplified check — we check if the block
                        # has two feasible successors
                        successors = project.factory.successors(blank_state)
                        flat_succs = successors.flat_successors
                        unsat_succs = successors.unsat_successors

                        if len(flat_succs) == 1 and len(unsat_succs) >= 1:
                            # One branch always taken
                            taken_addr = flat_succs[0].addr
                            dead_addr = unsat_succs[0].addr if unsat_succs else None
                            always_taken = (taken_addr == target)

                            return {
                                "block_address": hex(block_addr),
                                "instruction_address": hex(block_addr),
                                "always_taken": always_taken,
                                "dead_branch_target": hex(dead_addr) if dead_addr else "unknown",
                                "guard_expression": str(guard)[:200],
                            }
            except Exception:
                pass

            # Only check first conditional exit per block
            break

    except Exception as exc:
        logger.debug("Opaque predicate analysis failed for block %s: %s", hex(block_addr), exc)

    return None


def _sync_detect_opaque(target_addr, limit):
    """Synchronous opaque predicate detection worker."""
    _ensure_project_and_cfg()
    project, cfg = state.get_angr_snapshot()
    if not cfg or not project:
        return {"error": "No CFG/project available.", "findings": []}

    findings = []
    scanned_funcs = 0
    blocks_analyzed = 0
    solver_timeouts = 0
    funcs_to_scan = {}
    if target_addr is not None:
        if target_addr in cfg.functions:
            funcs_to_scan = {target_addr: cfg.functions[target_addr]}
        else:
            return {"error": f"Function at {hex(target_addr)} not found in CFG.", "findings": []}
    else:
        funcs_to_scan = dict(cfg.functions)

    for addr_int, func_obj in funcs_to_scan.items():
        if scanned_funcs >= MAX_OPAQUE_SCAN_FUNCTIONS:
            break
        if getattr(func_obj, 'is_simprocedure', False) or getattr(func_obj, 'is_syscall', False):
            continue
        if len(findings) >= limit:
            break

        scanned_funcs += 1
        graph = func_obj.graph
        if graph is None:
            continue

        for block in graph.nodes():
            if blocks_analyzed >= MAX_OPAQUE_PREDICATE_BLOCKS:
                break
            if len(findings) >= limit:
                break

            block_addr = block.addr if hasattr(block, 'addr') else block
            blocks_analyzed += 1

            result_holder = [None]

            def _check_block(_ba=block_addr, _ai=addr_int):
                result_holder[0] = _analyze_block_for_opaque(project, _ba, _ai)

            t = threading.Thread(target=_check_block, daemon=True)
            t.start()
            t.join(timeout=OPAQUE_PREDICATE_SOLVER_TIMEOUT)

            if t.is_alive():
                solver_timeouts += 1
                continue

            if result_holder[0] is not None:
                finding = result_holder[0]
                finding["function_address"] = hex(addr_int)
                finding["function_name"] = get_display_name(hex(addr_int), func_obj.name)
                findings.append(finding)

        if blocks_analyzed >= MAX_OPAQUE_PREDICATE_BLOCKS:
            break

    if solver_timeouts:
        logger.debug(
            "%d Z3 solver thread(s) timed out during opaque predicate detection; "
            "they will be reaped on process exit.",
            solver_timeouts,
        )

    return {
        "findings": findings[:limit],
        "total_findings": len(findings),
        "functions_scanned": scanned_funcs,
        "blocks_analyzed": blocks_analyzed,
        "solver_timeouts": solver_timeouts,
    }


@tool_decorator
async def detect_opaque_predicates(
    ctx: Context,
    function_address: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: explore] Detect opaque predicates — conditional branches where only
    one path is ever satisfiable, indicating dead code insertion by an obfuscator.

    ---compact: detect opaque predicates via Z3 constraint solving | dead code detection | needs: angr+CFG

    Uses angr's symbolic execution with Z3 constraint solving to check each
    conditional branch. When only one branch is feasible, it is flagged as an
    opaque predicate with the dead branch target identified.

    When to use: When you suspect code obfuscation (e.g. after
    detect_control_flow_flattening finds CFF patterns, or when decompiled
    code shows suspicious unreachable branches).

    Next steps: decompile_function_with_angr() to review the affected functions,
    get_function_cfg() to visualise the dead branches,
    propagate_constants() to simplify the control flow.

    Args:
        ctx: The MCP Context object.
        function_address: Analyse a specific function (hex address). Default: scan all.
        limit: Maximum findings to return (1-100000). Default 20.
    """
    _check_angr_ready("detect_opaque_predicates")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))

    target_addr = None
    if function_address:
        target_addr = _parse_addr(function_address, "function_address")

    await ctx.info("Scanning for opaque predicates via constraint solving...")

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_sync_detect_opaque, target_addr, limit),
            timeout=OBFUSCATION_DETECTION_TIMEOUT,
        )
    except asyncio.TimeoutError:
        raise RuntimeError(
            f"detect_opaque_predicates timed out after {OBFUSCATION_DETECTION_TIMEOUT}s."
        )

    return await _check_mcp_response_size(ctx, result, "detect_opaque_predicates")


# =====================================================================
#  VM Protection Detection
# =====================================================================

@tool_decorator
async def detect_vm_protection(
    ctx: Context,
) -> Dict[str, Any]:
    """Detect VM-based code obfuscation (VMProtect, Themida, Code Virtualizer).

    Phase: 3 — Map

    Identifies virtual machine-based code protection by analyzing section
    names, entropy patterns, dispatcher structures, and known protector
    signatures.

    ---compact: detect VMProtect/Themida/Code Virtualizer | section + entropy heuristics

    Does NOT attempt devirtualization — provides characterization
    for the analyst to decide on behavioral analysis vs. manual reversing.

    When to use: When triage or detect_packing() suggests heavy obfuscation,
    when section names or entropy patterns hint at VM protection, or when
    decompiled code shows handler-dispatch loops.

    Next steps: emulate_pe_with_windows_apis() for behavioral profiling,
    emulate_and_inspect() for post-emulation memory analysis,
    detect_control_flow_flattening() for complementary obfuscation detection.
    """
    _check_pe_loaded("detect_vm_protection")

    pe_data = state.pe_data or {}
    pe_obj = state.pe_object

    def _analyze():
        result = {
            "vm_protection_detected": False,
            "protector": None,
            "confidence": 0,
            "indicators": [],
            "virtualized_sections": [],
            "entry_point_info": {},
            "recommendation": "",
        }

        # ── 1. Section name analysis ────────────────────────────────
        _VM_SECTION_SIGS = {
            # VMProtect
            ".vmp0": ("VMProtect", 90),
            ".vmp1": ("VMProtect", 90),
            ".vmp2": ("VMProtect", 90),
            ".VMProtect": ("VMProtect", 95),
            # Themida / WinLicense
            ".themida": ("Themida/WinLicense", 95),
            ".winlice": ("WinLicense", 90),
            # Code Virtualizer
            ".cvirt": ("Code Virtualizer", 85),
            ".cv": ("Code Virtualizer", 70),
            # Enigma Protector
            ".enigma1": ("Enigma Protector", 90),
            ".enigma2": ("Enigma Protector", 90),
            # Obsidium
            ".obsidium": ("Obsidium", 90),
            # ASProtect
            ".aspack": ("ASProtect", 80),
            # Generic VM indicators
            ".vm": ("Unknown VM Protector", 50),
        }

        raw_sections = pe_data.get("sections")
        sections = raw_sections if isinstance(raw_sections, list) else []
        if not sections and pe_obj is not None and hasattr(pe_obj, 'sections'):
            sections = []
            for s in pe_obj.sections:
                try:
                    name = s.Name.decode("utf-8", errors="replace").rstrip("\x00").strip()
                    sections.append({
                        "name": name,
                        "entropy": s.get_entropy(),
                        "virtual_size": s.Misc_VirtualSize,
                        "raw_size": s.SizeOfRawData,
                        "characteristics": s.Characteristics,
                    })
                except Exception:
                    continue

        for sec in sections:
            sec_name = sec.get("name", "").strip()
            sec_lower = sec_name.lower()
            for pattern, (protector, conf) in _VM_SECTION_SIGS.items():
                if sec_lower == pattern.lower() or sec_lower.startswith(pattern.lower()):
                    result["indicators"].append({
                        "type": "section_name",
                        "value": sec_name,
                        "protector": protector,
                        "confidence": conf,
                    })
                    result["virtualized_sections"].append({
                        "name": sec_name,
                        "entropy": round(sec.get("entropy", 0), 2),
                        "virtual_size": sec.get("virtual_size", 0),
                        "raw_size": sec.get("raw_size", 0),
                    })
                    if conf > result["confidence"]:
                        result["confidence"] = conf
                        result["protector"] = protector

        # ── 2. High-entropy non-standard sections ───────────────────
        standard_names = {
            ".text", ".rdata", ".data", ".rsrc", ".reloc",
            ".pdata", ".idata", ".edata", ".bss", ".tls", ".CRT",
        }
        for sec in sections:
            sec_name = sec.get("name", "").strip()
            entropy = sec.get("entropy", 0)
            if sec_name not in standard_names and entropy > 7.0:
                rsize = sec.get("raw_size", 0)
                if rsize > 4096:  # Non-trivial section
                    result["indicators"].append({
                        "type": "high_entropy_section",
                        "value": f"{sec_name} (entropy: {entropy:.2f}, size: {rsize})",
                        "protector": result.get("protector") or "Unknown",
                        "confidence": 40,
                    })
                    if not result["protector"]:
                        result["confidence"] = max(result["confidence"], 40)

        # ── 3. Entry point analysis ─────────────────────────────────
        if pe_obj is not None:
            try:
                ep = pe_obj.OPTIONAL_HEADER.AddressOfEntryPoint
                ep_section = None
                for sec in pe_obj.sections:
                    sec_va = sec.VirtualAddress
                    sec_end = sec_va + sec.Misc_VirtualSize
                    if sec_va <= ep < sec_end:
                        ep_section = sec.Name.decode("utf-8", errors="replace").rstrip("\x00")
                        break

                result["entry_point_info"] = {
                    "address": hex(ep + pe_obj.OPTIONAL_HEADER.ImageBase),
                    "rva": hex(ep),
                    "section": ep_section or "unknown",
                }

                # Entry point in a VM section is a strong indicator
                if ep_section:
                    ep_lower = ep_section.strip().lower()
                    for pattern in _VM_SECTION_SIGS:
                        if ep_lower == pattern.lower() or ep_lower.startswith(pattern.lower()):
                            result["indicators"].append({
                                "type": "entry_in_vm_section",
                                "value": f"Entry point in {ep_section}",
                                "protector": _VM_SECTION_SIGS[pattern][0],
                                "confidence": 95,
                            })
                            result["confidence"] = max(result["confidence"], 95)
                            break
            except Exception:
                pass

        # ── 4. Import table analysis ────────────────────────────────
        imports_list = pe_data.get("imports") or []
        import_count = sum(len(d.get("symbols", [])) for d in imports_list if isinstance(d, dict))

        # Very few imports + VM section = strong VM protection signal
        if import_count < 10 and result["virtualized_sections"]:
            result["indicators"].append({
                "type": "minimal_imports",
                "value": f"Only {import_count} imports with VM sections present",
                "protector": result.get("protector") or "Unknown",
                "confidence": 70,
            })
            result["confidence"] = max(result["confidence"], 70)

        # ── 5. String-based signatures ──────────────────────────────
        if pe_obj is not None:
            try:
                raw_data = pe_obj.__data__
                # Scan first 2 MB only
                raw_str = raw_data[:min(len(raw_data), 2 * 1024 * 1024)]
                raw_text = raw_str.decode("latin-1", errors="replace")

                _STRING_SIGS = [
                    ("VMProtect begin", "VMProtect", 95),
                    ("VMProtect end", "VMProtect", 95),
                    ("VMProtect.Ultimate", "VMProtect", 98),
                    ("VMProtect.Mutation", "VMProtect", 90),
                    (".vmp.dll", "VMProtect", 85),
                    ("Themida", "Themida", 85),
                    ("WinLicense", "WinLicense", 85),
                    ("Code Virtualizer", "Code Virtualizer", 90),
                    ("Oreans Technologies", "Themida/Code Virtualizer", 90),
                    ("Enigma protector", "Enigma Protector", 90),
                    ("Obsidium", "Obsidium", 85),
                ]

                raw_lower = raw_text.lower()
                for sig_str, protector, conf in _STRING_SIGS:
                    if sig_str.lower() in raw_lower:
                        result["indicators"].append({
                            "type": "string_signature",
                            "value": sig_str,
                            "protector": protector,
                            "confidence": conf,
                        })
                        if conf > result["confidence"]:
                            result["confidence"] = conf
                            result["protector"] = protector
            except Exception:
                pass

        # ── 6. Dispatcher detection (if angr CFG available) ─────────
        # Optional enhancement — does not block if angr is unavailable
        proj = state.angr_project
        cfg = state.angr_cfg
        if proj is not None and cfg is not None:
            try:
                dispatch_candidates = []
                func_count = 0
                for func_addr, func in cfg.functions.items():
                    if func_count >= 500:
                        break
                    func_count += 1
                    if func.is_simprocedure or func.is_plt:
                        continue

                    try:
                        blocks = list(func.blocks)
                    except Exception:
                        continue
                    if len(blocks) <= 20:
                        continue

                    # Look for high in-degree blocks (dispatcher pattern)
                    try:
                        graph = func.graph
                        if graph is None:
                            continue
                        for node in graph.nodes():
                            in_degree = graph.in_degree(node)
                            if in_degree > 10:
                                dispatch_candidates.append({
                                    "function": hex(func_addr),
                                    "block": hex(node.addr),
                                    "in_degree": in_degree,
                                    "total_blocks": len(blocks),
                                })
                                break  # One per function
                    except Exception:
                        continue

                if dispatch_candidates:
                    dispatch_candidates.sort(key=lambda x: x["in_degree"], reverse=True)
                    result["dispatcher_candidates"] = dispatch_candidates[:10]
                    result["indicators"].append({
                        "type": "high_indegree_dispatcher",
                        "value": f"{len(dispatch_candidates)} functions with dispatcher-like patterns",
                        "protector": result.get("protector") or "Unknown VM",
                        "confidence": 60,
                    })
                    result["confidence"] = max(result["confidence"], 60)
            except Exception:
                pass

        # ── Final assessment ────────────────────────────────────────
        result["vm_protection_detected"] = result["confidence"] >= 50

        if result["vm_protection_detected"]:
            protector = result["protector"] or "Unknown"
            result["recommendation"] = (
                f"{protector} protection detected (confidence: {result['confidence']}%). "
                "Full devirtualization is not feasible via automated analysis. "
                "Recommended approach: (1) Use emulate_pe_with_windows_apis() for behavioral profiling, "
                "(2) Use emulate_and_inspect() for post-emulation memory analysis, "
                "(3) Focus on unprotected functions for static analysis."
            )
        else:
            result["recommendation"] = "No VM-based protection detected."

        result["indicator_count"] = len(result["indicators"])

        return result

    result = await asyncio.to_thread(_analyze)
    return await _check_mcp_response_size(ctx, result, "detect_vm_protection")
