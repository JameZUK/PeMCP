"""MCP tools for angr-based forensic and advanced binary analysis."""
import datetime
import uuid
import asyncio
import os
from typing import Dict, Any, Optional, List

from collections import deque

from pemcp.config import state, logger, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_angr_ready, _check_mcp_response_size
from pemcp.background import _update_progress, _run_background_task_wrapper
from pemcp.mcp._angr_helpers import _ensure_project_and_cfg, _parse_addr, _resolve_function_address, _raise_on_error_dict
from pemcp.utils import shannon_entropy

if ANGR_AVAILABLE:
    import angr
    import networkx as nx


# ---- BinDiff ---------------------------------------------------

@tool_decorator
async def diff_binaries(
    ctx: Context,
    file_path_b: str,
    limit: int = 50,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    Compares the currently loaded binary against another binary to find matching,
    differing, and unmatched functions. Useful for patch diffing and variant analysis.

    Args:
        file_path_b: Path to the second binary to compare against.
        limit: Max entries per category (identical, differing, unmatched).
        run_in_background: Run as background task (default True).
    """
    _check_angr_ready("diff_binaries")
    abs_path_b = os.path.abspath(file_path_b)
    state.check_path_allowed(abs_path_b)
    if not os.path.isfile(abs_path_b):
        return {"error": f"File not found: {file_path_b}"}

    def _diff(task_id_for_progress=None):
        _ensure_project_and_cfg()
        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Loading second binary...")

        try:
            proj_b = angr.Project(abs_path_b, auto_load_libs=False)
        except Exception as e:
            return {"error": f"Failed to load second binary: {e}"}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 20, "Building CFG for second binary...")

        try:
            cfg_b = proj_b.analyses.CFGFast(normalize=True)
        except Exception as e:
            return {"error": f"CFG generation failed for second binary: {e}"}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 50, "Running BinDiff analysis...")

        try:
            diff = state.angr_project.analyses.BinDiff(proj_b, cfg_a=state.angr_cfg, cfg_b=cfg_b)
        except Exception as e:
            return {"error": f"BinDiff failed: {e}"}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 90, "Formatting results...")

        identical = []
        differing = []
        unmatched_a = []
        unmatched_b = []

        try:
            for fa, fb in list(getattr(diff, 'identical_functions', []))[:limit]:
                identical.append({"a": hex(fa.addr), "b": hex(fb.addr), "name": fa.name})
        except Exception:
            pass
        try:
            for fa, fb in list(getattr(diff, 'differing_functions', []))[:limit]:
                differing.append({"a": hex(fa.addr), "b": hex(fb.addr), "name_a": fa.name, "name_b": fb.name})
        except Exception:
            pass
        try:
            for f in list(getattr(diff, 'unmatched_from_a', getattr(diff, 'unmatched_a', [])))[:limit]:
                unmatched_a.append({"address": hex(f.addr), "name": f.name})
        except Exception:
            pass
        try:
            for f in list(getattr(diff, 'unmatched_from_b', getattr(diff, 'unmatched_b', [])))[:limit]:
                unmatched_b.append({"address": hex(f.addr), "name": f.name})
        except Exception:
            pass

        return {
            "file_a": state.filepath,
            "file_b": file_path_b,
            "identical_count": len(identical),
            "differing_count": len(differing),
            "unmatched_a_count": len(unmatched_a),
            "unmatched_b_count": len(unmatched_b),
            "identical_functions": identical,
            "differing_functions": differing,
            "unmatched_in_a": unmatched_a,
            "unmatched_in_b": unmatched_b,
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing BinDiff...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "diff_binaries",
        })
        asyncio.create_task(_run_background_task_wrapper(task_id, _diff))
        return {"status": "queued", "task_id": task_id, "message": "BinDiff queued."}

    await ctx.info("Running BinDiff")
    result = await asyncio.to_thread(_diff)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "diff_binaries", "the 'limit' parameter")


# ---- Self-Modifying Code Detection ----------------------------

@tool_decorator
async def detect_self_modifying_code(
    ctx: Context,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Detects instructions or regions that write to executable memory, indicating
    self-modifying code (common in packers, crypters, and obfuscated malware).
    """
    await ctx.info("Scanning for self-modifying code")
    _check_angr_ready("detect_self_modifying_code")

    def _detect():
        _ensure_project_and_cfg()

        # Gather executable section ranges
        exec_ranges = []
        loader = state.angr_project.loader
        for obj in loader.all_objects:
            for seg in obj.segments:
                if seg.is_executable:
                    exec_ranges.append((seg.min_addr, seg.max_addr))

        def _addr_in_exec(addr_val):
            for lo, hi in exec_ranges:
                if lo <= addr_val <= hi:
                    return True
            return False

        findings = []

        # Scan all functions for memory writes to executable regions
        for addr, func in state.angr_cfg.functions.items():
            if func.is_simprocedure or func.is_syscall:
                continue
            for block in func.blocks:
                try:
                    vex = block.vex
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
                except Exception:
                    continue

            if len(findings) >= limit:
                break

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
        result = await asyncio.wait_for(asyncio.to_thread(_detect), timeout=300)
    except asyncio.TimeoutError:
        return {"error": "detect_self_modifying_code timed out after 300 seconds."}
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "detect_self_modifying_code", "the 'limit' parameter")


# ---- Code Cave Detection --------------------------------------

@tool_decorator
async def find_code_caves(
    ctx: Context,
    min_size: int = 16,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Finds unused/padding regions (code caves) within executable sections.
    Useful for detecting injected code or identifying safe patching locations.

    Args:
        min_size: Minimum cave size in bytes (default 16).
        limit: Max caves to return.
    """
    await ctx.info("Scanning for code caves")
    _check_angr_ready("find_code_caves")

    def _find_caves():
        _ensure_project_and_cfg()

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
                except Exception:
                    continue

                # Scan for runs of null bytes
                cave_start = None
                cave_len = 0
                for i, b in enumerate(data):
                    if b == 0x00 or b == 0xCC:  # null or INT3 padding
                        if cave_start is None:
                            cave_start = start + i
                            cave_len = 1
                        else:
                            cave_len += 1
                    else:
                        if cave_start is not None and cave_len >= min_size:
                            caves.append({
                                "address": hex(cave_start),
                                "size": cave_len,
                                "fill_byte": "0x00/0xCC",
                                "section": getattr(section, 'name', 'unknown'),
                            })
                        cave_start = None
                        cave_len = 0

                # Handle cave at end of section
                if cave_start is not None and cave_len >= min_size:
                    caves.append({
                        "address": hex(cave_start),
                        "size": cave_len,
                        "fill_byte": "0x00/0xCC",
                        "section": getattr(section, 'name', 'unknown'),
                    })

                if len(caves) >= limit:
                    break

        caves.sort(key=lambda c: c["size"], reverse=True)

        return {
            "total_caves": len(caves),
            "min_size_filter": min_size,
            "caves": caves[:limit],
        }

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_find_caves), timeout=300)
    except asyncio.TimeoutError:
        return {"error": "find_code_caves timed out after 300 seconds."}
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "find_code_caves", "the 'limit' parameter")


# ---- Packing Detection ----------------------------------------

@tool_decorator
async def detect_packing(ctx: Context) -> Dict[str, Any]:
    """
    Uses angr heuristics to detect if the binary is packed or obfuscated.
    Complements PEiD signatures with different detection methods (entropy, imports, sections).
    """
    await ctx.info("Detecting packing/obfuscation")
    _check_angr_ready("detect_packing")

    def _detect():
        _ensure_project_and_cfg()
        loader = state.angr_project.loader

        indicators = []
        score = 0

        # 1. Section entropy analysis
        for section in getattr(loader.main_object, 'sections', []):
            try:
                data = loader.memory.load(section.min_addr, section.memsize)
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
            except Exception:
                continue

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
        except Exception:
            pass

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
        except Exception:
            pass

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
        result = await asyncio.wait_for(asyncio.to_thread(_detect), timeout=300)
    except asyncio.TimeoutError:
        return {"error": "detect_packing timed out after 300 seconds."}
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "detect_packing")


# ---- Patch-to-Disk -------------------------------------------

@tool_decorator
async def save_patched_binary(
    ctx: Context,
    output_path: str,
) -> Dict[str, Any]:
    """
    Saves the current in-memory binary state (including any patches applied via
    patch_binary_memory) to a new file on disk.

    Args:
        output_path: File path to write the patched binary to.
    """
    await ctx.info(f"Saving patched binary to {output_path}")
    _check_angr_ready("save_patched_binary")

    # Validate output path against sandbox
    state.check_path_allowed(os.path.abspath(output_path))

    def _save():
        if state.angr_project is None:
            return {"error": "No angr project loaded. Open a file first."}

        proj = state.angr_project
        loader = proj.loader

        try:
            # Read the original binary
            with open(state.filepath, 'rb') as f:
                original_data = bytearray(f.read())

            # Apply all in-memory patches by comparing loader memory to original
            main_obj = loader.main_object
            base_addr = main_obj.min_addr
            patches_applied = 0

            for section in getattr(main_obj, 'sections', []):
                sec_offset = section.addr  # file offset or VA depending on loader
                sec_vaddr = section.min_addr
                sec_size = section.memsize

                try:
                    mem_data = loader.memory.load(sec_vaddr, sec_size)
                except Exception:
                    continue

                # Map VA to file offset
                file_offset = getattr(section, 'offset', None)
                if file_offset is None:
                    # Try to compute from section properties
                    try:
                        file_offset = sec_vaddr - main_obj.mapped_base + getattr(section, 'addr', 0)
                    except Exception:
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
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    Symbolic execution with configurable symbolic inputs — not limited to stdin.

    Args:
        target_address: Hex address to reach.
        avoid_address: Optional hex address to avoid.
        symbolic_registers: List of register names to make symbolic (e.g. ['eax', 'ebx']).
        symbolic_memory_ranges: List of 'addr:size' strings (e.g. ['0x404000:64']).
        concrete_memory: Dict of 'addr' -> 'hex_bytes' to pre-fill memory.
        max_steps: Max execution steps.
        run_in_background: Run as background task.
    """
    _check_angr_ready("find_path_with_custom_input")
    target = _parse_addr(target_address)
    avoid = _parse_addr(avoid_address, "avoid_address") if avoid_address else None

    def _solve(task_id_for_progress=None):
        _ensure_project_and_cfg()
        proj = state.angr_project

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Building initial state...")

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
                except Exception:
                    pass

        # Apply symbolic memory ranges
        if symbolic_memory_ranges:
            for spec in symbolic_memory_ranges:
                try:
                    parts = spec.split(":")
                    mem_addr = int(parts[0], 16)
                    mem_size = int(parts[1])
                    sym_mem = entry_state.solver.BVS(f"sym_mem_{hex(mem_addr)}", mem_size * 8)
                    entry_state.memory.store(mem_addr, sym_mem)
                except Exception:
                    continue

        # Apply concrete memory values
        if concrete_memory:
            for addr_hex, data_hex in concrete_memory.items():
                try:
                    mem_addr = int(addr_hex, 16)
                    data = bytes.fromhex(data_hex)
                    entry_state.memory.store(mem_addr, data)
                except Exception:
                    continue

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 15, "Starting symbolic exploration...")

        simgr = proj.factory.simulation_manager(entry_state)
        simgr.use_technique(angr.exploration_techniques.DFS())
        simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=max_steps))
        simgr.use_technique(angr.exploration_techniques.Explorer(find=target, avoid=avoid))

        steps = 0
        while len(simgr.active) > 0 and len(simgr.found) == 0 and steps < max_steps:
            if len(simgr.active) > 30:
                simgr.split(from_stash='active', to_stash='deferred', limit=30)
            simgr.step()
            steps += 1
            if task_id_for_progress and steps % 20 == 0:
                percent = min(95, int((steps / max_steps) * 100))
                _update_progress(task_id_for_progress, percent, f"Step {steps}, active: {len(simgr.active)}")

        if simgr.found:
            found_state = simgr.found[0]
            results = {"status": "success", "steps_taken": steps}

            # Dump stdin if available
            try:
                stdin_data = found_state.posix.dumps(0)
                if stdin_data:
                    results["stdin_hex"] = stdin_data.hex()
                    results["stdin_ascii"] = stdin_data.decode('utf-8', 'ignore')
            except Exception:
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
                        mem_addr = int(parts[0], 16)
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

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing custom solver...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "find_path_with_custom_input",
        })
        asyncio.create_task(_run_background_task_wrapper(task_id, _solve))
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
    Emulates a function with watchpoints (SimInspect breakpoints) that log
    memory reads/writes and register accesses at specific addresses.

    Args:
        function_address: Hex address of the function to emulate.
        watch_mem_writes: List of hex addresses to watch for memory writes.
        watch_mem_reads: List of hex addresses to watch for memory reads.
        watch_registers: List of register names to watch for writes.
        args_hex: Hex arguments to pass to the function.
        max_steps: Max emulation steps.
        run_in_background: Run as background task.
    """
    _check_angr_ready("emulate_with_watchpoints")
    target = _parse_addr(function_address)
    if args_hex is None:
        args_hex = []
    args = [int(a, 16) for a in args_hex]

    def _emulate(task_id_for_progress=None):
        _ensure_project_and_cfg()
        proj = state.angr_project

        events = []  # Collected watchpoint hits

        add_options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
        call_state = proj.factory.call_state(target, *args, add_options=add_options)

        # Install memory write watchpoints
        watch_write_addrs = set()
        if watch_mem_writes:
            for addr_hex in watch_mem_writes:
                watch_write_addrs.add(int(addr_hex, 16))

            def _on_mem_write(sim_state):
                try:
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
                except Exception:
                    pass

            call_state.inspect.b('mem_write', action=_on_mem_write)

        # Install memory read watchpoints
        watch_read_addrs = set()
        if watch_mem_reads:
            for addr_hex in watch_mem_reads:
                watch_read_addrs.add(int(addr_hex, 16))

            def _on_mem_read(sim_state):
                try:
                    read_addr = sim_state.solver.eval(sim_state.inspect.mem_read_address)
                    if not watch_read_addrs or read_addr in watch_read_addrs:
                        events.append({
                            "type": "mem_read",
                            "address": hex(read_addr),
                            "length": sim_state.inspect.mem_read_length,
                            "pc": hex(sim_state.addr),
                        })
                except Exception:
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
                except Exception:
                    pass

            def _on_reg_write(sim_state):
                try:
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
                except Exception:
                    pass

            call_state.inspect.b('reg_write', action=_on_reg_write)

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 10, "Emulating with watchpoints...")

        simgr = proj.factory.simulation_manager(call_state)
        steps_taken = 0
        chunk_size = 50
        while steps_taken < max_steps:
            if not simgr.active:
                break
            active_before = len(simgr.active)
            simgr.run(n=chunk_size)
            # Count actual steps: if all states died early, we took fewer than chunk_size
            steps_taken += chunk_size if simgr.active else min(chunk_size, max_steps - steps_taken)
            if task_id_for_progress:
                percent = min(95, int((steps_taken / max_steps) * 100))
                _update_progress(task_id_for_progress, percent, f"Step {steps_taken}, events: {len(events)}")

        status = "completed"
        if simgr.deadended:
            status = "function_returned"
        elif simgr.active:
            status = "max_steps_reached"
        elif simgr.errored:
            status = "errored"

        return {
            "status": status,
            "steps_taken": steps_taken,
            "total_events": len(events),
            "events": events[:500],  # cap to prevent huge responses
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing watchpoint emulation...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "emulate_with_watchpoints",
        })
        asyncio.create_task(_run_background_task_wrapper(task_id, _emulate))
        return {"status": "queued", "task_id": task_id, "message": "Watchpoint emulation queued."}

    await ctx.info(f"Emulating {function_address} with watchpoints")
    result = await asyncio.to_thread(_emulate)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "emulate_with_watchpoints")


# ---- Class Identification (C++) --------------------------------

@tool_decorator
async def identify_cpp_classes(
    ctx: Context,
    limit: int = 50,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    Identifies C++ class hierarchies by analysing vtables.
    Returns discovered classes with vtable addresses, virtual methods, and inheritance.

    Args:
        limit: Max classes to return.
        run_in_background: Run as background task.
    """
    _check_angr_ready("identify_cpp_classes")

    def _identify(task_id_for_progress=None):
        _ensure_project_and_cfg()

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 10, "Scanning for vtables...")

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
                    entry["methods"] = [hex(m) if isinstance(m, int) else str(m) for m in cls.methods[:20]]
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
            _update_progress(task_id_for_progress, 30, "Using heuristic vtable scanner...")

        loader = state.angr_project.loader
        vtables = []

        # Look for arrays of function pointers in data sections
        func_addrs = set(state.angr_cfg.functions.keys())
        for section in getattr(loader.main_object, 'sections', []):
            if getattr(section, 'is_executable', False):
                continue  # Skip code sections, vtables are in data

            try:
                data = loader.memory.load(section.min_addr, min(section.memsize, 65536))
            except Exception:
                continue

            ptr_size = state.angr_project.arch.bytes
            i = 0
            while i < len(data) - ptr_size * 2:
                # Read consecutive pointers
                consecutive_funcs = 0
                start_offset = i
                while i < len(data) - ptr_size:
                    if ptr_size == 4:
                        ptr_val = int.from_bytes(data[i:i+4], byteorder='little')
                    else:
                        ptr_val = int.from_bytes(data[i:i+8], byteorder='little')

                    if ptr_val in func_addrs:
                        consecutive_funcs += 1
                        i += ptr_size
                    else:
                        break

                if consecutive_funcs >= 2:  # At least 2 consecutive function pointers
                    vtable_addr = section.min_addr + start_offset
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
                        "method_count": consecutive_funcs,
                        "methods": methods[:20],
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
        state.set_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing class identification...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "identify_cpp_classes",
        })
        asyncio.create_task(_run_background_task_wrapper(task_id, _identify))
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
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Exports the full inter-procedural call graph (or a subgraph rooted at a function).

    Args:
        root_address: Optional; if set, return only the subgraph reachable from this function.
        max_depth: If >0 with root_address, limit traversal depth.
        limit: Max edges to return.
    """
    await ctx.info("Exporting call graph")
    _check_angr_ready("get_call_graph")
    root = _parse_addr(root_address, "root_address") if root_address else None

    def _extract():
        _ensure_project_and_cfg()
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
                # All descendants
                descendants = nx.descendants(callgraph, root)
                descendants.add(root)
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
        nodes = []
        for addr in list(callgraph.nodes())[:limit]:
            name = state.angr_cfg.functions[addr].name if addr in state.angr_cfg.functions else hex(addr)
            in_deg = callgraph.in_degree(addr)
            out_deg = callgraph.out_degree(addr)
            nodes.append({"address": hex(addr), "name": name, "callers": in_deg, "callees": out_deg})

        nodes.sort(key=lambda n: n["callees"], reverse=True)

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
        result = await asyncio.wait_for(asyncio.to_thread(_extract), timeout=300)
    except asyncio.TimeoutError:
        return {"error": "get_call_graph timed out after 300 seconds."}
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_call_graph", "the 'limit' parameter")
