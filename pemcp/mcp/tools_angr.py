"""MCP tools for angr-based binary analysis - decompilation, CFG, symbolic execution, etc."""
import datetime
import uuid
import asyncio
import sys

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_angr_ready, _check_mcp_response_size
from pemcp.background import _update_progress, _run_background_task_wrapper, _log_task_exception
from pemcp.mcp._angr_helpers import _ensure_project_and_cfg, _init_lock, _parse_addr, _resolve_function_address, _raise_on_error_dict

if ANGR_AVAILABLE:
    import angr
    import angr.analyses.decompiler
    import networkx as nx


@tool_decorator
async def list_angr_analyses(ctx: Context, category: str = "all") -> Dict[str, Any]:
    """
    Discovery tool: lists all available angr-based analysis capabilities with descriptions.
    Use this to understand what angr analyses are available before calling specific tools.

    Args:
        ctx: The MCP Context object.
        category: Filter by category - 'all', 'decompilation', 'cfg', 'symbolic',
                  'slicing', 'hooks', 'forensic', or 'comparison'.

    Returns:
        A dictionary of available analyses grouped by category.
    """
    analyses = {
        "decompilation": [
            {"tool": "decompile_function_with_angr", "params": "function_address",
             "description": "Decompile a function to C-like pseudocode."},
            {"tool": "get_annotated_disassembly", "params": "function_address, include_xrefs",
             "description": "Disassembly with variable names, xrefs, and comments."},
            {"tool": "disassemble_at_address", "params": "address, num_instructions",
             "description": "Raw disassembly at a specific address."},
        ],
        "cfg": [
            {"tool": "get_function_cfg", "params": "function_address",
             "description": "Control Flow Graph for a function (nodes/edges)."},
            {"tool": "get_call_graph", "params": "function_address, depth",
             "description": "Inter-procedural call graph from a function."},
            {"tool": "get_function_complexity_list", "params": "limit, sort_by",
             "description": "All functions sorted by cyclomatic complexity."},
            {"tool": "scan_for_indirect_jumps", "params": "limit",
             "description": "Find indirect jumps (jump tables, vtables)."},
        ],
        "data_flow": [
            {"tool": "get_forward_slice", "params": "function_address, variable_offset",
             "description": "Forward data-flow slice from a variable."},
            {"tool": "get_backward_slice", "params": "function_address, target_address",
             "description": "Backward slice to understand data origins."},
            {"tool": "get_reaching_definitions", "params": "function_address",
             "description": "Reaching definition analysis for a function."},
            {"tool": "get_data_dependencies", "params": "function_address",
             "description": "Data dependency analysis (def-use chains) for a function."},
            {"tool": "propagate_constants", "params": "function_address",
             "description": "Constant propagation analysis."},
            {"tool": "get_value_set_analysis", "params": "function_address",
             "description": "Value-set analysis for pointer tracking. Computationally expensive; "
                            "consider get_reaching_definitions or propagate_constants for lighter analysis."},
        ],
        "symbolic": [
            {"tool": "find_path_to_address", "params": "target_address, avoid_addresses, timeout",
             "description": "Symbolic execution to find input reaching a target address."},
            {"tool": "emulate_function_execution", "params": "function_address, args, timeout",
             "description": "Concolic execution of a function with concrete args."},
            {"tool": "find_path_with_custom_input", "params": "target_address, input_constraints",
             "description": "Path finding with custom symbolic constraints."},
            {"tool": "emulate_with_watchpoints", "params": "start_address, watchpoints, timeout",
             "description": "Emulation with memory/register watchpoints."},
        ],
        "structure": [
            {"tool": "get_function_xrefs", "params": "function_address",
             "description": "Cross-references (callers/callees) for a function."},
            {"tool": "get_dominators", "params": "function_address",
             "description": "Dominator tree for a function's CFG."},
            {"tool": "get_control_dependencies", "params": "function_address",
             "description": "Control dependency analysis."},
            {"tool": "analyze_binary_loops", "params": "function_address",
             "description": "Loop detection and analysis."},
            {"tool": "extract_function_constants", "params": "function_address",
             "description": "Extract constant values used in a function."},
            {"tool": "get_global_data_refs", "params": "limit",
             "description": "Global data references across the binary."},
            {"tool": "get_calling_conventions", "params": "limit",
             "description": "Detected calling conventions for functions."},
            {"tool": "get_function_variables", "params": "function_address",
             "description": "Stack/register variable analysis."},
            {"tool": "identify_library_functions", "params": "limit",
             "description": "Identify known library functions (FLIRT signatures)."},
            {"tool": "identify_cpp_classes", "params": "limit",
             "description": "Detect C++ class structures (vtables, RTTI)."},
        ],
        "forensic": [
            {"tool": "detect_self_modifying_code", "params": "limit",
             "description": "Detect self-modifying code patterns."},
            {"tool": "detect_packing", "params": "(none)",
             "description": "Detect packing/encryption via entropy and structure analysis."},
            {"tool": "find_code_caves", "params": "min_size, limit",
             "description": "Find unused code regions (potential injection sites)."},
            {"tool": "diff_binaries", "params": "other_file_path",
             "description": "Diff two binaries for function-level changes."},
        ],
        "hooks": [
            {"tool": "hook_function", "params": "address, return_value",
             "description": "Hook a function to control its return value."},
            {"tool": "unhook_function", "params": "address",
             "description": "Remove a previously installed hook."},
            {"tool": "list_hooks", "params": "(none)",
             "description": "List all currently installed hooks."},
        ],
        "modification": [
            {"tool": "patch_binary_memory", "params": "address, hex_bytes",
             "description": "Patch bytes at a specific address."},
            {"tool": "save_patched_binary", "params": "output_path",
             "description": "Save the patched binary to disk."},
            {"tool": "patch_with_assembly", "params": "address, assembly, architecture",
             "description": "Patch with assembled instructions (requires Keystone)."},
        ],
    }

    angr_available = ANGR_AVAILABLE
    angr_ready = state.angr_project is not None

    if category != "all" and category in analyses:
        filtered = {category: analyses[category]}
    else:
        filtered = analyses

    total_tools = sum(len(v) for v in filtered.values())

    return {
        "angr_available": angr_available,
        "angr_project_loaded": angr_ready,
        "cfg_available": state.angr_cfg is not None,
        "total_analyses": total_tools,
        "categories": filtered,
        "note": "Call any tool by name with the listed parameters. "
                "Most tools require angr to be available and a file to be loaded.",
    }


@tool_decorator
async def decompile_function_with_angr(ctx: Context, function_address: str) -> Dict[str, Any]:
    """
    Decompiles a function into C-like pseudocode using Angr.
    Automatically attempts to handle RVA (offsets) if the exact VA is not found.

    After reviewing the decompiled output, call auto_note_function(address) to
    save a one-line behavioral summary, or add_note(content, category='tool_result')
    to record specific findings. This builds the analysis digest without keeping
    full pseudocode in context.
    """

    await ctx.info(f"Requesting Angr decompilation for: {function_address}")
    _check_angr_ready("decompile_function_with_angr")
    target_addr = _parse_addr(function_address)

    def _decompile():

        _ensure_project_and_cfg()

        try:
            func, addr_to_use = _resolve_function_address(target_addr)
        except KeyError:
            return {
                "error": f"No function found at {hex(target_addr)} (or adjusted VA).",
                "hint": "Verify the address. If using an offset, ensure it matches the ImageBase."
            }

        try:
            dec = state.angr_project.analyses.Decompiler(func, cfg=state.angr_cfg.model)
            if not dec.codegen: return {"error": "Decompilation produced no code."}
            return {
                "function_name": func.name,
                "address": hex(addr_to_use),
                "c_pseudocode": dec.codegen.text,
                "next_step": "Call auto_note_function(address) to save a behavioral summary of this function.",
            }
        except Exception as e: return {"error": f"Decompilation failed: {e}"}

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_decompile), timeout=300)
    except asyncio.TimeoutError:
        raise RuntimeError("Decompilation timed out after 300 seconds.")
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "decompile_function_with_angr")

@tool_decorator
async def get_function_cfg(ctx: Context, function_address: str) -> Dict[str, Any]:
    """
    Retrieves the Control Flow Graph (CFG) for a function (Nodes/Blocks and Edges/Jumps).
    Automatically attempts to handle RVA (offsets) if the exact VA is not found.
    """

    await ctx.info(f"Requesting CFG for: {function_address}")
    _check_angr_ready("get_function_cfg")
    target_addr = _parse_addr(function_address)

    def _extract_graph():

        _ensure_project_and_cfg()

        try:
            func, addr_to_use = _resolve_function_address(target_addr)
        except KeyError:
            return {"error": f"No function found at {hex(target_addr)}."}

        nodes_data = [{"addr": hex(b.addr), "size": b.size} for b in func.blocks]
        edges_data = [{"src": hex(s.addr), "dst": hex(d.addr)} for s, d in func.graph.edges]
        return {"function_name": func.name, "address": hex(addr_to_use), "nodes": nodes_data, "edges": edges_data}

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_extract_graph), timeout=300)
    except asyncio.TimeoutError:
        raise RuntimeError("CFG extraction timed out after 300 seconds.")
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_function_cfg")

@tool_decorator
async def find_path_to_address(
    ctx: Context,
    target_address: str,
    avoid_address: Optional[str] = None,
    enable_veritesting: bool = True,
    use_dfs: bool = True,
    run_in_background: bool = True
) -> Dict[str, Any]:
    """
    Uses Symbolic Execution to find an input (stdin) that causes execution to reach 'target_address'.
    """

    _check_angr_ready("find_path_to_address")
    target = _parse_addr(target_address, "target_address")
    avoid = _parse_addr(avoid_address, "avoid_address") if avoid_address else None

    # --- IMPROVEMENT: Fail Fast Validation ---
    # Check if the address is actually mapped in the binary
    if state.angr_project is not None:
        try:
            # Attempt to check if address is mapped
            obj = state.angr_project.loader.find_object_containing(target)
            if not obj:
                # Also check if it's in dynamically mapped memory (less likely for static start)
                # But primarily, if it's not in the loader, it's usually a bad request.
                valid_min = state.angr_project.loader.min_addr
                valid_max = state.angr_project.loader.max_addr
                return {
                    "error": f"Target address {hex(target)} is unmapped.",
                    "message": f"The address {hex(target)} does not exist in the loaded binary memory.",
                    "valid_memory_range": f"{hex(valid_min)} - {hex(valid_max)}",
                    "tip": "Check 'sections' or 'function_complexity' to find valid addresses."
                }
        except Exception as e:
            logger.debug("Address validation check failed (proceeding anyway): %s", e)
    # -----------------------------------------

    # --- Internal Logic ---
    def _solve_path(task_id_for_progress=None):

        _ensure_project_and_cfg()

        stability_options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
        }
        entry_st = state.angr_project.factory.entry_state(add_options=stability_options)
        simgr = state.angr_project.factory.simulation_manager(entry_st)

        techniques_applied = []
        if enable_veritesting:
            try:
                simgr.use_technique(angr.exploration_techniques.Veritesting())
                techniques_applied.append("Veritesting")
            except Exception:
                logger.warning("Failed to enable Veritesting technique", exc_info=True)

        if use_dfs:
            simgr.use_technique(angr.exploration_techniques.DFS())
            techniques_applied.append("DFS")

        simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=5000))

        # Build avoid set: always include 0x0 (null-pointer jumps from
        # unresolved imports when auto_load_libs=False) to prevent
        # "No bytes in memory for block starting at 0x0" errors.
        avoid_set = set()
        if avoid is not None:
            avoid_set.add(avoid)
        avoid_set.add(0x0)
        simgr.use_technique(angr.exploration_techniques.Explorer(
            find=target, avoid=list(avoid_set),
        ))

        try:
            max_steps = 2000
            steps = 0

            if task_id_for_progress:
                _update_progress(task_id_for_progress, 0, f"Starting Solver... Techniques: {', '.join(techniques_applied)}")

            while len(simgr.active) > 0 and len(simgr.found) == 0 and steps < max_steps:
                # Pruning logic to keep memory low
                if len(simgr.active) > 30:
                    simgr.split(from_stash='active', to_stash='deferred', limit=30)

                simgr.step()
                steps += 1

                if task_id_for_progress and steps % 10 == 0:
                    active = len(simgr.active)
                    deferred = len(simgr.stashed) + len(getattr(simgr, 'deferred', []))
                    percent = min(95, int((steps / max_steps) * 100))
                    msg = f"Solving... Active: {active}, Deferred: {deferred} (Step {steps})"
                    _update_progress(task_id_for_progress, percent, msg)

            if len(simgr.found) > 0:
                solution = simgr.found[0].posix.dumps(0)
                return {
                    "status": "success",
                    "input_hex": solution.hex(),
                    "input_ascii": solution.decode('utf-8', 'ignore'),
                    "steps_taken": steps
                }

            return {
                "status": "failure",
                "message": f"No path found after {steps} steps.",
                "hint": "Try increasing max_steps, checking if the address is actually reachable, or disable 'use_dfs'."
            }

        except Exception as e:
            return {"status": "error", "error_message": str(e)}

    # --- Background Handling ---
    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing solver...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "find_path_to_address"
        })
        task = asyncio.create_task(_run_background_task_wrapper(task_id, _solve_path))
        task.add_done_callback(_log_task_exception(task_id))
        return {
            "status": "queued",
            "task_id": task_id,
            "message": f"Solver queued (Veritesting={enable_veritesting}, DFS={use_dfs})."
        }

    await ctx.info(f"Solving path to {target_address}")
    result = await asyncio.to_thread(_solve_path)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "find_path_to_address")

@tool_decorator
async def emulate_function_execution(
    ctx: Context,
    function_address: str,
    args_hex: Optional[List[str]] = None,
    max_steps: int = 1000,
    high_precision_mode: bool = False,
    run_in_background: bool = True
) -> Dict[str, Any]:
    """
    Emulates a function with specific concrete arguments.
    """

    if args_hex is None:
        args_hex = []
    _check_angr_ready("emulate_function_execution")
    target = _parse_addr(function_address)
    try:
        args = [int(a, 16) for a in args_hex]
    except ValueError: raise ValueError("Invalid format for arguments.")

    def _core_emulation(task_id_for_progress=None):

        _ensure_project_and_cfg()

        try:
            add_options = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
            if 'unicorn' in sys.modules: add_options.add(angr.options.UNICORN)
            remove_options = set()
            if not high_precision_mode:
                add_options.update({angr.options.FAST_MEMORY, angr.options.FAST_REGISTERS})
                remove_options.update({angr.options.UNICORN_TRACK_BBL_ADDRS, angr.options.UNICORN_TRACK_STACK_POINTERS})

            call_st = state.angr_project.factory.call_state(target, *args, add_options=add_options, remove_options=remove_options)
            simgr = state.angr_project.factory.simulation_manager(call_st)

            chunk_size = 50
            steps_taken = 0

            while steps_taken < max_steps:
                if not simgr.active: break
                simgr.run(n=chunk_size)
                steps_taken += chunk_size

                if task_id_for_progress:
                    percent = min(99, int((steps_taken / max_steps) * 100))
                    msg = f"Emulating... Step {steps_taken}/{max_steps}"
                    _update_progress(task_id_for_progress, percent, msg)

            if len(simgr.deadended) > 0:
                final = simgr.deadended[0]
                try:
                    # Use the architecture-appropriate return register
                    ret_reg = state.angr_project.arch.register_names.get(
                        state.angr_project.arch.ret_offset, "eax"
                    )
                    ret_val = hex(final.solver.eval(getattr(final.regs, ret_reg)))
                except Exception:
                    ret_val = "unknown"
                return {
                    "status": "success",
                    "return_value": ret_val,
                    "stdout": final.posix.dumps(1).decode('utf-8', 'ignore'),
                    "steps_taken_count": len(final.history.bbl_addrs)
                }
            elif len(simgr.active) > 0:
                # --- IMPROVEMENT: Explicit Hinting ---
                current_state = simgr.active[0]
                partial_stdout = current_state.posix.dumps(1).decode('utf-8', 'ignore')
                return {
                    "status": "incomplete",
                    "message": f"Execution exceeded {max_steps} steps. Function did not return yet.",
                    "hint": f"The function is complex. Rerun with 'max_steps' set to {max_steps * 2} or higher.",
                    "partial_stdout": partial_stdout,
                    "current_instruction": hex(current_state.addr)
                }
            elif len(simgr.errored) > 0:
                return {"status": "error", "message": str(simgr.errored[0].error)}
            else:
                return {"status": "uncertain", "message": "Simulation finished but no active or deadended states."}

        except Exception as e:
            return {"status": "crash", "error": str(e)}

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing emulation...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "emulate_function_execution"
        })
        task = asyncio.create_task(_run_background_task_wrapper(task_id, _core_emulation))
        task.add_done_callback(_log_task_exception(task_id))
        return {"status": "queued", "task_id": task_id, "message": "Emulation queued."}

    await ctx.info(f"Emulating {function_address} (Limit: {max_steps})")
    result = await asyncio.to_thread(_core_emulation)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "emulate_function_execution")

@tool_decorator
async def analyze_binary_loops(
    ctx: Context,
    min_loop_size: int = 0,
    limit: int = 50,
    resolve_indirect_jumps: bool = False,
    scan_data_refs: bool = False,
    run_in_background: bool = True
) -> Dict[str, Any]:
    """
    Scans the binary for loops. Uses existing analysis if available to save time.
    """

    _check_angr_ready("analyze_binary_loops")

    def _core_logic(task_id_for_progress=None):
        # Configuration requested by the user
        req_config = {"resolve_jumps": resolve_indirect_jumps, "data_refs": scan_data_refs}

        # Use _init_lock to prevent concurrent callers from duplicating
        # expensive project/CFG/loop builds (same lock as _ensure_project_and_cfg)
        with _init_lock:
            project, cfg = state.get_angr_snapshot()

            # Determine if we need to rebuild the CFG
            need_rebuild = False

            if project is None:
                project = angr.Project(state.filepath, auto_load_libs=False)
                state.set_angr_results(project, None, state.angr_loop_cache, state.angr_loop_cache_config)
                need_rebuild = True
            elif cfg is None:
                need_rebuild = True
            else:
                current_has_data = (state.angr_loop_cache_config or {}).get('data_refs', False)
                if scan_data_refs and not current_has_data:
                    need_rebuild = True

            if need_rebuild:
                if task_id_for_progress: _update_progress(task_id_for_progress, 10, "Building/Upgrading Control Flow Graph...")

                new_cfg = project.analyses.CFGFast(
                    normalize=True,
                    resolve_indirect_jumps=resolve_indirect_jumps,
                    data_references=scan_data_refs,
                    force_complete_scan=scan_data_refs
                )
                state.set_angr_results(project, new_cfg, None, state.angr_loop_cache_config)
                cfg = new_cfg

            # Ensure loop cache exists
            if state.angr_loop_cache is None:
                if task_id_for_progress: _update_progress(task_id_for_progress, 80, "Analyzing graph for loops...")

                loop_finder = project.analyses.LoopFinder(kb=project.kb)
                raw_loops = {}

                for loop in loop_finder.loops:
                    try:
                        node = cfg.model.get_any_node(loop.entry.addr)
                        if node and node.function_address:
                            func_addr = node.function_address
                            if func_addr not in raw_loops: raw_loops[func_addr] = []

                            block_count = len(list(loop.body_nodes))
                            raw_loops[func_addr].append({
                                "entry": hex(loop.entry.addr),
                                "blocks": block_count,
                                "subloops": bool(loop.subloops)
                            })
                    except Exception: continue

                state.set_angr_results(project, cfg, raw_loops, req_config)
            else:
                if task_id_for_progress: _update_progress(task_id_for_progress, 90, "Using cached analysis data...")

        # Filtering Results
        if task_id_for_progress: _update_progress(task_id_for_progress, 95, "Formatting results...")
        results = []
        current_cfg_ref = cfg

        for func_addr, loops in state.angr_loop_cache.items():
            valid_loops = [l for l in loops if l['blocks'] >= min_loop_size]
            if valid_loops:
                func_name = "Unknown"
                if current_cfg_ref and func_addr in current_cfg_ref.functions:
                     func_name = current_cfg_ref.functions[func_addr].name
                results.append({
                    "function_name": func_name,
                    "address": hex(func_addr),
                    "loop_count": len(valid_loops),
                    "loops": valid_loops
                })

        results.sort(key=lambda x: x['loop_count'], reverse=True)
        limited_results = results[:limit]

        return {
            "config_used": state.angr_loop_cache_config,
            "rebuild_triggered": need_rebuild,
            "total_functions_with_loops": len(results),
            "returned_count": len(limited_results),
            "functions_with_loops": limited_results
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Starting loop analysis...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "analyze_binary_loops"
        })
        task = asyncio.create_task(_run_background_task_wrapper(task_id, _core_logic))
        task.add_done_callback(_log_task_exception(task_id))
        return {"status": "queued", "task_id": task_id, "message": "Loop analysis queued."}

    result = await asyncio.to_thread(_core_logic)
    _raise_on_error_dict(result)
    limit_info = "the 'limit' parameter or increasing 'min_loop_size'"
    return await _check_mcp_response_size(ctx, result, "analyze_binary_loops", limit_info)

@tool_decorator
async def get_function_xrefs(
    ctx: Context,
    function_address: str,
    limit: int = 100
) -> Dict[str, Any]:
    """
    Retrieves Cross-References (Callers/Callees) for a function.
    """

    await ctx.info(f"Requesting X-Refs for: {function_address} (Limit: {limit})")
    _check_angr_ready("get_function_xrefs")
    target_addr = _parse_addr(function_address)

    def _get_xrefs():

        _ensure_project_and_cfg()
        try:
            func = state.angr_cfg.functions[target_addr]
        except KeyError:
            return {"error": f"No function found at {hex(target_addr)}."}

        callers = []
        if target_addr in state.angr_cfg.functions.callgraph:
             for pred in state.angr_cfg.functions.callgraph.predecessors(target_addr):
                 try: callers.append({"name": state.angr_cfg.functions[pred].name, "address": hex(pred)})
                 except Exception: callers.append({"name": "Unknown", "address": hex(pred)})

        callees = []
        if target_addr in state.angr_cfg.functions.callgraph:
            for succ in state.angr_cfg.functions.callgraph.successors(target_addr):
                try: callees.append({"name": state.angr_cfg.functions[succ].name, "address": hex(succ)})
                except Exception: callees.append({"name": "External", "address": hex(succ)})

        return {
            "function_name": func.name,
            "address": hex(target_addr),
            "total_callers": len(callers),
            "callers": callers[:limit],
            "total_callees": len(callees),
            "callees": callees[:limit]
        }

    result = await asyncio.to_thread(_get_xrefs)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_function_xrefs", "the 'limit' parameter")

@tool_decorator
async def get_backward_slice(
    ctx: Context,
    target_address: str,
    limit: int = 200
) -> Dict[str, Any]:
    """
    Finds all code (Basic Blocks) that can reach the target address (Control Flow Ancestors).
    """

    await ctx.info(f"Calculating backward reachability for: {target_address} (Limit: {limit})")
    _check_angr_ready("get_backward_slice")
    target_addr = _parse_addr(target_address)

    def _slice():
        _ensure_project_and_cfg()

        try:
            # Get the node. If exact match fails, try to find the block containing this addr
            target_node = state.angr_cfg.model.get_any_node(target_addr)
            if not target_node:
                block = state.angr_project.factory.block(target_addr)
                target_node = state.angr_cfg.model.get_any_node(block.addr)

            if not target_node: return {"error": f"Address {hex(target_addr)} not found in CFG."}

            # Use NetworkX to find ancestors
            ancestors = nx.ancestors(state.angr_cfg.graph, target_node)

            slice_nodes = []
            for n in ancestors:
                func_name = "Unknown"
                if n.function_address and n.function_address in state.angr_cfg.functions:
                    func_name = state.angr_cfg.functions[n.function_address].name
                slice_nodes.append({"address": hex(n.addr), "function": func_name})

            # Sort by address for readability
            sorted_nodes = sorted(slice_nodes, key=lambda x: int(x['address'], 16))

            return {
                "target": hex(target_addr),
                "total_nodes_found": len(sorted_nodes),
                "returned_count": min(len(sorted_nodes), limit),
                "slice_nodes": sorted_nodes[:limit]
            }
        except Exception as e: return {"error": f"Backward reachability failed: {e}"}

    result = await asyncio.to_thread(_slice)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_backward_slice", "the 'limit' parameter")

@tool_decorator
async def get_forward_slice(
    ctx: Context,
    source_address: str,
    limit: int = 200
) -> Dict[str, Any]:
    """
    Finds all code (Basic Blocks) reachable FROM the source address (Control Flow Descendants).
    """

    await ctx.info(f"Calculating forward reachability from: {source_address} (Limit: {limit})")
    _check_angr_ready("get_forward_slice")
    source_addr = _parse_addr(source_address)

    def _slice():
        _ensure_project_and_cfg()

        try:
            source_node = state.angr_cfg.model.get_any_node(source_addr)
            if not source_node:
                block = state.angr_project.factory.block(source_addr)
                source_node = state.angr_cfg.model.get_any_node(block.addr)

            if not source_node: return {"error": f"Address {hex(source_addr)} not found in CFG."}

            # Use NetworkX to find descendants
            descendants = nx.descendants(state.angr_cfg.graph, source_node)

            slice_nodes = []
            for n in descendants:
                func_name = "Unknown"
                if n.function_address and n.function_address in state.angr_cfg.functions:
                    func_name = state.angr_cfg.functions[n.function_address].name
                slice_nodes.append({"address": hex(n.addr), "function": func_name})

            sorted_nodes = sorted(slice_nodes, key=lambda x: int(x['address'], 16))

            return {
                "source": hex(source_addr),
                "total_nodes_found": len(sorted_nodes),
                "returned_count": min(len(sorted_nodes), limit),
                "impacted_nodes": sorted_nodes[:limit]
            }
        except Exception as e: return {"error": f"Forward reachability failed: {e}"}

    result = await asyncio.to_thread(_slice)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_forward_slice", "the 'limit' parameter")

@tool_decorator
async def get_dominators(ctx: Context, target_address: str) -> Dict[str, Any]:
    """
    Finds 'Dominator' blocks for a specific target (blocks that MUST execute to reach the target).
    """

    await ctx.info(f"Calculating dominators for: {target_address}")
    _check_angr_ready("get_dominators")
    target_addr = _parse_addr(target_address)

    def _find_dominators():
        _ensure_project_and_cfg()

        try:
            target_node = state.angr_cfg.model.get_any_node(target_addr)
            if not target_node:
                # Fallback to block start
                block = state.angr_project.factory.block(target_addr)
                target_node = state.angr_cfg.model.get_any_node(block.addr)

            if not target_node: return {"error": "Node not found in CFG."}

            # Dominators are calculated PER FUNCTION in Angr's CFG
            if not target_node.function_address:
                return {"error": "Target node does not belong to a known function, cannot calculate dominators."}

            func = state.angr_cfg.functions.get(target_node.function_address)
            if not func: return {"error": "Function object not found."}

            # Identify the entry node of the function graph
            # func.graph is a NetworkX DiGraph
            entry_node = None
            for node in func.graph.nodes():
                if node.addr == func.addr:
                    entry_node = node
                    break

            if not entry_node: return {"error": "Could not identify function entry node."}

            # Calculate immediate dominators using NetworkX directly
            # This returns a dict: {node: immediate_dominator}
            dom_dict = nx.immediate_dominators(func.graph, entry_node)

            # Trace back the dominator chain for our target
            dominators_list = []
            curr = target_node

            # Safety break to prevent infinite loops in malformed graphs
            iterations = 0
            while curr in dom_dict and iterations < 1000:
                dom = dom_dict[curr]
                # If a node dominates itself (start node), stop
                if dom == curr:
                    dominators_list.append({"address": hex(dom.addr), "size": dom.size, "type": "Function Entry"})
                    break

                dominators_list.append({"address": hex(dom.addr), "size": dom.size})
                curr = dom
                iterations += 1

            return {"target": hex(target_addr), "function": func.name, "dominators": dominators_list}

        except Exception as e: return {"error": f"Dominator analysis failed: {e}"}

    result = await asyncio.to_thread(_find_dominators)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_dominators")

@tool_decorator
async def get_function_complexity_list(
    ctx: Context,
    limit: int = 20,
    sort_by: str = "blocks",  # "blocks" or "edges"
    compact: bool = False,
) -> Dict[str, Any]:
    """
    Lists functions ranked by complexity (block count or edge count).
    Useful for identifying main logic or obfuscated routines.

    Args:
        limit: Max number of functions to return.
        sort_by: Criterion to sort by: 'blocks' (default) or 'edges'.
        compact: (bool) If True, return minimal fields (addr, name, blocks) only.
            Reduces per-function output size significantly. Default False.
    """

    await ctx.info(f"Requesting function complexity list. Limit: {limit}, Sort: {sort_by}")

    _check_angr_ready("get_function_complexity_list")

    def _analyze():

        _ensure_project_and_cfg()

        funcs_data = []
        for addr, func in state.angr_cfg.functions.items():
            # Filter out library/simprocedures or empty placeholders
            if func.is_simprocedure or func.is_syscall: continue

            # --- FIX: Convert generator to list before len() ---
            try:
                # func.blocks is often a generator in newer angr versions
                block_count = len(list(func.blocks))
            except Exception:
                # Fallback if access fails
                block_count = 0

            if compact:
                funcs_data.append({
                    "name": func.name,
                    "addr": hex(func.addr),
                    "blocks": block_count,
                })
            else:
                # func.graph.edges usually returns a View, list() ensures it's countable
                edge_count = len(list(func.graph.edges))

                funcs_data.append({
                    "name": func.name,
                    "address": hex(func.addr),
                    "blocks": block_count,
                    "edges": edge_count,
                    "is_entry_point": (func.addr == state.angr_project.entry)
                })

        # Sort
        key = "blocks"
        if not compact and sort_by == "edges":
            key = "edges"
        funcs_data.sort(key=lambda x: x.get(key, 0), reverse=True)

        return {
            "total_functions_scanned": len(funcs_data),
            "sort_metric": key,
            "top_functions": funcs_data[:limit]
        }

    result = await asyncio.to_thread(_analyze)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_function_complexity_list", "the 'limit' parameter")

@tool_decorator
async def extract_function_constants(
    ctx: Context,
    function_address: str,
    limit: int = 50
) -> Dict[str, Any]:
    """
    Scans a specific function for hardcoded constants (integers) and string references.
    Useful for extracting potential IOCs, keys, or config data from a target function.
    """

    await ctx.info(f"Extracting constants from: {function_address} (Limit: {limit})")

    _check_angr_ready("extract_function_constants")
    target_addr = _parse_addr(function_address)

    def _extract():

        _ensure_project_and_cfg()

        try:
            func = state.angr_cfg.functions[target_addr]
        except KeyError: return {"error": f"No function found at {hex(target_addr)}."}

        integers = set()
        strings = set()

        # Iterate over all blocks in the function
        for block in func.blocks:
            # Use Capstone (disassembly) to find immediate operands
            for insn in block.capstone.insns:
                # Iterate operands
                for op in insn.operands:
                    # CS_OP_IMM (Capstone immediate operand, value 2 across all archs)
                    CS_OP_IMM = 2
                    if op.type == CS_OP_IMM:
                        val = op.value.imm
                        # Filter out likely noise (small loop counters, etc)
                        if val > 0x1000:
                            integers.add(hex(val))

                            # Heuristic: Check if this immediate points to a string in memory
                            try:
                                # Read up to 64 bytes from this address
                                mem_data = state.angr_project.loader.memory.load(val, 64)
                                # Simple check for ASCII printable
                                str_candidate = ""
                                for b in mem_data:
                                    if b == 0: break
                                    if 32 <= b <= 126: str_candidate += chr(b)
                                    else:
                                        str_candidate = "" # Invalid char, discard
                                        break

                                if len(str_candidate) > 3:
                                    strings.add(f"{str_candidate} (@ {hex(val)})")
                            except Exception:
                                pass

        # Format for output
        sorted_ints = sorted(list(integers))
        sorted_strs = sorted(list(strings))

        return {
            "function": func.name,
            "integer_constants_count": len(sorted_ints),
            "string_references_count": len(sorted_strs),
            "integers": sorted_ints[:limit],
            "strings": sorted_strs[:limit]
        }

    result = await asyncio.to_thread(_extract)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "extract_function_constants", "the 'limit' parameter")

@tool_decorator
async def get_global_data_refs(
    ctx: Context,
    function_address: str,
    limit: int = 50
) -> Dict[str, Any]:
    """
    Identifies global memory addresses read from or written to by the target function.
    Useful for understanding what global state (flags, config, strings) a function interacts with.
    """

    await ctx.info(f"Scanning global refs in: {function_address} (Limit: {limit})")

    _check_angr_ready("scan_global_references")
    target_addr = _parse_addr(function_address)

    def _scan_refs():

        # Ensure a project exists via the standard locked path, then build a
        # *local* CFG with collect_data_references=True.  We must NOT replace
        # the shared state.angr_cfg because other tools expect a standard CFG
        # built without data-reference collection.
        _ensure_project_and_cfg()
        project, _ = state.get_angr_snapshot()
        # Build a separate local CFG with data reference tracking
        local_cfg = project.analyses.CFGFast(normalize=True, collect_data_references=True)

        try:
            func = local_cfg.functions[target_addr]
        except KeyError: return {"error": f"No function found at {hex(target_addr)}."}

        refs_found = []

        # Iterate blocks and check for MemoryData references associated with instruction addresses
        for block in func.blocks:
            for insn_addr in block.instruction_addrs:
                # --- FIX: Access XRefs using the dictionary index ---
                # .xrefs_by_ins_addr returns a set of XRef objects originating from this address
                xrefs = project.kb.xrefs.xrefs_by_ins_addr.get(insn_addr, [])

                for xref in xrefs:
                    # We care about memory data (not code jumps)
                    if xref.memory_data:
                        refs_found.append({
                            "instruction": hex(insn_addr),
                            "target_address": hex(xref.memory_data.addr),
                            "sort": xref.memory_data.sort, # e.g., 'string', 'unknown'
                            "content_preview": str(xref.memory_data.content)[:30] if xref.memory_data.content else "N/A"
                        })

        return {
            "function": func.name,
            "total_refs_found": len(refs_found),
            "references": refs_found[:limit]
        }

    result = await asyncio.to_thread(_scan_refs)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_global_data_refs", "the 'limit' parameter")

@tool_decorator
async def scan_for_indirect_jumps(
    ctx: Context,
    function_address: str,
    limit: int = 50
) -> Dict[str, Any]:
    """
    Scans a function for indirect jumps or calls (dynamic control flow).
    This helps detect switch tables, virtual function calls, or obfuscated control flow.
    """

    await ctx.info(f"Scanning for indirect jumps in: {function_address} (Limit: {limit})")

    _check_angr_ready("scan_for_indirect_jumps")
    target_addr = _parse_addr(function_address)

    def _scan_jumps():

        _ensure_project_and_cfg()

        try:
            func = state.angr_cfg.functions[target_addr]
        except KeyError: return {"error": f"No function found at {hex(target_addr)}."}

        indirect_flow = []

        for block in func.blocks:
            # VEX Jumpkind 'Ijk_Boring' is standard, 'Ijk_Call' is call.
            # We look for cases where the target is NOT a constant value.

            # Note: 'block.vex' lifts the block. This can be slow for huge functions.
            try:
                vex_block = block.vex
                # If the exit target is not a constant (e.g. it is a temporary variable or register)
                # and it's not a strict fallthrough
                if not isinstance(vex_block.next, int) and not hasattr(vex_block.next, 'value'):
                     # It is symbolic/dynamic
                     indirect_flow.append({
                         "block_addr": hex(block.addr),
                         "jump_kind": vex_block.jumpkind,
                         "instruction_count": len(vex_block.statements)
                     })
            except Exception:
                # Lifting failed or other error
                continue

        return {
            "function": func.name,
            "total_indirect_blocks": len(indirect_flow),
            "indirect_blocks": indirect_flow[:limit]
        }

    result = await asyncio.to_thread(_scan_jumps)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "scan_for_indirect_jumps", "the 'limit' parameter")

@tool_decorator
async def patch_binary_memory(ctx: Context, address: str, patch_bytes_hex: str) -> Dict[str, Any]:
    """
    Patches the loaded binary IN MEMORY with new bytes (affects future analysis).
    """

    await ctx.info(f"Patching memory at {address}")
    _check_angr_ready("patch_binary_memory")
    addr = _parse_addr(address)
    try:
        patch_data = bytes.fromhex(patch_bytes_hex)
    except ValueError: raise ValueError("Invalid hex data format.")

    def _patch():

        _ensure_project_and_cfg()
        try:
            state.angr_project.loader.memory.store(addr, patch_data)
            state.angr_cfg = None # Invalidate CFG
            return {"status": "success", "message": f"Patched {len(patch_data)} bytes. CFG cache cleared."}
        except Exception as e: return {"error": f"Patching failed: {e}"}

    result = await asyncio.to_thread(_patch)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "patch_binary_memory")


# ---- Cross-Reference Map (multi-dimensional, AI-friendly) ----

@tool_decorator
async def get_cross_reference_map(
    ctx: Context,
    function_addresses: List[str],
    depth: int = 1,
) -> Dict[str, Any]:
    """
    Returns a unified cross-reference view for one or more functions — connecting
    API calls, string references, callers, callees, suspicious imports, and
    complexity in a single compact response.

    Eliminates the need to call 3-4 separate tools (decompile, xrefs, strings,
    imports) to understand what a function does and how it connects.

    Args:
        ctx: The MCP Context object.
        function_addresses: (List[str]) One or more hex addresses of functions to map.
        depth: (int) Callee depth to follow (1 = direct callees only, 2 = callees of callees). Default 1.

    Returns:
        A dictionary with per-function cross-reference data.
    """
    from pemcp.mcp._category_maps import CATEGORIZED_IMPORTS_DB

    _check_angr_ready("get_cross_reference_map")
    if not function_addresses:
        raise ValueError("function_addresses must contain at least one address.")

    parsed_addrs = [_parse_addr(a) for a in function_addresses[:10]]  # cap at 10

    def _build_xref_map():
        _ensure_project_and_cfg()

        callgraph = state.angr_cfg.functions.callgraph

        # String address lookup
        string_addrs: Dict[int, str] = {}
        pe_data = state.pe_data or {}
        for s_obj in (pe_data.get('basic_ascii_strings') or []):
            if isinstance(s_obj, dict):
                addr = s_obj.get('offset')
                val = s_obj.get('string', '')
                if isinstance(addr, int) and val:
                    string_addrs[addr] = val[:80]

        functions_result: Dict[str, Any] = {}

        for target_addr in parsed_addrs:
            try:
                func, addr_used = _resolve_function_address(target_addr)
            except KeyError:
                functions_result[hex(target_addr)] = {"error": "Function not found"}
                continue

            # Callees (depth-aware)
            calls = []
            suspicious_apis = []
            visited = set()

            def _collect_callees(fn_addr, current_depth):
                if current_depth > depth or fn_addr in visited:
                    return
                visited.add(fn_addr)
                try:
                    for callee_addr in callgraph.successors(fn_addr):
                        if callee_addr in state.angr_cfg.functions:
                            cfunc = state.angr_cfg.functions[callee_addr]
                            cname = cfunc.name
                            if cname not in calls:
                                calls.append(cname)
                            for api_name, (risk, cat) in CATEGORIZED_IMPORTS_DB.items():
                                if api_name in cname:
                                    suspicious_apis.append({"name": cname, "risk": risk, "category": cat})
                                    break
                            if current_depth < depth:
                                _collect_callees(callee_addr, current_depth + 1)
                except Exception:
                    pass

            _collect_callees(addr_used, 1)

            # Callers
            callers = []
            try:
                for caller_addr in callgraph.predecessors(addr_used):
                    if caller_addr in state.angr_cfg.functions:
                        callers.append(state.angr_cfg.functions[caller_addr].name)
            except Exception:
                pass

            # String references
            strings_referenced = []
            try:
                for block in func.blocks:
                    for insn_addr in block.instruction_addrs:
                        xrefs = state.angr_project.kb.xrefs.xrefs_by_ins_addr.get(insn_addr, [])
                        for xref in xrefs:
                            if xref.memory_data and xref.memory_data.addr in string_addrs:
                                s = string_addrs[xref.memory_data.addr]
                                if s not in strings_referenced:
                                    strings_referenced.append(s)
            except Exception:
                pass

            # Complexity
            try:
                block_count = len(list(func.blocks))
                edge_count = func.graph.number_of_edges()
            except Exception:
                block_count = 0
                edge_count = 0

            functions_result[hex(addr_used)] = {
                "name": func.name,
                "calls": calls[:30],
                "called_by": callers[:20],
                "strings_referenced": strings_referenced[:20],
                "suspicious_apis": suspicious_apis,
                "complexity": {"blocks": block_count, "edges": edge_count},
            }

        return functions_result

    result_data = await asyncio.to_thread(_build_xref_map)

    result = {
        "functions": result_data,
        "depth": depth,
    }

    return await _check_mcp_response_size(ctx, result, "get_cross_reference_map")
