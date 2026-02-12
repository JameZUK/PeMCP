"""MCP tools for angr-based data flow analysis."""
import datetime
import uuid
import asyncio
from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_angr_ready, _check_mcp_response_size
from pemcp.background import _update_progress, _run_background_task_wrapper
from pemcp.mcp._angr_helpers import _ensure_project_and_cfg, _parse_addr, _resolve_function_address, _raise_on_error_dict

if ANGR_AVAILABLE:
    import angr
    import networkx as nx


# ---- Reaching Definitions Analysis -----------------------------

@tool_decorator
async def get_reaching_definitions(
    ctx: Context,
    function_address: str,
    target_instruction: Optional[str] = None,
    limit: int = 100,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    Computes reaching definitions for a function — which register/memory definitions
    reach each program point. Foundation for taint tracking and vulnerability hunting.

    Args:
        function_address: Hex address of the function to analyse.
        target_instruction: Optional hex address; if set, only show definitions reaching this point.
        limit: Max definition entries to return.
        run_in_background: Run as background task (default True).
    """
    _check_angr_ready("get_reaching_definitions")
    func_addr = _parse_addr(function_address)
    target_insn = _parse_addr(target_instruction, "target_instruction") if target_instruction else None

    def _rda(task_id_for_progress=None):
        _ensure_project_and_cfg()
        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Resolving function...")

        try:
            func, addr_used = _resolve_function_address(func_addr)
        except KeyError:
            return {"error": f"No function found at {hex(func_addr)}."}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 15, "Running ReachingDefinitionsAnalysis...")

        try:
            rd = state.angr_project.analyses.ReachingDefinitionsAnalysis(
                func, cfg=state.angr_cfg, observe_all=True,
            )
        except Exception as e:
            return {"error": f"ReachingDefinitionsAnalysis failed: {e}"}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 80, "Formatting results...")

        definitions = []
        try:
            for defn in rd.all_definitions:
                atom = defn.atom
                entry = {
                    "atom": str(atom),
                    "codeloc": str(defn.codeloc) if hasattr(defn, 'codeloc') else None,
                }
                definitions.append(entry)
                if len(definitions) >= limit:
                    break
        except Exception:
            pass

        # If target_instruction is specified, extract the observed result at that point
        observed = None
        if target_insn is not None:
            try:
                from angr.analyses.reaching_definitions.dep_graph import DepGraph
            except ImportError:
                pass
            # Try to get the live definitions at the target instruction
            try:
                for key, rd_state in rd.observed_results.items():
                    # key is typically a tuple (insn_addr, ...)  or an observation point
                    addr_val = None
                    if hasattr(key, 'ins_addr'):
                        addr_val = key.ins_addr
                    elif isinstance(key, tuple) and len(key) >= 2:
                        addr_val = key[1] if isinstance(key[1], int) else None
                    if addr_val == target_insn:
                        live_defs = []
                        for defn in rd_state.register_definitions.get_all_variables():
                            live_defs.append(str(defn))
                        observed = {
                            "observation_point": str(key),
                            "live_register_definitions": live_defs[:limit],
                        }
                        break
            except Exception:
                pass

        result = {
            "function_name": func.name,
            "address": hex(addr_used),
            "total_definitions": len(definitions),
            "definitions": definitions,
        }
        if observed:
            result["observed_at_target"] = observed

        return result

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing RDA...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "get_reaching_definitions",
        })
        asyncio.create_task(_run_background_task_wrapper(task_id, _rda))
        return {"status": "queued", "task_id": task_id, "message": "Reaching definitions analysis queued."}

    await ctx.info(f"Running reaching definitions for {function_address}")
    result = await asyncio.to_thread(_rda)
    return await _check_mcp_response_size(ctx, result, "get_reaching_definitions", "the 'limit' parameter")


# ---- Data Dependency Graph -------------------------------------

@tool_decorator
async def get_data_dependencies(
    ctx: Context,
    function_address: str,
    instruction_address: Optional[str] = None,
    direction: str = "backward",
    limit: int = 100,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    Builds a Data Dependency Graph (DDG) showing how data flows between instructions.
    Unlike control-flow slicing, this traces actual value producers and consumers.

    Args:
        function_address: Hex address of the function to analyse.
        instruction_address: Optional target instruction to focus on.
        direction: 'backward' (what produced this value) or 'forward' (what consumes it).
        limit: Max dependency entries to return.
        run_in_background: Run as background task (default True).
    """
    _check_angr_ready("get_data_dependencies")
    func_addr = _parse_addr(function_address)
    insn_addr = _parse_addr(instruction_address, "instruction_address") if instruction_address else None

    def _ddg(task_id_for_progress=None):
        _ensure_project_and_cfg()
        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Resolving function...")

        try:
            func, addr_used = _resolve_function_address(func_addr)
        except KeyError:
            return {"error": f"No function found at {hex(func_addr)}."}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 15, "Building Data Dependency Graph...")

        try:
            ddg = state.angr_project.analyses.DDG(func)
        except Exception as e:
            return {"error": f"DDG analysis failed: {e}"}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 75, "Extracting dependencies...")

        graph = ddg.graph
        if graph is None or len(graph) == 0:
            return {
                "function_name": func.name,
                "address": hex(addr_used),
                "total_nodes": 0,
                "dependencies": [],
                "note": "DDG produced an empty graph — function may be too simple or analysis unsupported.",
            }

        # If a specific instruction is requested, get its neighborhood
        if insn_addr is not None:
            target_nodes = [n for n in graph.nodes() if hasattr(n, 'insn_addr') and n.insn_addr == insn_addr]
            if not target_nodes:
                target_nodes = [n for n in graph.nodes()
                                if hasattr(n, 'code_loc') and hasattr(n.code_loc, 'ins_addr')
                                and n.code_loc.ins_addr == insn_addr]

            deps = []
            for tn in target_nodes:
                if direction == "backward":
                    related = nx.ancestors(graph, tn)
                else:
                    related = nx.descendants(graph, tn)
                for node in related:
                    deps.append({"node": str(node)})
                    if len(deps) >= limit:
                        break
                if len(deps) >= limit:
                    break

            return {
                "function_name": func.name,
                "address": hex(addr_used),
                "target": hex(insn_addr),
                "direction": direction,
                "total_related": len(deps),
                "dependencies": deps[:limit],
            }

        # Full graph summary
        edges = []
        for src, dst in list(graph.edges())[:limit]:
            edges.append({"src": str(src), "dst": str(dst)})

        return {
            "function_name": func.name,
            "address": hex(addr_used),
            "total_nodes": len(graph.nodes()),
            "total_edges": len(graph.edges()),
            "edges": edges,
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing DDG...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "get_data_dependencies",
        })
        asyncio.create_task(_run_background_task_wrapper(task_id, _ddg))
        return {"status": "queued", "task_id": task_id, "message": "DDG analysis queued."}

    await ctx.info(f"Building DDG for {function_address}")
    result = await asyncio.to_thread(_ddg)
    return await _check_mcp_response_size(ctx, result, "get_data_dependencies", "the 'limit' parameter")


# ---- Control Dependence Graph ----------------------------------

@tool_decorator
async def get_control_dependencies(
    ctx: Context,
    function_address: str,
    target_address: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Builds the Control Dependence Graph (CDG) for a function — shows which conditional
    branches control whether each block executes.

    Args:
        function_address: Hex address of the function.
        target_address: Optional; if set, return only the branches that control this block.
        limit: Max entries to return.
    """
    await ctx.info(f"Building CDG for {function_address}")
    _check_angr_ready("get_control_dependencies")
    func_addr = _parse_addr(function_address)
    target = _parse_addr(target_address, "target_address") if target_address else None

    def _cdg():
        _ensure_project_and_cfg()
        try:
            func, addr_used = _resolve_function_address(func_addr)
        except KeyError:
            return {"error": f"No function found at {hex(func_addr)}."}

        try:
            cdg = state.angr_project.analyses.CDG(func)
        except Exception as e:
            return {"error": f"CDG analysis failed: {e}"}

        graph = cdg.graph
        if graph is None:
            return {"error": "CDG produced no graph."}

        if target is not None:
            # Find the node for the target
            target_node = None
            for n in graph.nodes():
                if hasattr(n, 'addr') and n.addr == target:
                    target_node = n
                    break
            if not target_node:
                return {"error": f"Target {hex(target)} not found in CDG."}

            controllers = []
            for pred in graph.predecessors(target_node):
                controllers.append({
                    "controlling_block": hex(pred.addr) if hasattr(pred, 'addr') else str(pred),
                    "size": getattr(pred, 'size', None),
                })
            return {
                "function_name": func.name,
                "target": hex(target),
                "controlling_branches": controllers[:limit],
            }

        # Full CDG
        edges = []
        for src, dst in list(graph.edges())[:limit]:
            src_addr = hex(src.addr) if hasattr(src, 'addr') else str(src)
            dst_addr = hex(dst.addr) if hasattr(dst, 'addr') else str(dst)
            edges.append({"controller": src_addr, "dependent": dst_addr})

        return {
            "function_name": func.name,
            "address": hex(addr_used),
            "total_nodes": len(graph.nodes()),
            "total_edges": len(graph.edges()),
            "edges": edges,
        }

    result = await asyncio.to_thread(_cdg)
    return await _check_mcp_response_size(ctx, result, "get_control_dependencies", "the 'limit' parameter")


# ---- Constant Propagation --------------------------------------

@tool_decorator
async def propagate_constants(
    ctx: Context,
    function_address: str,
    limit: int = 80,
) -> Dict[str, Any]:
    """
    Runs constant propagation on a function to resolve computed values, simplify
    expressions, and de-obfuscate indirect call targets.

    Args:
        function_address: Hex address of the function.
        limit: Max propagated values to return.
    """
    await ctx.info(f"Propagating constants in {function_address}")
    _check_angr_ready("propagate_constants")
    func_addr = _parse_addr(function_address)

    def _propagate():
        _ensure_project_and_cfg()
        try:
            func, addr_used = _resolve_function_address(func_addr)
        except KeyError:
            return {"error": f"No function found at {hex(func_addr)}."}

        try:
            prop = state.angr_project.analyses.PropagatorAnalysis(
                func, cfg=state.angr_cfg.model,
            )
        except Exception as e:
            return {"error": f"PropagatorAnalysis failed: {e}"}

        # Extract replacements — these map (addr, register/tmp) -> constant value
        replacements = []
        try:
            rep = prop.replacements
            if hasattr(rep, 'items'):
                for key, val in rep.items():
                    if hasattr(val, 'items'):
                        for inner_key, inner_val in val.items():
                            replacements.append({
                                "location": str(key),
                                "atom": str(inner_key),
                                "resolved_value": str(inner_val),
                            })
                    else:
                        replacements.append({
                            "location": str(key),
                            "resolved_value": str(val),
                        })
                    if len(replacements) >= limit:
                        break
        except Exception:
            pass

        return {
            "function_name": func.name,
            "address": hex(addr_used),
            "total_replacements": len(replacements),
            "propagated_values": replacements[:limit],
        }

    result = await asyncio.to_thread(_propagate)
    return await _check_mcp_response_size(ctx, result, "propagate_constants", "the 'limit' parameter")


# ---- VFG / Value-Set Analysis ---------------------------------

@tool_decorator
async def get_value_set_analysis(
    ctx: Context,
    function_address: str,
    limit: int = 80,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    Runs Value-Set Analysis (VFG) on a function to compute possible value ranges
    for registers and memory at each program point. Helps reason about pointer
    aliasing and buffer bounds.

    WARNING: Computationally expensive. Best used on individual functions.

    Args:
        function_address: Hex address of the function.
        limit: Max value-set entries to return.
        run_in_background: Run as background task (default True).
    """
    _check_angr_ready("get_value_set_analysis")
    func_addr = _parse_addr(function_address)

    def _vsa(task_id_for_progress=None):
        _ensure_project_and_cfg()
        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Resolving function...")

        try:
            func, addr_used = _resolve_function_address(func_addr)
        except KeyError:
            return {"error": f"No function found at {hex(func_addr)}."}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 15, "Running VFG analysis...")

        try:
            vfg = state.angr_project.analyses.VFG(
                cfg=state.angr_cfg,
                function_start=addr_used,
                context_sensitivity_level=2,
            )
        except Exception as e:
            return {"error": f"VFG analysis failed: {e}"}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 80, "Extracting value sets...")

        nodes_info = []
        try:
            graph = vfg.graph
            if graph:
                for node in list(graph.nodes())[:limit]:
                    entry = {"address": hex(node.addr) if hasattr(node, 'addr') else str(node)}
                    nodes_info.append(entry)
        except Exception:
            pass

        return {
            "function_name": func.name,
            "address": hex(addr_used),
            "total_nodes": len(nodes_info),
            "vfg_nodes": nodes_info[:limit],
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing VFG...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "get_value_set_analysis",
        })
        asyncio.create_task(_run_background_task_wrapper(task_id, _vsa))
        return {"status": "queued", "task_id": task_id, "message": "Value-set analysis queued."}

    await ctx.info(f"Running VFG for {function_address}")
    result = await asyncio.to_thread(_vsa)
    return await _check_mcp_response_size(ctx, result, "get_value_set_analysis", "the 'limit' parameter")
