"""MCP tools for angr-based data flow analysis."""
import datetime
import traceback
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
            # The plugin name was shortened in newer angr versions:
            #   ReachingDefinitionsAnalysis → ReachingDefinitions
            # Try the new name first, fall back to the old one.
            _rda_cls = getattr(
                state.angr_project.analyses,
                'ReachingDefinitions',
                getattr(state.angr_project.analyses, 'ReachingDefinitionsAnalysis', None),
            )
            if _rda_cls is None:
                return {"error": "ReachingDefinitionsAnalysis is not registered in this angr version."}
            rd = _rda_cls(func, observe_all=True)
        except Exception as e:
            tb = traceback.format_exc()
            logger.error("RDA failed: %s", tb)
            return {"error": f"ReachingDefinitionsAnalysis failed: {type(e).__name__}: {e}", "traceback_tail": tb[-500:]}

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


# ---- Data Dependency Analysis ------------------------------------

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
    Analyses data dependencies showing how values flow between instructions.
    Uses ReachingDefinitionsAnalysis to build definition-use chains and a
    dependency graph. Unlike control-flow slicing, this traces actual value
    producers and consumers.

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
            _update_progress(task_id_for_progress, 15, "Running ReachingDefinitions for data dependencies...")

        # The DDG analysis is deprecated in angr >=9.2.  We use
        # ReachingDefinitionsAnalysis instead, which provides
        # definition-use chains that serve the same purpose.
        try:
            _rda_cls = getattr(
                state.angr_project.analyses,
                'ReachingDefinitions',
                getattr(state.angr_project.analyses, 'ReachingDefinitionsAnalysis', None),
            )
            if _rda_cls is None:
                return {
                    "error": "Neither ReachingDefinitions nor DDG analysis is available.",
                    "hint": "Ensure angr >=9.2 is installed.",
                }
            rd = _rda_cls(func, observe_all=True)
        except Exception as e:
            tb = traceback.format_exc()
            logger.error("RDA (data-dep) failed: %s", tb)
            return {"error": f"Data dependency analysis failed: {type(e).__name__}: {e}"}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 70, "Building dependency graph from RDA...")

        # Build a dependency graph from the RDA def-use chains.
        dep_graph = None
        try:
            dep_graph = getattr(rd, 'dep_graph', None)
            if dep_graph is not None:
                dep_graph = dep_graph.graph if hasattr(dep_graph, 'graph') else dep_graph
        except Exception:
            dep_graph = None

        # Collect all definitions as a flat list
        definitions = []
        try:
            for defn in rd.all_definitions:
                entry = {
                    "atom": str(defn.atom),
                    "codeloc": str(defn.codeloc) if hasattr(defn, 'codeloc') else None,
                }
                definitions.append(entry)
                if len(definitions) >= limit:
                    break
        except Exception:
            pass

        # If an instruction is targeted, filter definitions relevant to it
        if insn_addr is not None:
            filtered = []
            for defn_entry in definitions:
                codeloc_str = defn_entry.get("codeloc", "")
                if codeloc_str and hex(insn_addr) in codeloc_str:
                    filtered.append(defn_entry)
            if not filtered:
                # Try observed results at the target point
                try:
                    for key, rd_state in rd.observed_results.items():
                        addr_val = None
                        if hasattr(key, 'ins_addr'):
                            addr_val = key.ins_addr
                        elif isinstance(key, tuple) and len(key) >= 2:
                            addr_val = key[1] if isinstance(key[1], int) else None
                        if addr_val == insn_addr:
                            for live_def in rd_state.register_definitions.get_all_variables():
                                filtered.append({"atom": str(live_def), "codeloc": str(key)})
                                if len(filtered) >= limit:
                                    break
                            break
                except Exception:
                    pass

            return {
                "function_name": func.name,
                "address": hex(addr_used),
                "target": hex(insn_addr),
                "direction": direction,
                "method": "ReachingDefinitions",
                "total_related": len(filtered),
                "dependencies": filtered[:limit],
            }

        # Dependency graph edges if available
        edges = []
        if dep_graph is not None and hasattr(dep_graph, 'edges'):
            try:
                for src, dst in list(dep_graph.edges())[:limit]:
                    edges.append({"src": str(src), "dst": str(dst)})
            except Exception:
                pass

        return {
            "function_name": func.name,
            "address": hex(addr_used),
            "method": "ReachingDefinitions",
            "total_definitions": len(definitions),
            "total_edges": len(edges),
            "definitions": definitions[:limit],
            "edges": edges,
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running", "progress_percent": 0,
            "progress_message": "Initializing data dependency analysis...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": "get_data_dependencies",
        })
        asyncio.create_task(_run_background_task_wrapper(task_id, _ddg))
        return {"status": "queued", "task_id": task_id, "message": "Data dependency analysis queued."}

    await ctx.info(f"Analysing data dependencies for {function_address}")
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
            # CDG requires a CFGEmulated; CFGFast is not supported.
            # Attempt to build a CFGEmulated scoped to this function,
            # which is much cheaper than a full-binary CFGEmulated.
            try:
                cfg_emu = state.angr_project.analyses.CFGEmulated(
                    starts=[addr_used],
                    context_sensitivity_level=1,
                    call_depth=0,
                    normalize=True,
                )
            except Exception as e_emu:
                return {
                    "error": f"CDG requires CFGEmulated which failed to build: "
                             f"{type(e_emu).__name__}: {e_emu}",
                    "hint": "CDG analysis is not compatible with CFGFast. "
                            "A function-scoped CFGEmulated was attempted but failed. "
                            "Use get_dominators for a lighter control-flow analysis.",
                }
            cdg = state.angr_project.analyses.CDG(
                cfg=cfg_emu,
                start=addr_used,
            )
        except Exception as e:
            tb = traceback.format_exc()
            logger.error("CDG analysis failed: %s", tb)
            return {"error": f"CDG analysis failed: {type(e).__name__}: {e}"}

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
            # The plugin name was shortened in newer angr versions:
            #   PropagatorAnalysis → Propagator
            _prop_cls = getattr(
                state.angr_project.analyses,
                'Propagator',
                getattr(state.angr_project.analyses, 'PropagatorAnalysis', None),
            )
            if _prop_cls is None:
                return {"error": "PropagatorAnalysis is not registered in this angr version."}
            prop = _prop_cls(func)
        except Exception as e:
            tb = traceback.format_exc()
            logger.error("PropagatorAnalysis failed: %s", tb)
            return {"error": f"PropagatorAnalysis failed: {type(e).__name__}: {e}", "traceback_tail": tb[-500:]}

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
            # VFG constructor signature has changed across angr versions.
            # The cfg parameter may need to be the CFGFast analysis object
            # (not cfg.model) because VFG internally accesses .model on it.
            # Passing cfg.model causes "'CFGModel' object has no attribute 'model'".
            vfg = None
            last_err = None
            for vfg_kwargs in [
                {"cfg": state.angr_cfg, "function_start": addr_used, "context_sensitivity_level": 2},
                {"cfg": state.angr_cfg, "function_start": addr_used},
            ]:
                try:
                    vfg = state.angr_project.analyses.VFG(**vfg_kwargs)
                    break
                except (TypeError, AttributeError) as te:
                    last_err = te
                    continue
            if vfg is None:
                raise last_err or RuntimeError("VFG could not be instantiated")
        except Exception as e:
            return {
                "error": f"VFG analysis failed: {e}",
                "hint": "Value-set analysis (VFG) has known compatibility issues "
                        "with some angr versions. This is an upstream angr limitation. "
                        "Consider using get_reaching_definitions or propagate_constants "
                        "as alternatives for data-flow analysis.",
            }

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
