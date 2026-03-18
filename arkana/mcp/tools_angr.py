"""MCP tools for angr-based binary analysis - decompilation, CFG, symbolic execution, etc."""
import collections
import datetime
import threading
import time
import uuid
import asyncio
import sys

from typing import Dict, Any, Optional, List

from arkana.config import state, logger, Context, ANGR_AVAILABLE, ANGR_ANALYSIS_TIMEOUT
from arkana.constants import (
    MAX_BATCH_DECOMPILE, BATCH_DECOMPILE_PER_FUNCTION_TIMEOUT, MAX_TOOL_LIMIT,
    MAX_SYMBOLIC_STEPS, MAX_SYMBOLIC_ACTIVE_STATES, MAX_SYMBOLIC_FIND_ADDRESSES,
)
from arkana.state import TASK_RUNNING, TASK_FAILED
from arkana.mcp.server import tool_decorator, _check_angr_ready, _check_mcp_response_size
from arkana.background import _update_progress, _run_background_task_wrapper, _log_task_exception
from arkana.mcp._progress_bridge import ProgressBridge
from arkana.mcp._angr_helpers import _ensure_project_and_cfg, _build_region_cfg, _init_lock, _parse_addr, _resolve_function_address, _raise_on_error_dict, _safe_decompile, DECOMPILE_FALLBACK_NOTE
from arkana.mcp._rename_helpers import apply_function_renames_to_lines, apply_variable_renames_to_lines, get_display_name
from arkana.mcp._search_helpers import search_lines_with_context

# Cache for paginated decompilation results — avoids re-decompiling when
# the client requests subsequent pages of the same function.
# M-14: OrderedDict with LRU eviction (move_to_end on access, popitem(last=False) on eviction).
# Keys are (session_uuid, addr_int) for session isolation in HTTP mode.
_decompile_meta: collections.OrderedDict = collections.OrderedDict()  # cache_key -> {function_name, address, lines}
_decompile_meta_lock = threading.Lock()
_MAX_DECOMPILE_META = 2000


def _make_decompile_key(addr_int):
    """Build a session-scoped decompile cache key."""
    return (state._state_uuid, addr_int)


def _get_cached_lines(cache_key):
    """Look up decompiled lines from the authoritative meta store."""
    with _decompile_meta_lock:
        meta = _decompile_meta.get(cache_key)
        if meta:
            _decompile_meta.move_to_end(cache_key)  # M-14: LRU touch
            return meta.get("lines")
    return None


def _get_cached_entry(cache_key):
    """Thread-safe lookup returning the full meta dict (lines + metadata)."""
    with _decompile_meta_lock:
        meta = _decompile_meta.get(cache_key)
        if meta:
            _decompile_meta.move_to_end(cache_key)  # M-14: LRU touch
            return dict(meta)  # shallow copy to avoid mutation
    return None


def _get_cached_meta(cache_key):
    """Thread-safe read of decompile metadata."""
    with _decompile_meta_lock:
        meta = _decompile_meta.get(cache_key)
        if meta is not None:
            _decompile_meta.move_to_end(cache_key)  # M-14: LRU touch
            return dict(meta)
        return {}


def _set_decompile_meta(cache_key, value):
    """Thread-safe store with LRU eviction when exceeding max size."""
    with _decompile_meta_lock:
        if cache_key in _decompile_meta:
            _decompile_meta.move_to_end(cache_key)  # M-14: LRU touch on update
        _decompile_meta[cache_key] = value
        while len(_decompile_meta) > _MAX_DECOMPILE_META:
            _decompile_meta.popitem(last=False)  # M-14: evict least-recently-used


def clear_decompile_meta(session_uuid=None):
    """Clear the decompile meta cache.

    If *session_uuid* is given, only entries for that session are removed.
    Otherwise all entries are cleared (legacy behavior for close_file).
    """
    with _decompile_meta_lock:
        if session_uuid is None:
            _decompile_meta.clear()
        else:
            to_remove = [k for k in _decompile_meta if k[0] == session_uuid]
            for k in to_remove:
                del _decompile_meta[k]

if ANGR_AVAILABLE:
    import angr
    import angr.analyses.decompiler
    import networkx as nx


@tool_decorator
async def list_angr_analyses(ctx: Context, category: str = "all") -> Dict[str, Any]:
    """
    [Phase: context] Discovery tool: lists all available angr-based analysis capabilities with descriptions.
    Use this to understand what angr analyses are available before calling specific tools.

    When to use: At the start of analysis to discover available tools, or when unsure which tool to call next.
    Next steps: get_function_map() to find interesting functions, get_function_complexity_list() to rank by complexity,
    or decompile_function_with_angr() if you already have a target address.

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
             "description": "Decompile a function to C-like pseudocode. Works without full CFG (builds local region CFG)."},
            {"tool": "get_annotated_disassembly", "params": "function_address, include_xrefs",
             "description": "Disassembly with variable names, xrefs, and comments."},
            {"tool": "disassemble_at_address", "params": "address, num_instructions",
             "description": "Raw disassembly at a specific address. Works without full CFG."},
            {"tool": "get_angr_partial_functions", "params": "limit",
             "description": "List functions discovered so far, even while CFG is building or timed out."},
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
async def get_angr_partial_functions(
    ctx: Context,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    [Phase: explore] Lists functions discovered in angr's knowledge base, even
    while CFG is still building or has timed out. Useful to see what angr has
    found so far on packed/slow binaries.

    When to use: When check_task_status('startup-angr') shows CFG is stalled or
    timed out, use this to see which functions were discovered before it stopped.

    Next steps: decompile_function_with_angr() on any discovered function (it will
    build a local CFG automatically), or disassemble_at_address() for quick inspection.

    Args:
        limit: Max number of functions to return (default 50).
    """
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info("Listing partially discovered angr functions")
    _check_angr_ready("get_angr_partial_functions", require_cfg=False)

    def _list_partial():
        project = state.angr_project
        if project is None:
            return {"error": "No angr project loaded yet."}

        functions = []
        try:
            kb_funcs = project.kb.functions
        except Exception:
            return {"error": "Could not access angr knowledge base."}

        for addr, func in list(kb_funcs.items())[:limit]:
            try:
                block_count = func.graph.number_of_nodes() if func.graph else len(list(func.blocks))  # L6-v10: O(1)
            except Exception:
                block_count = 0
            functions.append({
                "address": hex(addr),
                "name": func.name,
                "size": func.size,
                "blocks": block_count,
            })

        cfg_status = "available" if state.angr_cfg is not None else "not_available"
        startup_task = state.get_task("startup-angr")
        if startup_task and startup_task["status"] == TASK_RUNNING:
            cfg_status = "building"
        elif startup_task and startup_task["status"] == TASK_FAILED:
            cfg_status = "failed"

        return {
            "cfg_status": cfg_status,
            "total_discovered": len(kb_funcs),
            "returned": len(functions),
            "functions": functions,
            "hint": (
                "decompile_function_with_angr() works on any of these functions — "
                "it will build a local CFG automatically when the full CFG is unavailable."
            ),
        }

    result = await asyncio.to_thread(_list_partial)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_angr_partial_functions", "the 'limit' parameter")


@tool_decorator
async def decompile_function_with_angr(
    ctx: Context,
    function_address: str,
    line_offset: int = 0,
    line_limit: int = 80,
    search: Optional[str] = None,
    context_lines: int = 2,
    case_sensitive: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Decompiles a function into C-like pseudocode using Angr.
    Automatically attempts to handle RVA (offsets) if the exact VA is not found.

    Output is paginated by line. The first call decompiles and caches the full
    result; subsequent calls with different ``line_offset`` values serve from
    cache without re-decompiling.

    When ``search`` is provided, returns only matching lines with surrounding
    context instead of paginated output.  Useful for finding specific patterns
    (e.g. ``search="xor"`` or ``search="CreateFile"``) without reading the
    entire function.

    When to use: After identifying a function of interest via get_function_map() or get_function_complexity_list().
    Next steps: auto_note_function(address) to save a behavioral summary, get_function_cfg() for control flow,
    or get_cross_reference_map() to understand callers/callees.

    After reviewing the decompiled output, call auto_note_function(address) to
    save a one-line behavioral summary, or add_note(content, category='tool_result')
    to record specific findings. This builds the analysis digest without keeping
    full pseudocode in context.

    Args:
        function_address: Hex address of the function to decompile (e.g. '0x140001000').
        line_offset: Start returning lines from this index (0-based). Default 0.
        line_limit: Maximum number of lines to return per page. Default 80.
        search: Optional regex pattern to grep for within the decompiled code.
            When provided, only matching lines with context are returned.
        context_lines: Number of context lines around each match (default 2, max 20).
        case_sensitive: Whether the search is case-sensitive (default False).
    """

    line_limit = max(1, min(line_limit, MAX_TOOL_LIMIT))
    await ctx.info(f"Requesting Angr decompilation for: {function_address}")
    _check_angr_ready("decompile_function_with_angr", require_cfg=False)
    target_addr = _parse_addr(function_address)

    # Check cache first — serves subsequent pages without re-decompiling
    cache_key = _make_decompile_key(target_addr)
    cached_entry = _get_cached_entry(cache_key)

    if cached_entry is not None:
        cached_lines = cached_entry.get("lines", [])
        cached_note = cached_entry.get("note")
        # Apply user renames to output
        renamed_lines = apply_function_renames_to_lines(cached_lines)
        renamed_lines = apply_variable_renames_to_lines(renamed_lines, hex(target_addr))
        display_name = get_display_name(hex(target_addr), cached_entry.get("function_name", "unknown"))

        if search:
            search_result = search_lines_with_context(renamed_lines, search, context_lines, case_sensitive)
            flat_lines = []
            for region in search_result["matched_regions"]:
                flat_lines.extend(region["items"])
            page = flat_lines[line_offset:line_offset + line_limit]
            has_more = (line_offset + line_limit) < len(flat_lines)
            cached_search_result = {
                "function_name": display_name,
                "address": cached_entry.get("address", hex(target_addr)),
                "lines": page,
                "count": len(page),
                "_search": {
                    "pattern": search,
                    "total_matches": search_result["total_matches"],
                    "total_lines": search_result["total_lines"],
                    "truncated": search_result["truncated"],
                    "regions": len(search_result["matched_regions"]),
                },
                "_pagination": {
                    "total": len(flat_lines),
                    "offset": line_offset,
                    "limit": line_limit,
                    "has_more": has_more,
                },
                "next_step": (
                    f"Call decompile_function_with_angr('{function_address}', search='{search}', line_offset={line_offset + line_limit}) to see more matches."
                    if has_more else
                    "Call auto_note_function(address) to save a behavioral summary of this function."
                ),
            }
            if cached_note:
                cached_search_result["note"] = cached_note
            return cached_search_result

        page = renamed_lines[line_offset:line_offset + line_limit]
        has_more = (line_offset + line_limit) < len(renamed_lines)
        cached_page_result = {
            "function_name": display_name,
            "address": cached_entry.get("address", hex(target_addr)),
            "lines": page,
            "count": len(page),
            "_pagination": {
                "total": len(cached_lines),
                "offset": line_offset,
                "limit": line_limit,
                "has_more": has_more,
            },
            "next_step": (
                f"Call decompile_function_with_angr('{function_address}', line_offset={line_offset + line_limit}) to see more lines."
                if has_more else
                "Call auto_note_function(address) to save a behavioral summary of this function."
            ),
        }
        if cached_note:
            cached_page_result["note"] = cached_note
        return cached_page_result

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _decompile():
        # Signal to background enrichment that on-demand decompile is waiting,
        # then acquire the decompile lock to ensure mutual exclusion with
        # the background decompile sweep.
        # M-8: _decompile_on_demand_count += 1 / -= 1 rely on CPython's GIL
        # for atomicity of int reference assignment.  The counter is only used
        # as a "someone is waiting" signal (> 0 vs == 0), so interleaved
        # increments/decrements cannot cause incorrect behavior.
        state._decompile_on_demand_count += 1
        try:
            if not state._decompile_lock.acquire(timeout=60):
                raise RuntimeError(
                    "Decompilation lock busy — background analysis in progress. Retry shortly."
                )
        except Exception:
            state._decompile_on_demand_count -= 1
            raise
        try:
            state._decompile_on_demand_count -= 1
            project, cfg = state.get_angr_snapshot()
            used_local_cfg = False

            if project is None:
                _ensure_project_and_cfg()
                project, cfg = state.get_angr_snapshot()

            bridge.report_progress(5, 100)
            bridge.info("Resolving function...")

            if cfg is not None:
                # Fast path: full CFG available
                addr_to_use = target_addr
                if addr_to_use not in cfg.functions:
                    if (state.pe_object
                            and hasattr(state.pe_object, 'OPTIONAL_HEADER')
                            and state.pe_object.OPTIONAL_HEADER):
                        image_base = state.pe_object.OPTIONAL_HEADER.ImageBase
                        potential_va = target_addr + image_base
                        if potential_va in cfg.functions:
                            addr_to_use = potential_va
                try:
                    func = cfg.functions[addr_to_use]
                except KeyError:
                    return {
                        "error": f"No function found at {hex(target_addr)} (or adjusted VA).",
                        "hint": "Verify the address. If using an offset, ensure it matches the ImageBase."
                    }
                decompiler_cfg = cfg.model
            else:
                # Fallback: no full CFG — build a region-scoped CFG
                bridge.info("No full CFG available — building local CFG around target...")
                try:
                    local_cfg = _build_region_cfg(project, target_addr)
                except Exception as e:
                    return {"error": f"Failed to build local CFG around {hex(target_addr)}: {e}"}
                used_local_cfg = True
                addr_to_use = target_addr
                if addr_to_use not in local_cfg.functions:
                    # Try RVA correction
                    if (state.pe_object
                            and hasattr(state.pe_object, 'OPTIONAL_HEADER')
                            and state.pe_object.OPTIONAL_HEADER):
                        image_base = state.pe_object.OPTIONAL_HEADER.ImageBase
                        potential_va = target_addr + image_base
                        if potential_va in local_cfg.functions:
                            addr_to_use = potential_va
                try:
                    func = local_cfg.functions[addr_to_use]
                except KeyError:
                    return {
                        "error": f"No function found at {hex(target_addr)} in local CFG region.",
                        "hint": "The address may not be a valid function start. "
                                "Use get_angr_partial_functions() to see discovered functions."
                    }
                decompiler_cfg = local_cfg.model

            bridge.report_progress(20, 100)
            bridge.info(f"Decompiling {func.name}...")
            try:
                dec, used_fallback = _safe_decompile(project, func, decompiler_cfg)
                bridge.report_progress(90, 100)
                bridge.info("Formatting output...")
                if not dec.codegen:
                    return {"error": "Decompilation produced no code."}
                result = {
                    "function_name": func.name,
                    "address": hex(addr_to_use),
                    "c_pseudocode": dec.codegen.text,
                }
                notes = []
                if used_local_cfg:
                    notes.append(
                        "Decompiled using a local region CFG (full binary CFG was not available). "
                        "Results may be less complete — cross-references and callee resolution "
                        "are limited to the local region."
                    )
                if used_fallback:
                    notes.append(DECOMPILE_FALLBACK_NOTE)
                if notes:
                    result["note"] = " | ".join(notes)
                return result
            except Exception as e:
                return {"error": f"Decompilation failed: {e}"}
        finally:
            state._decompile_lock.release()

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_decompile), timeout=ANGR_ANALYSIS_TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError(f"Decompilation timed out after {ANGR_ANALYSIS_TIMEOUT} seconds.")
    _raise_on_error_dict(result)

    # Cache full result (raw, before renames) and return paginated
    all_lines = result["c_pseudocode"].splitlines()
    meta = {
        "function_name": result["function_name"],
        "address": result["address"],
        "lines": all_lines,
    }
    if result.get("note"):
        meta["note"] = result["note"]
    _set_decompile_meta(cache_key, meta)

    # Persist to disk cache (throttled, non-blocking)
    try:
        from arkana.enrichment import save_decompile_cache_async
        save_decompile_cache_async(state)
    except Exception:
        pass

    # Apply user renames to output
    renamed_lines = apply_function_renames_to_lines(all_lines)
    renamed_lines = apply_variable_renames_to_lines(renamed_lines, hex(target_addr))
    display_name = get_display_name(hex(target_addr), result["function_name"])

    if search:
        search_result = search_lines_with_context(renamed_lines, search, context_lines, case_sensitive)
        flat_lines = []
        for region in search_result["matched_regions"]:
            flat_lines.extend(region["items"])
        page = flat_lines[line_offset:line_offset + line_limit]
        has_more = (line_offset + line_limit) < len(flat_lines)
        paginated_result = {
            "function_name": display_name,
            "address": result["address"],
            "lines": page,
            "count": len(page),
            "_search": {
                "pattern": search,
                "total_matches": search_result["total_matches"],
                "total_lines": search_result["total_lines"],
                "truncated": search_result["truncated"],
                "regions": len(search_result["matched_regions"]),
            },
            "_pagination": {
                "total": len(flat_lines),
                "offset": line_offset,
                "limit": line_limit,
                "has_more": has_more,
            },
            "next_step": (
                f"Call decompile_function_with_angr('{function_address}', search='{search}', line_offset={line_offset + line_limit}) to see more matches."
                if has_more else
                "Call auto_note_function(address) to save a behavioral summary of this function."
            ),
        }
    else:
        page = renamed_lines[line_offset:line_offset + line_limit]
        has_more = (line_offset + line_limit) < len(renamed_lines)
        paginated_result = {
            "function_name": display_name,
            "address": result["address"],
            "lines": page,
            "count": len(page),
            "_pagination": {
                "total": len(all_lines),
                "offset": line_offset,
                "limit": line_limit,
                "has_more": has_more,
            },
            "next_step": (
                f"Call decompile_function_with_angr('{function_address}', line_offset={line_offset + line_limit}) to see more lines."
                if has_more else
                "Call auto_note_function(address) to save a behavioral summary of this function."
            ),
        }
    if result.get("note"):
        paginated_result["note"] = result["note"]
    return await _check_mcp_response_size(
        ctx, paginated_result, "decompile_function_with_angr",
        "line_offset and line_limit parameters",
    )

@tool_decorator
async def get_function_cfg(
    ctx: Context,
    function_address: str,
    node_limit: int = 50,
    edge_limit: int = 100,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Retrieves the Control Flow Graph (CFG) for a function (Nodes/Blocks and Edges/Jumps).
    Automatically attempts to handle RVA (offsets) if the exact VA is not found.

    When to use: After decompilation shows complex control flow (many branches, loops, or obfuscation).
    Next steps: get_annotated_disassembly() for instruction-level detail, get_dominators() for dominator tree,
    or analyze_binary_loops() to identify loop structures.

    Args:
        function_address: Hex address of the function (e.g. '0x140001000').
        node_limit: Max basic blocks to return (default 50).
        edge_limit: Max edges to return (default 100).
    """

    node_limit = max(1, min(node_limit, MAX_TOOL_LIMIT))
    edge_limit = max(1, min(edge_limit, MAX_TOOL_LIMIT))
    await ctx.info(f"Requesting CFG for: {function_address}")
    _check_angr_ready("get_function_cfg")
    target_addr = _parse_addr(function_address)
    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _extract_graph():

        _ensure_project_and_cfg()
        bridge.report_progress(5, 100)
        bridge.info("Resolving function...")

        try:
            func, addr_to_use = _resolve_function_address(target_addr)
        except KeyError:
            return {"error": f"No function found at {hex(target_addr)}."}

        bridge.report_progress(30, 100)
        bridge.info("Extracting graph nodes and edges...")
        all_nodes = [{"addr": hex(b.addr), "size": b.size} for b in func.blocks]
        all_edges = [{"src": hex(s.addr), "dst": hex(d.addr)} for s, d in func.graph.edges]
        bridge.report_progress(90, 100)
        bridge.info("Formatting...")
        result = {
            "function_name": func.name,
            "address": hex(addr_to_use),
            "total_nodes": len(all_nodes),
            "total_edges": len(all_edges),
            "nodes": all_nodes[:node_limit],
            "edges": all_edges[:edge_limit],
        }
        if len(all_nodes) > node_limit or len(all_edges) > edge_limit:
            result["_truncation_warning"] = (
                f"CFG truncated: showing {min(len(all_nodes), node_limit)}/{len(all_nodes)} nodes, "
                f"{min(len(all_edges), edge_limit)}/{len(all_edges)} edges. "
                f"Increase node_limit/edge_limit for more."
            )
        return result

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_extract_graph), timeout=ANGR_ANALYSIS_TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError(f"CFG extraction timed out after {ANGR_ANALYSIS_TIMEOUT} seconds.")
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_function_cfg", "node_limit and edge_limit parameters")

@tool_decorator
async def find_path_to_address(
    ctx: Context,
    target_address: str,
    avoid_address: Optional[str] = None,
    enable_veritesting: bool = True,
    use_dfs: bool = True,
    max_steps: int = 2000,
    run_in_background: bool = True
) -> Dict[str, Any]:
    """
    [Phase: advanced] Uses Symbolic Execution to find an input (stdin) that causes execution to reach 'target_address'.

    When to use: When you need to find concrete input that triggers a specific code path (e.g., reaching a vulnerability or a hidden branch).
    Next steps: emulate_function_execution() to test with found input, add_note() to record the solution,
    or find_path_with_custom_input() for more control over symbolic inputs.

    Args:
        target_address: Hex address to reach.
        avoid_address: Optional hex address to avoid.
        enable_veritesting: Enable Veritesting technique.
        use_dfs: Use DFS exploration strategy.
        max_steps: Max execution steps (1-100000). Default 2000.
        run_in_background: Run as background task.
    """

    _check_angr_ready("find_path_to_address")
    target = _parse_addr(target_address, "target_address")
    avoid = _parse_addr(avoid_address, "avoid_address") if avoid_address else None
    max_steps = max(1, min(max_steps, 100_000))

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
    _partial = {}  # shared state for on_timeout callback

    def _solve_path(task_id_for_progress=None, _progress_bridge=None):

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
            steps = 0

            if task_id_for_progress:
                _update_progress(task_id_for_progress, 0, f"Starting Solver... Techniques: {', '.join(techniques_applied)}", bridge=_progress_bridge)

            while len(simgr.active) > 0 and len(simgr.found) == 0 and steps < max_steps:
                # Pruning logic to keep memory low
                if len(simgr.active) > 30:
                    simgr.split(from_stash='active', to_stash='deferred', limit=30)
                # Cap deferred stash to prevent unbounded state accumulation
                deferred = getattr(simgr, 'deferred', None)
                if deferred is not None and len(deferred) > 500:
                    simgr.drop(stash='deferred', filter_func=lambda s: True)

                simgr.step()
                steps += 1
                _partial['steps'] = steps
                _partial['active'] = len(simgr.active)

                if task_id_for_progress and steps % 10 == 0:
                    active = len(simgr.active)
                    deferred = len(simgr.stashed) + len(getattr(simgr, 'deferred', []))
                    percent = min(95, int((steps / max_steps) * 100))
                    msg = f"Solving... Active: {active}, Deferred: {deferred} (Step {steps})"
                    _update_progress(task_id_for_progress, percent, msg, bridge=_progress_bridge)

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
            return {"status": "error", "error_message": str(e)[:200]}

    def _on_timeout_path():
        return {
            "steps_completed": _partial.get('steps', 0),
            "active_states": _partial.get('active', 0),
            "message": f"Timed out after {_partial.get('steps', 0)} steps. No path found.",
            "hint": "Try: smaller max_steps, add avoid addresses, or decompile first.",
        }

    # --- Background Handling ---
    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing solver...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "find_path_to_address"
        })
        task = asyncio.create_task(_run_background_task_wrapper(
            task_id, _solve_path, ctx=ctx,
            timeout=600, on_timeout=_on_timeout_path))
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
    [Phase: advanced] Emulates a function with specific concrete arguments.

    When to use: When you want to observe a function's runtime behavior (return value, stdout) with known inputs.
    Next steps: auto_note_function(address) to save a behavioral summary, emulate_with_watchpoints() to trace
    memory/register access, or hook_function() to stub out problematic callees before re-emulating.
    """

    if args_hex is None:
        args_hex = []
    _MAX_EMU_STEPS = 10_000_000
    if max_steps < 1 or max_steps > _MAX_EMU_STEPS:
        raise ValueError(f"max_steps must be 1-{_MAX_EMU_STEPS}, got {max_steps}")
    _check_angr_ready("emulate_function_execution")
    target = _parse_addr(function_address)
    try:
        args = [_parse_addr(a, "argument") for a in args_hex]
    except ValueError: raise ValueError("Invalid format for arguments.")

    _partial_emu = {}  # shared state for on_timeout callback

    def _core_emulation(task_id_for_progress=None, _progress_bridge=None):

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

                # M-2: Prune active states to prevent state explosion
                if len(simgr.active) > 30:
                    simgr.split(from_stash='active', to_stash='deferred', limit=30)
                deferred = getattr(simgr, 'deferred', None)
                if deferred is not None and len(deferred) > 500:
                    simgr.drop(stash='deferred')

                _partial_emu['steps'] = steps_taken
                try:
                    _partial_emu['stdout'] = simgr.active[0].posix.dumps(1).decode('utf-8', 'ignore') if simgr.active else ""
                except Exception:
                    pass

                if task_id_for_progress:
                    percent = min(99, int((steps_taken / max_steps) * 100))
                    msg = f"Emulating... Step {steps_taken}/{max_steps}"
                    _update_progress(task_id_for_progress, percent, msg, bridge=_progress_bridge)

            if len(simgr.deadended) > 0:
                final = simgr.deadended[0]
                try:
                    # Use the architecture-appropriate return register
                    ret_reg = state.angr_project.arch.register_names.get(
                        state.angr_project.arch.ret_offset, "eax"
                    )
                    ret_val = hex(final.solver.eval(getattr(final.regs, ret_reg)))
                except Exception:
                    logger.debug("emulate_function_execution: failed to resolve return value", exc_info=True)
                    ret_val = "unknown"
                return {
                    "status": "success",
                    "return_value": ret_val,
                    "stdout": final.posix.dumps(1).decode('utf-8', 'ignore'),
                    "steps_taken_count": len(final.history.bbl_addrs),
                    "next_step": (
                        "Call auto_note_function(address) to save a behavioral summary, "
                        "or add_note(content, category='tool_result') to record emulation findings."
                    ),
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
            return {"status": "crash", "error": str(e)[:200]}

    def _on_timeout_emu():
        return {
            "steps_taken": _partial_emu.get('steps', 0),
            "partial_stdout": _partial_emu.get('stdout', ''),
            "message": f"Timed out after {_partial_emu.get('steps', 0)} steps.",
            "hint": "Try: smaller max_steps, or hook_function() to stub complex callees.",
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing emulation...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "emulate_function_execution"
        })
        task = asyncio.create_task(_run_background_task_wrapper(
            task_id, _core_emulation, ctx=ctx,
            timeout=300, on_timeout=_on_timeout_emu))
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
    limit: int = 20,
    resolve_indirect_jumps: bool = False,
    scan_data_refs: bool = False,
    run_in_background: bool = True
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Scans the binary for loops. Uses existing analysis if available to save time.

    When to use: After CFG analysis reveals complex functions, or to find crypto/encoding routines that rely on loops.
    Next steps: decompile_function_with_angr() on functions with many loops, get_function_cfg() for loop structure,
    or extract_function_constants() to find crypto constants in loop bodies.
    """

    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    _check_angr_ready("analyze_binary_loops")

    def _core_logic(task_id_for_progress=None, _progress_bridge=None):
        # Configuration requested by the user
        req_config = {"resolve_jumps": resolve_indirect_jumps, "data_refs": scan_data_refs}

        # Acquire _init_lock to check state, but release before expensive CFGFast
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

        # Expensive CFG build runs outside _init_lock to avoid blocking other tools
        if need_rebuild:
            if task_id_for_progress: _update_progress(task_id_for_progress, 10, "Building/Upgrading Control Flow Graph...", bridge=_progress_bridge)

            new_cfg = project.analyses.CFGFast(
                normalize=True,
                resolve_indirect_jumps=resolve_indirect_jumps,
                data_references=scan_data_refs,
                force_complete_scan=scan_data_refs
            )
            with _init_lock:
                state.set_angr_results(project, new_cfg, None, state.angr_loop_cache_config)
                cfg = new_cfg

        # M-5: Double-check pattern -- build loop cache outside _init_lock,
        # then acquire lock only to store the result.
        need_loop_build = False
        with _init_lock:
            if state.angr_loop_cache is None:
                need_loop_build = True
            else:
                if task_id_for_progress: _update_progress(task_id_for_progress, 90, "Using cached analysis data...", bridge=_progress_bridge)

        if need_loop_build:
            if task_id_for_progress: _update_progress(task_id_for_progress, 80, "Analyzing graph for loops...", bridge=_progress_bridge)

            loop_finder = project.analyses.LoopFinder(kb=project.kb)
            raw_loops = {}

            for loop in loop_finder.loops:
                try:
                    node = cfg.model.get_any_node(loop.entry.addr)
                    if node and node.function_address:
                        func_addr = node.function_address
                        if func_addr not in raw_loops: raw_loops[func_addr] = []

                        block_count = len(loop.body_nodes)  # L10-v10: body_nodes is already a set
                        raw_loops[func_addr].append({
                            "entry": hex(loop.entry.addr),
                            "blocks": block_count,
                            "subloops": bool(loop.subloops)
                        })
                except Exception:
                    logger.debug("analyze_binary_loops: failed to process loop at %s", hex(loop.entry.addr) if hasattr(loop, 'entry') else 'unknown', exc_info=True)
                    continue

            with _init_lock:
                # Double-check: another thread may have built it while we were computing
                if state.angr_loop_cache is None:
                    state.set_angr_results(project, cfg, raw_loops, req_config)

        # Filtering Results
        if task_id_for_progress: _update_progress(task_id_for_progress, 95, "Formatting results...", bridge=_progress_bridge)
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
            "created_at_epoch": time.time(),
            "tool": "analyze_binary_loops"
        })
        task = asyncio.create_task(_run_background_task_wrapper(
            task_id, _core_logic, ctx=ctx, timeout=300))
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
    limit: int = 20
) -> Dict[str, Any]:
    """
    Retrieves Cross-References (Callers/Callees) for a function.
    """

    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info(f"Requesting X-Refs for: {function_address} (Limit: {limit})")
    _check_angr_ready("get_function_xrefs")
    target_addr = _parse_addr(function_address)

    def _get_xrefs():

        _ensure_project_and_cfg()
        # H6: Use snapshot to prevent race condition with concurrent CFG invalidation
        _, cfg_snap = state.get_angr_snapshot()
        if cfg_snap is None:
            return {"error": "CFG not available."}
        try:
            func = cfg_snap.functions[target_addr]
        except KeyError:
            return {"error": f"No function found at {hex(target_addr)}."}

        callers = []
        if target_addr in cfg_snap.functions.callgraph:
             for pred in cfg_snap.functions.callgraph.predecessors(target_addr):
                 try: callers.append({"name": cfg_snap.functions[pred].name, "address": hex(pred)})
                 except Exception: callers.append({"name": "Unknown", "address": hex(pred)})

        callees = []
        if target_addr in cfg_snap.functions.callgraph:
            for succ in cfg_snap.functions.callgraph.successors(target_addr):
                try: callees.append({"name": cfg_snap.functions[succ].name, "address": hex(succ)})
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
    limit: int = 20
) -> Dict[str, Any]:
    """
    Finds all code (Basic Blocks) that can reach the target address (Control Flow Ancestors).
    """

    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info(f"Calculating backward reachability for: {target_address} (Limit: {limit})")
    _check_angr_ready("get_backward_slice")
    target_addr = _parse_addr(target_address)

    def _slice():
        _ensure_project_and_cfg()
        project_snap, cfg_snap = state.get_angr_snapshot()
        if cfg_snap is None:
            return {"error": "CFG not available."}

        try:
            # Get the node. If exact match fails, try to find the block containing this addr
            target_node = cfg_snap.model.get_any_node(target_addr)
            if not target_node:
                block = project_snap.factory.block(target_addr)
                target_node = cfg_snap.model.get_any_node(block.addr)

            if not target_node: return {"error": f"Address {hex(target_addr)} not found in CFG."}

            # Bounded BFS instead of unbounded nx.ancestors
            _MAX_SLICE_NODES = 10_000
            visited = set()
            queue = collections.deque([target_node])
            while queue and len(visited) < _MAX_SLICE_NODES:
                node = queue.popleft()
                if node in visited:
                    continue
                visited.add(node)
                queue.extend(cfg_snap.graph.predecessors(node))
            ancestors = visited - {target_node}

            slice_nodes = []
            for n in ancestors:
                func_name = "Unknown"
                if n.function_address and n.function_address in cfg_snap.functions:
                    func_name = cfg_snap.functions[n.function_address].name
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
    limit: int = 20
) -> Dict[str, Any]:
    """
    Finds all code (Basic Blocks) reachable FROM the source address (Control Flow Descendants).
    """

    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info(f"Calculating forward reachability from: {source_address} (Limit: {limit})")
    _check_angr_ready("get_forward_slice")
    source_addr = _parse_addr(source_address)

    def _slice():
        _ensure_project_and_cfg()
        project_snap, cfg_snap = state.get_angr_snapshot()
        if cfg_snap is None:
            return {"error": "CFG not available."}

        try:
            source_node = cfg_snap.model.get_any_node(source_addr)
            if not source_node:
                block = project_snap.factory.block(source_addr)
                source_node = cfg_snap.model.get_any_node(block.addr)

            if not source_node: return {"error": f"Address {hex(source_addr)} not found in CFG."}

            # Bounded BFS instead of unbounded nx.descendants
            _MAX_SLICE_NODES = 10_000
            visited = set()
            queue = collections.deque([source_node])
            while queue and len(visited) < _MAX_SLICE_NODES:
                node = queue.popleft()
                if node in visited:
                    continue
                visited.add(node)
                queue.extend(cfg_snap.graph.successors(node))
            descendants = visited - {source_node}

            slice_nodes = []
            for n in descendants:
                func_name = "Unknown"
                if n.function_address and n.function_address in cfg_snap.functions:
                    func_name = cfg_snap.functions[n.function_address].name
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
        project_snap, cfg_snap = state.get_angr_snapshot()
        if cfg_snap is None:
            return {"error": "CFG not available."}

        try:
            target_node = cfg_snap.model.get_any_node(target_addr)
            if not target_node:
                # Fallback to block start
                block = project_snap.factory.block(target_addr)
                target_node = cfg_snap.model.get_any_node(block.addr)

            if not target_node: return {"error": "Node not found in CFG."}

            # Dominators are calculated PER FUNCTION in Angr's CFG
            if not target_node.function_address:
                return {"error": "Target node does not belong to a known function, cannot calculate dominators."}

            func = cfg_snap.functions.get(target_node.function_address)
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

    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info(f"Requesting function complexity list. Limit: {limit}, Sort: {sort_by}")

    _check_angr_ready("get_function_complexity_list")

    def _analyze():

        _ensure_project_and_cfg()
        # H6: Use snapshot to prevent race condition with concurrent CFG invalidation
        _, cfg_snap = state.get_angr_snapshot()
        if cfg_snap is None:
            return {"error": "CFG not available."}

        funcs_data = []
        for _addr, func in cfg_snap.functions.items():
            # Filter out library/simprocedures or empty placeholders
            if func.is_simprocedure or func.is_syscall: continue

            # Use O(1) graph methods instead of materializing lists
            try:
                block_count = func.graph.number_of_nodes()
            except Exception:
                try:
                    block_count = len(list(func.blocks))
                except Exception:
                    logger.debug("get_function_complexity_list: failed to count blocks for func at %s", hex(func.addr), exc_info=True)
                    block_count = 0

            # Always compute full data (edge count + entry point) for caching
            try:
                edge_count = func.graph.number_of_edges()
            except Exception:
                try:
                    edge_count = len(list(func.graph.edges))
                except Exception:
                    edge_count = 0

            funcs_data.append({
                "name": func.name,
                "addr": hex(func.addr),
                "address": hex(func.addr),
                "blocks": block_count,
                "edges": edge_count,
                "is_entry_point": (func.addr == state.angr_project.entry),
            })

        return funcs_data

    # Cache the full function list — sorting/compact/limit are presentation-only
    _complexity_cache_key = ()
    cached_funcs = state.result_cache.get("_complexity_list", _complexity_cache_key)
    if cached_funcs is None:
        cached_funcs = await asyncio.to_thread(_analyze)
        state.result_cache.set("_complexity_list", _complexity_cache_key, cached_funcs)

    # Sort
    sort_key = "blocks"
    if not compact and sort_by == "edges":
        sort_key = "edges"
    sorted_funcs = sorted(cached_funcs, key=lambda x: x.get(sort_key, 0), reverse=True)

    # Apply compact/limit as presentation
    if compact:
        top = [{"name": f["name"], "addr": f["addr"], "blocks": f["blocks"]} for f in sorted_funcs[:limit]]
    else:
        top = [dict(f) for f in sorted_funcs[:limit]]

    result = {
        "total_functions_scanned": len(cached_funcs),
        "sort_metric": sort_key,
        "top_functions": top,
    }
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_function_complexity_list", "the 'limit' parameter")

@tool_decorator
async def extract_function_constants(
    ctx: Context,
    function_address: str,
    limit: int = 20
) -> Dict[str, Any]:
    """
    Scans a specific function for hardcoded constants (integers) and string references.
    Useful for extracting potential IOCs, keys, or config data from a target function.
    """

    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info(f"Extracting constants from: {function_address} (Limit: {limit})")

    _check_angr_ready("extract_function_constants")
    target_addr = _parse_addr(function_address)

    def _extract():

        _ensure_project_and_cfg()
        # H6: Use snapshot to prevent race condition with concurrent CFG invalidation
        _, cfg_snap = state.get_angr_snapshot()
        if cfg_snap is None:
            return {"error": "CFG not available."}

        try:
            func = cfg_snap.functions[target_addr]
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
                                logger.debug("extract_function_constants: failed to read string at %s", hex(val), exc_info=True)

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
    limit: int = 20
) -> Dict[str, Any]:
    """
    Identifies global memory addresses read from or written to by the target function.
    Useful for understanding what global state (flags, config, strings) a function interacts with.
    """

    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info(f"Scanning global refs in: {function_address} (Limit: {limit})")

    _check_angr_ready("scan_global_references")
    target_addr = _parse_addr(function_address)

    def _scan_refs():

        # Ensure a project exists via the standard locked path, then try to
        # reuse the existing CFG.  Only build a local CFG with
        # collect_data_references=True if the function isn't found or the
        # existing CFG lacks xref data.
        _ensure_project_and_cfg()
        project, existing_cfg = state.get_angr_snapshot()

        # M10: Try existing CFG first to avoid duplicate expensive builds
        local_cfg = None
        if existing_cfg and target_addr in existing_cfg.functions:
            # Check if xrefs are available from the existing CFG
            try:
                xrefs = project.kb.xrefs.xrefs_by_ins_addr
                if xrefs is not None:
                    local_cfg = existing_cfg
            except (AttributeError, TypeError):
                pass
        if local_cfg is None:
            local_cfg = project.analyses.CFGFast(normalize=True, collect_data_references=True)
            # Note: do NOT replace the global CFG — other tools depend on the
            # original CFG's state (loop cache, function scores, enrichment).
            # The data-reference CFG is used locally only.

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
    limit: int = 20
) -> Dict[str, Any]:
    """
    Scans a function for indirect jumps or calls (dynamic control flow).
    This helps detect switch tables, virtual function calls, or obfuscated control flow.
    """

    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    await ctx.info(f"Scanning for indirect jumps in: {function_address} (Limit: {limit})")

    _check_angr_ready("scan_for_indirect_jumps")
    target_addr = _parse_addr(function_address)

    def _scan_jumps():

        _ensure_project_and_cfg()
        # H6: Use snapshot to prevent race condition with concurrent CFG invalidation
        _, cfg_snap = state.get_angr_snapshot()
        if cfg_snap is None:
            return {"error": "CFG not available."}

        try:
            func = cfg_snap.functions[target_addr]
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
                logger.debug("scan_for_indirect_jumps: VEX lifting failed for block at %s", hex(block.addr), exc_info=True)
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
    _MAX_HEX_INPUT_LEN = 2_000_000  # 2M hex chars = 1MB decoded
    if len(patch_bytes_hex) > _MAX_HEX_INPUT_LEN:
        raise ValueError(
            f"Hex input too large ({len(patch_bytes_hex):,} chars, "
            f"limit {_MAX_HEX_INPUT_LEN:,})."
        )
    try:
        patch_data = bytes.fromhex(patch_bytes_hex)
    except ValueError: raise ValueError("Invalid hex data format.")

    def _patch():

        _ensure_project_and_cfg()
        try:
            state.angr_project.loader.memory.store(addr, patch_data)
            # H1: Invalidate CFG under lock to prevent race conditions with
            # concurrent tools reading the CFG.
            with state._angr_lock:
                state.angr_cfg = None
                state.angr_loop_cache = None
                state.angr_loop_cache_config = None
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
    from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB

    _check_angr_ready("get_cross_reference_map")
    if not function_addresses:
        raise ValueError("function_addresses must contain at least one address.")
    depth = max(1, min(depth, 5))

    _MAX_XREF_ADDRESSES = 10
    _truncated_xref = len(function_addresses) > _MAX_XREF_ADDRESSES
    parsed_addrs = [_parse_addr(a) for a in function_addresses[:_MAX_XREF_ADDRESSES]]

    def _build_xref_map():
        _ensure_project_and_cfg()
        project_snap, cfg_snap = state.get_angr_snapshot()
        if cfg_snap is None:
            return {"error": "CFG not available."}

        callgraph = cfg_snap.functions.callgraph

        # String address lookup (cached)
        string_addrs = state.result_cache.get("_string_addr_map", ())
        if string_addrs is None:
            string_addrs_build: Dict[int, str] = {}
            pe_data = state.pe_data or {}
            for s_obj in (pe_data.get('basic_ascii_strings') or []):
                if isinstance(s_obj, dict):
                    addr = s_obj.get('offset')
                    val = s_obj.get('string', '')
                    if isinstance(addr, int) and val:
                        string_addrs_build[addr] = val[:80]
            string_addrs = string_addrs_build
            # List wrapper required: result_cache API expects list values for get/set
            state.result_cache.set("_string_addr_map", (), [string_addrs])
        elif isinstance(string_addrs, list) and string_addrs:
            string_addrs = string_addrs[0]  # Unwrap from list (see set() above)

        functions_result: Dict[str, Any] = {}

        for target_addr in parsed_addrs:
            try:
                func, addr_used = _resolve_function_address(target_addr)
            except KeyError:
                functions_result[hex(target_addr)] = {"error": "Function not found"}
                continue

            # Callees (depth-aware)
            calls = set()
            suspicious_apis = []
            visited = set()

            def _collect_callees(fn_addr, current_depth):
                if current_depth > depth or fn_addr in visited:
                    return
                if len(visited) > 1000:
                    return
                visited.add(fn_addr)
                try:
                    for callee_addr in callgraph.successors(fn_addr):
                        if callee_addr in cfg_snap.functions:
                            cfunc = cfg_snap.functions[callee_addr]
                            cname = cfunc.name
                            if cname not in calls:
                                calls.add(cname)
                            for api_name, (risk, cat) in CATEGORIZED_IMPORTS_DB.items():
                                if api_name in cname:
                                    suspicious_apis.append({"name": cname, "risk": risk, "category": cat})
                                    break
                            if current_depth < depth:
                                _collect_callees(callee_addr, current_depth + 1)
                except Exception:
                    logger.debug("get_cross_reference_map: failed to collect callees for %s", hex(fn_addr), exc_info=True)

            _collect_callees(addr_used, 1)

            # Callers
            callers = []
            try:
                for caller_addr in callgraph.predecessors(addr_used):
                    if caller_addr in cfg_snap.functions:
                        callers.append(cfg_snap.functions[caller_addr].name)
            except Exception:
                logger.debug("get_cross_reference_map: failed to collect callers for %s", hex(addr_used), exc_info=True)

            # String references
            strings_referenced = []
            try:
                for block in func.blocks:
                    for insn_addr in block.instruction_addrs:
                        xrefs = project_snap.kb.xrefs.xrefs_by_ins_addr.get(insn_addr, [])
                        for xref in xrefs:
                            if xref.memory_data and xref.memory_data.addr in string_addrs:
                                s = string_addrs[xref.memory_data.addr]
                                if s not in strings_referenced:
                                    strings_referenced.append(s)
            except Exception:
                logger.debug("get_cross_reference_map: failed to collect string refs for %s", hex(addr_used), exc_info=True)

            # Complexity
            try:
                block_count = func.graph.number_of_nodes()
                edge_count = func.graph.number_of_edges()
            except Exception:
                logger.debug("get_cross_reference_map: failed to compute complexity for %s", hex(addr_used), exc_info=True)
                block_count = 0
                edge_count = 0

            functions_result[hex(addr_used)] = {
                "name": func.name,
                "calls": sorted(calls)[:30],
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
    if _truncated_xref:
        result["_truncated"] = f"Input truncated from {len(function_addresses)} to {_MAX_XREF_ADDRESSES} addresses"

    return await _check_mcp_response_size(ctx, result, "get_cross_reference_map")


@tool_decorator
async def batch_decompile(
    ctx: Context,
    addresses: List[str],
    max_lines_per_function: int = 30,
    summary_mode: bool = False,
    search: Optional[str] = None,
    context_lines: int = 2,
    case_sensitive: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Decompile multiple functions in a single call. Results
    are cached per-function so subsequent single-function requests hit cache.

    When ``search`` is provided, only functions containing matches are returned,
    with matched lines and context.  Useful for finding a pattern across many
    functions (e.g. ``search="xor"`` to locate crypto routines).

    When to use: After get_function_map identifies several interesting functions,
    batch-decompile them to get a quick overview before deep-diving into specifics.

    Args:
        ctx: The MCP Context object.
        addresses: (List[str]) List of function addresses to decompile (max 20).
        max_lines_per_function: (int) Max lines per function (default 30).
        summary_mode: (bool) If True, return only signature + first 5 lines.
        search: Optional regex pattern to grep for. Only functions with matches
            are included in results.
        context_lines: Number of context lines around each match (default 2, max 20).
        case_sensitive: Whether the search is case-sensitive (default False).

    Returns:
        Decompilation results for each function.
    """
    _check_angr_ready("batch_decompile", require_cfg=False)

    if not addresses:
        raise ValueError("addresses must not be empty.")
    if len(addresses) > MAX_BATCH_DECOMPILE:
        raise ValueError(f"Maximum {MAX_BATCH_DECOMPILE} functions per batch call.")

    # Validate search pattern once before the loop (fail fast)
    if search:
        from arkana.utils import validate_regex_pattern
        validate_regex_pattern(search)

    lines_limit = 5 if summary_mode else max_lines_per_function
    results = []
    succeeded = 0
    failed = 0
    total_search_matches = 0

    for i, addr_str in enumerate(addresses):
        await ctx.report_progress(i, len(addresses))
        target_addr = _parse_addr(addr_str)
        cache_key = _make_decompile_key(target_addr)
        func_result: Dict[str, Any] = {"address": addr_str}

        # Check per-function cache first (no lock needed — _decompile_meta has its own lock)
        cached_lines = _get_cached_lines(cache_key)
        if cached_lines is not None:
            meta = _get_cached_meta(cache_key)
            renamed_lines = apply_function_renames_to_lines(cached_lines)
            renamed_lines = apply_variable_renames_to_lines(renamed_lines, hex(target_addr))
            display_name = get_display_name(hex(target_addr), meta.get("function_name", "unknown"))

            if search:
                sr = search_lines_with_context(renamed_lines, search, context_lines, case_sensitive)
                if sr["total_matches"] == 0:
                    continue  # Skip functions with no matches
                flat = []
                for region in sr["matched_regions"]:
                    flat.extend(region["items"])
                func_result["function_name"] = display_name
                func_result["lines"] = flat
                func_result["match_count"] = sr["total_matches"]
                func_result["total_lines"] = sr["total_lines"]
                func_result["from_cache"] = True
                total_search_matches += sr["total_matches"]
            else:
                page = renamed_lines[:lines_limit]
                func_result["function_name"] = display_name
                func_result["lines"] = page
                func_result["total_lines"] = len(renamed_lines)
                func_result["from_cache"] = True
            results.append(func_result)
            succeeded += 1
            continue

        # Fresh decompilation with per-function timeout.
        # Lock is acquired/released inside the thread worker (not across await).
        def _decompile_one(t_addr=target_addr):
            state._decompile_on_demand_count += 1
            if not state._decompile_lock.acquire(timeout=60):
                state._decompile_on_demand_count -= 1
                return {"error": "Decompilation lock busy — background analysis in progress. Retry shortly."}
            try:
                state._decompile_on_demand_count -= 1
                try:
                    func, addr_used = _resolve_function_address(t_addr)
                except (KeyError, RuntimeError) as e:
                    return {"error": f"No function at {hex(t_addr)}: {e}"}
                project, cfg = state.get_angr_snapshot()
                cfg_model = cfg.model if cfg else None
                try:
                    dec, used_fallback = _safe_decompile(project, func, cfg_model)
                    if dec.codegen is None:
                        return {"error": f"Decompilation produced no output for {hex(t_addr)}."}
                    result = {
                        "function_name": func.name,
                        "address": hex(func.addr),
                        "c_pseudocode": dec.codegen.text,
                    }
                    if used_fallback:
                        result["note"] = DECOMPILE_FALLBACK_NOTE
                    return result
                except Exception as e:
                    return {"error": f"Decompilation failed for {hex(t_addr)}: {e}"}
            finally:
                state._decompile_lock.release()

        try:
            # Note: asyncio.wait_for timeout is advisory — the thread continues
            # after timeout. The decompile lock may be held until the thread completes.
            result = await asyncio.wait_for(
                asyncio.to_thread(_decompile_one),
                timeout=BATCH_DECOMPILE_PER_FUNCTION_TIMEOUT,
            )
        except asyncio.TimeoutError:
            func_result["error"] = f"Timed out after {BATCH_DECOMPILE_PER_FUNCTION_TIMEOUT}s."
            results.append(func_result)
            failed += 1
            continue

        if "error" in result:
            func_result["error"] = result["error"]
            results.append(func_result)
            failed += 1
            continue

        # Cache raw lines and apply renames
        all_lines = result["c_pseudocode"].splitlines()
        _set_decompile_meta(cache_key, {
            "function_name": result["function_name"],
            "address": result["address"],
            "lines": all_lines,
        })
        renamed_lines = apply_function_renames_to_lines(all_lines)
        renamed_lines = apply_variable_renames_to_lines(renamed_lines, hex(target_addr))
        display_name = get_display_name(hex(target_addr), result["function_name"])

        if search:
            sr = search_lines_with_context(renamed_lines, search, context_lines, case_sensitive)
            if sr["total_matches"] == 0:
                continue  # Skip functions with no matches
            flat = []
            for region in sr["matched_regions"]:
                flat.extend(region["items"])
            func_result["function_name"] = display_name
            func_result["lines"] = flat
            func_result["match_count"] = sr["total_matches"]
            func_result["total_lines"] = sr["total_lines"]
            func_result["from_cache"] = False
            total_search_matches += sr["total_matches"]
        else:
            page = renamed_lines[:lines_limit]
            func_result["function_name"] = display_name
            func_result["lines"] = page
            func_result["total_lines"] = len(renamed_lines)
            func_result["from_cache"] = False
        results.append(func_result)
        succeeded += 1

    await ctx.report_progress(len(addresses), len(addresses))
    output = {
        "functions": results,
        "summary": {
            "requested": len(addresses),
            "succeeded": succeeded,
            "failed": failed,
            "summary_mode": summary_mode,
            "max_lines_per_function": lines_limit,
        },
    }
    if search:
        output["_search"] = {
            "pattern": search,
            "functions_with_matches": len([r for r in results if "match_count" in r]),
            "total_matches_across_functions": total_search_matches,
        }
    return await _check_mcp_response_size(ctx, output, "batch_decompile")


# =====================================================================
#  Symbolic Execution Extensions
# =====================================================================

@tool_decorator
async def solve_constraints_for_path(
    ctx: Context,
    target_address: str,
    start_address: Optional[str] = None,
    avoid_addresses: Optional[List[str]] = None,
    max_steps: int = 2000,
    timeout_seconds: int = 120,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Solve constraints to find concrete input that reaches a target address.

    Uses symbolic execution with the angr constraint solver to find concrete values
    for stdin, argv, and symbolic registers that cause execution to reach the target.
    Similar to find_path_to_address but returns detailed constraint solutions.

    When to use: When you need to find specific input values to trigger a code path,
    e.g. for CTF challenges, reaching a vulnerability, or understanding branch conditions.
    Next steps: emulate_function_execution() with solved input, add_note() to record solution.

    Args:
        target_address: Hex address to reach (e.g. '0x401234').
        start_address: Optional start address (default: binary entry point).
        avoid_addresses: List of hex addresses to avoid during exploration.
        max_steps: Maximum simulation steps (100-100000). Default 2000.
        timeout_seconds: Timeout in seconds (10-1800). Default 120.
        run_in_background: Run as background task. Default True.
    """
    _check_angr_ready("solve_constraints_for_path")

    target = _parse_addr(target_address, "target_address")
    start = _parse_addr(start_address, "start_address") if start_address else None
    max_steps = max(100, min(max_steps, MAX_SYMBOLIC_STEPS))
    timeout_seconds = max(10, min(timeout_seconds, 1800))

    avoid_set = {0x0}  # Always avoid null-pointer jumps
    if avoid_addresses:
        for addr_str in avoid_addresses:
            avoid_set.add(_parse_addr(addr_str, "avoid_address"))

    # Validate target is mapped
    if state.angr_project is not None:
        try:
            obj = state.angr_project.loader.find_object_containing(target)
            if not obj:
                valid_min = state.angr_project.loader.min_addr
                valid_max = state.angr_project.loader.max_addr
                return {
                    "error": f"Target address {hex(target)} is unmapped.",
                    "valid_memory_range": f"{hex(valid_min)} - {hex(valid_max)}",
                    "hint": "Check 'sections' or 'function_complexity' to find valid addresses.",
                }
        except Exception:
            pass

    _partial = {}

    def _solve(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()

        stability_options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }

        if start:
            entry_st = state.angr_project.factory.blank_state(
                addr=start, add_options=stability_options
            )
        else:
            entry_st = state.angr_project.factory.entry_state(
                add_options=stability_options
            )

        simgr = state.angr_project.factory.simulation_manager(entry_st)

        # Apply techniques
        simgr.use_technique(angr.exploration_techniques.DFS())
        simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=5000))
        simgr.use_technique(angr.exploration_techniques.Explorer(
            find=target, avoid=list(avoid_set),
        ))

        try:
            steps = 0
            if task_id_for_progress:
                _update_progress(task_id_for_progress, 0, "Starting constraint solver...",
                                 bridge=_progress_bridge)

            while len(simgr.active) > 0 and len(simgr.found) == 0 and steps < max_steps:
                if len(simgr.active) > 30:
                    simgr.split(from_stash='active', to_stash='deferred', limit=30)
                deferred = getattr(simgr, 'deferred', None)
                if deferred is not None and len(deferred) > 500:
                    simgr.drop(stash='deferred', filter_func=lambda s: True)

                simgr.step()
                steps += 1
                _partial['steps'] = steps
                _partial['active'] = len(simgr.active)

                if task_id_for_progress and steps % 10 == 0:
                    active = len(simgr.active)
                    percent = min(95, int((steps / max_steps) * 100))
                    _update_progress(task_id_for_progress, percent,
                                     f"Solving... Active: {active} (Step {steps})",
                                     bridge=_progress_bridge)

            if simgr.found:
                found_state = simgr.found[0]
                solutions = {}

                # Extract stdin solution
                try:
                    stdin_data = found_state.posix.dumps(0)
                    solutions["stdin"] = {
                        "hex": stdin_data.hex(),
                        "ascii": stdin_data.decode('utf-8', 'ignore'),
                        "length": len(stdin_data),
                    }
                except Exception:
                    solutions["stdin"] = None

                # Extract constraint count and summary
                solver = found_state.solver
                constraint_count = len(solver.constraints) if hasattr(solver, 'constraints') else 0

                # Try to evaluate symbolic registers
                reg_solutions = {}
                try:
                    for reg_name in ["eax", "ebx", "ecx", "edx", "rax", "rbx", "rcx", "rdx"]:
                        try:
                            reg_val = getattr(found_state.regs, reg_name, None)
                            if reg_val is not None and reg_val.symbolic:
                                concrete = solver.eval(reg_val)
                                reg_solutions[reg_name] = hex(concrete)
                        except Exception:
                            pass
                except Exception:
                    pass

                return {
                    "status": "solved",
                    "solutions": solutions,
                    "symbolic_registers": reg_solutions if reg_solutions else None,
                    "constraint_count": constraint_count,
                    "steps_taken": steps,
                    "target_reached": hex(target),
                    "start_address": hex(start) if start else "entry_point",
                }

            return {
                "status": "unsolved",
                "message": f"No solution found after {steps} steps.",
                "steps_taken": steps,
                "hint": "Try increasing max_steps, adding avoid_addresses, or changing start_address.",
            }
        except Exception as e:
            return {"status": "error", "error_message": str(e)[:300]}

    def _on_timeout():
        return {
            "steps_completed": _partial.get('steps', 0),
            "active_states": _partial.get('active', 0),
            "message": f"Timed out after {_partial.get('steps', 0)} steps.",
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing constraint solver...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "solve_constraints_for_path",
        })
        task = asyncio.create_task(_run_background_task_wrapper(
            task_id, _solve, ctx=ctx,
            timeout=timeout_seconds, on_timeout=_on_timeout))
        task.add_done_callback(_log_task_exception(task_id))
        return {
            "status": "queued",
            "task_id": task_id,
            "message": f"Constraint solver queued (target={hex(target)}, max_steps={max_steps}).",
        }

    await ctx.info(f"Solving constraints to reach {target_address}")
    result = await asyncio.to_thread(_solve)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "solve_constraints_for_path")


@tool_decorator
async def explore_symbolic_states(
    ctx: Context,
    find_addresses: List[str],
    avoid_addresses: Optional[List[str]] = None,
    start_address: Optional[str] = None,
    strategy: str = "dfs",
    max_steps: int = 2000,
    max_active: int = 30,
    timeout_seconds: int = 120,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: advanced] Explore symbolic execution states with configurable strategy.

    Explores multiple target addresses simultaneously with selectable exploration strategy
    (DFS, BFS, or directed). Reports all found states with their constraint summaries
    and solved input values.

    When to use: When you need to explore multiple code paths simultaneously, e.g.
    finding inputs that reach any of several interesting locations, or when DFS alone
    isn't effective and you want to try BFS or directed exploration.
    Next steps: solve_constraints_for_path() for a specific target, emulate_function_execution()
    to test with found input.

    Args:
        find_addresses: List of hex addresses to search for (max 20).
        avoid_addresses: Optional list of hex addresses to avoid.
        start_address: Optional start address (default: binary entry point).
        strategy: Exploration strategy — 'dfs', 'bfs', or 'directed'. Default 'dfs'.
        max_steps: Maximum simulation steps (100-100000). Default 2000.
        max_active: Maximum concurrent active states (1-100). Default 30.
        timeout_seconds: Timeout in seconds (10-1800). Default 120.
        run_in_background: Run as background task. Default True.
    """
    _check_angr_ready("explore_symbolic_states")

    if not find_addresses:
        return {"error": "find_addresses list cannot be empty."}
    if len(find_addresses) > MAX_SYMBOLIC_FIND_ADDRESSES:
        return {"error": f"Too many find_addresses ({len(find_addresses)}). Maximum is {MAX_SYMBOLIC_FIND_ADDRESSES}."}

    find_addrs = [_parse_addr(a, "find_address") for a in find_addresses]
    start = _parse_addr(start_address, "start_address") if start_address else None
    max_steps = max(100, min(max_steps, MAX_SYMBOLIC_STEPS))
    max_active = max(1, min(max_active, MAX_SYMBOLIC_ACTIVE_STATES))
    timeout_seconds = max(10, min(timeout_seconds, 1800))

    valid_strategies = ("dfs", "bfs", "directed")
    if strategy not in valid_strategies:
        return {"error": f"Invalid strategy '{strategy}'. Use one of: {', '.join(valid_strategies)}"}

    avoid_set = {0x0}
    if avoid_addresses:
        for addr_str in avoid_addresses:
            avoid_set.add(_parse_addr(addr_str, "avoid_address"))

    _partial = {}

    def _explore(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()

        stability_options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }

        if start:
            entry_st = state.angr_project.factory.blank_state(
                addr=start, add_options=stability_options
            )
        else:
            entry_st = state.angr_project.factory.entry_state(
                add_options=stability_options
            )

        simgr = state.angr_project.factory.simulation_manager(entry_st)

        # Apply strategy
        if strategy == "dfs":
            simgr.use_technique(angr.exploration_techniques.DFS())
        elif strategy == "directed":
            # Directed towards the first find address
            try:
                simgr.use_technique(angr.exploration_techniques.Director(
                    cfg_keep_states=True,
                    goal_satisfyingness_ratio=0.1,
                ))
            except Exception:
                # Fallback to DFS if Director fails
                simgr.use_technique(angr.exploration_techniques.DFS())

        simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=5000))
        simgr.use_technique(angr.exploration_techniques.Explorer(
            find=find_addrs, avoid=list(avoid_set),
        ))

        try:
            steps = 0
            if task_id_for_progress:
                _update_progress(task_id_for_progress, 0,
                                 f"Exploring ({strategy})...",
                                 bridge=_progress_bridge)

            while len(simgr.active) > 0 and steps < max_steps:
                # Pruning
                if len(simgr.active) > max_active:
                    simgr.split(from_stash='active', to_stash='deferred', limit=max_active)
                deferred = getattr(simgr, 'deferred', None)
                if deferred is not None and len(deferred) > 500:
                    simgr.drop(stash='deferred', filter_func=lambda s: True)

                simgr.step()
                steps += 1
                _partial['steps'] = steps
                _partial['active'] = len(simgr.active)
                _partial['found'] = len(simgr.found)

                if task_id_for_progress and steps % 10 == 0:
                    active = len(simgr.active)
                    found = len(simgr.found)
                    percent = min(95, int((steps / max_steps) * 100))
                    _update_progress(task_id_for_progress, percent,
                                     f"Exploring... Active: {active}, Found: {found} (Step {steps})",
                                     bridge=_progress_bridge)

            # Process found states
            found_states = []
            for i, fs in enumerate(simgr.found[:10]):  # Cap at 10 found states
                state_info = {
                    "address_reached": hex(fs.addr),
                    "index": i,
                }
                try:
                    stdin_data = fs.posix.dumps(0)
                    state_info["stdin"] = {
                        "hex": stdin_data.hex(),
                        "ascii": stdin_data.decode('utf-8', 'ignore'),
                        "length": len(stdin_data),
                    }
                except Exception:
                    state_info["stdin"] = None

                try:
                    state_info["constraint_count"] = len(fs.solver.constraints)
                except Exception:
                    state_info["constraint_count"] = None

                found_states.append(state_info)

            return {
                "status": "completed",
                "strategy": strategy,
                "found_states": found_states,
                "total_found": len(simgr.found),
                "steps_taken": steps,
                "final_active": len(simgr.active),
                "deadended": len(simgr.deadended) if hasattr(simgr, 'deadended') else 0,
                "errored": len(simgr.errored) if hasattr(simgr, 'errored') else 0,
                "target_addresses": [hex(a) for a in find_addrs],
                "avoided_addresses": [hex(a) for a in avoid_set if a != 0],
            }
        except Exception as e:
            return {"status": "error", "error_message": str(e)[:300]}

    def _on_timeout():
        return {
            "steps_completed": _partial.get('steps', 0),
            "active_states": _partial.get('active', 0),
            "found_so_far": _partial.get('found', 0),
            "message": f"Timed out after {_partial.get('steps', 0)} steps.",
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": f"Initializing explorer ({strategy})...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "explore_symbolic_states",
        })
        task = asyncio.create_task(_run_background_task_wrapper(
            task_id, _explore, ctx=ctx,
            timeout=timeout_seconds, on_timeout=_on_timeout))
        task.add_done_callback(_log_task_exception(task_id))
        return {
            "status": "queued",
            "task_id": task_id,
            "message": f"Explorer queued (strategy={strategy}, targets={len(find_addrs)}, max_steps={max_steps}).",
        }

    await ctx.info(f"Exploring symbolic states ({strategy})")
    result = await asyncio.to_thread(_explore)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "explore_symbolic_states")
