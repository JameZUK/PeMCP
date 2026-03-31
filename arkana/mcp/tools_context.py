"""MCP tool for aggregating analysis context about a single function."""
import asyncio

from typing import Dict, Any, Optional, List

from arkana.config import state, logger, Context, ANGR_AVAILABLE
from arkana.constants import (
    MAX_CONTEXT_DECOMPILE_LINES, MAX_CONTEXT_STRINGS, MAX_CONTEXT_XREFS,
    MAX_TOOL_LIMIT,
)
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._angr_helpers import _parse_addr, _resolve_function_address, _ensure_project_and_cfg
from arkana.mcp._rename_helpers import get_display_name


def _gather_context(
    addr_int: int,
    include_decompilation: bool,
    include_xrefs: bool,
    include_strings: bool,
    include_notes: bool,
    max_decompile_lines: int,
) -> Dict[str, Any]:
    """Synchronous worker — runs in thread."""
    addr_hex = hex(addr_int)
    result: Dict[str, Any] = {
        "function_address": addr_hex,
        "function_name": None,
        "triage_status": None,
        "enrichment_score": None,
    }

    # --- Triage status ---
    try:
        result["triage_status"] = state.get_triage_status(addr_hex)
    except Exception as e:
        logger.debug("triage_status lookup failed for %s: %s", addr_hex, e)

    # --- Enrichment score ---
    try:
        scores = getattr(state, "_cached_function_scores", None) or {}
        result["enrichment_score"] = scores.get(addr_hex)
    except Exception as e:
        logger.debug("enrichment_score lookup failed for %s: %s", addr_hex, e)

    # --- Resolve function via angr ---
    func = None
    func_name = None
    if ANGR_AVAILABLE:
        try:
            func, resolved_addr = _resolve_function_address(addr_int)
            addr_int = resolved_addr
            addr_hex = hex(addr_int)
            result["function_address"] = addr_hex
            func_name = get_display_name(addr_hex, func.name if func else None)
            result["function_name"] = func_name
        except (KeyError, RuntimeError) as exc:
            logger.debug("Could not resolve function at %s: %s", addr_hex, exc)
            # Still continue — we can gather notes/triage without angr

    if func_name is None:
        result["function_name"] = get_display_name(addr_hex, None)

    # --- Decompilation ---
    if include_decompilation:
        try:
            from arkana.mcp.tools_angr import _decompile_meta, _decompile_meta_lock, _make_decompile_key
            from arkana.mcp._rename_helpers import apply_function_renames_to_lines, apply_variable_renames_to_lines

            cache_key = _make_decompile_key(addr_int)
            with _decompile_meta_lock:
                meta = _decompile_meta.get(cache_key)
                if meta:
                    _decompile_meta.move_to_end(cache_key)

            if meta and meta.get("lines"):
                lines = list(meta["lines"])
                lines = apply_function_renames_to_lines(lines)
                lines = apply_variable_renames_to_lines(lines, addr_hex)
                capped = max(1, min(max_decompile_lines, MAX_TOOL_LIMIT))
                result["decompilation"] = {
                    "lines": lines[:capped],
                    "total_lines": len(lines),
                    "truncated": len(lines) > capped,
                    "source": "cache",
                }
                if meta.get("note"):
                    result["decompilation"]["note"] = meta["note"]
            else:
                result["decompilation"] = {"available": False, "hint": "Use decompile_function_with_angr() first."}
        except Exception as exc:
            result["decompilation"] = {"available": False, "error": str(exc)[:200]}

    # --- Cross-references ---
    if include_xrefs and func is not None:
        try:
            _project, cfg = state.get_angr_snapshot()
            xref_data: Dict[str, Any] = {"callers": [], "callees": []}

            # Callers
            if hasattr(func, "predecessors") and func.predecessors is not None:
                for pred in list(func.predecessors)[:MAX_CONTEXT_XREFS]:
                    pred_addr = hex(pred.addr)
                    xref_data["callers"].append({
                        "address": pred_addr,
                        "name": get_display_name(pred_addr, pred.name if hasattr(pred, 'name') else None),
                    })

            # Callees
            if cfg is not None:
                # Use transition graph for callees
                if hasattr(func, 'transition_graph'):
                    seen = set()
                    for node in func.transition_graph.nodes():
                        if hasattr(node, 'addr') and node.addr != addr_int:
                            callee_addr = node.addr
                            if callee_addr in cfg.functions and callee_addr not in seen:
                                seen.add(callee_addr)
                                callee = cfg.functions[callee_addr]
                                callee_hex = hex(callee_addr)
                                xref_data["callees"].append({
                                    "address": callee_hex,
                                    "name": get_display_name(callee_hex, callee.name),
                                })
                                if len(seen) >= MAX_CONTEXT_XREFS:
                                    break

            # Suspicious API detection
            from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB
            suspicious_apis = []
            for callee_info in xref_data["callees"]:
                callee_name = callee_info.get("name", "")
                for api_name, (risk, cat) in CATEGORIZED_IMPORTS_DB.items():
                    if api_name.lower() in callee_name.lower():
                        suspicious_apis.append({
                            "api": api_name,
                            "risk": risk,
                            "category": cat,
                            "callee_address": callee_info["address"],
                        })
                        break

            xref_data["suspicious_apis"] = suspicious_apis
            result["xrefs"] = xref_data
        except Exception as exc:
            result["xrefs"] = {"available": False, "error": str(exc)[:200]}

    # --- Strings in function range ---
    if include_strings and func is not None:
        try:
            func_start = func.addr
            func_end = func_start + (func.size or 0)
            strings_in_range = []

            pe_data = state.pe_data or {}

            # Check FLOSS strings
            floss = pe_data.get("floss_analysis") or {}
            for stype in ("decoded_strings", "stack_strings", "static_strings"):
                slist = floss.get(stype, [])
                if isinstance(slist, list):
                    for s in slist:
                        if isinstance(s, dict):
                            # Check if string references this function
                            ref_addr = s.get("decoding_routine_va") or s.get("function_va") or 0
                            if isinstance(ref_addr, str):
                                try:
                                    ref_addr = int(ref_addr, 0)
                                except (ValueError, TypeError):
                                    ref_addr = 0
                            if func_start <= ref_addr < func_end:
                                strings_in_range.append({
                                    "value": (s.get("string") or s.get("value", ""))[:200],
                                    "type": stype.replace("_strings", ""),
                                    "address": hex(ref_addr),
                                })
                                if len(strings_in_range) >= MAX_CONTEXT_STRINGS:
                                    break
                    if len(strings_in_range) >= MAX_CONTEXT_STRINGS:
                        break

            # Check regular strings
            if len(strings_in_range) < MAX_CONTEXT_STRINGS:
                all_strings = pe_data.get("strings_analysis", pe_data.get("strings", []))
                if isinstance(all_strings, list):
                    for s in all_strings:
                        if isinstance(s, dict):
                            s_va = s.get("va") or s.get("address") or 0
                            if isinstance(s_va, str):
                                try:
                                    s_va = int(s_va, 0)
                                except (ValueError, TypeError):
                                    s_va = 0
                            if func_start <= s_va < func_end:
                                strings_in_range.append({
                                    "value": (s.get("string") or s.get("value", ""))[:200],
                                    "type": "static",
                                    "address": hex(s_va),
                                })
                                if len(strings_in_range) >= MAX_CONTEXT_STRINGS:
                                    break

            result["strings"] = {
                "items": strings_in_range,
                "count": len(strings_in_range),
                "capped_at": MAX_CONTEXT_STRINGS,
            }
        except Exception as exc:
            result["strings"] = {"available": False, "error": str(exc)[:200]}

    # --- Notes ---
    if include_notes:
        try:
            all_notes = state.get_notes()
            func_notes = []
            for note in all_notes:
                if isinstance(note, dict):
                    note_addr = note.get("address", "")
                    if note_addr and (note_addr == addr_hex or note_addr == addr_hex.lower()):
                        func_notes.append({
                            "id": note.get("id"),
                            "category": note.get("category", "general"),
                            "content": (note.get("content") or "")[:500],
                            "created_at": note.get("created_at"),
                        })
            result["notes"] = func_notes
        except Exception as e:
            logger.debug("notes lookup failed for %s: %s", addr_hex, e)
            result["notes"] = []

    # --- Complexity ---
    if func is not None:
        try:
            result["complexity"] = {
                "block_count": len(list(func.blocks)) if hasattr(func, 'blocks') else None,
                "size": func.size,
                "is_simprocedure": func.is_simprocedure if hasattr(func, 'is_simprocedure') else False,
                "is_plt": func.is_plt if hasattr(func, 'is_plt') else False,
            }
        except Exception as e:
            logger.debug("complexity lookup failed for %s: %s", addr_hex, e)

    return result


@tool_decorator
async def get_analysis_context_for_function(
    ctx: Context,
    function_address: str,
    include_decompilation: bool = True,
    include_xrefs: bool = True,
    include_strings: bool = True,
    include_notes: bool = True,
    max_decompile_lines: int = 60,
) -> Dict[str, Any]:
    """
    [Phase: analysis] Get comprehensive analysis context for a single function in one call.

    ---compact: aggregate decompile + xrefs + strings + notes + triage for one function | needs: file

    Aggregates decompiled code, cross-references, suspicious API usage, strings, notes,
    triage status, enrichment score, and complexity into a single response. Avoids
    the need to call multiple tools individually.

    When to use: When you want a complete picture of a function's behaviour and context
    before making analysis decisions. Ideal as a first step when investigating a function.
    Next steps: add_note() to record findings, generate_frida_hook_script() to instrument,
    scan_for_vulnerability_patterns() to check for vulns.

    Args:
        function_address: Hex address of the function (e.g. '0x401000').
        include_decompilation: Include decompiled code (from cache). Default True.
        include_xrefs: Include callers/callees and suspicious API detection. Default True.
        include_strings: Include strings within the function's address range. Default True.
        include_notes: Include notes associated with this function address. Default True.
        max_decompile_lines: Max decompiled code lines to include (1-100000). Default 60.
    """
    _check_pe_loaded("get_analysis_context_for_function")

    addr_int = _parse_addr(function_address, "function_address")
    max_decompile_lines = max(1, min(max_decompile_lines, MAX_TOOL_LIMIT))

    result = await asyncio.to_thread(
        _gather_context,
        addr_int,
        include_decompilation,
        include_xrefs,
        include_strings,
        include_notes,
        max_decompile_lines,
    )

    return await _check_mcp_response_size(
        ctx, result, "get_analysis_context_for_function",
        limit_param_info="Disable sections with include_*=False or reduce max_decompile_lines."
    )
