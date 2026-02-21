"""MCP tools for angr-based disassembly and function recovery."""
import asyncio
import os
import traceback
from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_angr_ready, _check_mcp_response_size
from pemcp.mcp._angr_helpers import _ensure_project_and_cfg, _parse_addr, _resolve_function_address, _format_cc_info, _raise_on_error_dict

if ANGR_AVAILABLE:
    import angr


# ---- Disassemble Address Range --------------------------------

@tool_decorator
async def disassemble_at_address(
    ctx: Context,
    address: str,
    num_instructions: int = 30,
    num_bytes: int = 0,
) -> Dict[str, Any]:
    """
    Disassembles raw instructions at any address — not limited to known functions.
    Useful for inspecting shellcode, data-as-code, or arbitrary offsets.

    Args:
        address: Hex address to start disassembling (e.g. '0x401000').
        num_instructions: Max instructions to return (default 30). Ignored if num_bytes is set.
        num_bytes: If >0, disassemble this many bytes instead of counting instructions.
    """
    await ctx.info(f"Disassembling at {address}")
    _check_angr_ready("disassemble_at_address")
    target = _parse_addr(address)

    def _disasm():
        _ensure_project_and_cfg()

        kwargs = {}
        if num_bytes > 0:
            kwargs["size"] = min(num_bytes, 4096)
        else:
            kwargs["num_inst"] = min(num_instructions, 200)

        try:
            block = state.angr_project.factory.block(target, **kwargs)
        except Exception as e:
            return {"error": f"Failed to lift block at {hex(target)}: {e}"}

        instructions = []
        for insn in block.capstone.insns:
            instructions.append({
                "address": hex(insn.address),
                "bytes": insn.bytes.hex(),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            })

        # Try to identify which function this belongs to
        func_name = None
        if state.angr_cfg:
            node = state.angr_cfg.model.get_any_node(target)
            if node and node.function_address and node.function_address in state.angr_cfg.functions:
                func_name = state.angr_cfg.functions[node.function_address].name

        return {
            "start_address": hex(target),
            "function": func_name,
            "instruction_count": len(instructions),
            "total_bytes": sum(len(bytes.fromhex(i["bytes"])) for i in instructions),
            "instructions": instructions,
        }

    result = await asyncio.to_thread(_disasm)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "disassemble_at_address")


# ---- Calling Convention Recovery --------------------------------

@tool_decorator
async def get_calling_conventions(
    ctx: Context,
    function_address: Optional[str] = None,
    recover_all: bool = False,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Recovers calling conventions, parameter counts, and return types for functions.

    Args:
        function_address: Hex address of a single function to analyse.
        recover_all: If True, run full-binary calling convention analysis (slow).
        limit: Max functions to return when recover_all is True.
    """
    await ctx.info("Recovering calling conventions")
    _check_angr_ready("get_calling_conventions")

    def _recover():
        _ensure_project_and_cfg()

        if function_address is not None:
            target = _parse_addr(function_address, "function_address")
            try:
                func, addr_used = _resolve_function_address(target)
            except KeyError:
                return {"error": f"No function found at {hex(target)}."}

            try:
                state.angr_project.analyses.CallingConventionAnalysis(func, cfg=state.angr_cfg.model, analyze_callsites=True)
            except Exception as e:
                logger.debug("Skipped item during processing: %s", e)

            return _format_cc_info(func)

        # Recover all — try with variable recovery first, fall back to
        # a lightweight pass if the full analysis fails (variable recovery
        # depends on APIs that may be absent in some angr versions).
        try:
            state.angr_project.analyses.CompleteCallingConventionsAnalysis(
                recover_variables=True, cfg=state.angr_cfg.model,
            )
        except Exception as e:
            logger.debug("Skipped item during processing: %s", e)
            try:
                state.angr_project.analyses.CompleteCallingConventionsAnalysis(
                    recover_variables=False, cfg=state.angr_cfg.model,
                )
            except Exception as e:
                logger.debug("Skipped item during processing: %s", e)
                # Final fallback: run per-function CallingConventionAnalysis
                # in a loop, which is slower but more compatible.
                try:
                    for _addr, _func in list(state.angr_cfg.functions.items())[:500]:
                        if _func.is_simprocedure or _func.is_syscall:
                            continue
                        try:
                            state.angr_project.analyses.CallingConventionAnalysis(
                                _func, cfg=state.angr_cfg.model, analyze_callsites=True,
                            )
                        except Exception as e:
                            logger.debug("Skipped item during processing: %s", e)
                except Exception as e:
                    tb = traceback.format_exc()
                    logger.error("CC recovery failed: %s", tb)
                    return {"error": f"CompleteCallingConventionsAnalysis failed: {type(e).__name__}: {e}"}

        results = []
        for addr, func in state.angr_cfg.functions.items():
            if func.is_simprocedure or func.is_syscall:
                continue
            info = _format_cc_info(func)
            if info.get("calling_convention") or info.get("prototype"):
                results.append(info)
            if len(results) >= limit:
                break

        return {
            "total_recovered": len(results),
            "functions": results,
        }

    result = await asyncio.to_thread(_recover)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_calling_conventions", "the 'limit' parameter")


# ---- Variable Recovery -----------------------------------------

@tool_decorator
async def get_function_variables(
    ctx: Context,
    function_address: str,
    limit: int = 80,
) -> Dict[str, Any]:
    """
    Recovers local variables and parameters for a function.
    Returns variable names, sizes, stack offsets or register locations, and access counts.

    Args:
        function_address: Hex address of the target function.
        limit: Max variables to return.
    """
    await ctx.info(f"Recovering variables for {function_address}")
    _check_angr_ready("get_function_variables")
    target = _parse_addr(function_address)

    def _recover():
        _ensure_project_and_cfg()
        try:
            func, addr_used = _resolve_function_address(target)
        except KeyError:
            return {"error": f"No function found at {hex(target)}."}

        try:
            state.angr_project.analyses.VariableRecoveryFast(func)
        except Exception as e:
            return {"error": f"Variable recovery failed: {e}"}

        # In angr >=9.2 the variable manager lives in the KB, not on
        # the Function object.  Try the KB first, then fall back.
        vm = None
        try:
            vm = state.angr_project.kb.variables[func.addr]
        except (KeyError, TypeError, AttributeError):
            pass
        if vm is None:
            vm = getattr(func, 'variable_manager', None)
        if vm is None:
            return {
                "error": "Variable manager unavailable for this function. "
                         "This is typically caused by an angr version mismatch — "
                         "ensure angr >=9.2.90 is installed.",
            }

        # The VariableManager API changed across angr versions:
        #   - Older: vm.local_variables / vm.input_variables (properties)
        #   - Newer: vm.get_variables() returns all, with .category field
        variables = []
        params = []

        if hasattr(vm, 'get_variables'):
            # Newer angr API — single method returns everything
            try:
                for var in vm.get_variables():
                    entry = {
                        "name": var.name if hasattr(var, 'name') else str(var),
                        "size": getattr(var, 'size', None),
                        "category": getattr(var, 'category', None),
                        "ident": str(var),
                    }
                    cat = getattr(var, 'category', None)
                    if cat == 'parameter' or (hasattr(var, 'is_parameter') and var.is_parameter):
                        params.append(entry)
                    else:
                        variables.append(entry)
            except Exception as e:
                # Some builds have get_variables with different signatures
                logger.debug("Skipped item during processing: %s", e)

        if not variables and not params:
            # Fallback: try the older property-based API
            try:
                for var in vm.local_variables:
                    variables.append({
                        "name": var.name if hasattr(var, 'name') else str(var),
                        "size": getattr(var, 'size', None),
                        "category": getattr(var, 'category', None),
                        "ident": str(var),
                    })
            except (AttributeError, TypeError):
                pass

            try:
                for var in vm.input_variables:
                    params.append({
                        "name": var.name if hasattr(var, 'name') else str(var),
                        "size": getattr(var, 'size', None),
                        "ident": str(var),
                    })
            except (AttributeError, TypeError):
                pass

        return {
            "function_name": func.name,
            "address": hex(addr_used),
            "local_variable_count": len(variables),
            "parameter_count": len(params),
            "parameters": params[:limit],
            "local_variables": variables[:limit],
        }

    result = await asyncio.to_thread(_recover)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_function_variables", "the 'limit' parameter")


# ---- FLIRT Signature Matching ---------------------------------

@tool_decorator
async def identify_library_functions(
    ctx: Context,
    signature_path: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Matches functions against FLIRT signatures to identify known library code
    (statically linked CRT, OpenSSL, zlib, etc.). Reduces analysis noise.

    Automatically loads FLIRT signatures from FLOSS's bundled sigs directory
    if available. Custom signature files (.sig/.pat) can be provided via
    the signature_path parameter.

    Args:
        signature_path: Path to .sig/.pat file or directory. If None, auto-discovers
            signatures from FLOSS sigs and standard locations.
        limit: Max identified functions to return.
    """
    await ctx.info("Running FLIRT signature matching")
    _check_angr_ready("identify_library_functions")

    def _flirt():
        _ensure_project_and_cfg()

        # Snapshot names before FLIRT
        names_before = {addr: f.name for addr, f in state.angr_cfg.functions.items()}

        try:
            # angr >=9.2.199 renamed FlirtAnalysis to Flirt and requires
            # signatures to be pre-loaded via angr.flirt.load_signatures().
            import angr.flirt
            if not angr.flirt.FLIRT_SIGNATURES_BY_ARCH:
                sig_dirs = [
                    "/usr/local/lib/python3.11/site-packages/floss/sigs/",
                    "/usr/local/share/flirt_signatures/",
                ]
                for sd in sig_dirs:
                    if os.path.isdir(sd):
                        try:
                            angr.flirt.load_signatures(sd)
                        except Exception as e:
                            logger.debug("Skipped item during processing: %s", e)

            if signature_path:
                state.angr_project.analyses.Flirt(signature_path)
            else:
                state.angr_project.analyses.Flirt()
        except AttributeError as e:
            # Flirt is built into angr but depends on `nampa`
            # for parsing .sig files and on signature files being present.
            if "nampa" in str(e).lower() or "flirt" in str(e).lower():
                return {
                    "error": f"FLIRT analysis failed: {e}",
                    "hint": "Flirt analysis requires the 'nampa' package and FLIRT signature "
                            "files. Install nampa with: pip install nampa. "
                            "For signature files, clone https://github.com/angr/flirt_signatures "
                            "and pass the path via the signature_path parameter.",
                }
            return {
                "error": f"Flirt analysis failed: {e}",
                "hint": "Flirt analysis is built into angr but may require FLIRT signature "
                        "files. Provide a path to .sig/.pat files via signature_path, or "
                        "clone https://github.com/angr/flirt_signatures.",
            }
        except Exception as e:
            return {"error": f"FLIRT analysis failed: {e}"}

        identified = []
        for addr, func in state.angr_cfg.functions.items():
            old_name = names_before.get(addr, "")
            if func.name != old_name and not func.name.startswith("sub_"):
                identified.append({
                    "address": hex(addr),
                    "identified_name": func.name,
                    "previous_name": old_name,
                })
            if len(identified) >= limit:
                break

        return {
            "total_identified": len(identified),
            "functions": identified,
        }

    result = await asyncio.to_thread(_flirt)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "identify_library_functions", "the 'limit' parameter")


# ---- Annotated Disassembly ------------------------------------

@tool_decorator
async def get_annotated_disassembly(
    ctx: Context,
    function_address: str,
    limit: int = 300,
) -> Dict[str, Any]:
    """
    Returns disassembly annotated with variable names, cross-references, and string
    references for a function. Richer than raw disassembly.

    Args:
        function_address: Hex address of the function.
        limit: Max instructions to return.
    """
    await ctx.info(f"Generating annotated disassembly for {function_address}")
    _check_angr_ready("get_annotated_disassembly")
    func_addr = _parse_addr(function_address)

    def _annotate():
        _ensure_project_and_cfg()
        try:
            func, addr_used = _resolve_function_address(func_addr)
        except KeyError:
            return {"error": f"No function found at {hex(func_addr)}."}

        # Try running variable recovery to get names
        try:
            state.angr_project.analyses.VariableRecoveryFast(func)
        except Exception as e:
            logger.debug("Skipped item during processing: %s", e)

        # Build xref lookup for this function
        xref_map = {}
        try:
            for block in func.blocks:
                for insn_addr in block.instruction_addrs:
                    xrefs = state.angr_project.kb.xrefs.xrefs_by_ins_addr.get(insn_addr, [])
                    for xref in xrefs:
                        if xref.memory_data:
                            xref_map[insn_addr] = {
                                "target": hex(xref.memory_data.addr),
                                "sort": xref.memory_data.sort,
                                "content": str(xref.memory_data.content)[:60] if xref.memory_data.content else None,
                            }
        except Exception as e:
            logger.debug("Skipped item during processing: %s", e)

        # Build callee lookup from CFG
        call_targets = {}
        try:
            callgraph = state.angr_cfg.functions.callgraph
            if addr_used in callgraph:
                for succ in callgraph.successors(addr_used):
                    if succ in state.angr_cfg.functions:
                        call_targets[succ] = state.angr_cfg.functions[succ].name
        except Exception as e:
            logger.debug("Skipped item during processing: %s", e)

        instructions = []
        for block in func.blocks:
            for insn in block.capstone.insns:
                entry = {
                    "address": hex(insn.address),
                    "bytes": insn.bytes.hex(),
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                }

                # Add xref annotation
                if insn.address in xref_map:
                    entry["xref"] = xref_map[insn.address]

                # Add call target annotation
                if insn.mnemonic.startswith("call"):
                    try:
                        target_val = int(insn.op_str, 16)
                        if target_val in call_targets:
                            entry["call_target"] = call_targets[target_val]
                        elif target_val in state.angr_cfg.functions:
                            entry["call_target"] = state.angr_cfg.functions[target_val].name
                    except ValueError:
                        pass

                instructions.append(entry)
                if len(instructions) >= limit:
                    break
            if len(instructions) >= limit:
                break

        return {
            "function_name": func.name,
            "address": hex(addr_used),
            "instruction_count": len(instructions),
            "instructions": instructions,
            "next_step": (
                "Call auto_note_function(address) to save a behavioral summary, "
                "or add_note(content, category='tool_result') to record specific findings."
            ),
        }

    result = await asyncio.to_thread(_annotate)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "get_annotated_disassembly", "the 'limit' parameter")


# ---- Smart Function Map (AI-friendly ranking & grouping) ----

@tool_decorator
async def get_function_map(
    ctx: Context,
    limit: int = 30,
    group_by: str = "category",
    include_details: bool = False,
) -> Dict[str, Any]:
    """
    Ranks all functions by 'interestingness' and groups them by purpose.

    Combines complexity, suspicious API calls, string references, cross-reference
    count, and entry point status into a single score per function. Groups into
    categories like process_injection, networking, crypto, anti_analysis, etc.

    Much more context-efficient than listing all 500+ functions — targets the
    AI directly at the functions worth decompiling.

    Falls back to import-based categorization when angr is not available.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max number of top functions to return. Default 30.
        group_by: (str) 'category' for semantic grouping, 'score' for flat ranked list.
        include_details: (bool) If True, include callee names and string refs per function.

    Returns:
        A dictionary with scored, grouped functions and a suggested starting point.
    """
    from pemcp.mcp._category_maps import CATEGORIZED_IMPORTS_DB, RISK_ORDER, CATEGORY_DESCRIPTIONS
    from pemcp.mcp.server import _check_pe_loaded

    _check_pe_loaded("get_function_map")

    # PE-only fallback when angr is unavailable
    if not ANGR_AVAILABLE or state.angr_project is None or state.angr_cfg is None:
        return await _pe_only_function_map(ctx, limit)

    def _build_map():
        _ensure_project_and_cfg()

        # Build a set of known string addresses for xref matching
        string_addrs: Dict[int, str] = {}
        pe_data = state.pe_data or {}
        for s_list_key in ('basic_ascii_strings',):
            for s_obj in (pe_data.get(s_list_key) or []):
                if isinstance(s_obj, dict):
                    addr = s_obj.get('offset')
                    val = s_obj.get('string', '')
                    if isinstance(addr, int) and val:
                        string_addrs[addr] = val[:60]

        callgraph = state.angr_cfg.functions.callgraph
        entry_addr = state.angr_project.entry

        scored_funcs = []
        for addr, func in state.angr_cfg.functions.items():
            if func.is_simprocedure or func.is_syscall:
                continue

            # Block count (complexity proxy)
            try:
                block_count = len(list(func.blocks))
            except Exception:
                block_count = 0
            if block_count == 0:
                continue

            # Callers (xref in count)
            try:
                callers = list(callgraph.predecessors(addr))
            except Exception:
                callers = []

            # Callees — identify suspicious APIs
            suspicious_callees = []
            callee_names = []
            categories_hit: set = set()
            try:
                for callee_addr in callgraph.successors(addr):
                    if callee_addr in state.angr_cfg.functions:
                        callee_func = state.angr_cfg.functions[callee_addr]
                        cname = callee_func.name
                        callee_names.append(cname)
                        for api_name, (risk, cat) in CATEGORIZED_IMPORTS_DB.items():
                            if api_name in cname:
                                suspicious_callees.append({"name": cname, "risk": risk, "category": cat})
                                categories_hit.add(cat)
                                break
            except Exception:
                pass

            # String references
            string_refs = []
            try:
                for block in func.blocks:
                    for insn_addr in block.instruction_addrs:
                        xrefs = state.angr_project.kb.xrefs.xrefs_by_ins_addr.get(insn_addr, [])
                        for xref in xrefs:
                            if xref.memory_data and xref.memory_data.addr in string_addrs:
                                string_refs.append(string_addrs[xref.memory_data.addr])
            except Exception:
                pass

            # Compute score
            is_entry = (addr == entry_addr)
            score = (
                min(block_count, 100)  # complexity (capped)
                + len(suspicious_callees) * 15
                + min(len(string_refs), 20) * 2
                + min(len(callers), 10)
                + (20 if is_entry else 0)
            )

            # Primary category — pick the highest-risk one
            primary_cat = "main_logic"
            if categories_hit:
                sorted_cats = sorted(
                    categories_hit,
                    key=lambda c: min(
                        (RISK_ORDER.get(r, 3) for api, (r, ct) in CATEGORIZED_IMPORTS_DB.items() if ct == c),
                        default=3,
                    ),
                )
                primary_cat = sorted_cats[0]
            elif block_count >= 20:
                primary_cat = "main_logic"
            else:
                primary_cat = "utility"

            # Build reason string
            reasons = []
            if suspicious_callees:
                api_list = ', '.join(s['name'] for s in suspicious_callees[:3])
                reasons.append(f"calls {api_list}")
            if len(callers) > 3:
                reasons.append(f"{len(callers)} callers")
            if string_refs:
                reasons.append(f"{len(string_refs)} string refs")
            if is_entry:
                reasons.append("entry point")
            reason = '; '.join(reasons) if reasons else f"{block_count} blocks"

            entry = {
                "addr": hex(addr),
                "name": func.name,
                "score": score,
                "reason": reason,
                "blocks": block_count,
                "category": primary_cat,
            }
            if include_details:
                entry["callees"] = callee_names[:15]
                entry["suspicious_apis"] = suspicious_callees
                entry["string_refs"] = string_refs[:10]
                entry["callers"] = [hex(c) for c in callers[:10]]

            scored_funcs.append(entry)

        # Sort by score descending
        scored_funcs.sort(key=lambda x: x['score'], reverse=True)

        return scored_funcs

    scored = await asyncio.to_thread(_build_map)

    # Cache for use by other tools
    state._cached_function_scores = scored

    total_functions = len(scored)
    top = scored[:limit]

    if group_by == "category":
        groups: Dict[str, list] = {}
        for f in top:
            cat = f.get("category", "other")
            groups.setdefault(cat, []).append(f)
        result = {
            "total_functions": total_functions,
            "returned": len(top),
            "groups": groups,
        }
    else:
        result = {
            "total_functions": total_functions,
            "returned": len(top),
            "functions": top,
        }

    # Suggested starting point
    if top:
        best = top[0]
        result["suggested_start"] = (
            f"{best['addr']} ({best['name']}) — score {best['score']}, {best['reason']}"
        )

    return await _check_mcp_response_size(ctx, result, "get_function_map")


async def _pe_only_function_map(ctx: Context, limit: int) -> Dict[str, Any]:
    """Fallback function map using PE import data only (no angr required)."""
    from pemcp.mcp._category_maps import CATEGORIZED_IMPORTS_DB, CATEGORY_DESCRIPTIONS

    pe_data = state.pe_data or {}
    imports = pe_data.get('imports', [])

    by_category: Dict[str, list] = {}
    total_suspicious = 0

    for dll_entry in imports:
        if not isinstance(dll_entry, dict):
            continue
        dll_name = dll_entry.get('dll_name', 'Unknown')
        for sym in dll_entry.get('symbols', []):
            func_name = sym.get('name', '') if isinstance(sym, dict) else ''
            for api_name, (risk, cat) in CATEGORIZED_IMPORTS_DB.items():
                if api_name in func_name:
                    by_category.setdefault(cat, []).append({
                        "dll": dll_name,
                        "function": func_name,
                        "risk": risk,
                    })
                    total_suspicious += 1
                    break

    # Truncate each category
    for cat in by_category:
        by_category[cat] = by_category[cat][:limit]

    result: Dict[str, Any] = {
        "mode": "pe_only",
        "note": "angr is not available — showing import-based categorization only. "
                "No function-level scoring or grouping. Use get_focused_imports() for detailed import analysis.",
        "total_suspicious_apis": total_suspicious,
        "categories": {
            cat: {
                "description": CATEGORY_DESCRIPTIONS.get(cat, cat),
                "count": len(items),
                "apis": [i["function"] for i in items[:5]],
            }
            for cat, items in sorted(by_category.items())
        },
    }

    return await _check_mcp_response_size(ctx, result, "get_function_map")
