"""MCP tools for angr-based disassembly and function recovery."""
import asyncio
from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_angr_ready, _check_mcp_response_size
from pemcp.mcp._angr_helpers import _ensure_project_and_cfg, _parse_addr, _resolve_function_address, _format_cc_info

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
            except Exception:
                pass  # best-effort; results still land on func

            return _format_cc_info(func)

        # Recover all
        try:
            state.angr_project.analyses.CompleteCallingConventionsAnalysis(
                recover_variables=True, cfg=state.angr_cfg.model,
            )
        except Exception as e:
            return {"error": f"CompleteCallingConventionsAnalysis failed: {e}"}

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

        vm = func.variable_manager
        variables = []

        for var in vm.local_variables:
            entry = {
                "name": var.name if hasattr(var, 'name') else str(var),
                "size": getattr(var, 'size', None),
                "category": getattr(var, 'category', None),
                "ident": str(var),
            }
            variables.append(entry)

        params = []
        try:
            for var in vm.input_variables:
                params.append({
                    "name": var.name if hasattr(var, 'name') else str(var),
                    "size": getattr(var, 'size', None),
                    "ident": str(var),
                })
        except Exception:
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

    Args:
        signature_path: Path to .sig/.pat file or directory. If None, uses angr defaults.
        limit: Max identified functions to return.
    """
    await ctx.info("Running FLIRT signature matching")
    _check_angr_ready("identify_library_functions")

    def _flirt():
        _ensure_project_and_cfg()

        # Snapshot names before FLIRT
        names_before = {addr: f.name for addr, f in state.angr_cfg.functions.items()}

        try:
            if signature_path:
                state.angr_project.analyses.FlirtAnalysis(signature_path)
            else:
                state.angr_project.analyses.FlirtAnalysis()
        except AttributeError:
            return {"error": "FlirtAnalysis is not available in this angr version."}
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
        except Exception:
            pass

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
        except Exception:
            pass

        # Build callee lookup from CFG
        call_targets = {}
        try:
            callgraph = state.angr_cfg.functions.callgraph
            if addr_used in callgraph:
                for succ in callgraph.successors(addr_used):
                    if succ in state.angr_cfg.functions:
                        call_targets[succ] = state.angr_cfg.functions[succ].name
        except Exception:
            pass

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
        }

    result = await asyncio.to_thread(_annotate)
    return await _check_mcp_response_size(ctx, result, "get_annotated_disassembly", "the 'limit' parameter")
