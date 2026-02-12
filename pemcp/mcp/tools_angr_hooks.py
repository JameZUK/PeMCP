"""MCP tools for angr function hooking."""
import asyncio
from typing import Dict, Any, Optional

from pemcp.config import state, logger, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_angr_ready, _check_mcp_response_size
from pemcp.mcp._angr_helpers import _ensure_project_and_cfg, _parse_addr, _raise_on_error_dict

if ANGR_AVAILABLE:
    import angr


# ---- Function Hooking ------------------------------------------

@tool_decorator
async def hook_function(
    ctx: Context,
    address_or_name: str,
    return_value_hex: Optional[str] = None,
    nop: bool = False,
) -> Dict[str, Any]:
    """
    Hooks a function so future emulation/symbolic execution uses the hook instead of real code.
    Provide either a hex address or an imported symbol name.

    Args:
        address_or_name: Hex address (e.g. '0x401000') or symbol name (e.g. 'malloc').
        return_value_hex: Hex value the hooked function should return (e.g. '0x1'). None = void.
        nop: If True, the function does nothing and returns 0.
    """
    await ctx.info(f"Hooking {address_or_name}")
    _check_angr_ready("hook_function")

    def _hook():
        _ensure_project_and_cfg()
        proj = state.angr_project

        ret_val = None
        if return_value_hex is not None:
            ret_val = int(return_value_hex, 16)
        elif nop:
            ret_val = 0

        # Build a dynamic SimProcedure that returns the requested value
        if ret_val is not None:
            rv = ret_val
            bits = proj.arch.bits

            class _ReturnHook(angr.SimProcedure):
                def run(self):
                    return self.state.solver.BVV(rv, bits)

            hook_proc = _ReturnHook()
        else:
            class _VoidHook(angr.SimProcedure):
                IS_FUNCTION = True
                def run(self):
                    return

            hook_proc = _VoidHook()

        # Determine if it's an address or symbol name
        is_hex = False
        try:
            addr = int(address_or_name, 0)
            is_hex = True
        except ValueError:
            addr = None

        hook_label = address_or_name
        if is_hex:
            proj.hook(addr, hook_proc)
            hook_label = hex(addr)
        else:
            try:
                proj.hook_symbol(address_or_name, hook_proc)
            except Exception as e:
                return {"error": f"Failed to hook symbol '{address_or_name}': {e}"}

        state.angr_hooks[hook_label] = {
            "target": hook_label,
            "return_value": hex(ret_val) if ret_val is not None else "void",
            "nop": nop,
        }

        # Invalidate CFG since hooks change control flow
        state.angr_cfg = None
        state.angr_loop_cache = None

        return {
            "status": "success",
            "message": f"Hooked {hook_label}. Returns {hex(ret_val) if ret_val is not None else 'void'}. CFG cache cleared.",
        }

    result = await asyncio.to_thread(_hook)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "hook_function")


# ---- List Hooks ------------------------------------------------

@tool_decorator
async def list_hooks(ctx: Context) -> Dict[str, Any]:
    """Lists all currently installed function hooks."""
    await ctx.info("Listing hooks")
    _check_angr_ready("list_hooks")

    hooks_list = list(state.angr_hooks.values())
    proj_hooks_count = 0
    if state.angr_project:
        proj_hooks_count = len(state.angr_project._sim_procedures)

    return {
        "user_hooks": hooks_list,
        "total_user_hooks": len(hooks_list),
        "total_angr_hooks_loaded": proj_hooks_count,
    }


# ---- Unhook Function -------------------------------------------

@tool_decorator
async def unhook_function(ctx: Context, address_or_name: str) -> Dict[str, Any]:
    """
    Removes a previously installed hook.

    Args:
        address_or_name: The same address or name used when hooking.
    """
    await ctx.info(f"Unhooking {address_or_name}")
    _check_angr_ready("unhook_function")

    def _unhook():
        _ensure_project_and_cfg()
        proj = state.angr_project

        try:
            addr = int(address_or_name, 16)
            proj.unhook(addr)
            key = hex(addr)
        except ValueError:
            # It's a symbol name; angr doesn't expose unhook_symbol directly,
            # but we can find the symbol address and unhook that
            try:
                sym = proj.loader.find_symbol(address_or_name)
                if sym:
                    proj.unhook(sym.rebased_addr)
                    key = address_or_name
                else:
                    return {"error": f"Symbol '{address_or_name}' not found."}
            except Exception as e:
                return {"error": f"Failed to unhook '{address_or_name}': {e}"}

        state.angr_hooks.pop(key, None)
        state.angr_hooks.pop(address_or_name, None)
        state.angr_cfg = None
        state.angr_loop_cache = None

        return {"status": "success", "message": f"Unhooked {address_or_name}. CFG cache cleared."}

    result = await asyncio.to_thread(_unhook)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "unhook_function")
