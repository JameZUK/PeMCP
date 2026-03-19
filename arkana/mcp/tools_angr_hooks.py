"""MCP tools for angr function hooking."""
import asyncio
from typing import Dict, Any, Optional

from arkana.config import state, logger, Context, ANGR_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_angr_ready, _check_mcp_response_size
from arkana.mcp._angr_helpers import _ensure_project_and_cfg, _parse_addr, _raise_on_error_dict, _make_return_hook

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
    [Phase: advanced] Hooks a function so future emulation/symbolic execution uses
    the hook instead of real code. Provide a hex address or imported symbol name.

    When to use: Before emulate_function_execution() or find_path_to_address() when
    a callee causes issues (infinite loops, missing APIs, crashes). Stub it out.

    Next steps: emulate_function_execution() or find_path_to_address() with the
    hook active. Use list_hooks() to verify, unhook_function() to remove.

    Args:
        address_or_name: Hex address (e.g. '0x401000') or symbol name (e.g. 'malloc').
        return_value_hex: Hex or decimal value the hooked function should return (e.g. '0x1' or '1'). None = void.
        nop: If True, the function does nothing and returns 0.
    """
    await ctx.info(f"Hooking {address_or_name}")
    _check_angr_ready("hook_function")

    def _hook():
        _ensure_project_and_cfg()
        proj = state.angr_project

        ret_val = None
        if return_value_hex is not None:
            ret_val = int(return_value_hex, 0)
        elif nop:
            ret_val = 0

        # Build a SimProcedure that returns the requested value
        if ret_val is not None:
            hook_proc = _make_return_hook(ret_val, proj.arch.bits)
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
            try:
                proj.hook(addr, hook_proc)
            except Exception as e:
                return {"error": f"Failed to hook address {hex(addr)}: {e}"}
            hook_label = hex(addr)
        else:
            try:
                proj.hook_symbol(address_or_name, hook_proc)
            except Exception as e:
                return {"error": f"Failed to hook symbol '{address_or_name}': {e}"}

        # Register hook in state AFTER successful hooking to avoid ghost entries
        with state._angr_lock:
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
    """
    [Phase: utility] Lists all currently installed function hooks.

    When to use: Before emulation to verify which hooks are active, or to
    audit the current hook state during debugging.
    """
    await ctx.info("Listing hooks")
    _check_angr_ready("list_hooks")

    with state._angr_lock:
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
    [Phase: utility] Removes a previously installed hook to restore original code.

    When to use: After emulation is complete and you want to restore the original
    function behavior for subsequent analysis.

    Args:
        address_or_name: The same address or name used when hooking.
    """
    await ctx.info(f"Unhooking {address_or_name}")
    _check_angr_ready("unhook_function")

    def _unhook():
        _ensure_project_and_cfg()
        proj = state.angr_project

        try:
            addr = int(address_or_name, 0)
            proj.unhook(addr)
            key = hex(addr)
        except ValueError:
            # It's a symbol name.  hook_function() used proj.hook_symbol()
            # which resolves the symbol internally and hooks the resolved
            # address.  proj.loader.find_symbol() uses different resolution
            # and often fails.  Instead, search angr's internal hook table
            # for a SimProcedure whose display_name matches the symbol.
            unhooked = False
            for hooked_addr, sim_proc in list(proj._sim_procedures.items()):
                proc_name = getattr(sim_proc, 'display_name', '') or ''
                cls_name = type(sim_proc).__name__ if sim_proc else ''
                if address_or_name in (proc_name, cls_name):
                    proj.unhook(hooked_addr)
                    unhooked = True
                    break

            if not unhooked:
                # Fallback: check state.angr_hooks for the stored key
                with state._angr_lock:
                    if address_or_name in state.angr_hooks:
                        # The hook was registered but we can't find it in
                        # angr's table — just clean up our tracking
                        state.angr_hooks.pop(address_or_name, None)
                        state.angr_cfg = None
                        state.angr_loop_cache = None
                        return {
                            "status": "success",
                            "message": f"Removed tracking for {address_or_name}. CFG cache cleared.",
                            "note": "Hook was not found in angr's internal table (may have been cleared already).",
                        }
                return {"error": f"No hook found for symbol '{address_or_name}'. Use list_hooks() to see active hooks."}
            key = address_or_name

        with state._angr_lock:
            state.angr_hooks.pop(key, None)
            state.angr_hooks.pop(address_or_name, None)
            state.angr_cfg = None
            state.angr_loop_cache = None

        return {"status": "success", "message": f"Unhooked {address_or_name}. CFG cache cleared."}

    result = await asyncio.to_thread(_unhook)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(ctx, result, "unhook_function")
