"""Shared helper functions for angr-based analysis tools."""
import threading
from typing import Dict, Any

from pemcp.config import state, logger, ANGR_AVAILABLE

if ANGR_AVAILABLE:
    import angr

# Serialize project/CFG initialization to prevent duplicate expensive builds
_init_lock = threading.Lock()


def _rebuild_project_with_hooks():
    """Rebuild the angr project from scratch and re-apply user hooks.

    Hooking modifies the project's internal ``_sim_procedures`` mapping, which
    can leave stale ``BlockNode`` references in the knowledge base after the
    CFG is invalidated.  Recreating the project and re-applying hooks gives
    ``CFGFast`` a clean slate so every block in the resulting graph is
    consistent.
    """
    proj = angr.Project(state.filepath, auto_load_libs=False)

    for key, info in state.angr_hooks.items():
        ret_raw = info.get("return_value", "void")
        nop = info.get("nop", False)

        ret_val = None
        if ret_raw != "void":
            ret_val = int(ret_raw, 16)
        elif nop:
            ret_val = 0

        # Build the same SimProcedure that hook_function creates
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

        # Install: hex address → proj.hook, symbol name → proj.hook_symbol
        try:
            addr = int(key, 16)
            proj.hook(addr, hook_proc)
        except ValueError:
            try:
                proj.hook_symbol(key, hook_proc)
            except Exception:
                logger.warning("Failed to re-apply hook for '%s' during CFG rebuild", key)

    state.set_angr_results(proj, None, state.angr_loop_cache, state.angr_loop_cache_config)


def _ensure_project_and_cfg():
    """Ensure angr project and CFG are initialized.

    Uses a module-level lock to prevent concurrent callers from both
    creating separate ``angr.Project`` instances (expensive) when the
    first caller has not yet stored its result.
    """
    with _init_lock:
        project, cfg = state.get_angr_snapshot()
        if project is None:
            project = angr.Project(state.filepath, auto_load_libs=False)
            state.set_angr_results(project, None, state.angr_loop_cache, state.angr_loop_cache_config)
        if cfg is None:
            if state.angr_hooks:
                _rebuild_project_with_hooks()
                project, cfg = state.get_angr_snapshot()
            if cfg is None:
                cfg = project.analyses.CFGFast(normalize=True)
                state.set_angr_results(project, cfg, state.angr_loop_cache, state.angr_loop_cache_config)


def _parse_addr(hex_string: str, name: str = "address") -> int:
    """Parse an address string (hex or decimal) to int."""
    try:
        # int(x, 0) auto-detects base: 0x prefix → hex, plain digits → decimal
        return int(hex_string, 0)
    except ValueError:
        raise ValueError(f"Invalid {name} format. Provide a hex string like '0x401000' or a decimal integer.")


def _resolve_function_address(target_addr: int):
    """Resolve a function address, trying RVA-to-VA correction if needed.
    Returns (function_object, address_used).

    Uses a local snapshot of the CFG to avoid races with background workers
    that may replace ``state.angr_cfg`` between the lock release inside
    ``_ensure_project_and_cfg()`` and the attribute access here.
    """
    _ensure_project_and_cfg()
    # Take a local snapshot so a concurrent reset cannot set cfg to None
    _project, cfg = state.get_angr_snapshot()
    if cfg is None:
        raise RuntimeError(
            "CFG is not available. The background analysis may still be running "
            "or was reset. Use check_task_status('startup-angr') to monitor progress."
        )
    addr_to_use = target_addr

    if addr_to_use not in cfg.functions:
        if (state.pe_object
                and hasattr(state.pe_object, 'OPTIONAL_HEADER')
                and state.pe_object.OPTIONAL_HEADER):
            image_base = state.pe_object.OPTIONAL_HEADER.ImageBase
            potential_va = target_addr + image_base
            if potential_va in cfg.functions:
                addr_to_use = potential_va

    func = cfg.functions[addr_to_use]  # may raise KeyError
    return func, addr_to_use


def _raise_on_error_dict(result):
    """Convert an ``{"error": "..."}`` dict return into a RuntimeError.

    Many inner synchronous helpers return error dicts instead of raising.
    Calling this after ``asyncio.to_thread`` standardises the pattern so
    every tool failure surfaces as an exception that the MCP framework
    converts to an ``isError=True`` response.
    """
    if isinstance(result, dict) and "error" in result and len(result) <= 3:
        hint = result.get("hint", "")
        msg = result["error"]
        if hint:
            msg = f"{msg} ({hint})"
        raise RuntimeError(msg)
    return result


def _format_cc_info(func) -> Dict[str, Any]:
    """Format calling convention info for a single angr Function object."""
    info: Dict[str, Any] = {
        "function_name": func.name,
        "address": hex(func.addr),
    }
    cc = func.calling_convention
    if cc:
        info["calling_convention"] = cc.__class__.__name__
        try:
            info["arg_locations"] = [str(a) for a in cc.ARG_REGS[:8]] if hasattr(cc, "ARG_REGS") else []
        except Exception:
            info["arg_locations"] = []
        try:
            info["return_location"] = str(cc.RETURN_VAL) if hasattr(cc, "RETURN_VAL") else None
        except Exception:
            info["return_location"] = None
        # Try to extract argument objects from cc.args
        try:
            if hasattr(cc, 'args') and cc.args:
                info["num_args"] = len(cc.args)
                info["arg_details"] = [str(a) for a in cc.args[:8]]
        except Exception:
            pass
    proto = func.prototype
    if proto:
        try:
            info["prototype"] = str(proto)
        except Exception:
            info["prototype"] = repr(proto)
        try:
            info["num_args"] = len(proto.args) if hasattr(proto, "args") else None
        except Exception:
            info["num_args"] = None

    # Even without a formal CC, provide useful heuristic data
    if not cc and not proto:
        try:
            info["block_count"] = len(list(func.blocks))
            info["has_return"] = func.has_return
            info["is_plt"] = getattr(func, 'is_plt', False)
        except Exception:
            pass

    return info
