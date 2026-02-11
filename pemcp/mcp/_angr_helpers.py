"""Shared helper functions for angr-based analysis tools."""
from typing import Dict, Any

from pemcp.config import state, logger, ANGR_AVAILABLE

if ANGR_AVAILABLE:
    import angr


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

    state.angr_project = proj


def _ensure_project_and_cfg():
    """Ensure angr project and CFG are initialized."""
    if state.angr_project is None:
        state.angr_project = angr.Project(state.filepath, auto_load_libs=False)
    if state.angr_cfg is None:
        if state.angr_hooks:
            _rebuild_project_with_hooks()
        state.angr_cfg = state.angr_project.analyses.CFGFast(normalize=True)


def _parse_addr(hex_string: str, name: str = "address") -> int:
    """Parse a hex address string to int."""
    try:
        return int(hex_string, 16)
    except ValueError:
        raise ValueError(f"Invalid {name} format. Provide a hex string like '0x401000'.")


def _resolve_function_address(target_addr: int):
    """Resolve a function address, trying RVA-to-VA correction if needed.
    Returns (function_object, address_used)."""
    _ensure_project_and_cfg()
    addr_to_use = target_addr

    if addr_to_use not in state.angr_cfg.functions:
        if (state.pe_object
                and hasattr(state.pe_object, 'OPTIONAL_HEADER')
                and state.pe_object.OPTIONAL_HEADER):
            image_base = state.pe_object.OPTIONAL_HEADER.ImageBase
            potential_va = target_addr + image_base
            if potential_va in state.angr_cfg.functions:
                addr_to_use = potential_va

    func = state.angr_cfg.functions[addr_to_use]  # may raise KeyError
    return func, addr_to_use


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
    return info
