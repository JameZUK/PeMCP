#!/usr/bin/env python
"""Persistent Qiling debug subprocess -- invoked via subprocess from Arkana.

Unlike qiling_runner.py which is one-shot (stdin JSON → stdout JSON → exit),
this runner maintains a persistent JSONL command loop over stdin/stdout.
Each line is a JSON command; each response is a JSON line on stdout.

This script runs inside /app/qiling-venv which has unicorn 1.x.

Protocol:
    → {"action": "init", "filepath": "/path/to/binary", ...}
    ← {"status": "ok", "pc": "0x401000", "registers": {...}, ...}
    → {"action": "step", "count": 1}
    ← {"status": "ok", "pc": "0x401002", ...}
    → {"action": "stop"}
    ← {"status": "ok"}
"""
import json
import os
import sys
import time
import traceback

# --- Reuse helpers from qiling_runner.py (same venv) ---
# Add scripts/ to path so we can import from qiling_runner
_scripts_dir = os.path.dirname(os.path.abspath(__file__))
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

from qiling_runner import (
    _detect_binary_format, _find_rootfs, _init_qiling_for_binary,
    _cleanup_staged_binary, _ql_arch, _ql_os, _check_windows_dlls,
    _ensure_windows_registry, _hex, _validate_file_path,
)

from qiling import Qiling
from qiling.const import QL_VERBOSE

try:
    from qiling.const import QL_INTERCEPT
except ImportError:
    class QL_INTERCEPT:
        CALL = 0
        EXIT = 1

# --- Capstone imports (bundled with Qiling) ---
try:
    from capstone import (
        Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS,
        CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_MIPS32,
        CS_MODE_LITTLE_ENDIAN,
    )
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


# ---------------------------------------------------------------------------
#  Module-level state (persistent across commands within one session)
# ---------------------------------------------------------------------------

_ql = None                   # Active Qiling instance
_arch = ""                   # Detected architecture string
_os_type = ""                # Detected OS string
_staged_path = None          # Staged binary path (for cleanup)
_dll_warning = None          # DLL warning from init

_breakpoints = {}            # id → {address, api_name, conditions, hook_handle, temporary}
_watchpoints = {}            # id → {address, size, type, hook_handle}
_snapshots = {}              # id → {name, note, snapshot_data, pc, insn_count, timestamp}

_bp_counter = 0
_wp_counter = 0
_snap_counter = 0

_insn_count = 0              # Total instructions executed
_stop_reason = ""            # Why execution stopped
_hit_bp_id = None            # Which breakpoint was hit
_hit_wp_id = None            # Which watchpoint was hit
_wp_access_info = None       # Watchpoint access details

# Memory hooks (global, one per type)
_mem_read_hook = None
_mem_write_hook = None

# Capstone disassembler instance (created on init)
_cs = None


# ---------------------------------------------------------------------------
#  Cross-architecture register map
# ---------------------------------------------------------------------------

_REGISTER_MAP = {
    "x86":    ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip", "eflags"],
    "x8664":  ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9",
                "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"],
    "arm":    ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
                "r10", "r11", "r12", "sp", "lr", "pc", "cpsr"],
    "arm64":  [f"x{i}" for i in range(31)] + ["sp", "pc", "nzcv"],
    "mips":   ["v0", "v1", "a0", "a1", "a2", "a3"] +
              [f"t{i}" for i in range(10)] + [f"s{i}" for i in range(8)] +
              ["gp", "sp", "fp", "ra", "pc"],
}

# PC register name per architecture
_PC_REG = {
    "x86": "eip", "x8664": "rip", "arm": "pc", "arm64": "pc", "mips": "pc",
}

# SP register name per architecture
_SP_REG = {
    "x86": "esp", "x8664": "rsp", "arm": "sp", "arm64": "sp", "mips": "sp",
}


# ---------------------------------------------------------------------------
#  Capstone setup
# ---------------------------------------------------------------------------

def _init_capstone(arch):
    """Initialize capstone disassembler for the given architecture."""
    global _cs
    if not CAPSTONE_AVAILABLE:
        _cs = None
        return

    arch_map = {
        "x86":   (CS_ARCH_X86, CS_MODE_32),
        "x8664": (CS_ARCH_X86, CS_MODE_64),
        "arm":   (CS_ARCH_ARM, CS_MODE_ARM),
        "arm64": (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
        "mips":  (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN),
    }
    cs_arch, cs_mode = arch_map.get(arch, (CS_ARCH_X86, CS_MODE_32))
    _cs = Cs(cs_arch, cs_mode)


# ---------------------------------------------------------------------------
#  Helper functions
# ---------------------------------------------------------------------------

def _get_pc():
    """Get current program counter value."""
    reg_name = _PC_REG.get(_arch, "pc")
    try:
        return getattr(_ql.arch.regs, reg_name)
    except (AttributeError, Exception):
        return 0


def _get_registers():
    """Read all registers for the current architecture."""
    regs = {}
    reg_list = _REGISTER_MAP.get(_arch, [])
    for reg in reg_list:
        try:
            val = getattr(_ql.arch.regs, reg)
            regs[reg] = _hex(val)
        except (AttributeError, Exception):
            regs[reg] = None
    return regs


def _disassemble_at(address, count=5):
    """Disassemble up to `count` instructions at `address`."""
    if _cs is None or _ql is None:
        return []

    # Read enough bytes for count instructions (estimate 15 bytes each for x86)
    read_size = count * 15
    try:
        data = _ql.mem.read(address, read_size)
    except Exception:
        return []

    insns = []
    for insn in _cs.disasm(bytes(data), address):
        insns.append({
            "address": _hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex(),
            "size": insn.size,
        })
        if len(insns) >= count:
            break
    return insns


def _get_stack_top(count=8):
    """Read the top N values from the stack."""
    sp_reg = _SP_REG.get(_arch, "sp")
    try:
        sp = getattr(_ql.arch.regs, sp_reg)
    except (AttributeError, Exception):
        return []

    ptr_size = 8 if _arch in ("x8664", "arm64") else 4
    stack = []
    for i in range(count):
        addr = sp + i * ptr_size
        try:
            if ptr_size == 8:
                val = int.from_bytes(_ql.mem.read(addr, 8), "little")
            else:
                val = int.from_bytes(_ql.mem.read(addr, 4), "little")
            stack.append({"offset": _hex(i * ptr_size), "address": _hex(addr), "value": _hex(val)})
        except Exception:
            break
    return stack


def _get_memory_map():
    """Get a summary of the memory map."""
    try:
        regions = _ql.mem.get_mapinfo()
    except Exception:
        return []

    result = []
    for region in regions:
        # Qiling mapinfo returns tuples: (start, end, perms, label, ...)
        if len(region) >= 4:
            result.append({
                "start": _hex(region[0]),
                "end": _hex(region[1]),
                "permissions": region[2] if isinstance(region[2], str) else str(region[2]),
                "label": str(region[3]) if len(region) > 3 else "",
            })
        elif len(region) >= 3:
            result.append({
                "start": _hex(region[0]),
                "end": _hex(region[1]),
                "permissions": region[2] if isinstance(region[2], str) else str(region[2]),
            })
    return result[:100]  # Cap at 100 regions


def _build_execution_state(extra=None):
    """Build the standard execution state response."""
    pc = _get_pc()
    result = {
        "status": "ok",
        "pc": _hex(pc),
        "instructions_executed": _insn_count,
        "registers": _get_registers(),
        "next_instructions": _disassemble_at(pc, 5),
        "stack_top": _get_stack_top(8),
    }
    if extra:
        result.update(extra)
    return result


def _parse_address(addr_str):
    """Parse an address string (hex or decimal) to int."""
    if isinstance(addr_str, int):
        return addr_str
    if isinstance(addr_str, str):
        addr_str = addr_str.strip()
        if addr_str.startswith("0x") or addr_str.startswith("0X"):
            return int(addr_str, 16)
        return int(addr_str)
    raise ValueError(f"Invalid address: {addr_str}")


def _evaluate_condition(conditions):
    """Evaluate breakpoint conditions. Returns True if conditions are met."""
    if not conditions:
        return True

    for cond in conditions:
        cond_type = cond.get("type", "register")
        if cond_type == "register":
            reg = cond.get("register", "")
            expected = cond.get("value")
            operator = cond.get("operator", "==")
            try:
                actual = getattr(_ql.arch.regs, reg)
                expected_val = _parse_address(expected)
                if operator == "==" and actual != expected_val:
                    return False
                elif operator == "!=" and actual == expected_val:
                    return False
                elif operator == ">" and actual <= expected_val:
                    return False
                elif operator == "<" and actual >= expected_val:
                    return False
                elif operator == ">=" and actual < expected_val:
                    return False
                elif operator == "<=" and actual > expected_val:
                    return False
            except (AttributeError, ValueError):
                return False
        elif cond_type == "memory":
            addr = _parse_address(cond.get("address", "0"))
            size = cond.get("size", 4)
            expected = _parse_address(cond.get("value", "0"))
            operator = cond.get("operator", "==")
            try:
                data = _ql.mem.read(addr, size)
                actual = int.from_bytes(data, "little")
                if operator == "==" and actual != expected:
                    return False
                elif operator == "!=" and actual == expected:
                    return False
            except Exception:
                return False
    return True


# ---------------------------------------------------------------------------
#  Instruction counter hook
# ---------------------------------------------------------------------------

def _instruction_counter_hook(ql, address, size):
    """Global code hook that increments instruction count."""
    global _insn_count
    _insn_count += 1


# ---------------------------------------------------------------------------
#  Breakpoint callbacks
# ---------------------------------------------------------------------------

def _address_breakpoint_callback(ql):
    """Called when an address breakpoint is hit."""
    global _stop_reason, _hit_bp_id
    pc = _get_pc()
    for bp_id, bp in _breakpoints.items():
        if bp.get("address") == pc:
            if _evaluate_condition(bp.get("conditions")):
                _stop_reason = "breakpoint_hit"
                _hit_bp_id = bp_id
                ql.emu_stop()
                return


def _make_address_bp_callback(bp_id, address, conditions):
    """Create a breakpoint callback for a specific address."""
    def callback(ql):
        global _stop_reason, _hit_bp_id
        if _evaluate_condition(conditions):
            _stop_reason = "breakpoint_hit"
            _hit_bp_id = bp_id
            ql.emu_stop()
    return callback


def _make_api_bp_callback(bp_id, api_name, conditions):
    """Create an API breakpoint callback."""
    def callback(ql, address, params):
        global _stop_reason, _hit_bp_id
        if _evaluate_condition(conditions):
            _stop_reason = "breakpoint_hit"
            _hit_bp_id = bp_id
            ql.emu_stop()
    return callback


def _make_temp_bp_callback():
    """Create a temporary breakpoint callback that fires once."""
    def callback(ql):
        global _stop_reason
        _stop_reason = "temporary_breakpoint"
        ql.emu_stop()
    return callback


# ---------------------------------------------------------------------------
#  Watchpoint callbacks
# ---------------------------------------------------------------------------

def _mem_write_callback(ql, access, address, size, value):
    """Global memory write callback — checks all write watchpoints."""
    global _stop_reason, _hit_wp_id, _wp_access_info
    for wp_id, wp in _watchpoints.items():
        if wp.get("type") not in ("write", "readwrite"):
            continue
        wp_start = wp["address"]
        wp_end = wp_start + wp["size"]
        if address < wp_end and address + size > wp_start:
            _stop_reason = "watchpoint_hit"
            _hit_wp_id = wp_id
            _wp_access_info = {
                "access_type": "write",
                "access_address": _hex(address),
                "access_size": size,
                "value_written": _hex(value),
            }
            ql.emu_stop()
            return


def _mem_read_callback(ql, access, address, size, value):
    """Global memory read callback — checks all read watchpoints."""
    global _stop_reason, _hit_wp_id, _wp_access_info
    for wp_id, wp in _watchpoints.items():
        if wp.get("type") not in ("read", "readwrite"):
            continue
        wp_start = wp["address"]
        wp_end = wp_start + wp["size"]
        if address < wp_end and address + size > wp_start:
            _stop_reason = "watchpoint_hit"
            _hit_wp_id = wp_id
            _wp_access_info = {
                "access_type": "read",
                "access_address": _hex(address),
                "access_size": size,
            }
            ql.emu_stop()
            return


def _install_mem_hooks():
    """Install global memory hooks if watchpoints exist."""
    global _mem_read_hook, _mem_write_hook
    has_read = any(wp.get("type") in ("read", "readwrite") for wp in _watchpoints.values())
    has_write = any(wp.get("type") in ("write", "readwrite") for wp in _watchpoints.values())

    if has_write and _mem_write_hook is None:
        try:
            _mem_write_hook = _ql.hook_mem_write(_mem_write_callback)
        except Exception:
            pass
    if has_read and _mem_read_hook is None:
        try:
            _mem_read_hook = _ql.hook_mem_read(_mem_read_callback)
        except Exception:
            pass


def _uninstall_mem_hooks():
    """Uninstall global memory hooks if no watchpoints remain."""
    global _mem_read_hook, _mem_write_hook
    has_read = any(wp.get("type") in ("read", "readwrite") for wp in _watchpoints.values())
    has_write = any(wp.get("type") in ("write", "readwrite") for wp in _watchpoints.values())

    if not has_write and _mem_write_hook is not None:
        try:
            _ql.hook_del(_mem_write_hook)
        except Exception:
            pass
        _mem_write_hook = None
    if not has_read and _mem_read_hook is not None:
        try:
            _ql.hook_del(_mem_read_hook)
        except Exception:
            pass
        _mem_read_hook = None


# ---------------------------------------------------------------------------
#  Command handlers
# ---------------------------------------------------------------------------

def cmd_init(cmd):
    """Initialize Qiling for the given binary, pause at entry point."""
    global _ql, _arch, _os_type, _staged_path, _dll_warning, _insn_count
    global _breakpoints, _watchpoints, _snapshots
    global _bp_counter, _wp_counter, _snap_counter
    global _stop_reason, _hit_bp_id, _hit_wp_id, _wp_access_info
    global _mem_read_hook, _mem_write_hook

    filepath = cmd["filepath"]
    rootfs_path = cmd.get("rootfs_path")

    _validate_file_path(filepath)

    ql, os_type, arch, fmt_desc, init_result, staged_path = _init_qiling_for_binary(filepath, rootfs_path)
    if ql is None:
        return init_result  # Error dict

    _ql = ql
    _arch = arch
    _os_type = os_type
    _staged_path = staged_path
    _dll_warning = init_result if isinstance(init_result, str) else None
    _insn_count = 0
    _breakpoints = {}
    _watchpoints = {}
    _snapshots = {}
    _bp_counter = 0
    _wp_counter = 0
    _snap_counter = 0
    _stop_reason = ""
    _hit_bp_id = None
    _hit_wp_id = None
    _wp_access_info = None
    _mem_read_hook = None
    _mem_write_hook = None

    # Initialize capstone disassembler
    _init_capstone(arch)

    # Install global instruction counter
    _ql.hook_code(_instruction_counter_hook)

    pc = _get_pc()
    result = {
        "status": "ok",
        "pc": _hex(pc),
        "architecture": arch,
        "os_type": os_type,
        "format": fmt_desc,
        "registers": _get_registers(),
        "next_instructions": _disassemble_at(pc, 5),
        "memory_map": _get_memory_map(),
    }
    if _dll_warning:
        result["warning"] = _dll_warning
    return result


def cmd_step(cmd):
    """Execute N instructions."""
    global _stop_reason, _hit_bp_id, _hit_wp_id, _wp_access_info

    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    count = max(1, min(cmd.get("count", 1), 10000))
    _stop_reason = ""
    _hit_bp_id = None
    _hit_wp_id = None
    _wp_access_info = None

    try:
        _ql.run(count=count)
    except Exception as e:
        err_str = str(e)
        # Qiling may raise on program exit or unmapped access — expected
        if "unmapped" in err_str.lower() or "invalid" in err_str.lower():
            return _build_execution_state({"stop_reason": "memory_error", "error_detail": err_str[:500]})
        return _build_execution_state({"stop_reason": "exception", "error_detail": err_str[:500]})

    extra = {}
    if _stop_reason:
        extra["stop_reason"] = _stop_reason
        if _hit_bp_id is not None:
            extra["breakpoint_id"] = _hit_bp_id
        if _hit_wp_id is not None:
            extra["watchpoint_id"] = _hit_wp_id
        if _wp_access_info:
            extra.update(_wp_access_info)
    else:
        extra["stop_reason"] = "step_completed"
    return _build_execution_state(extra)


def cmd_step_over(cmd):
    """Step over a call instruction (set temp BP after call, then continue)."""
    global _stop_reason, _hit_bp_id

    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    pc = _get_pc()
    insns = _disassemble_at(pc, 1)

    if not insns:
        # Can't disassemble — just step 1
        return cmd_step({"count": 1})

    insn = insns[0]
    mnemonic = insn["mnemonic"].lower()

    # Check if it's a call instruction
    is_call = mnemonic in ("call", "bl", "blx", "blr", "jal", "jalr", "callq")
    if not is_call:
        # Not a call — just step 1
        return cmd_step({"count": 1})

    # Set temporary breakpoint at the instruction after the call
    next_addr = _parse_address(insn["address"]) + insn["size"]
    _stop_reason = ""
    _hit_bp_id = None

    temp_callback = _make_temp_bp_callback()
    try:
        hook = _ql.hook_address(temp_callback, next_addr)
    except Exception as e:
        return {"error": f"Failed to set temp breakpoint: {e}"}

    max_insns = cmd.get("max_instructions", 1_000_000)
    try:
        _ql.run(count=max_insns)
    except Exception:
        pass

    # Remove temp hook
    try:
        _ql.hook_del(hook)
    except Exception:
        pass

    extra = {"stop_reason": "step_over_completed"}
    if _stop_reason == "breakpoint_hit":
        extra["stop_reason"] = "breakpoint_hit"
        extra["breakpoint_id"] = _hit_bp_id
    elif _stop_reason == "watchpoint_hit":
        extra["stop_reason"] = "watchpoint_hit"
        extra["watchpoint_id"] = _hit_wp_id
        if _wp_access_info:
            extra.update(_wp_access_info)
    return _build_execution_state(extra)


def cmd_continue(cmd):
    """Continue execution until breakpoint, watchpoint, or max instructions."""
    global _stop_reason, _hit_bp_id, _hit_wp_id, _wp_access_info

    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    max_insns = max(1, min(cmd.get("max_instructions", 10_000_000), 10_000_000))
    _stop_reason = ""
    _hit_bp_id = None
    _hit_wp_id = None
    _wp_access_info = None

    try:
        _ql.run(count=max_insns)
    except Exception as e:
        err_str = str(e)
        if "unmapped" in err_str.lower() or "exit" in err_str.lower():
            return _build_execution_state({"stop_reason": "exited", "exit_reason": err_str[:500]})
        return _build_execution_state({"stop_reason": "exception", "error_detail": err_str[:500]})

    extra = {}
    if _stop_reason:
        extra["stop_reason"] = _stop_reason
        if _hit_bp_id is not None:
            extra["breakpoint_id"] = _hit_bp_id
        if _hit_wp_id is not None:
            extra["watchpoint_id"] = _hit_wp_id
        if _wp_access_info:
            extra.update(_wp_access_info)
    else:
        extra["stop_reason"] = "max_instructions_reached"
        extra["max_instructions"] = max_insns
    return _build_execution_state(extra)


def cmd_run_until(cmd):
    """Set a temporary breakpoint at address and continue."""
    global _stop_reason, _hit_bp_id, _hit_wp_id, _wp_access_info

    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    address = _parse_address(cmd["address"])
    max_insns = max(1, min(cmd.get("max_instructions", 10_000_000), 10_000_000))
    _stop_reason = ""
    _hit_bp_id = None
    _hit_wp_id = None
    _wp_access_info = None

    temp_callback = _make_temp_bp_callback()
    try:
        hook = _ql.hook_address(temp_callback, address)
    except Exception as e:
        return {"error": f"Failed to set temp breakpoint at {_hex(address)}: {e}"}

    try:
        _ql.run(count=max_insns)
    except Exception as e:
        err_str = str(e)
        if "unmapped" in err_str.lower() or "exit" in err_str.lower():
            return _build_execution_state({"stop_reason": "exited", "exit_reason": err_str[:500]})
        return _build_execution_state({"stop_reason": "exception", "error_detail": err_str[:500]})
    finally:
        try:
            _ql.hook_del(hook)
        except Exception:
            pass

    extra = {}
    if _stop_reason == "temporary_breakpoint":
        extra["stop_reason"] = "address_reached"
        extra["target_address"] = _hex(address)
    elif _stop_reason == "breakpoint_hit":
        extra["stop_reason"] = "breakpoint_hit"
        extra["breakpoint_id"] = _hit_bp_id
    elif _stop_reason == "watchpoint_hit":
        extra["stop_reason"] = "watchpoint_hit"
        extra["watchpoint_id"] = _hit_wp_id
        if _wp_access_info:
            extra.update(_wp_access_info)
    else:
        extra["stop_reason"] = "max_instructions_reached"
        extra["max_instructions"] = max_insns
    return _build_execution_state(extra)


def cmd_set_breakpoint(cmd):
    """Register a breakpoint (address, API, or conditional)."""
    global _bp_counter

    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    address = cmd.get("address")
    api_name = cmd.get("api_name")
    conditions = cmd.get("conditions", [])

    if not address and not api_name:
        return {"error": "Must provide 'address' or 'api_name' for breakpoint"}

    _bp_counter += 1
    bp_id = _bp_counter

    bp_entry = {
        "id": bp_id,
        "conditions": conditions,
        "temporary": False,
    }

    if address is not None:
        addr_int = _parse_address(address)
        bp_entry["address"] = addr_int
        bp_entry["address_hex"] = _hex(addr_int)
        callback = _make_address_bp_callback(bp_id, addr_int, conditions)
        try:
            hook = _ql.hook_address(callback, addr_int)
            bp_entry["hook_handle"] = hook
        except Exception as e:
            return {"error": f"Failed to set breakpoint at {_hex(addr_int)}: {e}"}
    elif api_name:
        bp_entry["api_name"] = api_name
        callback = _make_api_bp_callback(bp_id, api_name, conditions)
        try:
            _ql.os.set_api(api_name, callback, QL_INTERCEPT.CALL)
            bp_entry["hook_handle"] = api_name  # For removal
        except Exception as e:
            return {"error": f"Failed to set API breakpoint for '{api_name}': {e}"}

    _breakpoints[bp_id] = bp_entry
    return {
        "status": "ok",
        "breakpoint_id": bp_id,
        "type": "api" if api_name else "address",
        "address": bp_entry.get("address_hex"),
        "api_name": bp_entry.get("api_name"),
        "total_breakpoints": len(_breakpoints),
    }


def cmd_remove_breakpoint(cmd):
    """Remove a breakpoint by ID."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    bp_id = cmd.get("breakpoint_id")
    if bp_id not in _breakpoints:
        return {"error": f"Breakpoint {bp_id} not found"}

    bp = _breakpoints.pop(bp_id)
    hook = bp.get("hook_handle")
    if hook is not None:
        try:
            if bp.get("api_name"):
                # API hooks can't be easily removed in Qiling — best effort
                pass
            else:
                _ql.hook_del(hook)
        except Exception:
            pass

    return {"status": "ok", "breakpoint_id": bp_id, "total_breakpoints": len(_breakpoints)}


def cmd_set_watchpoint(cmd):
    """Register a memory watchpoint."""
    global _wp_counter

    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    address = _parse_address(cmd["address"])
    size = max(1, min(cmd.get("size", 4), 1_048_576))  # 1MB max
    wp_type = cmd.get("type", "write")
    if wp_type not in ("read", "write", "readwrite"):
        return {"error": f"Invalid watchpoint type: {wp_type}. Must be 'read', 'write', or 'readwrite'"}

    _wp_counter += 1
    wp_id = _wp_counter

    _watchpoints[wp_id] = {
        "id": wp_id,
        "address": address,
        "address_hex": _hex(address),
        "size": size,
        "type": wp_type,
    }

    # Install global memory hooks if needed
    _install_mem_hooks()

    return {
        "status": "ok",
        "watchpoint_id": wp_id,
        "address": _hex(address),
        "size": size,
        "type": wp_type,
        "total_watchpoints": len(_watchpoints),
    }


def cmd_remove_watchpoint(cmd):
    """Remove a watchpoint by ID."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    wp_id = cmd.get("watchpoint_id")
    if wp_id not in _watchpoints:
        return {"error": f"Watchpoint {wp_id} not found"}

    _watchpoints.pop(wp_id)
    _uninstall_mem_hooks()

    return {"status": "ok", "watchpoint_id": wp_id, "total_watchpoints": len(_watchpoints)}


def cmd_list_breakpoints(cmd):
    """Return all breakpoints and watchpoints."""
    bps = []
    for bp_id, bp in _breakpoints.items():
        bps.append({
            "id": bp_id,
            "type": "api" if bp.get("api_name") else "address",
            "address": bp.get("address_hex"),
            "api_name": bp.get("api_name"),
            "conditions": bp.get("conditions", []),
        })

    wps = []
    for wp_id, wp in _watchpoints.items():
        wps.append({
            "id": wp_id,
            "address": wp.get("address_hex"),
            "size": wp.get("size"),
            "type": wp.get("type"),
        })

    return {
        "status": "ok",
        "breakpoints": bps,
        "watchpoints": wps,
        "total_breakpoints": len(bps),
        "total_watchpoints": len(wps),
    }


def cmd_read_state(cmd):
    """Read full execution state: registers, PC, stack, memory map, next insns."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    pc = _get_pc()
    return {
        "status": "ok",
        "pc": _hex(pc),
        "architecture": _arch,
        "os_type": _os_type,
        "instructions_executed": _insn_count,
        "registers": _get_registers(),
        "next_instructions": _disassemble_at(pc, cmd.get("disasm_count", 5)),
        "stack_top": _get_stack_top(cmd.get("stack_count", 8)),
        "memory_map": _get_memory_map(),
        "breakpoint_count": len(_breakpoints),
        "watchpoint_count": len(_watchpoints),
        "snapshot_count": len(_snapshots),
    }


def cmd_read_memory(cmd):
    """Read N bytes at address, return hex and optional disassembly."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    address = _parse_address(cmd["address"])
    length = max(1, min(cmd.get("length", 256), 1_048_576))  # 1MB max
    fmt = cmd.get("format", "hex")

    try:
        data = bytes(_ql.mem.read(address, length))
    except Exception as e:
        return {"error": f"Failed to read memory at {_hex(address)}: {e}"}

    result = {
        "status": "ok",
        "address": _hex(address),
        "length": len(data),
        "hex": data.hex(),
    }

    if fmt == "disasm" and _cs:
        insns = []
        for insn in _cs.disasm(data, address):
            insns.append({
                "address": _hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
            })
            if len(insns) >= 100:
                break
        result["disassembly"] = insns

    # ASCII representation
    ascii_repr = ""
    for b in data[:1024]:
        ascii_repr += chr(b) if 32 <= b < 127 else "."
    if ascii_repr:
        result["ascii"] = ascii_repr

    return result


def cmd_write_memory(cmd):
    """Write bytes to memory at address."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    address = _parse_address(cmd["address"])
    hex_bytes = cmd.get("hex_bytes", "")
    if not hex_bytes or len(hex_bytes) > 4_194_304:  # 2MB hex = 1MB data
        return {"error": "hex_bytes required and must be ≤2MB hex string"}
    if len(hex_bytes) % 2 != 0:
        return {"error": "hex_bytes must have even length"}

    try:
        data = bytes.fromhex(hex_bytes)
    except ValueError as e:
        return {"error": f"Invalid hex: {e}"}

    try:
        _ql.mem.write(address, data)
    except Exception as e:
        return {"error": f"Failed to write memory at {_hex(address)}: {e}"}

    return {
        "status": "ok",
        "address": _hex(address),
        "bytes_written": len(data),
    }


def cmd_write_register(cmd):
    """Write a value to a register."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    reg = cmd.get("register", "").lower()
    value = _parse_address(cmd.get("value", 0))

    valid_regs = set(_REGISTER_MAP.get(_arch, []))
    if reg not in valid_regs:
        return {"error": f"Invalid register '{reg}' for {_arch}. Valid: {sorted(valid_regs)}"}

    try:
        setattr(_ql.arch.regs, reg, value)
    except Exception as e:
        return {"error": f"Failed to write register {reg}: {e}"}

    # Read back to confirm
    try:
        actual = getattr(_ql.arch.regs, reg)
    except Exception:
        actual = value

    return {
        "status": "ok",
        "register": reg,
        "value": _hex(actual),
    }


def cmd_snapshot_save(cmd):
    """Save a snapshot of the current execution state."""
    global _snap_counter

    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    _snap_counter += 1
    snap_id = _snap_counter

    name = cmd.get("name", f"snapshot_{snap_id}")
    note = cmd.get("note", "")

    try:
        snapshot_data = _ql.save()
    except Exception as e:
        return {"error": f"Failed to save snapshot: {e}"}

    pc = _get_pc()
    _snapshots[snap_id] = {
        "id": snap_id,
        "name": name,
        "note": note,
        "snapshot_data": snapshot_data,
        "pc": _hex(pc),
        "insn_count": _insn_count,
        "registers": _get_registers(),
        "timestamp": time.time(),
    }

    return {
        "status": "ok",
        "snapshot_id": snap_id,
        "name": name,
        "pc": _hex(pc),
        "instructions_executed": _insn_count,
        "total_snapshots": len(_snapshots),
    }


def cmd_snapshot_restore(cmd):
    """Restore execution state from a snapshot."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    snap_id = cmd.get("snapshot_id")
    if snap_id not in _snapshots:
        return {"error": f"Snapshot {snap_id} not found"}

    snap = _snapshots[snap_id]
    try:
        _ql.restore(snap["snapshot_data"])
    except Exception as e:
        return {"error": f"Failed to restore snapshot: {e}"}

    return _build_execution_state({
        "stop_reason": "snapshot_restored",
        "snapshot_id": snap_id,
        "snapshot_name": snap["name"],
    })


def cmd_snapshot_list(cmd):
    """Return all snapshots with metadata."""
    snaps = []
    for snap_id, snap in _snapshots.items():
        snaps.append({
            "id": snap_id,
            "name": snap.get("name"),
            "note": snap.get("note", ""),
            "pc": snap.get("pc"),
            "instructions_executed": snap.get("insn_count"),
            "timestamp": snap.get("timestamp"),
            "registers": snap.get("registers"),
        })

    return {
        "status": "ok",
        "snapshots": snaps,
        "total_snapshots": len(snaps),
    }


def cmd_snapshot_diff(cmd):
    """Compare registers and memory between two snapshots."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    snap_id_a = cmd.get("snapshot_id_a")
    snap_id_b = cmd.get("snapshot_id_b")

    if snap_id_a not in _snapshots:
        return {"error": f"Snapshot {snap_id_a} not found"}
    if snap_id_b not in _snapshots:
        return {"error": f"Snapshot {snap_id_b} not found"}

    snap_a = _snapshots[snap_id_a]
    snap_b = _snapshots[snap_id_b]

    # Compare registers
    regs_a = snap_a.get("registers", {})
    regs_b = snap_b.get("registers", {})
    reg_diffs = []
    for reg in _REGISTER_MAP.get(_arch, []):
        val_a = regs_a.get(reg)
        val_b = regs_b.get(reg)
        if val_a != val_b:
            reg_diffs.append({
                "register": reg,
                "snapshot_a": val_a,
                "snapshot_b": val_b,
            })

    # Compare memory regions by restoring each snapshot and checksumming
    mem_diffs = []
    try:
        # Save current state
        current_state = _ql.save()

        # Restore A and get memory info
        _ql.restore(snap_a["snapshot_data"])
        regions_a = {}
        try:
            for region in _ql.mem.get_mapinfo():
                if len(region) >= 2:
                    start, end = region[0], region[1]
                    size = end - start
                    if size <= 4_194_304:  # Only compare regions ≤ 4MB
                        try:
                            data = bytes(_ql.mem.read(start, size))
                            import hashlib
                            regions_a[start] = (size, hashlib.md5(data).hexdigest())
                        except Exception:
                            pass
        except Exception:
            pass

        # Restore B and compare
        _ql.restore(snap_b["snapshot_data"])
        try:
            for region in _ql.mem.get_mapinfo():
                if len(region) >= 2:
                    start, end = region[0], region[1]
                    size = end - start
                    if size <= 4_194_304:
                        try:
                            data = bytes(_ql.mem.read(start, size))
                            hash_b = hashlib.md5(data).hexdigest()
                            entry_a = regions_a.get(start)
                            if entry_a is None:
                                mem_diffs.append({
                                    "address": _hex(start),
                                    "size": size,
                                    "change": "new_in_b",
                                })
                            elif entry_a[1] != hash_b:
                                mem_diffs.append({
                                    "address": _hex(start),
                                    "size": size,
                                    "change": "modified",
                                })
                        except Exception:
                            pass
        except Exception:
            pass

        # Regions only in A
        b_starts = set()
        try:
            for region in _ql.mem.get_mapinfo():
                if len(region) >= 2:
                    b_starts.add(region[0])
        except Exception:
            pass
        for start, (size, _) in regions_a.items():
            if start not in b_starts:
                mem_diffs.append({
                    "address": _hex(start),
                    "size": size,
                    "change": "removed_in_b",
                })

        # Restore original state
        _ql.restore(current_state)
    except Exception as e:
        mem_diffs = [{"error": f"Memory diff failed: {str(e)[:200]}"}]

    return {
        "status": "ok",
        "snapshot_a": {"id": snap_id_a, "name": snap_a.get("name"), "pc": snap_a.get("pc")},
        "snapshot_b": {"id": snap_id_b, "name": snap_b.get("name"), "pc": snap_b.get("pc")},
        "register_diffs": reg_diffs,
        "memory_diffs": mem_diffs[:100],
        "total_register_diffs": len(reg_diffs),
        "total_memory_diffs": len(mem_diffs),
    }


def cmd_stop(cmd):
    """Clean up and signal exit."""
    global _ql, _staged_path
    if _staged_path:
        _cleanup_staged_binary(_staged_path)
        _staged_path = None
    _ql = None
    return {"status": "ok"}


# ---------------------------------------------------------------------------
#  Command dispatch table
# ---------------------------------------------------------------------------

DISPATCH = {
    "init": cmd_init,
    "step": cmd_step,
    "step_over": cmd_step_over,
    "continue": cmd_continue,
    "run_until": cmd_run_until,
    "set_breakpoint": cmd_set_breakpoint,
    "remove_breakpoint": cmd_remove_breakpoint,
    "set_watchpoint": cmd_set_watchpoint,
    "remove_watchpoint": cmd_remove_watchpoint,
    "list_breakpoints": cmd_list_breakpoints,
    "read_state": cmd_read_state,
    "read_memory": cmd_read_memory,
    "write_memory": cmd_write_memory,
    "write_register": cmd_write_register,
    "snapshot_save": cmd_snapshot_save,
    "snapshot_restore": cmd_snapshot_restore,
    "snapshot_list": cmd_snapshot_list,
    "snapshot_diff": cmd_snapshot_diff,
    "stop": cmd_stop,
}


# ---------------------------------------------------------------------------
#  Main JSONL loop
# ---------------------------------------------------------------------------

def main():
    """Persistent JSONL command loop over stdin/stdout."""
    # Redirect stdout → stderr for Qiling's internal prints.
    # We use real_stdout for our JSON protocol.
    real_stdout = sys.stdout
    sys.stdout = sys.stderr

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            cmd = json.loads(line)
        except json.JSONDecodeError as e:
            result = {"error": f"Invalid JSON: {e}"}
            real_stdout.write(json.dumps(result) + "\n")
            real_stdout.flush()
            continue

        action = cmd.get("action", "")

        try:
            handler = DISPATCH.get(action)
            if handler is None:
                result = {"error": f"Unknown action: {action}"}
            else:
                result = handler(cmd)
        except Exception as e:
            result = {
                "error": f"{type(e).__name__}: {e}",
                "traceback": traceback.format_exc()[:2000],
            }

        try:
            real_stdout.write(json.dumps(result) + "\n")
            real_stdout.flush()
        except Exception:
            # If we can't write, nothing we can do
            pass

        # Exit on stop
        if action == "stop":
            break


if __name__ == "__main__":
    main()
