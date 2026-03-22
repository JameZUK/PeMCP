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
import struct
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

# Note: QL_INTERCEPT and set_api() are intentionally NOT used.
# We use hook_address() per IAT entry to avoid Qiling's forwarded-API
# double-hook issue on x86 STDCALL.

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

# --- I/O stubs state ---
_stub_io = False                     # Whether I/O stubs are installed
_captured_output = []                # [{seq, api, text, byte_count, timestamp}]
_pending_input = []                  # [bytes, ...] — queued input data
_io_seq_counter = 0                  # Sequence counter for captured output

# --- API trace state ---
_api_trace = []                      # [{seq, api, args, retval, timestamp}]
_api_trace_seq = 0                   # Sequence counter for trace entries
_api_trace_filter = None             # None = trace all, set = whitelist
_api_trace_enabled = True            # Master enable flag

# --- CRT stubs state ---
_stub_crt = False                    # Whether CRT stubs are installed
_user_stubs = {}                     # api_name → {"return_value", "writes", "num_params", "patched"}
_fls_counter = 0                     # For FlsAlloc stub
_tls_counter = 0                     # For TlsAlloc stub
_stub_alloc_base = None              # Pre-mapped page for string-returning stubs
_stub_alloc_offset = 0               # Current offset within alloc page
_crt_stub_names = set()              # Names of installed CRT stubs

# hook_address() refactor state
_api_address_map = {}                # api_name → [sym_addr, ...] built once at init
_stub_hooks = {}                     # api_name → [hook_handle, ...] for all stub types
_trace_hooks = []                    # [hook_handle, ...] for trace hooks
_io_stub_names = set()               # Track I/O stub names for trace dedup

# Limits (matching constants.py)
_MAX_CAPTURED_OUTPUT = 10_000
_MAX_PENDING_INPUT = 1_000
_MAX_API_TRACE = 10_000
_MAX_SEARCH_MATCHES = 100
_MAX_USER_STUBS = 200
_MAX_STUB_WRITE_SIZE = 1024
_MAX_STUB_WRITES = 8


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
        if addr_str < 0:
            raise ValueError(f"Invalid address: negative value {addr_str}")
        return addr_str
    if isinstance(addr_str, str):
        addr_str = addr_str.strip()
        if addr_str.startswith("0x") or addr_str.startswith("0X"):
            val = int(addr_str, 16)
        else:
            val = int(addr_str)
        if val < 0:
            raise ValueError(f"Invalid address: negative value {addr_str}")
        return val
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
#  I/O stub helpers
# ---------------------------------------------------------------------------

def _read_string_from_memory(addr, max_len=4096):
    """Read a null-terminated ASCII string from memory."""
    try:
        data = bytes(_ql.mem.read(addr, max_len))
        null_idx = data.find(b'\x00')
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode('utf-8', errors='replace')
    except Exception:
        return ""


def _read_wstring_from_memory(addr, max_len=4096):
    """Read a null-terminated UTF-16LE string from memory."""
    try:
        data = bytes(_ql.mem.read(addr, max_len * 2))
        # Find null terminator (two zero bytes aligned)
        for i in range(0, len(data) - 1, 2):
            if data[i] == 0 and data[i + 1] == 0:
                data = data[:i]
                break
        return data.decode('utf-16-le', errors='replace')
    except Exception:
        return ""


def _capture_output(api, text, byte_count=0):
    """Append to captured output buffer (capped)."""
    global _io_seq_counter
    if len(_captured_output) >= _MAX_CAPTURED_OUTPUT:
        return
    _io_seq_counter += 1
    _captured_output.append({
        "seq": _io_seq_counter,
        "api": api,
        "text": text[:4096],
        "byte_count": byte_count or len(text),
        "timestamp": time.time(),
    })


def _consume_input(n):
    """Pop up to n bytes from pending input queue."""
    result = b""
    while len(result) < n and _pending_input:
        chunk = _pending_input[0]
        needed = n - len(result)
        if len(chunk) <= needed:
            result += _pending_input.pop(0)
        else:
            result += chunk[:needed]
            _pending_input[0] = chunk[needed:]
    return result


def _stub_read_param(index):
    """Read the Nth parameter (0-indexed) for the current architecture.

    For x86 STDCALL: params are on the stack at ESP+4, ESP+8, etc.
    For x86-64 fastcall: first 4 params in RCX, RDX, R8, R9; rest on stack.
    """
    if _arch == "x8664":
        regs = [_ql.arch.regs.rcx, _ql.arch.regs.rdx,
                _ql.arch.regs.r8, _ql.arch.regs.r9]
        if index < 4:
            return regs[index] & 0xFFFFFFFFFFFFFFFF
        rsp = _ql.arch.regs.rsp
        data = _ql.mem.read(rsp + 8 + index * 8, 8)
        return struct.unpack('<Q', bytes(data))[0]
    else:
        esp = _ql.arch.regs.esp
        data = _ql.mem.read(esp + 4 + index * 4, 4)
        return struct.unpack('<I', bytes(data))[0]


def _stub_set_retval(retval):
    """Set the API return value register for the current architecture."""
    if _arch == "x8664":
        _ql.arch.regs.rax = retval & 0xFFFFFFFFFFFFFFFF
    else:
        _ql.arch.regs.eax = retval & 0xFFFFFFFF


def _build_api_address_map():
    """Build api_name → [import_symbol_addresses] map for hook_address targeting."""
    global _api_address_map
    _api_address_map = {}
    if _ql is None or not hasattr(_ql, 'loader') or not hasattr(_ql.loader, 'import_symbols'):
        return
    for addr, entry in _ql.loader.import_symbols.items():
        name = entry.get('name')
        if not name:
            continue
        api_name = name.decode() if isinstance(name, bytes) else str(name)
        _api_address_map.setdefault(api_name, []).append(addr)


def _wrap_for_hook_address(hook_fn, api_name):
    """Adapt a (ql, address, api_name) stub for hook_address's (ql) signature."""
    def wrapper(ql):
        hook_fn(ql, _get_pc(), api_name)
    return wrapper


def _hook_api_by_address(api_name, hook_fn, num_params=0, patch=True):
    """Patch+hook an API at its import symbol addresses via hook_address().

    Unlike set_api() which hooks ALL Qiling-internal addresses (including forwarded),
    this only hooks IAT addresses from import_symbols — the ones we patch with ret N.

    Args:
        api_name: Windows API name
        hook_fn: Callback with signature (ql) for hook_address
        num_params: STDCALL param count for x86 ret N patching
        patch: If True, write ret N before hooking (False for breakpoints)

    Returns: (hook_handles: list, patched: bool)
    """
    hooks = []
    patched = False
    for sym_addr in _api_address_map.get(api_name, []):
        if patch:
            try:
                if _arch == "x8664":
                    _ql.mem.write(sym_addr, b'\xc3')
                else:
                    n_bytes = num_params * 4
                    _ql.mem.write(sym_addr,
                                  b'\xc3' if n_bytes == 0
                                  else b'\xc2' + struct.pack('<H', n_bytes))
                patched = True
            except Exception:
                continue
        try:
            h = _ql.hook_address(hook_fn, sym_addr)
            hooks.append(h)
        except Exception:
            pass
    return hooks, patched


def _alloc_stub_data(data_bytes):
    """Allocate bytes in pre-mapped stub data page. Returns address or 0."""
    global _stub_alloc_offset
    if _stub_alloc_base is None or _ql is None:
        return 0
    size = len(data_bytes)
    if _stub_alloc_offset + size > 4096:
        return 0  # Page full
    addr = _stub_alloc_base + _stub_alloc_offset
    try:
        _ql.mem.write(addr, data_bytes)
    except Exception:
        return 0
    # Align to 8 bytes
    _stub_alloc_offset += (size + 7) & ~7
    return addr


def _make_generic_stub(api_name, retval, writes=None):
    """Factory: create a CALL-hook closure for a data-driven stub.

    Args:
        api_name: API function name (for trace logging)
        retval: Return value (int) or None for void
        writes: List of {"param_index": int, "data_hex": str, "size": int}
    """
    def _generic_stub(ql, address, _api_name):
        params = {}
        if writes:
            for w in writes:
                idx = w["param_index"]
                ptr = _stub_read_param(idx)
                params[f"param{idx}"] = _hex(ptr)
                if ptr:
                    try:
                        data = bytes.fromhex(w["data_hex"])
                        ql.mem.write(ptr, data)
                    except Exception:
                        pass
        _add_trace_entry(api_name, address, params, retval)
        if retval is not None:
            _stub_set_retval(retval)
    return _generic_stub


# ---------------------------------------------------------------------------
#  CRT Stub Registry — data-driven API stubs for MSVC CRT initialization
# ---------------------------------------------------------------------------

# Type 1: Simple return value stubs
_CRT_SIMPLE_STUBS = [
    {"name": "GetCurrentProcessId", "params": 0, "return_value": 0x1000},
    {"name": "GetCurrentThreadId", "params": 0, "return_value": 0x1004},
    {"name": "GetTickCount", "params": 0, "return_value": 300000},
    {"name": "GetTickCount64", "params": 0, "return_value": 300000},
    {"name": "IsDebuggerPresent", "params": 0, "return_value": 0},
    {"name": "GetACP", "params": 0, "return_value": 1252},
    {"name": "GetOEMCP", "params": 0, "return_value": 437},
    {"name": "GetProcessHeap", "params": 0, "return_value": 0x10000},
    {"name": "HeapSetInformation", "params": 4, "return_value": 1},
    {"name": "SetUnhandledExceptionFilter", "params": 1, "return_value": 0},
    {"name": "GetLastError", "params": 0, "return_value": 0},
    {"name": "SetLastError", "params": 1, "return_value": None},
    {"name": "FlsSetValue", "params": 2, "return_value": 1},
    {"name": "FlsGetValue", "params": 1, "return_value": 0},
    {"name": "FlsFree", "params": 1, "return_value": 1},
    {"name": "TlsSetValue", "params": 2, "return_value": 1},
    {"name": "TlsGetValue", "params": 1, "return_value": 0},
    {"name": "TlsFree", "params": 1, "return_value": 1},
    {"name": "FreeEnvironmentStringsW", "params": 1, "return_value": 1},
    {"name": "DeleteCriticalSection", "params": 1, "return_value": None},
    {"name": "EnterCriticalSection", "params": 1, "return_value": None},
    {"name": "LeaveCriticalSection", "params": 1, "return_value": None},
    {"name": "InitializeCriticalSectionAndSpinCount", "params": 2, "return_value": 1},
    {"name": "InitializeCriticalSectionEx", "params": 3, "return_value": 1},
    {"name": "UnhandledExceptionFilter", "params": 1, "return_value": 1},
    {"name": "IsValidCodePage", "params": 1, "return_value": 1},
    {"name": "GetStringTypeW", "params": 4, "return_value": 1},
    {"name": "LCMapStringW", "params": 6, "return_value": 0},
    {"name": "GetLocaleInfoW", "params": 4, "return_value": 0},
    {"name": "GetUserDefaultLCID", "params": 0, "return_value": 0x0409},
    {"name": "RtlUnwind", "params": 4, "return_value": None},
]

# Type 2: Pointer-write stubs (write data to output pointers + return)
_CRT_WRITE_STUBS = [
    {"name": "GetSystemTimeAsFileTime", "params": 1, "return_value": None,
     "writes": [{"param_index": 0, "data_hex": "00000000d61a0100", "size": 8}]},
    {"name": "QueryPerformanceCounter", "params": 1, "return_value": 1,
     "writes": [{"param_index": 0, "data_hex": "0000000001000000", "size": 8}]},
    {"name": "QueryPerformanceFrequency", "params": 1, "return_value": 1,
     "writes": [{"param_index": 0, "data_hex": "00093d0000000000", "size": 8}]},
    {"name": "InitializeSListHead", "params": 1, "return_value": None,
     "writes": [{"param_index": 0, "data_hex": "0000000000000000" + "0000000000000000", "size": 16}]},
    {"name": "GetCPInfo", "params": 2, "return_value": 1,
     "writes": [{"param_index": 1, "data_hex": "01000000" + "3f00" + "00" * 14, "size": 20}]},
    {"name": "GetStartupInfoW", "params": 1, "return_value": None,
     "writes": [{"param_index": 0, "data_hex": "44000000" + "00" * 64, "size": 68}]},
]


def _install_crt_stubs():
    """Install CRT initialization stubs to prevent crashes during MSVC CRT init.

    Three categories of stubs:
    1. Simple return-value stubs (data-driven via _CRT_SIMPLE_STUBS)
    2. Pointer-write stubs (data-driven via _CRT_WRITE_STUBS)
    3. Custom handler stubs (require special logic)
    """
    global _stub_crt, _crt_stub_names, _fls_counter, _tls_counter
    global _stub_alloc_base, _stub_alloc_offset

    if _ql is None:
        return

    _crt_stub_names = set()
    _fls_counter = 0
    _tls_counter = 0

    # Map a 4KB page for string data (command line, environment)
    _stub_alloc_base = None
    _stub_alloc_offset = 0
    try:
        alloc_addr = 0x7FFE0000
        _ql.mem.map(alloc_addr, 4096, info="[crt_stub_data]")
        _stub_alloc_base = alloc_addr
    except Exception:
        # Try alternate address
        try:
            alloc_addr = 0x6FFE0000
            _ql.mem.map(alloc_addr, 4096, info="[crt_stub_data]")
            _stub_alloc_base = alloc_addr
        except Exception:
            pass  # No string data stubs

    # Pre-allocate string data for command-line / environment stubs
    _cmdline_a_addr = 0
    _cmdline_w_addr = 0
    _envstrings_addr = 0
    if _stub_alloc_base is not None:
        # GetCommandLineA: "binary.exe\0"
        _cmdline_a_addr = _alloc_stub_data(b"binary.exe\x00")
        # GetCommandLineW: L"binary.exe\0"
        _cmdline_w_addr = _alloc_stub_data("binary.exe\x00".encode("utf-16-le"))
        # GetEnvironmentStringsW: L"=\0\0" (minimal env block)
        _envstrings_addr = _alloc_stub_data(b"\x00\x00\x00\x00")

    # --- Install Type 1: simple return-value stubs ---
    for spec in _CRT_SIMPLE_STUBS:
        name = spec["name"]
        stub = _make_generic_stub(name, spec["return_value"])
        wrapped = _wrap_for_hook_address(stub, name)
        try:
            hooks, _ = _hook_api_by_address(name, wrapped, spec["params"])
            if hooks:
                _stub_hooks[name] = hooks
                _crt_stub_names.add(name)
        except Exception:
            pass

    # --- Install Type 2: pointer-write stubs ---
    for spec in _CRT_WRITE_STUBS:
        name = spec["name"]
        stub = _make_generic_stub(name, spec["return_value"], spec["writes"])
        wrapped = _wrap_for_hook_address(stub, name)
        try:
            hooks, _ = _hook_api_by_address(name, wrapped, spec["params"])
            if hooks:
                _stub_hooks[name] = hooks
                _crt_stub_names.add(name)
        except Exception:
            pass

    # --- Install Type 3: custom handler stubs ---

    def _stub_IsProcessorFeaturePresent(ql, address, _api_name):
        feature = _stub_read_param(0) & 0xFFFFFFFF
        # PF_XMMI_INSTRUCTIONS_AVAILABLE (6), PF_XMMI64_INSTRUCTIONS_AVAILABLE (10),
        # PF_SSE3_INSTRUCTIONS_AVAILABLE (13), PF_NX_ENABLED (12),
        # PF_FASTFAIL_AVAILABLE (23), PF_COMPARE_EXCHANGE128 (14)
        supported = {6, 10, 12, 13, 14, 23}
        retval = 1 if feature in supported else 0
        _add_trace_entry("IsProcessorFeaturePresent", address,
                         {"ProcessorFeature": str(feature)}, retval)
        _stub_set_retval(retval)

    def _stub_GetModuleHandleW(ql, address, _api_name):
        param0 = _stub_read_param(0)
        if param0 == 0:
            # NULL → return image base
            retval = ql.loader.pe_image_address if hasattr(ql.loader, 'pe_image_address') else 0x400000
        else:
            retval = 0
        _add_trace_entry("GetModuleHandleW", address,
                         {"lpModuleName": _hex(param0)}, retval)
        _stub_set_retval(retval)

    def _stub_GetModuleHandleA(ql, address, _api_name):
        param0 = _stub_read_param(0)
        if param0 == 0:
            retval = ql.loader.pe_image_address if hasattr(ql.loader, 'pe_image_address') else 0x400000
        else:
            retval = 0
        _add_trace_entry("GetModuleHandleA", address,
                         {"lpModuleName": _hex(param0)}, retval)
        _stub_set_retval(retval)

    def _stub_EncodePointer(ql, address, _api_name):
        ptr = _stub_read_param(0)
        _add_trace_entry("EncodePointer", address, {"Ptr": _hex(ptr)}, ptr)
        _stub_set_retval(ptr)

    def _stub_DecodePointer(ql, address, _api_name):
        ptr = _stub_read_param(0)
        _add_trace_entry("DecodePointer", address, {"Ptr": _hex(ptr)}, ptr)
        _stub_set_retval(ptr)

    def _stub_FlsAlloc(ql, address, _api_name):
        global _fls_counter
        _fls_counter += 1
        _add_trace_entry("FlsAlloc", address,
                         {"lpCallback": _hex(_stub_read_param(0))}, _fls_counter)
        _stub_set_retval(_fls_counter)

    def _stub_TlsAlloc(ql, address, _api_name):
        global _tls_counter
        _tls_counter += 1
        _add_trace_entry("TlsAlloc", address, {}, _tls_counter)
        _stub_set_retval(_tls_counter)

    def _stub_GetCommandLineA(ql, address, _api_name):
        _add_trace_entry("GetCommandLineA", address, {}, _cmdline_a_addr)
        _stub_set_retval(_cmdline_a_addr)

    def _stub_GetCommandLineW(ql, address, _api_name):
        _add_trace_entry("GetCommandLineW", address, {}, _cmdline_w_addr)
        _stub_set_retval(_cmdline_w_addr)

    def _stub_GetEnvironmentStringsW(ql, address, _api_name):
        _add_trace_entry("GetEnvironmentStringsW", address, {}, _envstrings_addr)
        _stub_set_retval(_envstrings_addr)

    custom_stubs = {
        "IsProcessorFeaturePresent": (1, _stub_IsProcessorFeaturePresent),
        "GetModuleHandleW": (1, _stub_GetModuleHandleW),
        "GetModuleHandleA": (1, _stub_GetModuleHandleA),
        "EncodePointer": (1, _stub_EncodePointer),
        "DecodePointer": (1, _stub_DecodePointer),
        "FlsAlloc": (1, _stub_FlsAlloc),
        "TlsAlloc": (0, _stub_TlsAlloc),
        "GetCommandLineA": (0, _stub_GetCommandLineA),
        "GetCommandLineW": (0, _stub_GetCommandLineW),
        "GetEnvironmentStringsW": (0, _stub_GetEnvironmentStringsW),
    }

    for name, (nparams, stub_fn) in custom_stubs.items():
        wrapped = _wrap_for_hook_address(stub_fn, name)
        try:
            hooks, _ = _hook_api_by_address(name, wrapped, nparams)
            if hooks:
                _stub_hooks[name] = hooks
                _crt_stub_names.add(name)
        except Exception:
            pass

    _stub_crt = len(_crt_stub_names) > 0


def _install_io_stubs():
    """Install Win32 console API stubs to prevent crashes from console I/O.

    Strategy: register CALL hooks that set the return value in EAX/RAX, then
    patch the simprocedure memory with `ret N` (STDCALL) or `ret` (fastcall).
    The CALL hook fires before the instruction at the simprocedure address.
    After the hook sets EAX and returns, the `ret N` instruction executes,
    performing the standard STDCALL return (pop return addr, clean params).

    This avoids the Unicorn 1.x limitation where emu_stop() takes effect
    AFTER the current instruction executes (so changing EIP in a hook_code
    callback and calling emu_stop doesn't prevent the old instruction from
    running).

    CALL hooks preempt ENTER hooks in hook_winapi, so trace entries are
    added manually inside each stub.
    """
    global _stub_io
    if _ql is None:
        return

    STD_INPUT_HANDLE = 0xFFFFFFF6   # -10
    STD_OUTPUT_HANDLE = 0xFFFFFFF5  # -11
    STD_ERROR_HANDLE = 0xFFFFFFF4   # -12

    _VIRTUAL_HANDLES = {
        STD_INPUT_HANDLE & 0xFFFFFFFF: 0x100,
        STD_OUTPUT_HANDLE & 0xFFFFFFFF: 0x200,
        STD_ERROR_HANDLE & 0xFFFFFFFF: 0x300,
    }

    def _stub_GetStdHandle(ql, address, _api_name):
        nStdHandle = _stub_read_param(0) & 0xFFFFFFFF
        handle = _VIRTUAL_HANDLES.get(nStdHandle, 0x200)
        _add_trace_entry("GetStdHandle", address,
                         {"nStdHandle": _hex(nStdHandle)}, handle)
        _stub_set_retval(handle)

    def _stub_WriteConsoleA(ql, address, _api_name):
        buf_addr = _stub_read_param(1)
        n_chars = _stub_read_param(2) & 0xFFFFFFFF
        written_addr = _stub_read_param(3)
        if buf_addr and n_chars > 0:
            text = _read_string_from_memory(buf_addr, min(n_chars, 4096))
            _capture_output("WriteConsoleA", text, n_chars)
        if written_addr:
            try:
                ql.mem.write(written_addr, n_chars.to_bytes(4, "little"))
            except Exception:
                pass
        _add_trace_entry("WriteConsoleA", address,
                         {"lpBuffer": _hex(buf_addr),
                          "nNumberOfCharsToWrite": str(n_chars)}, 1)
        _stub_set_retval(1)

    def _stub_WriteConsoleW(ql, address, _api_name):
        buf_addr = _stub_read_param(1)
        n_chars = _stub_read_param(2) & 0xFFFFFFFF
        written_addr = _stub_read_param(3)
        if buf_addr and n_chars > 0:
            text = _read_wstring_from_memory(buf_addr, min(n_chars, 4096))
            _capture_output("WriteConsoleW", text, n_chars)
        if written_addr:
            try:
                ql.mem.write(written_addr, n_chars.to_bytes(4, "little"))
            except Exception:
                pass
        _add_trace_entry("WriteConsoleW", address,
                         {"lpBuffer": _hex(buf_addr),
                          "nNumberOfCharsToWrite": str(n_chars)}, 1)
        _stub_set_retval(1)

    def _stub_ReadConsoleA(ql, address, _api_name):
        buf_addr = _stub_read_param(1)
        n_chars = _stub_read_param(2) & 0xFFFFFFFF
        read_addr = _stub_read_param(3)
        retval = 1
        if not buf_addr or n_chars <= 0:
            retval = 0
        else:
            input_data = _consume_input(n_chars)
            if not input_data:
                input_data = b"\n"
            try:
                ql.mem.write(buf_addr, input_data)
            except Exception:
                retval = 0
                input_data = b""
            if read_addr and retval:
                try:
                    ql.mem.write(read_addr,
                                 len(input_data).to_bytes(4, "little"))
                except Exception:
                    pass
            if retval:
                _capture_output("ReadConsoleA",
                                input_data.decode('utf-8', errors='replace'),
                                len(input_data))
        _add_trace_entry("ReadConsoleA", address,
                         {"lpBuffer": _hex(buf_addr),
                          "nNumberOfCharsToRead": str(n_chars)}, retval)
        _stub_set_retval(retval)

    def _stub_SetConsoleMode(ql, address, _api_name):
        _add_trace_entry("SetConsoleMode", address, {}, 1)
        _stub_set_retval(1)

    def _stub_GetConsoleMode(ql, address, _api_name):
        mode_addr = _stub_read_param(1)
        if mode_addr:
            try:
                ql.mem.write(mode_addr, (0x3).to_bytes(4, "little"))
            except Exception:
                pass
        _add_trace_entry("GetConsoleMode", address, {}, 1)
        _stub_set_retval(1)

    def _stub_AllocConsole(ql, address, _api_name):
        _add_trace_entry("AllocConsole", address, {}, 1)
        _stub_set_retval(1)

    def _stub_FreeConsole(ql, address, _api_name):
        _add_trace_entry("FreeConsole", address, {}, 1)
        _stub_set_retval(1)

    # Map API name → (num_params, stub_function)
    stub_map = {
        "GetStdHandle": (1, _stub_GetStdHandle),
        "WriteConsoleA": (5, _stub_WriteConsoleA),
        "WriteConsoleW": (5, _stub_WriteConsoleW),
        "ReadConsoleA": (5, _stub_ReadConsoleA),
        "SetConsoleMode": (2, _stub_SetConsoleMode),
        "GetConsoleMode": (2, _stub_GetConsoleMode),
        "AllocConsole": (0, _stub_AllocConsole),
        "FreeConsole": (0, _stub_FreeConsole),
    }

    for api_name, (_np, stub_fn) in stub_map.items():
        wrapped = _wrap_for_hook_address(stub_fn, api_name)
        try:
            hooks, _ = _hook_api_by_address(api_name, wrapped, _np)
            if hooks:
                _stub_hooks[api_name] = hooks
                _io_stub_names.add(api_name)
        except Exception:
            pass

    _stub_io = len(_io_stub_names) > 0


# ---------------------------------------------------------------------------
#  API trace hooks
# ---------------------------------------------------------------------------

def _add_trace_entry(api_name, address=None, params=None, retval=None):
    """Add an entry to the API trace from any hook or stub."""
    global _api_trace_seq
    if not _api_trace_enabled:
        return
    if len(_api_trace) >= _MAX_API_TRACE:
        return
    if _api_trace_filter is not None and api_name not in _api_trace_filter:
        return

    _api_trace_seq += 1
    safe_params = {}
    if isinstance(params, dict):
        for k, v in list(params.items())[:10]:
            try:
                if k.startswith("__"):
                    continue  # Skip Qiling internal keys
                if isinstance(v, int):
                    safe_params[k] = _hex(v)
                else:
                    safe_params[k] = str(v)[:200]
            except Exception:
                safe_params[k] = "?"
    _api_trace.append({
        "seq": _api_trace_seq,
        "api": api_name,
        "args": safe_params,
        "retval": _hex(retval) if isinstance(retval, int) else str(retval)[:200] if retval is not None else None,
        "address": _hex(address) if isinstance(address, int) and address else str(address) if address else None,
        "timestamp": time.time(),
    })


def _make_trace_address_hook(api_name):
    """Create a hook_address callback that traces an API call with raw params."""
    def _trace(ql):
        params = {}
        for i in range(4):
            try:
                params[f"p{i}"] = _hex(_stub_read_param(i))
            except Exception:
                break
        _add_trace_entry(api_name, _get_pc(), params)
    return _trace


def _install_api_trace():
    """Install per-API hook_address hooks to trace all Windows API calls.

    Only hooks APIs that are NOT already stubbed (CRT, I/O, or user stubs),
    since those stubs already record trace entries via _add_trace_entry().
    """
    global _api_trace_enabled, _trace_hooks

    if _ql is None:
        return

    _trace_hooks = []

    # Skip APIs already covered by stubs (they record their own trace entries)
    stubbed = _crt_stub_names | _io_stub_names | set(_user_stubs.keys())

    hooked_count = 0
    try:
        for api_name, addrs in _api_address_map.items():
            if api_name in stubbed:
                continue
            hook_fn = _make_trace_address_hook(api_name)
            for addr in addrs:
                try:
                    h = _ql.hook_address(hook_fn, addr)
                    _trace_hooks.append(h)
                    hooked_count += 1
                except Exception:
                    pass
    except Exception:
        _api_trace_enabled = False

    if hooked_count == 0:
        _api_trace_enabled = False


# ---------------------------------------------------------------------------
#  Breakpoint callbacks
# ---------------------------------------------------------------------------

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
    global _stub_io, _captured_output, _pending_input, _io_seq_counter
    global _api_trace, _api_trace_seq, _api_trace_filter, _api_trace_enabled
    global _stub_crt, _user_stubs, _fls_counter, _tls_counter
    global _stub_alloc_base, _stub_alloc_offset, _crt_stub_names
    global _api_address_map, _stub_hooks, _trace_hooks, _io_stub_names

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

    # Reset I/O and trace state
    _stub_io = False
    _captured_output = []
    _pending_input = []
    _io_seq_counter = 0
    _api_trace = []
    _api_trace_seq = 0
    _api_trace_filter = None
    _api_trace_enabled = True

    # Reset CRT stubs state
    _stub_crt = False
    _user_stubs = {}
    _fls_counter = 0
    _tls_counter = 0
    _stub_alloc_base = None
    _stub_alloc_offset = 0
    _crt_stub_names = set()

    # Reset hook_address refactor state
    _api_address_map = {}
    _stub_hooks = {}
    _trace_hooks = []
    _io_stub_names = set()

    # Initialize capstone disassembler
    _init_capstone(arch)

    # Build API address map from import symbols (must be before stub installation)
    _build_api_address_map()

    # Install global instruction counter
    _ql.hook_code(_instruction_counter_hook)

    # Install CRT stubs (before I/O stubs so I/O stubs can override)
    stub_crt = cmd.get("stub_crt", True)
    if stub_crt:
        _install_crt_stubs()

    # Install I/O stubs (overrides CRT stubs for console APIs)
    stub_io = cmd.get("stub_io", True)
    if stub_io:
        _install_io_stubs()

    # Install API call tracing (lowest priority)
    _install_api_trace()

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
        "stub_io": _stub_io,
        "crt_stubs": _stub_crt,
        "crt_stub_count": len(_crt_stub_names),
        "api_trace_enabled": _api_trace_enabled,
    }
    if _dll_warning:
        result["warning"] = _dll_warning
    return result


def _run_with_reentry(max_insns):
    """Run emulation with re-entry loop for API hook processing.

    Qiling's ql.run() returns after each API hook dispatch (simprocedure
    handling). This loop re-enters ql.run() until we either hit max_insns,
    a stop reason is set (breakpoint/watchpoint), or the emulation exits.

    Returns (error_extra: dict or None). If None, check _stop_reason.
    """
    remaining = max_insns
    stall_count = 0
    max_stalls = 200  # Safety: avoid infinite loop if emulation is stuck
    reentries = 0
    max_reentries = 500  # Hard cap on total loop iterations

    while remaining > 0 and reentries < max_reentries:
        reentries += 1
        prev_count = _insn_count
        prev_pc = _get_pc()

        try:
            _ql.run(count=remaining)
        except Exception as e:
            err_str = str(e)
            if "unmapped" in err_str.lower() or "exit" in err_str.lower():
                return {"stop_reason": "exited", "exit_reason": err_str[:500]}
            return {"stop_reason": "exception", "error_detail": err_str[:500]}

        # Check if a stop reason was set (breakpoint, watchpoint, temp bp)
        if _stop_reason:
            return None

        delta = _insn_count - prev_count
        remaining -= max(delta, 0)

        if remaining <= 0:
            break

        # Check for stall (no progress — emulation returned without advancing)
        current_pc = _get_pc()
        if delta == 0 and current_pc == prev_pc:
            stall_count += 1
            if stall_count >= max_stalls:
                return {"stop_reason": "stalled",
                        "note": "Emulation not making progress after repeated re-entry"}
        else:
            stall_count = 0

    return None  # max_insns reached normally


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

    error_extra = _run_with_reentry(count)
    if error_extra:
        return _build_execution_state(error_extra)

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
    error_extra = _run_with_reentry(max_insns)

    # Remove temp hook
    try:
        _ql.hook_del(hook)
    except Exception:
        pass

    if error_extra:
        return _build_execution_state(error_extra)

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

    error_extra = _run_with_reentry(max_insns)
    if error_extra:
        return _build_execution_state(error_extra)

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

    error_extra = _run_with_reentry(max_insns)

    # Remove temp hook
    try:
        _ql.hook_del(hook)
    except Exception:
        pass

    if error_extra:
        return _build_execution_state(error_extra)

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

    if len(_breakpoints) >= 100:
        return {"error": "Breakpoint limit reached (100). Remove existing breakpoints first."}

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
        def _bp_wrapper(ql, _cb=callback, _name=api_name):
            _cb(ql, _get_pc(), {})
        hooks, _ = _hook_api_by_address(api_name, _bp_wrapper, patch=False)
        if not hooks:
            return {"error": f"API '{api_name}' not found in imports"}
        bp_entry["hook_handles"] = hooks

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
    if bp.get("api_name"):
        # API breakpoints have hook_address handles — clean removal
        for h in bp.get("hook_handles", []):
            try:
                _ql.hook_del(h)
            except Exception:
                pass
    else:
        hook = bp.get("hook_handle")
        if hook is not None:
            try:
                _ql.hook_del(hook)
            except Exception:
                pass

    return {"status": "ok", "breakpoint_id": bp_id, "total_breakpoints": len(_breakpoints)}


def cmd_set_watchpoint(cmd):
    """Register a memory watchpoint."""
    global _wp_counter

    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    if len(_watchpoints) >= 50:
        return {"error": "Watchpoint limit reached (50). Remove existing watchpoints first."}

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
    global _captured_output, _pending_input, _api_trace
    global _user_stubs, _crt_stub_names
    global _breakpoints, _watchpoints, _snapshots
    global _bp_counter, _wp_counter, _snap_counter
    global _stop_reason, _hit_bp_id, _hit_wp_id, _wp_access_info
    global _mem_read_hook, _mem_write_hook
    global _api_address_map, _stub_hooks, _trace_hooks, _io_stub_names
    if _staged_path:
        _cleanup_staged_binary(_staged_path)
        _staged_path = None
    _captured_output = []
    _pending_input = []
    _api_trace = []
    _user_stubs = {}
    _crt_stub_names = set()
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
    _api_address_map = {}
    _stub_hooks = {}
    _trace_hooks = []
    _io_stub_names = set()
    _ql = None
    return {"status": "ok"}


# ---------------------------------------------------------------------------
#  I/O and trace command handlers
# ---------------------------------------------------------------------------

def cmd_set_input(cmd):
    """Queue input data for stubbed ReadConsole."""
    global _pending_input
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    data_str = cmd.get("data", "")
    encoding = cmd.get("encoding", "utf-8")

    if not data_str:
        return {"error": "'data' is required"}

    try:
        if encoding == "hex":
            if len(data_str) % 2 != 0:
                return {"error": "Hex data must have even length"}
            data_bytes = bytes.fromhex(data_str)
        elif encoding == "utf-8":
            data_bytes = data_str.encode("utf-8")
        else:
            data_bytes = data_str.encode("utf-8")
    except (ValueError, UnicodeEncodeError) as e:
        return {"error": f"Failed to encode input data: {e}"}

    if len(_pending_input) >= _MAX_PENDING_INPUT:
        return {"error": f"Pending input queue full (max {_MAX_PENDING_INPUT} entries)"}

    _pending_input.append(data_bytes)
    total_bytes = sum(len(c) for c in _pending_input)
    return {
        "status": "ok",
        "bytes_queued": len(data_bytes),
        "total_pending_bytes": total_bytes,
        "queue_entries": len(_pending_input),
    }


def cmd_get_output(cmd):
    """Return captured output (paginated, optional clear)."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    offset = max(0, cmd.get("offset", 0))
    limit = max(1, min(cmd.get("limit", 100), 1000))
    do_clear = cmd.get("clear", False)

    entries = _captured_output[offset:offset + limit]
    total = len(_captured_output)

    result = {
        "status": "ok",
        "entries": entries,
        "total": total,
        "offset": offset,
        "limit": limit,
        "returned": len(entries),
        "has_more": offset + limit < total,
    }

    if do_clear:
        _captured_output.clear()
        result["cleared"] = True

    return result


def cmd_get_api_trace(cmd):
    """Return API trace entries (paginated, optional filter)."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    offset = max(0, cmd.get("offset", 0))
    limit = max(1, min(cmd.get("limit", 100), 1000))
    api_filter = cmd.get("filter")  # Optional API name filter

    if api_filter:
        # Filter entries by API name (case-insensitive substring)
        api_filter_lower = api_filter.lower()
        filtered = [e for e in _api_trace if api_filter_lower in e.get("api", "").lower()]
    else:
        filtered = _api_trace

    entries = filtered[offset:offset + limit]
    total = len(filtered)

    return {
        "status": "ok",
        "entries": entries,
        "total": total,
        "offset": offset,
        "limit": limit,
        "returned": len(entries),
        "has_more": offset + limit < total,
        "trace_enabled": _api_trace_enabled,
        "filter_active": _api_trace_filter is not None,
    }


def cmd_clear_api_trace(cmd):
    """Clear the API trace buffer."""
    global _api_trace, _api_trace_seq
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    count = len(_api_trace)
    _api_trace = []
    _api_trace_seq = 0
    return {"status": "ok", "entries_cleared": count}


def cmd_set_trace_filter(cmd):
    """Set API trace filter (whitelist) or enable/disable tracing."""
    global _api_trace_filter, _api_trace_enabled
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    # Handle enable/disable
    if "enabled" in cmd:
        _api_trace_enabled = bool(cmd["enabled"])

    # Handle filter
    apis = cmd.get("apis")
    if apis is not None:
        if isinstance(apis, list) and len(apis) > 0:
            _api_trace_filter = set(apis)
        else:
            _api_trace_filter = None  # Clear filter = trace all

    return {
        "status": "ok",
        "trace_enabled": _api_trace_enabled,
        "filter": sorted(_api_trace_filter) if _api_trace_filter else None,
    }


def cmd_search_memory(cmd):
    """Search across all mapped memory for a pattern."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    pattern = cmd.get("pattern", "")
    pattern_type = cmd.get("pattern_type", "string")
    max_matches = max(1, min(cmd.get("max_matches", _MAX_SEARCH_MATCHES), _MAX_SEARCH_MATCHES))
    context_bytes = max(0, min(cmd.get("context_bytes", 32), 256))
    region_filter = cmd.get("region_filter")  # Optional label substring filter

    if not pattern:
        return {"error": "'pattern' is required"}

    # Build search patterns
    search_patterns = []
    if pattern_type == "string":
        # Search both UTF-8 and UTF-16LE
        try:
            search_patterns.append(("utf-8", pattern.encode("utf-8")))
            search_patterns.append(("utf-16le", pattern.encode("utf-16-le")))
        except UnicodeEncodeError as e:
            return {"error": f"Failed to encode pattern: {e}"}
    elif pattern_type == "hex":
        # Support ?? wildcards
        hex_str = pattern.replace(" ", "")
        if len(hex_str) % 2 != 0:
            return {"error": "Hex pattern must have even length (use ?? for wildcards)"}
        tokens = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
        if len(tokens) > 200:
            return {"error": "Hex pattern too long (max 200 bytes)"}
        # Build bytes and mask
        pattern_bytes = bytearray()
        mask = bytearray()
        for token in tokens:
            if token == "??":
                pattern_bytes.append(0)
                mask.append(0)
            else:
                try:
                    pattern_bytes.append(int(token, 16))
                    mask.append(0xFF)
                except ValueError:
                    return {"error": f"Invalid hex byte: {token}"}
        search_patterns.append(("hex", (bytes(pattern_bytes), bytes(mask))))
    else:
        return {"error": f"Invalid pattern_type: {pattern_type}. Must be 'string' or 'hex'"}

    # Search memory regions
    matches = []
    try:
        regions = _ql.mem.get_mapinfo()
    except Exception:
        return {"error": "Failed to get memory map"}

    for region in regions:
        if len(matches) >= max_matches:
            break
        if len(region) < 2:
            continue
        start, end = region[0], region[1]
        label = str(region[3]) if len(region) > 3 else ""

        if region_filter and region_filter.lower() not in label.lower():
            continue

        size = end - start
        if size <= 0 or size > 64 * 1024 * 1024:  # Skip regions > 64MB
            continue

        try:
            data = bytes(_ql.mem.read(start, size))
        except Exception:
            continue

        for encoding_label, pat in search_patterns:
            if len(matches) >= max_matches:
                break

            if encoding_label == "hex":
                pat_bytes, pat_mask = pat
                pat_len = len(pat_bytes)
                if pat_len == 0:
                    continue
                # Manual search with mask
                for i in range(len(data) - pat_len + 1):
                    if len(matches) >= max_matches:
                        break
                    match = True
                    for j in range(pat_len):
                        if (data[i + j] & pat_mask[j]) != (pat_bytes[j] & pat_mask[j]):
                            match = False
                            break
                    if match:
                        ctx_start = max(0, i - context_bytes)
                        ctx_end = min(len(data), i + pat_len + context_bytes)
                        matches.append({
                            "address": _hex(start + i),
                            "region_start": _hex(start),
                            "region_label": label,
                            "encoding": "hex",
                            "match_hex": data[i:i + pat_len].hex(),
                            "context_hex": data[ctx_start:ctx_end].hex(),
                            "context_offset": i - ctx_start,
                        })
            else:
                # Byte string search
                pat_bytes = pat
                idx = 0
                while idx < len(data) and len(matches) < max_matches:
                    pos = data.find(pat_bytes, idx)
                    if pos < 0:
                        break
                    ctx_start = max(0, pos - context_bytes)
                    ctx_end = min(len(data), pos + len(pat_bytes) + context_bytes)
                    # ASCII context
                    match_data = data[pos:pos + len(pat_bytes)]
                    context_data = data[ctx_start:ctx_end]
                    ascii_ctx = ""
                    for b in context_data:
                        ascii_ctx += chr(b) if 32 <= b < 127 else "."
                    matches.append({
                        "address": _hex(start + pos),
                        "region_start": _hex(start),
                        "region_label": label,
                        "encoding": encoding_label,
                        "match_hex": match_data.hex(),
                        "context_hex": context_data.hex(),
                        "context_ascii": ascii_ctx,
                        "context_offset": pos - ctx_start,
                    })
                    idx = pos + 1

    return {
        "status": "ok",
        "pattern": pattern,
        "pattern_type": pattern_type,
        "matches": matches,
        "total_matches": len(matches),
        "max_matches": max_matches,
        "truncated": len(matches) >= max_matches,
    }


# ---------------------------------------------------------------------------
#  CRT stub command handlers
# ---------------------------------------------------------------------------

def cmd_stub_api(cmd):
    """Create a user-defined API stub at runtime."""
    global _user_stubs
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    api_name = cmd.get("api_name", "").strip()
    if not api_name:
        return {"error": "'api_name' is required"}
    if len(api_name) > 128:
        return {"error": "'api_name' too long (max 128 chars)"}
    import re
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', api_name):
        return {"error": f"Invalid api_name '{api_name}': must be alphanumeric + underscore"}

    if len(_user_stubs) >= _MAX_USER_STUBS:
        return {"error": f"User stub limit reached ({_MAX_USER_STUBS}). Remove stubs first."}

    # Parse return value
    return_value_str = cmd.get("return_value", "0x0")
    if return_value_str in ("void", "null", "none", "None"):
        return_value = None
    else:
        try:
            if isinstance(return_value_str, int):
                return_value = return_value_str
            elif return_value_str.startswith(("0x", "0X")):
                return_value = int(return_value_str, 16)
            else:
                return_value = int(return_value_str)
        except (ValueError, AttributeError):
            return {"error": f"Invalid return_value: '{return_value_str}'. Use hex (0x...), decimal, or 'void'"}

    num_params = max(0, min(cmd.get("num_params", 0), 20))

    # Parse writes
    writes = []
    writes_raw = cmd.get("writes")
    if writes_raw:
        if isinstance(writes_raw, str):
            try:
                writes_raw = json.loads(writes_raw)
            except json.JSONDecodeError as e:
                return {"error": f"Invalid writes JSON: {e}"}
        if not isinstance(writes_raw, list):
            return {"error": "'writes' must be a JSON array"}
        if len(writes_raw) > _MAX_STUB_WRITES:
            return {"error": f"Too many write operations (max {_MAX_STUB_WRITES})"}
        for i, w in enumerate(writes_raw):
            if not isinstance(w, dict):
                return {"error": f"writes[{i}] must be an object"}
            pi = w.get("param_index")
            dh = w.get("data_hex", "")
            if pi is None or not isinstance(pi, int) or pi < 0 or pi > 20:
                return {"error": f"writes[{i}].param_index must be 0-20"}
            if not dh or len(dh) % 2 != 0:
                return {"error": f"writes[{i}].data_hex must be an even-length hex string"}
            if len(dh) // 2 > _MAX_STUB_WRITE_SIZE:
                return {"error": f"writes[{i}].data_hex too large (max {_MAX_STUB_WRITE_SIZE} bytes)"}
            try:
                bytes.fromhex(dh)
            except ValueError:
                return {"error": f"writes[{i}].data_hex is not valid hex"}
            writes.append({"param_index": pi, "data_hex": dh, "size": len(dh) // 2})

    # Create and register the stub
    stub_fn = _make_generic_stub(api_name, return_value, writes if writes else None)
    wrapped = _wrap_for_hook_address(stub_fn, api_name)
    hooks, patched = _hook_api_by_address(api_name, wrapped, num_params)
    _stub_hooks[api_name] = hooks

    _user_stubs[api_name] = {
        "return_value": return_value,
        "num_params": num_params,
        "writes": writes,
        "patched": patched,
    }

    return {
        "status": "ok",
        "api_name": api_name,
        "return_value": _hex(return_value) if isinstance(return_value, int) else None,
        "num_params": num_params,
        "writes_count": len(writes),
        "patched": patched,
        "total_user_stubs": len(_user_stubs),
    }


def cmd_list_stubs(cmd):
    """List all installed API stubs (builtin + user-defined)."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    # I/O stubs (always 8 APIs when enabled)
    io_stubs = []
    if _stub_io:
        io_stubs = ["GetStdHandle", "WriteConsoleA", "WriteConsoleW",
                     "ReadConsoleA", "SetConsoleMode", "GetConsoleMode",
                     "AllocConsole", "FreeConsole"]

    # CRT stubs
    crt_stubs = sorted(_crt_stub_names) if _stub_crt else []

    # User stubs
    user_stubs = []
    for name, info in _user_stubs.items():
        user_stubs.append({
            "api_name": name,
            "return_value": _hex(info["return_value"]) if isinstance(info["return_value"], int) else None,
            "num_params": info["num_params"],
            "writes_count": len(info.get("writes", [])),
            "patched": info["patched"],
        })

    return {
        "status": "ok",
        "builtin_io": io_stubs,
        "builtin_io_count": len(io_stubs),
        "builtin_crt": crt_stubs,
        "builtin_crt_count": len(crt_stubs),
        "user": user_stubs,
        "user_count": len(user_stubs),
        "total_stubs": len(io_stubs) + len(crt_stubs) + len(user_stubs),
    }


def cmd_remove_stub(cmd):
    """Remove a user-defined API stub."""
    global _user_stubs
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    api_name = cmd.get("api_name", "").strip()
    if not api_name:
        return {"error": "'api_name' is required"}

    # Check if it's a builtin stub (can't remove)
    io_names = {"GetStdHandle", "WriteConsoleA", "WriteConsoleW",
                "ReadConsoleA", "SetConsoleMode", "GetConsoleMode",
                "AllocConsole", "FreeConsole"}
    if api_name in io_names:
        return {"error": f"Cannot remove builtin I/O stub '{api_name}'. "
                "Restart the session with stub_io=False to disable I/O stubs."}
    if api_name in _crt_stub_names:
        return {"error": f"Cannot remove builtin CRT stub '{api_name}'. "
                "Restart the session with stub_crt=False to disable CRT stubs."}

    if api_name not in _user_stubs:
        return {"error": f"No user-defined stub for '{api_name}'"}

    # Remove hook_address handles
    for h in _stub_hooks.get(api_name, []):
        try:
            _ql.hook_del(h)
        except Exception:
            pass
    _stub_hooks.pop(api_name, None)

    del _user_stubs[api_name]
    return {
        "status": "ok",
        "api_name": api_name,
        "remaining_user_stubs": len(_user_stubs),
    }


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
    "set_input": cmd_set_input,
    "get_output": cmd_get_output,
    "get_api_trace": cmd_get_api_trace,
    "clear_api_trace": cmd_clear_api_trace,
    "set_trace_filter": cmd_set_trace_filter,
    "search_memory": cmd_search_memory,
    "stub_api": cmd_stub_api,
    "list_stubs": cmd_list_stubs,
    "remove_stub": cmd_remove_stub,
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
    real_stderr = sys.stderr
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
            # Log traceback to stderr (not sent to client) to avoid leaking
            # internal paths and stack details through the JSONL protocol.
            traceback.print_exc(file=real_stderr)
            result = {
                "error": f"{type(e).__name__}: {e}",
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
