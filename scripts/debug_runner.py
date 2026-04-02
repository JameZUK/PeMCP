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
import threading
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
from trace_query import (
    parse_query, parse_sequence, filter_trace, match_sequences,
)

from qiling import Qiling
from qiling.const import QL_VERBOSE

# Note: On x86, QL_INTERCEPT and set_api() are NOT used to avoid the
# forwarded-API double-hook issue with STDCALL stack cleanup.
# On x8664, set_api() IS used as a FALLBACK to catch DLL-internal
# forwarded calls (e.g. kernel32→kernelbase) that bypass the IAT.
# The hook_address() per-IAT-entry approach remains primary for both.

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
_last_error_code = 0                 # Thread-local last error (for GetLastError/SetLastError)

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

    # Resolve forwarded exports (x64 only — critical for real DLL rootfs)
    if _arch == "x8664":
        _resolve_forwarded_exports()


def _resolve_forwarded_exports():
    """Fix Qiling's unresolved forwarded DLL exports.

    Problem: Windows DLLs use export forwarding (e.g. kernel32!HeapAlloc →
    NTDLL.RtlAllocateHeap). Qiling's PE loader doesn't resolve these chains,
    leaving IAT entries pointing at the forwarding STRING data instead of
    actual function code. When executed, this crashes immediately.

    Solution: Scan all import symbols. For each one, read the bytes at the
    target address. If they look like a forwarding string ("DLLNAME.FuncName"),
    resolve the target by looking up the function in the forwarded DLL's
    export table, then patch the IAT entry to point to the real code.
    """
    if _ql is None or not hasattr(_ql, 'loader'):
        return

    resolved = 0
    failed = 0

    # Build DLL export lookup: dll_name_lower → {func_name → address}
    dll_exports = {}
    if hasattr(_ql.loader, 'import_address_table'):
        for dll_name, iat in _ql.loader.import_address_table.items():
            dll_exports[dll_name.lower()] = {
                (k.decode() if isinstance(k, bytes) else str(k)): v
                for k, v in iat.items()
                if isinstance(k, (str, bytes))  # skip ordinal entries
            }

    if not dll_exports:
        return

    # Scan all import symbols for forwarding strings
    for addr, entry in list(_ql.loader.import_symbols.items()):
        try:
            # Read bytes at the import target address
            target_bytes = _ql.mem.read(addr, 64)
        except Exception:
            continue

        # Check if this looks like a forwarding string: "DLLNAME.FunctionName\0"
        # Forwarding strings are ASCII, contain exactly one '.', and are null-terminated
        try:
            null_idx = target_bytes.index(0)
            if null_idx < 5 or null_idx > 60:
                continue
            fwd_str = target_bytes[:null_idx].decode('ascii')
        except (ValueError, UnicodeDecodeError):
            continue

        if '.' not in fwd_str or fwd_str.count('.') != 1:
            continue

        # Validate: must look like "DLLNAME.FuncName" (alphanumeric + underscore)
        dll_part, func_part = fwd_str.split('.', 1)
        if not dll_part or not func_part:
            continue
        if not all(c.isalnum() or c == '_' for c in dll_part):
            continue
        if not all(c.isalnum() or c == '_' for c in func_part):
            continue

        # Look up the target function in the forwarded DLL
        target_dll = dll_part.lower() + '.dll'
        target_addr = None

        if target_dll in dll_exports:
            target_addr = dll_exports[target_dll].get(func_part)

        if target_addr is None:
            # Try without .dll suffix
            if dll_part.lower() in dll_exports:
                target_addr = dll_exports[dll_part.lower()].get(func_part)

        if target_addr is not None:
            # Check if the resolved address is ALSO a forwarding string (chain)
            try:
                check_bytes = _ql.mem.read(target_addr, 64)
                check_null = check_bytes.index(0)
                check_str = check_bytes[:check_null].decode('ascii')
                if '.' in check_str and check_str.count('.') == 1:
                    # It's a chain — skip for now (would need recursive resolution)
                    failed += 1
                    continue
            except Exception:
                pass

            # Patch: write a JMP to the real target at the forwarding string address.
            # On x64: mov rax, imm64; jmp rax = 48 B8 <8 bytes> FF E0 (12 bytes)
            try:
                jmp_code = b'\x48\xB8' + target_addr.to_bytes(8, 'little') + b'\xFF\xE0'
                _ql.mem.write(addr, jmp_code)
                resolved += 1
            except Exception:
                failed += 1
        else:
            failed += 1


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


def _make_generic_stub(api_name, retval, writes=None, set_last_error=None):
    """Factory: create a CALL-hook closure for a data-driven stub.

    Args:
        api_name: API function name (for trace logging)
        retval: Return value (int) or None for void
        writes: List of {"param_index": int, "data_hex": str, "size": int}
        set_last_error: If not None, set _last_error_code to this value before
            returning. Used to bypass GetLastError() anti-emulation checks.
    """
    def _generic_stub(ql, address, _api_name):
        global _last_error_code
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
        if set_last_error is not None:
            _last_error_code = set_last_error & 0xFFFFFFFF
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
    # GetLastError/SetLastError are installed as Type 3 custom handlers below
    # to support dynamic _last_error_code state for anti-emulation bypass.
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

    # Map pages for string data (command line, environment) and heap stubs.
    # 4KB for CRT string data, 1MB for stub heap allocations.
    _stub_alloc_base = None
    _stub_alloc_offset = 0
    global _stub_heap_base, _stub_heap_offset, _STUB_HEAP_SIZE
    _stub_heap_base = None
    _stub_heap_offset = 0
    _STUB_HEAP_SIZE = 0x100000  # 1MB for stub heap

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

    # Map a 1MB stub heap region for HeapAlloc/VirtualAlloc returns
    try:
        heap_addr = 0x50000
        _ql.mem.map(heap_addr, _STUB_HEAP_SIZE, info="[stub_heap]")
        _stub_heap_base = heap_addr
    except Exception:
        try:
            heap_addr = 0x10100000
            _ql.mem.map(heap_addr, _STUB_HEAP_SIZE, info="[stub_heap]")
            _stub_heap_base = heap_addr
        except Exception:
            pass

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

    # GetLastError / SetLastError — dynamic stubs that read/write _last_error_code
    # to support anti-emulation bypass (e.g. TA505 GetLastError technique).
    def _stub_GetLastError(ql, address, _api_name):
        _add_trace_entry("GetLastError", address, {}, _last_error_code)
        _stub_set_retval(_last_error_code)

    def _stub_SetLastError(ql, address, _api_name):
        global _last_error_code
        error_code = _stub_read_param(0) & 0xFFFFFFFF
        _last_error_code = error_code
        _add_trace_entry("SetLastError", address,
                         {"dwErrCode": _hex(error_code)}, None)

    for _le_name, _le_fn, _le_params in [
        ("GetLastError", _stub_GetLastError, 0),
        ("SetLastError", _stub_SetLastError, 1),
    ]:
        _le_wrapped = _wrap_for_hook_address(_le_fn, _le_name)
        try:
            _le_hooks, _ = _hook_api_by_address(_le_name, _le_wrapped, _le_params)
            if _le_hooks:
                _stub_hooks[_le_name] = _le_hooks
                _crt_stub_names.add(_le_name)
        except Exception:
            pass

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

    # --- x64 fallback: also register stubs via set_api() ---
    # On x64, there's no STDCALL stack cleanup issue, so set_api() is safe.
    # This catches DLL-internal forwarded calls (e.g. kernel32→kernelbase)
    # that bypass the main binary's IAT and therefore bypass hook_address().
    if _arch == "x8664" and _ql is not None:
        _install_set_api_fallbacks()


def _make_set_api_wrapper(stub_fn, api_name):
    """Wrap a hook_address-style stub for use with ql.os.set_api().

    set_api callbacks receive (ql, pc, params) but our stubs use
    (ql, address, _api_name). This adapter bridges the two.
    """
    def _wrapper(ql, pc, params):
        stub_fn(ql, pc, api_name)
    return _wrapper


def _install_set_api_fallbacks():
    """Register stubs via set_api() AND patch DLL export entry points for x64.

    Three-layer approach for maximum compatibility:
    1. set_api() — catches Qiling-dispatched API calls
    2. DLL export patching — writes `xor eax,eax; ret` (or trampoline) at the
       actual function address in loaded DLLs (ntdll, kernel32, kernelbase, etc.)
       This prevents native DLL code from executing when set_api dispatch fails.
    3. Bump allocator — HeapAlloc/VirtualAlloc return unique addresses from a
       pre-mapped 1MB heap region instead of fixed values.

    Only called on x64 where the STDCALL double-hook issue doesn't apply.
    """
    if _ql is None:
        return

    # --- Collect all stub definitions: name → return_value ---
    _all_stub_defs = {}

    for spec in _CRT_SIMPLE_STUBS:
        _all_stub_defs[spec["name"]] = spec["return_value"]

    for spec in _CRT_WRITE_STUBS:
        _all_stub_defs[spec["name"]] = spec["return_value"]

    # Extra x64 stubs for DLL-forwarded APIs
    _extra_x64_stubs = [
        ("GetFileType", 0x2),
        ("SetHandleCount", 0x20),
        ("SetStdHandle", 1),
        ("GetModuleFileNameA", 0),
        ("GetModuleFileNameW", 0),
        ("RtlCaptureContext", None),
        ("RtlLookupFunctionEntry", 0),
        ("RtlVirtualUnwind", 0),
        ("RtlUnwindEx", None),
        ("HeapFree", 1),
        ("RtlFreeHeap", 1),
        ("HeapSize", 0x1000),
        ("RtlSizeHeap", 0x1000),
        ("HeapCreate", 0x20000),
        ("GetVersionExW", 1),
        ("GetVersionExA", 1),
        ("GetVersion", 0x0A280105),
        ("GetProcAddress", 0),
        ("LdrGetProcedureAddress", 0xC0000139),
        ("LdrLoadDll", 0xC0000135),
        ("LdrGetDllHandle", 0xC0000135),
        ("LoadLibraryA", 0),
        ("LoadLibraryW", 0),
        ("LoadLibraryExA", 0),
        ("LoadLibraryExW", 0),
        ("FreeLibrary", 1),
        ("VirtualQuery", 0),
        ("VirtualQueryEx", 0),
        ("VirtualProtect", 1),
        ("NtProtectVirtualMemory", 0),
        ("CloseHandle", 1),
        ("NtClose", 0),
        ("DuplicateHandle", 1),
        ("CreateFileA", 0xFFFFFFFFFFFFFFFF),
        ("CreateFileW", 0xFFFFFFFFFFFFFFFF),
        ("NtCreateFile", 0xC0000034),
        ("NtOpenFile", 0xC0000034),
        ("ReadFile", 0),
        ("NtReadFile", 0xC0000008),
        ("WriteFile", 1),
        ("GetConsoleMode", 1),
        ("SetConsoleMode", 1),
        ("GetConsoleCP", 65001),
        ("GetConsoleOutputCP", 65001),
        ("MultiByteToWideChar", 0),
        ("WideCharToMultiByte", 0),
        ("RtlMultiByteToUnicodeN", 0),
        ("RtlUnicodeToMultiByteN", 0),
        ("IsValidLocale", 1),
        ("GetLocaleInfoEx", 0),
        ("CompareStringEx", 0),
        ("GetTimeZoneInformation", 0),
        ("GetDynamicTimeZoneInformation", 0),
        ("SystemTimeToTzSpecificLocalTime", 1),
        ("FileTimeToSystemTime", 1),
        ("GetNativeSystemInfo", None),
        ("GetSystemInfo", None),
        ("InitOnceExecuteOnce", 1),
        ("RtlInitUnicodeString", None),
        ("RtlInitUnicodeStringEx", 0),
        ("RtlInitAnsiString", None),
        ("NtAllocateVirtualMemory", 0),
        ("NtFreeVirtualMemory", 0),
        ("NtQueryVirtualMemory", 0xC0000004),
        ("RtlInitializeCriticalSection", 0),
        ("RtlEnterCriticalSection", 0),
        ("RtlLeaveCriticalSection", 0),
        ("RtlDeleteCriticalSection", 0),
    ]
    for name, retval in _extra_x64_stubs:
        _all_stub_defs[name] = retval

    # --- Step 1: Register all stubs via set_api() ---
    registered = 0
    for name, retval in _all_stub_defs.items():
        try:
            stub = _make_generic_stub(name, retval)
            wrapper = _make_set_api_wrapper(stub, name)
            _ql.os.set_api(name, wrapper)
            registered += 1
        except Exception:
            pass

    # Also register write stubs with their write specs
    for spec in _CRT_WRITE_STUBS:
        try:
            stub = _make_generic_stub(spec["name"], spec["return_value"], spec["writes"])
            wrapper = _make_set_api_wrapper(stub, spec["name"])
            _ql.os.set_api(spec["name"], wrapper)
        except Exception:
            pass

    # --- Step 2: Bump-allocator stubs for heap APIs ---
    def _stub_heap_alloc(ql, address, _api_name):
        global _stub_heap_offset
        size = _stub_read_param(2) & 0xFFFFF
        if size == 0:
            size = 16
        size = (size + 15) & ~15
        if _stub_heap_base and _stub_heap_offset + size <= _STUB_HEAP_SIZE:
            addr = _stub_heap_base + _stub_heap_offset
            _stub_heap_offset += size
        else:
            addr = 0
        _add_trace_entry(_api_name, address, {"size": _hex(size)}, addr)
        _stub_set_retval(addr)

    def _stub_heap_realloc(ql, address, _api_name):
        global _stub_heap_offset
        size = _stub_read_param(3) & 0xFFFFF
        if size == 0:
            size = 16
        size = (size + 15) & ~15
        if _stub_heap_base and _stub_heap_offset + size <= _STUB_HEAP_SIZE:
            addr = _stub_heap_base + _stub_heap_offset
            _stub_heap_offset += size
        else:
            addr = 0
        _add_trace_entry(_api_name, address, {"size": _hex(size)}, addr)
        _stub_set_retval(addr)

    def _stub_virtual_alloc(ql, address, _api_name):
        global _stub_heap_offset
        size = _stub_read_param(1) & 0xFFFFF
        if size == 0:
            size = 0x1000
        size = (size + 0xFFF) & ~0xFFF
        if _stub_heap_base and _stub_heap_offset + size <= _STUB_HEAP_SIZE:
            addr = _stub_heap_base + _stub_heap_offset
            _stub_heap_offset += size
        else:
            addr = 0
        _add_trace_entry(_api_name, address, {"size": _hex(size)}, addr)
        _stub_set_retval(addr)

    _heap_api_map = {
        "HeapAlloc": _stub_heap_alloc,
        "RtlAllocateHeap": _stub_heap_alloc,
        "HeapReAlloc": _stub_heap_realloc,
        "RtlReAllocateHeap": _stub_heap_realloc,
        "VirtualAlloc": _stub_virtual_alloc,
        "NtAllocateVirtualMemory": _stub_virtual_alloc,
    }
    for _heap_name, _heap_fn in _heap_api_map.items():
        try:
            wrapper = _make_set_api_wrapper(_heap_fn, _heap_name)
            _ql.os.set_api(_heap_name, wrapper)
        except Exception:
            pass

    # --- Step 3: Patch DLL export entry points directly ---
    # This is the critical fix: even when set_api doesn't prevent native code
    # execution, patching the actual function bytes ensures the native code
    # immediately returns instead of running (and crashing on missing structures).
    _patch_dll_exports(_all_stub_defs, _heap_api_map)


def _patch_dll_exports(stub_defs, heap_api_map):
    """Patch actual DLL export function addresses with `xor eax,eax; ret`.

    Iterates all loaded DLL images, finds exported function names that match
    our stub definitions, and overwrites the first bytes of the function with
    a short return sequence. This prevents native DLL code from executing
    when Qiling's set_api dispatch doesn't fully intercept the call.

    For heap allocator APIs, patches with a sequence that returns the bump
    allocator's current address (updated via the set_api hook that fires first).
    """
    if _ql is None or not hasattr(_ql, 'loader'):
        return

    # Merge all API names we want to patch
    all_names = set(stub_defs.keys()) | set(heap_api_map.keys())

    # Build name → return_value for non-heap APIs
    ret_map = {}
    for name in all_names:
        if name in heap_api_map:
            ret_map[name] = None  # Heap APIs use bump allocator, patched differently
        elif name in stub_defs:
            ret_map[name] = stub_defs[name]

    # x64 ret sequence: xor eax, eax; ret (returns 0) = 31 C0 C3
    _RET_ZERO = b'\x31\xc0\xc3'
    # x64 ret sequence: mov eax, 1; ret (returns 1) = B8 01 00 00 00 C3
    _RET_ONE = b'\xb8\x01\x00\x00\x00\xc3'
    # x64 just ret (for void functions) = C3
    _RET_VOID = b'\xc3'

    patched_count = 0
    # Iterate all loaded images (DLLs)
    if not hasattr(_ql.loader, 'images'):
        return

    for image in _ql.loader.images:
        dll_name = image.path.split('/')[-1].split('\\')[-1].lower()
        # Only patch system DLLs, not the target binary
        if not any(dll_name.startswith(d) for d in (
            'ntdll', 'kernel32', 'kernelbase', 'ucrtbase', 'msvcrt',
            'advapi32', 'user32', 'gdi32', 'ws2_32', 'ole32',
            'combase', 'rpcrt4', 'sechost', 'bcrypt', 'crypt32',
        )):
            continue

        # Read the DLL's export table from Qiling's export_symbols
        if not hasattr(_ql.loader, 'export_symbols'):
            continue

        for ea, entry in _ql.loader.export_symbols.items():
            # Only patch exports within this DLL's address range
            if not (image.base <= ea < image.end):
                continue

            name = entry.get('name')
            if not name:
                continue
            api_name = name.decode() if isinstance(name, bytes) else str(name)

            if api_name not in all_names:
                continue

            # Determine patch bytes based on return value
            retval = ret_map.get(api_name)
            if api_name in heap_api_map:
                # For heap APIs: patch with ret that returns a value from
                # the stub_heap region. The set_api hook updates RAX before
                # the native code runs; but if it doesn't, this ensures we
                # at least return 0 instead of crashing.
                patch = _RET_ZERO
            elif retval is None:
                patch = _RET_VOID
            elif retval == 0:
                patch = _RET_ZERO
            elif retval == 1:
                patch = _RET_ONE
            else:
                # mov eax, imm32; ret
                patch = b'\xb8' + (retval & 0xFFFFFFFF).to_bytes(4, 'little') + b'\xc3'

            try:
                _ql.mem.write(ea, patch)
                patched_count += 1
            except Exception:
                pass


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


def _extend_stack(ql):
    """Extend the Qiling stack for x64 Windows binaries.

    Qiling's default stack (~128KB) is insufficient for complex binaries
    like interpreters (AutoIt3, Python, etc.) that have deep call chains
    during CRT initialization. Windows default is 1MB reserved.

    This function maps additional memory below the current stack to provide
    ~1MB total stack space.
    """
    try:
        rsp = ql.arch.regs.read("rsp")
        # Find the stack base by checking the current mapping
        stack_base = None
        for start, end, perm, label, *_ in ql.mem.get_mapinfo():
            if start <= rsp <= end:
                stack_base = start
                break
        if stack_base is None:
            return

        # Map 896KB below the current stack base (giving ~1MB total)
        extension_size = 0xE0000  # 896KB
        extension_base = stack_base - extension_size
        if extension_base < 0x10000:
            return  # Not enough address space

        ql.mem.map(extension_base, extension_size, info="[stack_extension]")
    except Exception:
        pass  # Non-critical — emulation continues with original stack


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
    global _stub_alloc_base, _stub_alloc_offset, _crt_stub_names, _last_error_code
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

    # Extend the stack for x64 Windows binaries — Qiling defaults to ~128KB
    # but MSVC CRT and complex binaries like interpreters need 1MB+.
    if arch == "x8664" and os_type == "windows":
        _extend_stack(ql)
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
    _last_error_code = 0

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


_auto_recover_count = 0
_AUTO_RECOVER_MAX = 500  # Max auto-recoveries before giving up


def _auto_recover_unmapped(err_str):
    """Auto-recover from unmapped/exception errors on x64 by unwinding to caller.

    When a DLL function crashes on unmapped memory or an unhandled CPU exception
    (common with forwarded exports, unimplemented APIs, or null function pointers),
    this function:
    1. Scans the stack for the first valid return address
    2. Sets RAX=0 (generic failure return)
    3. Adjusts RSP past the found return address
    4. Redirects RIP to the return address

    Stack scanning: if [RSP] is not a valid code address (< 0x10000 or > max),
    scans up to 8 QWORD slots deeper in the stack looking for a valid address
    in the main binary (0x140000000-0x140200000) or loaded DLLs (0x180000000+).

    Limited to _AUTO_RECOVER_MAX recoveries to prevent infinite loops.

    Returns True if recovery was successful and emulation should retry.
    """
    global _auto_recover_count
    if _ql is None:
        return False

    _auto_recover_count += 1
    if _auto_recover_count > _AUTO_RECOVER_MAX:
        return False

    try:
        pc = _get_pc()
        rsp = _ql.arch.regs.read("rsp")

        # Scan the stack for a valid return address (up to 8 slots deep)
        ret_addr = 0
        ret_rsp = rsp
        for slot in range(8):
            addr = rsp + slot * 8
            try:
                val_bytes = _ql.mem.read(addr, 8)
                val = int.from_bytes(val_bytes, 'little')
            except Exception:
                continue
            # Valid return address: in binary or DLL address space
            if 0x140000000 <= val <= 0x1401FFFFF:  # Main binary
                ret_addr = val
                ret_rsp = addr + 8  # Pop past this slot
                break
            if 0x180000000 <= val <= 0x181FFFFFF:  # Loaded DLLs
                ret_addr = val
                ret_rsp = addr + 8
                break

        if ret_addr == 0:
            return False  # No valid return address found

        # Log the recovery
        _add_trace_entry(f"_auto_recover@{_hex(pc)}", pc,
                         {"error": err_str[:80], "ret_to": _hex(ret_addr)},
                         0)

        # Set RAX=0 (default failure return), adjust RSP past the found slot, redirect RIP
        _ql.arch.regs.write("rax", 0)
        _ql.arch.regs.write("rsp", ret_rsp)  # Pop past the return address slot
        _ql.arch.regs.write("rip", ret_addr)

        return True
    except Exception:
        return False


def _run_with_reentry(max_insns, timeout_seconds=None):
    """Run emulation with re-entry loop for API hook processing.

    Qiling's ql.run() returns after each API hook dispatch (simprocedure
    handling). This loop re-enters ql.run() until we either hit max_insns,
    a stop reason is set (breakpoint/watchpoint), the emulation exits,
    or the timeout is reached.

    When ``timeout_seconds`` is set, each ``_ql.run()`` call is executed in
    a daemon thread.  If the deadline is exceeded the main thread calls
    ``_ql.emu_stop()`` (Unicorn's thread-safe stop) which causes the
    current ``ql.run()`` to return cleanly.  All CPU / memory state is
    preserved, so the session can be inspected and resumed afterwards.

    Returns (error_extra: dict or None). If None, check _stop_reason.
    """
    remaining = max_insns
    stall_count = 0
    max_stalls = 200  # Safety: avoid infinite loop if emulation is stuck
    reentries = 0
    max_reentries = 500  # Hard cap on total loop iterations

    deadline = (time.monotonic() + timeout_seconds) if timeout_seconds else None

    while remaining > 0 and reentries < max_reentries:
        reentries += 1
        prev_count = _insn_count
        prev_pc = _get_pc()

        # Check deadline before each iteration
        if deadline and time.monotonic() >= deadline:
            return {"stop_reason": "timeout",
                    "timeout_seconds": timeout_seconds,
                    "note": ("Command timed out. Session is still alive and "
                             "resumable — use debug_read_state, debug_read_memory, "
                             "debug_search_memory to inspect, then debug_continue "
                             "to resume execution.")}

        if deadline:
            # Run emulation in a thread so we can interrupt via emu_stop()
            run_result = [None]  # [exception | None]

            def _emu_thread():
                try:
                    _ql.run(count=remaining)
                except Exception as exc:
                    run_result[0] = exc

            t = threading.Thread(target=_emu_thread, daemon=True)
            t.start()

            wait_time = max(0.0, deadline - time.monotonic())
            t.join(timeout=wait_time)

            if t.is_alive():
                # Deadline exceeded while _ql.run() is still going —
                # emu_stop() is thread-safe (Unicorn guarantee).
                try:
                    _ql.emu_stop()
                except Exception:
                    pass
                t.join(timeout=5)  # Give Unicorn a moment to wind down
                return {"stop_reason": "timeout",
                        "timeout_seconds": timeout_seconds,
                        "note": ("Command timed out. Session is still alive and "
                                 "resumable — use debug_read_state, debug_read_memory, "
                                 "debug_search_memory to inspect, then debug_continue "
                                 "to resume execution.")}

            if run_result[0] is not None:
                e = run_result[0]
                err_str = str(e)
                if "unmapped" in err_str.lower() or "exception" in err_str.lower():
                    if _arch == "x8664" and _auto_recover_unmapped(err_str):
                        continue  # Retry after recovery
                    return {"stop_reason": "exited", "exit_reason": err_str[:500]}
                if "exit" in err_str.lower():
                    return {"stop_reason": "exited", "exit_reason": err_str[:500]}
                return {"stop_reason": "exception", "error_detail": err_str[:500]}
        else:
            # No timeout — run directly (original fast path)
            try:
                _ql.run(count=remaining)
            except Exception as e:
                err_str = str(e)
                if "unmapped" in err_str.lower() or "exception" in err_str.lower():
                    # --- Auto-recovery for x64: unwind to caller ---
                    if _arch == "x8664" and _auto_recover_unmapped(err_str):
                        continue  # Retry the loop after recovery
                    return {"stop_reason": "exited", "exit_reason": err_str[:500]}
                if "exit" in err_str.lower():
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
    timeout_seconds = cmd.get("timeout_seconds")
    _stop_reason = ""
    _hit_bp_id = None
    _hit_wp_id = None
    _wp_access_info = None

    error_extra = _run_with_reentry(count, timeout_seconds=timeout_seconds)
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
    timeout_seconds = cmd.get("timeout_seconds")
    error_extra = _run_with_reentry(max_insns, timeout_seconds=timeout_seconds)

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
    timeout_seconds = cmd.get("timeout_seconds")
    _stop_reason = ""
    _hit_bp_id = None
    _hit_wp_id = None
    _wp_access_info = None

    error_extra = _run_with_reentry(max_insns, timeout_seconds=timeout_seconds)
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

    timeout_seconds = cmd.get("timeout_seconds")

    temp_callback = _make_temp_bp_callback()
    try:
        hook = _ql.hook_address(temp_callback, address)
    except Exception as e:
        return {"error": f"Failed to set temp breakpoint at {_hex(address)}: {e}"}

    error_extra = _run_with_reentry(max_insns, timeout_seconds=timeout_seconds)

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
        "trace_seq": _api_trace_seq,  # For cross-snapshot attribution
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

    result = {
        "status": "ok",
        "snapshot_a": {"id": snap_id_a, "name": snap_a.get("name"), "pc": snap_a.get("pc")},
        "snapshot_b": {"id": snap_id_b, "name": snap_b.get("name"), "pc": snap_b.get("pc")},
        "register_diffs": reg_diffs,
        "memory_diffs": mem_diffs[:100],
        "total_register_diffs": len(reg_diffs),
        "total_memory_diffs": len(mem_diffs),
    }

    # Cross-snapshot attribution: correlate memory changes with API calls
    if cmd.get("attribute_changes"):
        attribution = _attribute_memory_changes(snap_a, snap_b, mem_diffs)
        result.update(attribution)

    return result


# ---------------------------------------------------------------------------
# Memory-to-API attribution for snapshot diffs
# ---------------------------------------------------------------------------

# APIs known to allocate, write to, or modify memory regions
_ALLOC_APIS = frozenset({
    "virtualalloc", "virtualallocex", "heapalloc", "localalloc",
    "globalalloc", "ntmapviewofsection", "ntallocatevirtualmemory",
    "rtlallocateheap", "mapviewoffile",
})
_WRITE_APIS = frozenset({
    "writeprocessmemory", "ntwritevirtualmemory", "memcpy", "memmove",
    "rtlmovememory", "rtlcopymemory", "rtlfillmemory", "memset",
})
_IO_APIS = frozenset({
    "readfile", "recv", "internetreadfile", "wsarecv",
    "ntreadfile", "readfilescatter",
})
_PROTECT_APIS = frozenset({
    "virtualprotect", "virtualprotectex", "ntprotectvirtualmemory",
})

_MAX_ATTRIBUTED_CALLS = 200


def _attribute_memory_changes(snap_a, snap_b, mem_diffs):
    """Correlate memory diffs with API calls between two snapshots.

    Returns a dict with ``api_calls_between``, ``attribution``, and
    ``unattributed_changes`` to be merged into the diff result.
    """
    seq_a = snap_a.get("trace_seq", 0)
    seq_b = snap_b.get("trace_seq", 0)

    # Ensure ordering
    lo, hi = min(seq_a, seq_b), max(seq_a, seq_b)

    # Collect API calls between the two snapshots
    calls_between = [e for e in _api_trace if lo < e.get("seq", 0) <= hi]

    # Build attribution categories
    allocations = []
    writes = []
    io_reads = []
    protections = []

    for call in calls_between:
        api_lower = str(call.get("api", "")).lower()

        if api_lower in _ALLOC_APIS:
            retval = call.get("retval", "0x0")
            size_arg = call.get("args", {}).get("p1", "0")
            allocations.append({
                "api": call.get("api"),
                "seq": call.get("seq"),
                "address": retval,
                "size": size_arg,
            })
        elif api_lower in _WRITE_APIS:
            args = call.get("args", {})
            writes.append({
                "api": call.get("api"),
                "seq": call.get("seq"),
                "target": args.get("p1", "unknown"),
                "size": args.get("p3", args.get("p2", "unknown")),
            })
        elif api_lower in _IO_APIS:
            args = call.get("args", {})
            io_reads.append({
                "api": call.get("api"),
                "seq": call.get("seq"),
                "buffer": args.get("p1", "unknown"),
                "size": args.get("p2", "unknown"),
            })
        elif api_lower in _PROTECT_APIS:
            args = call.get("args", {})
            protections.append({
                "api": call.get("api"),
                "seq": call.get("seq"),
                "address": args.get("p0", args.get("p1", "unknown")),
                "new_protection": args.get("p2", args.get("p3", "unknown")),
            })

    # Count unattributed changes: memory diffs not explainable by any API
    attributed_addrs = set()
    for a in allocations:
        addr = _try_parse_hex(a.get("address"))
        if addr is not None:
            attributed_addrs.add(addr)
    for w in writes:
        addr = _try_parse_hex(w.get("target"))
        if addr is not None:
            attributed_addrs.add(addr)
    for io in io_reads:
        addr = _try_parse_hex(io.get("buffer"))
        if addr is not None:
            attributed_addrs.add(addr)

    unattributed = 0
    for diff in mem_diffs:
        diff_addr = _try_parse_hex(diff.get("address"))
        if diff_addr is not None and diff_addr not in attributed_addrs:
            unattributed += 1

    # Warn if snapshots lack trace_seq (old format)
    warnings = []
    if "trace_seq" not in snap_a or "trace_seq" not in snap_b:
        warnings.append(
            "One or both snapshots lack trace_seq — attribution may be "
            "inaccurate. Re-save snapshots for reliable results."
        )

    result = {
        "api_calls_between": calls_between[:_MAX_ATTRIBUTED_CALLS],
        "api_calls_between_count": len(calls_between),
        "attribution": {
            "memory_allocations": allocations,
            "memory_writes": writes,
            "io_reads": io_reads,
            "protection_changes": protections,
        },
        "unattributed_changes": unattributed,
    }
    if warnings:
        result["attribution_warnings"] = warnings
    return result


def _try_parse_hex(value):
    """Try to parse a hex string to int, return None on failure."""
    if value is None:
        return None
    try:
        return int(str(value), 16)
    except (ValueError, OverflowError):
        try:
            return int(str(value))
        except (ValueError, OverflowError):
            return None


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
    """Return API trace entries (paginated, optional filter/query/sequence)."""
    if _ql is None:
        return {"error": "No debug session active. Call 'init' first."}

    offset = max(0, cmd.get("offset", 0))
    limit = max(1, min(cmd.get("limit", 100), 1000))
    api_filter = cmd.get("filter")  # Legacy: simple API name substring
    query_str = cmd.get("query", "")  # Structured query predicates
    sequence_str = cmd.get("sequence", "")  # Ordered API sequence matching

    # Step 1: Apply legacy name filter
    if api_filter:
        api_filter_lower = api_filter.lower()
        filtered = [e for e in _api_trace if api_filter_lower in e.get("api", "").lower()]
    else:
        filtered = _api_trace

    # Step 2: Apply structured query predicates
    if query_str:
        try:
            predicates = parse_query(query_str)
            filtered = filter_trace(filtered, predicates)
        except ValueError as e:
            return {"error": f"Invalid query: {e}"}

    # Step 3: Handle sequence matching (separate from pagination)
    if sequence_str:
        try:
            steps = parse_sequence(sequence_str)
        except ValueError as e:
            return {"error": f"Invalid sequence: {e}"}
        if steps:
            gap_max = max(0, cmd.get("gap_max", 0))
            seq_matches = match_sequences(filtered, steps, gap_max=gap_max)
            return {
                "status": "ok",
                "sequence_matches": seq_matches,
                "sequence_pattern": sequence_str,
                "total_matches": len(seq_matches),
                "trace_size": len(_api_trace),
                "filtered_size": len(filtered),
                "trace_enabled": _api_trace_enabled,
            }

    # Step 4: Paginate
    entries = filtered[offset:offset + limit]
    total = len(filtered)

    result = {
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
    if query_str:
        result["query"] = query_str
    return result


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

    # Parse set_last_error (for GetLastError anti-emulation bypass)
    set_last_error_val = cmd.get("set_last_error")
    if set_last_error_val is not None:
        try:
            if isinstance(set_last_error_val, int):
                pass  # Already an int from MCP layer
            elif isinstance(set_last_error_val, str):
                if set_last_error_val.startswith(("0x", "0X")):
                    set_last_error_val = int(set_last_error_val, 16)
                else:
                    set_last_error_val = int(set_last_error_val)
            else:
                return {"error": f"Invalid set_last_error type: {type(set_last_error_val).__name__}"}
            if set_last_error_val < 0 or set_last_error_val > 0xFFFFFFFF:
                return {"error": "set_last_error must be 0-0xFFFFFFFF"}
        except (ValueError, TypeError):
            return {"error": f"Invalid set_last_error: '{set_last_error_val}'. Use hex or decimal."}

    # Create and register the stub
    stub_fn = _make_generic_stub(
        api_name, return_value, writes if writes else None,
        set_last_error=set_last_error_val,
    )
    wrapped = _wrap_for_hook_address(stub_fn, api_name)
    hooks, patched = _hook_api_by_address(api_name, wrapped, num_params)
    _stub_hooks[api_name] = hooks

    # On x64, also register via set_api() to catch DLL-internal forwarded calls
    set_api_registered = False
    if _arch == "x8664" and _ql is not None:
        try:
            sa_wrapper = _make_set_api_wrapper(stub_fn, api_name)
            _ql.os.set_api(api_name, sa_wrapper)
            set_api_registered = True
        except Exception:
            pass

    _user_stubs[api_name] = {
        "return_value": return_value,
        "num_params": num_params,
        "writes": writes,
        "patched": patched,
        "set_api_registered": set_api_registered,
        "set_last_error": set_last_error_val,
    }

    return {
        "status": "ok",
        "api_name": api_name,
        "return_value": _hex(return_value) if isinstance(return_value, int) else None,
        "set_last_error": _hex(set_last_error_val) if set_last_error_val is not None else None,
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
        entry = {
            "api_name": name,
            "return_value": _hex(info["return_value"]) if isinstance(info["return_value"], int) else None,
            "num_params": info["num_params"],
            "writes_count": len(info.get("writes", [])),
            "patched": info["patched"],
        }
        sle = info.get("set_last_error")
        if sle is not None:
            entry["set_last_error"] = _hex(sle)
        user_stubs.append(entry)

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
