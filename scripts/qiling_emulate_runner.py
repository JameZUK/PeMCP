#!/usr/bin/env python
"""Persistent Qiling emulation runner -- invoked via subprocess from Arkana.

Unlike qiling_runner.py which is one-shot (stdin JSON -> stdout JSON -> exit),
this runner maintains a persistent JSONL command loop over stdin/stdout.
After emulation completes, the Qiling object stays alive so memory can be
inspected via read_memory, search_memory, and memory_map commands.

This script runs inside /app/qiling-venv which has unicorn 1.x.

Protocol:
    -> {"action": "emulate_binary", "filepath": "/path/to/binary", ...}
    <- {"status": "completed", "api_calls": [...], ...}
    -> {"action": "search_memory", "search_patterns": ["http://"], ...}
    <- {"status": "ok", "total_matches": 3, "matches": [...]}
    -> {"action": "read_memory", "address": "0x401000", "length": 256}
    <- {"status": "ok", "address": "0x401000", "hex": "...", "ascii": "..."}
    -> {"action": "stop"}
    <- {"status": "ok"}
"""
import hashlib
import json
import os
import sys
import threading
import traceback

# --- Reuse helpers from qiling_runner.py (same venv) ---
_scripts_dir = os.path.dirname(os.path.abspath(__file__))
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

from qiling_runner import (  # noqa: E402
    _validate_file_path, _safe_slice, _hex,
    _setup_api_hooks, _setup_syscall_trace, _analyze_memory_activity,
    _init_qiling_for_binary, _cleanup_staged_binary,
    _find_rootfs, _ql_os, _ql_arch,
)

from qiling import Qiling  # noqa: E402
from qiling.const import QL_VERBOSE  # noqa: E402

try:
    from capstone import (  # noqa: E402
        Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS,
        CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_MIPS32,
        CS_MODE_LITTLE_ENDIAN,
    )
    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False

# ---------------------------------------------------------------------------
#  Hard timeout safety net
# ---------------------------------------------------------------------------
# asyncio.wait_for() on the MCP side may fail to cancel subprocess pipe reads
# (observed on Python 3.12+).  This timer guarantees the subprocess dies even
# if the parent's timeout mechanism is broken.

_emulation_timer = None          # threading.Timer for hard self-destruct


def _start_hard_timeout(seconds):
    """Start a hard timeout that kills this process after *seconds*."""
    global _emulation_timer
    _cancel_hard_timeout()

    def _die():
        sys.stderr.write(
            f"[qiling_emulate_runner] Hard timeout ({seconds}s) reached — "
            f"forcing exit.\n"
        )
        sys.stderr.flush()
        os._exit(99)

    _emulation_timer = threading.Timer(seconds, _die)
    _emulation_timer.daemon = True
    _emulation_timer.start()


def _cancel_hard_timeout():
    """Cancel the hard timeout if it's running."""
    global _emulation_timer
    if _emulation_timer is not None:
        _emulation_timer.cancel()
        _emulation_timer = None


# ---------------------------------------------------------------------------
#  Module state — persists across commands
# ---------------------------------------------------------------------------

_ql = None               # Qiling instance (kept alive after emulation)
_cs = None               # Capstone disassembler instance
_arch = ""               # Detected architecture string
_staged_path = None       # Staged binary path for cleanup
_emulation_completed = False
_dll_warning = None

_MAX_MEMORY_READ = 1_048_576   # 1MB
_MAX_SEARCH_MATCHES = 100
_DEFAULT_CONTEXT_BYTES = 32
_MAX_DISASM_INSTRUCTIONS = 100


def _init_capstone(arch):
    """Initialize Capstone disassembler for the given architecture."""
    global _cs
    if not _CAPSTONE_AVAILABLE:
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
#  Command handlers
# ---------------------------------------------------------------------------

def cmd_emulate_binary(cmd):
    """Full binary emulation — keeps Qiling alive for post-emulation inspection."""
    global _ql, _cs, _arch, _staged_path, _emulation_completed, _dll_warning

    if _emulation_completed:
        return {"error": "Emulation already completed. Use memory inspection commands, "
                "or send 'stop' and start a new session."}

    filepath = cmd["filepath"]
    _validate_file_path(filepath)
    rootfs_path = cmd.get("rootfs_path")
    timeout_seconds = cmd.get("timeout_seconds", 60)
    max_instructions = cmd.get("max_instructions", 0)
    limit = cmd.get("limit", 200)
    trace_syscalls = cmd.get("trace_syscalls", False)
    syscall_filter = cmd.get("syscall_filter", [])
    track_memory = cmd.get("track_memory", False)

    ql, os_type, arch, fmt_desc, init_result, staged_path = _init_qiling_for_binary(filepath, rootfs_path)
    if ql is None:
        return init_result

    _ql = ql
    _arch = arch
    _init_capstone(arch)
    _staged_path = staged_path
    _dll_warning = init_result  # dll_warning is returned as init_result on success

    api_calls = []
    file_activity = []
    registry_activity = []
    network_activity = []
    syscall_timeline = []

    if trace_syscalls:
        _setup_syscall_trace(ql, os_type, api_calls, syscall_timeline,
                             syscall_filter, limit)
    else:
        _setup_api_hooks(ql, os_type, api_calls, limit)

    # Hard safety net: kill this process if emulation hangs.
    _start_hard_timeout(timeout_seconds + 15)

    emulation_exception = None
    try:
        if max_instructions > 0:
            ql.run(count=max_instructions, timeout=timeout_seconds * 1000000)
        else:
            ql.run(timeout=timeout_seconds * 1000000)
    except Exception as e:
        emulation_exception = f"{type(e).__name__}: {e}"

    _cancel_hard_timeout()
    _emulation_completed = True

    # Post-hoc activity classification
    for entry in api_calls:
        api_lower = (entry.get("api") or "").lower()
        if any(k in api_lower for k in ("createfile", "writefile", "readfile", "deletefile",
                                         "open", "write", "read", "fopen", "fwrite")):
            if len(file_activity) < limit:
                file_activity.append({"api": entry["api"], "params": entry["params"]})
        elif any(k in api_lower for k in ("regopen", "regset", "regquery", "regcreate", "regdelete")):
            if len(registry_activity) < limit:
                registry_activity.append({"api": entry["api"], "params": entry["params"]})
        elif any(k in api_lower for k in ("socket", "connect", "send", "recv", "wsastartup",
                                           "bind", "listen", "accept", "getaddrinfo",
                                           "internetopen", "httpopen", "urldownload")):
            if len(network_activity) < limit:
                network_activity.append({"api": entry["api"], "params": entry["params"]})

    result = {
        "status": "completed",
        "session_alive": True,
        "format": fmt_desc,
        "os_type": os_type,
        "architecture": arch,
        "total_api_calls": len(api_calls),
        "api_calls": _safe_slice(api_calls, limit),
        "file_activity": _safe_slice(file_activity, limit),
        "registry_activity": _safe_slice(registry_activity, limit),
        "network_activity": _safe_slice(network_activity, limit),
        "hint": "Session alive. Use read_memory, search_memory, memory_map to inspect emulated memory. Send 'stop' when done.",
    }

    if trace_syscalls and syscall_timeline:
        result["syscall_timeline"] = _safe_slice(syscall_timeline, limit)
        result["total_syscalls_traced"] = len(syscall_timeline)
        counts = {}
        for entry in syscall_timeline:
            name = entry.get("api") or entry.get("syscall", "unknown")
            counts[name] = counts.get(name, 0) + 1
        result["syscall_summary"] = dict(sorted(counts.items(), key=lambda x: -x[1])[:20])

    if track_memory:
        result["memory_activity"] = _analyze_memory_activity(api_calls, limit)

    if emulation_exception:
        result["emulation_exception"] = emulation_exception

    if _dll_warning:
        result["warning"] = _dll_warning

    return result


def cmd_emulate_shellcode(cmd):
    """Shellcode emulation — keeps Qiling alive for post-emulation inspection."""
    global _ql, _cs, _arch, _emulation_completed, _dll_warning

    if _emulation_completed:
        return {"error": "Emulation already completed. Use memory inspection commands, "
                "or send 'stop' and start a new session."}

    shellcode_hex = cmd.get("shellcode_hex")
    filepath = cmd.get("filepath")
    os_type = cmd.get("os_type", "windows")
    arch = cmd.get("architecture", "x86")
    rootfs_path = cmd.get("rootfs_path")
    timeout_seconds = cmd.get("timeout_seconds", 30)
    max_instructions = cmd.get("max_instructions", 0)
    limit = cmd.get("limit", 200)

    if shellcode_hex:
        sc_data = bytes.fromhex(shellcode_hex)
    elif filepath:
        _validate_file_path(filepath)
        with open(filepath, "rb") as f:
            sc_data = f.read()
    else:
        return {"error": "No shellcode provided (no shellcode_hex or filepath)."}

    rootfs, err, dll_warning = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}
    _dll_warning = dll_warning

    api_calls = []

    try:
        ql = Qiling(
            code=sc_data,
            rootfs=rootfs,
            ostype=_ql_os(os_type),
            archtype=_ql_arch(arch),
            verbose=QL_VERBOSE.DISABLED,
        )
    except Exception as e:
        err_msg = f"Failed to initialize Qiling for shellcode: {e}"
        if dll_warning:
            err_msg += f"\n\nNote: {dll_warning}"
        return {"error": err_msg}

    _ql = ql
    _arch = arch
    _init_capstone(arch)
    _setup_api_hooks(ql, os_type, api_calls, limit)

    # Hard safety net: kill this process if emulation hangs.
    _start_hard_timeout(timeout_seconds + 15)

    emulation_exception = None
    try:
        if max_instructions > 0:
            ql.run(count=max_instructions, timeout=timeout_seconds * 1000000)
        else:
            ql.run(timeout=timeout_seconds * 1000000)
    except Exception as e:
        emulation_exception = f"{type(e).__name__}: {e}"

    _cancel_hard_timeout()
    _emulation_completed = True

    result = {
        "status": "completed",
        "session_alive": True,
        "os_type": os_type,
        "architecture": arch,
        "shellcode_size": len(sc_data),
        "shellcode_sha256": hashlib.sha256(sc_data).hexdigest(),
        "total_api_calls": len(api_calls),
        "api_calls": _safe_slice(api_calls, limit),
        "hint": "Session alive. Use read_memory, search_memory, memory_map to inspect emulated memory. Send 'stop' when done.",
    }
    if emulation_exception:
        result["emulation_exception"] = emulation_exception
    if dll_warning:
        result["warning"] = dll_warning
    return result


def cmd_read_memory(cmd):
    """Read memory from the emulated process."""
    if _ql is None or not _emulation_completed:
        return {"error": "Emulation has not been run yet. Send 'emulate_binary' or 'emulate_shellcode' first."}

    address = cmd.get("address", "")
    try:
        if isinstance(address, str):
            address = int(address, 16) if address.startswith(("0x", "0X")) else int(address)
    except (ValueError, AttributeError):
        return {"error": f"Invalid address format: {address!r}. Expected hex (0x...) or decimal."}
    length = min(max(1, cmd.get("length", 256)), _MAX_MEMORY_READ)

    fmt = cmd.get("format", "hex")

    try:
        data = bytes(_ql.mem.read(address, length))
    except Exception as e:
        return {"error": f"Memory read failed at {_hex(address)}: {e}"}

    result = {
        "status": "ok",
        "address": _hex(address),
        "length": len(data),
        "hex": data.hex(),
    }

    if fmt == "disasm" and _cs is not None:
        insns = []
        for insn in _cs.disasm(data, address):
            insns.append({
                "address": _hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
            })
            if len(insns) >= _MAX_DISASM_INSTRUCTIONS:
                break
        result["disassembly"] = insns

    # Build ASCII representation
    ascii_repr = ""
    for b in data[:1024]:
        ascii_repr += chr(b) if 32 <= b < 127 else "."
    if ascii_repr:
        result["ascii"] = ascii_repr

    return result


def cmd_memory_map(cmd):
    """Return the full memory map of the emulated process."""
    if _ql is None or not _emulation_completed:
        return {"error": "Emulation has not been run yet. Send 'emulate_binary' or 'emulate_shellcode' first."}

    try:
        maps = _ql.mem.get_mapinfo()
    except Exception as e:
        return {"error": f"Memory map query failed: {e}"}

    regions = []
    for entry in maps[:200]:
        if len(entry) >= 4:
            start, end, perms, label = entry[0], entry[1], entry[2], entry[3]
        else:
            continue
        regions.append({
            "start": _hex(start),
            "end": _hex(end),
            "size": end - start,
            "permissions": perms if isinstance(perms, str) else str(perms),
            "label": str(label) if label else "",
        })

    return {
        "status": "ok",
        "total_regions": len(regions),
        "regions": regions,
    }


def cmd_search_memory(cmd):
    """Search emulated memory for string or hex patterns."""
    if _ql is None or not _emulation_completed:
        return {"error": "Emulation has not been run yet. Send 'emulate_binary' or 'emulate_shellcode' first."}

    search_patterns = cmd.get("search_patterns", [])
    search_hex = cmd.get("search_hex")
    context_bytes = min(max(0, cmd.get("context_bytes", _DEFAULT_CONTEXT_BYTES)), 256)
    limit = min(max(1, cmd.get("limit", 50)), _MAX_SEARCH_MATCHES)

    # Build search needles
    needles = []
    for pat in search_patterns:
        needles.append(("string", pat, pat.encode("utf-8")))
        needles.append(("string_wide", pat, pat.encode("utf-16-le")))
    if search_hex:
        try:
            needles.append(("hex", search_hex, bytes.fromhex(search_hex)))
        except ValueError as e:
            return {"error": f"Invalid hex pattern: {e}"}

    if not needles:
        return {"error": "No search patterns provided. Use 'search_patterns' (strings) or 'search_hex'."}

    matches = []
    try:
        maps = _ql.mem.get_mapinfo()
        for entry in maps:
            if len(matches) >= limit:
                break
            start, end = entry[0], entry[1]
            label = entry[3] if len(entry) > 3 else ""
            region_size = end - start
            if region_size > 64 * 1024 * 1024:
                continue  # Skip regions > 64MB

            try:
                region_data = bytes(_ql.mem.read(start, region_size))
            except Exception:
                continue

            for needle_type, needle_display, needle_bytes in needles:
                if len(matches) >= limit:
                    break
                offset = 0
                while offset < len(region_data):
                    idx = region_data.find(needle_bytes, offset)
                    if idx == -1:
                        break
                    abs_addr = start + idx
                    ctx_start = max(0, idx - context_bytes)
                    ctx_end = min(len(region_data), idx + len(needle_bytes) + context_bytes)
                    context_data = region_data[ctx_start:ctx_end]

                    matches.append({
                        "address": _hex(abs_addr),
                        "type": needle_type,
                        "pattern": needle_display,
                        "region": f"{_hex(start)}-{_hex(end)} ({label})",
                        "context_hex": context_data.hex(),
                    })
                    if len(matches) >= limit:
                        break
                    offset = idx + len(needle_bytes)
    except Exception as e:
        return {"error": f"Memory search failed: {e}"}

    return {
        "status": "ok",
        "total_matches": len(matches),
        "matches": matches,
    }


def cmd_write_memory(cmd):
    """Write bytes to emulated memory."""
    if _ql is None or not _emulation_completed:
        return {"error": "Emulation has not been run yet. Send 'emulate_binary' or 'emulate_shellcode' first."}

    address = cmd.get("address", "")
    try:
        if isinstance(address, str):
            address = int(address, 16) if address.startswith(("0x", "0X")) else int(address)
    except (ValueError, AttributeError):
        return {"error": f"Invalid address format: {address!r}. Expected hex (0x...) or decimal."}

    hex_bytes = cmd.get("hex_bytes", "")
    if not hex_bytes or len(hex_bytes) > 2_097_152:  # 2MB hex = 1MB data
        return {"error": "hex_bytes required and must be <= 2MB hex string"}
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


def cmd_resume(cmd):
    """Resume emulation from where it left off (e.g. after a timeout).

    Continues executing from the current CPU state.  Useful for long-running
    operations (like UPX decompression) that need more time than a single
    timeout window allows.
    """
    if _ql is None:
        return {"error": "No Qiling instance. Run emulate_binary or emulate_shellcode first."}
    if not _emulation_completed:
        return {"error": "Emulation has not completed its first run yet."}

    timeout_seconds = cmd.get("timeout_seconds", 300)
    max_instructions = cmd.get("max_instructions", 0)

    _start_hard_timeout(timeout_seconds + 15)

    emulation_exception = None
    try:
        if max_instructions > 0:
            _ql.run(count=max_instructions, timeout=timeout_seconds * 1000000)
        else:
            _ql.run(timeout=timeout_seconds * 1000000)
    except Exception as e:
        emulation_exception = f"{type(e).__name__}: {e}"

    _cancel_hard_timeout()

    # Read the current program counter to report progress
    try:
        pc = _ql.arch.regs.arch_pc
    except Exception:
        pc = None

    result = {
        "status": "resumed_ok",
        "timeout_seconds": timeout_seconds,
        "program_counter": _hex(pc) if pc else None,
    }
    if emulation_exception:
        result["emulation_exception"] = emulation_exception
    return result


def cmd_stop(cmd):
    """Clean up and signal exit."""
    global _ql, _staged_path, _emulation_completed
    _cleanup_staged_binary(_staged_path)
    _ql = None
    _staged_path = None
    _emulation_completed = False
    return {"status": "ok"}


# ---------------------------------------------------------------------------
#  Dispatch and main JSONL loop
# ---------------------------------------------------------------------------

DISPATCH = {
    "emulate_binary": cmd_emulate_binary,
    "emulate_shellcode": cmd_emulate_shellcode,
    "resume": cmd_resume,
    "read_memory": cmd_read_memory,
    "write_memory": cmd_write_memory,
    "memory_map": cmd_memory_map,
    "search_memory": cmd_search_memory,
    "stop": cmd_stop,
}


def main():
    """Persistent JSONL command loop over stdin/stdout."""
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
            traceback.print_exc(file=real_stderr)
            result = {"error": f"{type(e).__name__}: {e}"}

        try:
            real_stdout.write(json.dumps(result) + "\n")
            real_stdout.flush()
        except Exception:
            pass

        if action == "stop":
            break


if __name__ == "__main__":
    main()
