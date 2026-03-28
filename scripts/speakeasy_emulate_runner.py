#!/usr/bin/env python
"""Persistent Speakeasy emulation runner -- invoked via subprocess from Arkana.

Unlike speakeasy_runner.py which is one-shot (stdin JSON -> stdout JSON -> exit),
this runner maintains a persistent JSONL command loop over stdin/stdout.
After emulation completes, the Speakeasy object stays alive so memory can be
inspected via read_memory, search_memory, and memory_map commands.

This script runs inside /app/speakeasy-venv which has unicorn 1.x.

Protocol:
    -> {"action": "emulate_pe", "filepath": "/path/to/binary", ...}
    <- {"status": "completed", "api_calls": [...], ...}
    -> {"action": "search_memory", "search_patterns": ["http://"], ...}
    <- {"status": "ok", "total_matches": 3, "matches": [...]}
    -> {"action": "stop"}
    <- {"status": "ok"}
"""
import json
import os
import struct
import sys
import threading
import traceback

import speakeasy
import speakeasy.winenv.arch as _arch


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
            f"[speakeasy_emulate_runner] Hard timeout ({seconds}s) reached — "
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
#  Helpers (reused from speakeasy_runner.py)
# ---------------------------------------------------------------------------

def _validate_file_path(filepath):
    """Validate that a file path exists and is a regular file."""
    import os
    if not filepath:
        raise ValueError("No file path provided")
    filepath = os.path.realpath(filepath)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    if not os.path.isfile(filepath):
        raise ValueError(f"Path is not a regular file: {filepath}")


def _safe_slice(value, n):
    """Safely slice a value to at most *n* items."""
    if isinstance(value, (list, tuple)):
        return value[:n]
    if isinstance(value, dict):
        keys = list(value.keys())[:n]
        return {k: value[k] for k in keys}
    if isinstance(value, str):
        return value[:n]
    return value


def _hex(val):
    """Convert an integer to hex string, handling None."""
    if val is None:
        return None
    return hex(val) if isinstance(val, int) else str(val)


def _collect_api_calls(report, limit):
    """Extract and truncate API call entries from a Speakeasy report."""
    api_calls = []
    for event in report.get("api_calls", []):
        args = event.get("args", [])
        if isinstance(args, (list, tuple)):
            args = args[:5]
        else:
            args = str(args)
        entry = {
            "api": event.get("api_name", ""),
            "args": args,
            "ret_val": event.get("ret_val"),
        }
        if "caller" in event:
            entry["caller"] = hex(event["caller"]) if event.get("caller") else None
        api_calls.append(entry)
        if len(api_calls) >= limit:
            break
    return api_calls


# ---------------------------------------------------------------------------
#  Module state — persists across commands
# ---------------------------------------------------------------------------

_se = None               # Speakeasy instance (kept alive after emulation)
_emulation_completed = False

_MAX_MEMORY_READ = 1_048_576   # 1MB
_MAX_SEARCH_MATCHES = 100
_DEFAULT_CONTEXT_BYTES = 32


def _get_emu(se):
    """Get the unicorn emulator from the Speakeasy object.

    Speakeasy wraps unicorn; the exact attribute path varies by version.
    Try common paths in order.
    """
    # Most common: se.emu is the PeEmulator/ShellcodeEmulator
    emu = getattr(se, 'emu', None)
    if emu is not None:
        return emu
    return None


def _mem_read(emu, address, size):
    """Read memory from the Speakeasy emulator."""
    # PeEmulator.mem_read() wraps unicorn
    if hasattr(emu, 'mem_read'):
        return bytes(emu.mem_read(address, size))
    # Fallback: direct unicorn access
    uc = getattr(emu, 'uc', None) or getattr(emu, '_uc', None)
    if uc and hasattr(uc, 'mem_read'):
        return bytes(uc.mem_read(address, size))
    raise RuntimeError("Cannot access emulator memory — unsupported Speakeasy version")


def _get_memory_regions(emu):
    """Get memory regions from the Speakeasy emulator.

    Speakeasy's memory manager API varies by version:
    - Some versions: emu.get_address_map() returns all regions
    - Others: emu.get_address_map(addr) returns info for one address
    - Fallback: emu.mem.get_mem_maps() or iterate emu.mem._map_info
    """
    # Try parameterless call first
    if hasattr(emu, 'get_address_map'):
        try:
            result = emu.get_address_map()
            if isinstance(result, (list, tuple)) and len(result) > 0:
                return result
        except TypeError:
            pass  # Needs an argument — skip

    # Try the memory manager's internal map list
    mem_mgr = getattr(emu, 'mem', None)
    if mem_mgr is not None:
        # get_mem_maps() is available in some versions
        if hasattr(mem_mgr, 'get_mem_maps'):
            try:
                return mem_mgr.get_mem_maps()
            except Exception:
                pass
        # _map_info is the internal list of MemMap objects
        map_info = getattr(mem_mgr, '_map_info', None) or getattr(mem_mgr, 'map_info', None)
        if map_info and isinstance(map_info, (list, tuple)):
            regions = []
            for m in map_info:
                entry = {}
                entry["base"] = getattr(m, 'base', getattr(m, 'addr', 0))
                entry["size"] = getattr(m, 'size', 0)
                entry["tag"] = getattr(m, 'tag', getattr(m, 'name', ""))
                entry["perms"] = getattr(m, 'perms', "")
                regions.append(entry)
            return regions

    return None


def _probe_memory_regions(emu):
    """Fallback: probe common PE memory ranges when get_address_map is unavailable.

    Tries to read at standard base addresses and reports which are readable.
    This gives search_memory something to scan even without a proper map.
    """
    regions = []
    # Standard PE bases, common DLL ranges, stack, heap
    probes = [
        (0x400000, 0x100000, "PE image"),
        (0x10000, 0x10000, "low memory"),
        (0x10000000, 0x100000, "DLL range 1"),
        (0x70000000, 0x100000, "DLL range 2"),
        (0x7FFE0000, 0x1000, "KUSER_SHARED_DATA"),
    ]

    # Also try to detect the actual image size from the PE header
    try:
        pe_header = _mem_read(emu, 0x400000, 0x200)
        if pe_header[:2] == b'MZ':
            e_lfanew = struct.unpack_from('<I', pe_header, 0x3C)[0]
            if e_lfanew + 0x54 <= len(pe_header):
                size_of_image = struct.unpack_from('<I', pe_header, e_lfanew + 0x50)[0]
                if 0 < size_of_image < 0x10000000:
                    probes[0] = (0x400000, size_of_image, "PE image")
    except Exception:
        pass

    for base, size, label in probes:
        try:
            # Try reading the first byte to check if the region is mapped
            _mem_read(emu, base, 1)
            regions.append({"base": base, "size": size, "tag": label})
        except Exception:
            continue

    return regions if regions else None


# ---------------------------------------------------------------------------
#  Command handlers
# ---------------------------------------------------------------------------

def cmd_emulate_pe(cmd):
    """PE emulation — keeps Speakeasy alive for post-emulation inspection."""
    global _se, _emulation_completed

    if _emulation_completed:
        return {"error": "Emulation already completed. Use memory inspection commands, "
                "or send 'stop' and start a new session."}

    filepath = cmd["filepath"]
    _validate_file_path(filepath)
    timeout_seconds = cmd.get("timeout_seconds", 60)
    limit = cmd.get("limit", 200)

    se = speakeasy.Speakeasy()
    try:
        module = se.load_module(filepath)
    except Exception as e:
        _cancel_hard_timeout()
        return {"error": f"Failed to load module: {e}"}

    # Hard safety net: kill this process if emulation hangs.
    # Adds 15s buffer beyond the user-requested timeout so the normal
    # timeout path has a chance to fire first.
    _start_hard_timeout(timeout_seconds + 15)

    emulation_exception = None
    try:
        # Speakeasy's run_module signature varies by version —
        # some accept timeout= kwarg, others only positional.
        try:
            se.run_module(module, timeout=timeout_seconds)
        except TypeError:
            se.run_module(module)
    except (SystemExit, KeyboardInterrupt):
        _cancel_hard_timeout()
        raise
    except Exception as e:
        emulation_exception = f"{type(e).__name__}: {e}"

    _cancel_hard_timeout()
    _se = se
    _emulation_completed = True

    report = se.get_report()

    # Check if memory inspection is available
    emu = _get_emu(se)
    memory_available = emu is not None and hasattr(emu, 'mem_read')

    result = {
        "status": "completed",
        "session_alive": True,
        "memory_inspection_available": memory_available,
        "total_api_calls": len(report.get("api_calls", [])),
        "api_calls": _collect_api_calls(report, limit),
        "strings_found": _safe_slice(report.get("strings", []), 100),
        "network_activity": _safe_slice(report.get("network", []), 50),
        "file_activity": _safe_slice(report.get("file_access", []), 50),
        "registry_activity": _safe_slice(report.get("registry", []), 50),
        "hint": "Session alive. Use read_memory, search_memory, memory_map to inspect emulated memory. Send 'stop' when done.",
    }
    if emulation_exception:
        result["emulation_exception"] = emulation_exception
    return result


def cmd_emulate_shellcode(cmd):
    """Shellcode emulation — keeps Speakeasy alive for post-emulation inspection."""
    global _se, _emulation_completed

    if _emulation_completed:
        return {"error": "Emulation already completed. Use memory inspection commands, "
                "or send 'stop' and start a new session."}

    shellcode_hex = cmd.get("shellcode_hex")
    filepath = cmd.get("filepath")
    architecture = cmd.get("architecture", "x86")
    timeout_seconds = cmd.get("timeout_seconds", 30)
    limit = cmd.get("limit", 200)

    se = speakeasy.Speakeasy()

    if shellcode_hex:
        sc_data = bytes.fromhex(shellcode_hex)
    elif filepath:
        _validate_file_path(filepath)
        with open(filepath, "rb") as f:
            sc_data = f.read()
    else:
        return {"error": "No shellcode provided and no file loaded."}

    try:
        arch_val = _arch.ARCH_X86 if architecture == "x86" else _arch.ARCH_AMD64
    except AttributeError:
        arch_val = architecture

    try:
        addr = se.load_shellcode(
            filepath if not shellcode_hex else None,
            arch_val,
            data=sc_data,
        )
    except Exception as e:
        _cancel_hard_timeout()
        return {"error": f"Failed to load shellcode: {e}"}

    # Hard safety net: kill this process if emulation hangs.
    _start_hard_timeout(timeout_seconds + 15)

    emulation_exception = None
    try:
        # Speakeasy's run_shellcode signature varies by version —
        # some accept timeout= kwarg, others only positional.
        try:
            se.run_shellcode(addr, timeout=timeout_seconds)
        except TypeError:
            se.run_shellcode(addr)
    except (SystemExit, KeyboardInterrupt):
        _cancel_hard_timeout()
        raise
    except Exception as e:
        emulation_exception = f"{type(e).__name__}: {e}"

    _cancel_hard_timeout()
    _se = se
    _emulation_completed = True

    report = se.get_report()

    emu = _get_emu(se)
    memory_available = emu is not None and hasattr(emu, 'mem_read')

    result = {
        "status": "completed",
        "session_alive": True,
        "memory_inspection_available": memory_available,
        "architecture": architecture,
        "total_api_calls": len(report.get("api_calls", [])),
        "api_calls": _collect_api_calls(report, limit),
        "strings_found": _safe_slice(report.get("strings", []), 100),
        "network_activity": _safe_slice(report.get("network", []), 50),
        "hint": "Session alive. Use read_memory, search_memory, memory_map to inspect emulated memory. Send 'stop' when done.",
    }
    if emulation_exception:
        result["emulation_exception"] = emulation_exception
    return result


def cmd_read_memory(cmd):
    """Read memory from the emulated process."""
    if _se is None or not _emulation_completed:
        return {"error": "Emulation has not been run yet. Send 'emulate_pe' or 'emulate_shellcode' first."}

    emu = _get_emu(_se)
    if emu is None:
        return {"error": "Memory inspection not available — cannot access Speakeasy emulator internals."}

    address = cmd.get("address", "")
    try:
        if isinstance(address, str):
            address = int(address, 16) if address.startswith(("0x", "0X")) else int(address)
    except (ValueError, AttributeError):
        return {"error": f"Invalid address format: {address!r}. Expected hex (0x...) or decimal."}
    length = min(max(1, cmd.get("length", 256)), _MAX_MEMORY_READ)

    try:
        data = _mem_read(emu, address, length)
    except Exception as e:
        return {"error": f"Memory read failed at {_hex(address)}: {e}"}

    ascii_repr = ""
    for b in data:
        ascii_repr += chr(b) if 32 <= b < 127 else "."

    return {
        "status": "ok",
        "address": _hex(address),
        "length": len(data),
        "hex": data.hex(),
        "ascii": ascii_repr,
    }


def cmd_memory_map(cmd):
    """Return the memory map of the emulated process."""
    if _se is None or not _emulation_completed:
        return {"error": "Emulation has not been run yet. Send 'emulate_pe' or 'emulate_shellcode' first."}

    emu = _get_emu(_se)
    if emu is None:
        return {"error": "Memory inspection not available — cannot access Speakeasy emulator internals."}

    addr_map = _get_memory_regions(emu)
    if addr_map is None:
        # Fallback: probe standard PE memory ranges
        addr_map = _probe_memory_regions(emu)
    if not addr_map:
        return {"error": "Memory map not available in this Speakeasy version."}

    regions = []
    for entry in addr_map[:200]:
        if isinstance(entry, dict):
            regions.append({
                "start": _hex(entry.get("base", entry.get("start", 0))),
                "end": _hex(entry.get("base", 0) + entry.get("size", 0)),
                "size": entry.get("size", 0),
                "permissions": entry.get("perms", entry.get("permissions", "")),
                "label": entry.get("tag", entry.get("label", entry.get("name", ""))),
            })
        elif isinstance(entry, (list, tuple)) and len(entry) >= 3:
            start, end = entry[0], entry[1]
            regions.append({
                "start": _hex(start),
                "end": _hex(end),
                "size": end - start,
                "permissions": str(entry[2]) if len(entry) > 2 else "",
                "label": str(entry[3]) if len(entry) > 3 else "",
            })

    return {
        "status": "ok",
        "total_regions": len(regions),
        "regions": regions,
    }


def cmd_search_memory(cmd):
    """Search emulated memory for string or hex patterns."""
    if _se is None or not _emulation_completed:
        return {"error": "Emulation has not been run yet. Send 'emulate_pe' or 'emulate_shellcode' first."}

    emu = _get_emu(_se)
    if emu is None:
        return {"error": "Memory inspection not available — cannot access Speakeasy emulator internals."}

    search_patterns = cmd.get("search_patterns", [])
    search_hex = cmd.get("search_hex")
    context_bytes = min(max(0, cmd.get("context_bytes", _DEFAULT_CONTEXT_BYTES)), 256)
    limit = min(max(1, cmd.get("limit", 50)), _MAX_SEARCH_MATCHES)

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

    addr_map = _get_memory_regions(emu)
    if addr_map is None:
        addr_map = _probe_memory_regions(emu)
    if not addr_map:
        return {"error": "Memory map not available — cannot enumerate regions for search."}

    matches = []
    for entry in addr_map:
        if len(matches) >= limit:
            break

        if isinstance(entry, dict):
            start = entry.get("base", entry.get("start", 0))
            size = entry.get("size", 0)
            label = entry.get("tag", entry.get("label", ""))
        elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
            start, end = entry[0], entry[1]
            size = end - start
            label = entry[3] if len(entry) > 3 else ""
        else:
            continue

        if size > 64 * 1024 * 1024 or size <= 0:
            continue

        try:
            region_data = _mem_read(emu, start, size)
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
                    "region": f"{_hex(start)}-{_hex(start + size)} ({label})",
                    "context_hex": context_data.hex(),
                })
                if len(matches) >= limit:
                    break
                offset = idx + len(needle_bytes)

    return {
        "status": "ok",
        "total_matches": len(matches),
        "matches": matches,
    }


def cmd_write_memory(cmd):
    """Write bytes to emulated memory."""
    if _se is None or not _emulation_completed:
        return {"error": "Emulation has not been run yet. Send 'emulate_pe' or 'emulate_shellcode' first."}

    emu = _get_emu(_se)
    if emu is None:
        return {"error": "Memory inspection not available — cannot access Speakeasy emulator internals."}

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
        if hasattr(emu, 'mem_write'):
            emu.mem_write(address, data)
        else:
            uc = getattr(emu, 'uc', None) or getattr(emu, '_uc', None)
            if uc and hasattr(uc, 'mem_write'):
                uc.mem_write(address, data)
            else:
                return {"error": "Memory write not available — unsupported Speakeasy version"}
    except Exception as e:
        return {"error": f"Failed to write memory at {_hex(address)}: {e}"}

    return {
        "status": "ok",
        "address": _hex(address),
        "bytes_written": len(data),
    }


def cmd_resume(cmd):
    """Resume emulation from where it left off (e.g. after a timeout).

    Speakeasy doesn't natively support resume, so this is a no-op that
    reports the current state. Use Qiling for resumable emulation.
    """
    if _se is None or not _emulation_completed:
        return {"error": "No completed emulation session to resume. "
                "Note: Speakeasy does not support resumable emulation. Use Qiling engine instead."}
    return {
        "status": "ok",
        "message": "Speakeasy does not support resume. Memory is available for inspection. "
                   "Use Qiling engine for resumable emulation.",
    }


def cmd_stop(cmd):
    """Clean up and signal exit."""
    global _se, _emulation_completed
    _se = None
    _emulation_completed = False
    return {"status": "ok"}


# ---------------------------------------------------------------------------
#  Dispatch and main JSONL loop
# ---------------------------------------------------------------------------

DISPATCH = {
    "emulate_pe": cmd_emulate_pe,
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
