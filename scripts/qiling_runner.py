#!/usr/bin/env python
"""Standalone Qiling Framework runner -- invoked via subprocess from PeMCP.

Reads a JSON command from stdin, runs the requested Qiling emulation,
and writes a JSON result to stdout.

This script is executed inside the qiling venv (/app/qiling-venv)
which has unicorn 1.x, keeping the main env free to use unicorn 2.x
for angr's native unicorn bridge.
"""
import json
import os
import sys
import struct
import hashlib
import traceback

from qiling import Qiling
from qiling.const import QL_VERBOSE


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

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


def _detect_binary_format(filepath):
    """Detect binary format from magic bytes. Returns (os_type, arch, format_desc)."""
    with open(filepath, "rb") as f:
        magic = f.read(4)

    if magic[:2] == b"MZ":
        # PE file -- check for 32/64 bit
        with open(filepath, "rb") as f:
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) < 4:
                return "windows", "x86", "PE (32-bit, assumed)"
            pe_offset = struct.unpack("<I", pe_offset_bytes)[0]
            f.seek(pe_offset + 4)  # Skip "PE\0\0"
            machine = f.read(2)
            if len(machine) < 2:
                return "windows", "x86", "PE (32-bit, assumed)"
            machine_val = struct.unpack("<H", machine)[0]
            if machine_val == 0x8664:
                return "windows", "x8664", "PE (64-bit)"
            elif machine_val == 0x14C:
                return "windows", "x86", "PE (32-bit)"
            elif machine_val == 0x1C0:
                return "windows", "arm", "PE (ARM)"
            return "windows", "x86", f"PE (machine={hex(machine_val)})"

    elif magic == b"\x7fELF":
        with open(filepath, "rb") as f:
            f.seek(4)
            ei_class = f.read(1)
            f.seek(18)
            e_machine = struct.unpack("<H", f.read(2))[0]
        if ei_class == b"\x02":
            if e_machine == 0x3E:
                return "linux", "x8664", "ELF (64-bit x86_64)"
            elif e_machine == 0xB7:
                return "linux", "arm64", "ELF (64-bit ARM64)"
            elif e_machine == 0x08:
                return "linux", "mips", "ELF (64-bit MIPS)"
            return "linux", "x8664", f"ELF (64-bit, machine={hex(e_machine)})"
        else:
            if e_machine == 0x03:
                return "linux", "x86", "ELF (32-bit x86)"
            elif e_machine == 0x28:
                return "linux", "arm", "ELF (32-bit ARM)"
            elif e_machine == 0x08:
                return "linux", "mips", "ELF (32-bit MIPS)"
            return "linux", "x86", f"ELF (32-bit, machine={hex(e_machine)})"

    elif magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        return "macos", "x86", "Mach-O (32-bit)"
    elif magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "macos", "x8664", "Mach-O (64-bit)"

    return None, None, "Unknown format"


def _find_rootfs(os_type, arch, rootfs_path):
    """Find the appropriate rootfs directory for the given OS and architecture."""
    if not rootfs_path:
        rootfs_path = "/app/qiling-rootfs"

    # Map to Qiling's rootfs directory naming convention
    rootfs_map = {
        ("windows", "x86"): "x86_windows",
        ("windows", "x8664"): "x8664_windows",
        ("windows", "arm"): "arm_windows",
        ("linux", "x86"): "x86_linux",
        ("linux", "x8664"): "x8664_linux",
        ("linux", "arm"): "arm_linux",
        ("linux", "arm64"): "arm64_linux",
        ("linux", "mips"): "mips32_linux",
        ("macos", "x8664"): "x8664_macos",
    }

    dir_name = rootfs_map.get((os_type, arch))
    if not dir_name:
        return None, f"No rootfs mapping for {os_type}/{arch}"

    rootfs = os.path.join(rootfs_path, dir_name)
    if os.path.isdir(rootfs):
        return rootfs, None
    return None, f"Rootfs directory not found: {rootfs}. Use the download_qiling_rootfs tool to fetch it."


# ---------------------------------------------------------------------------
#  Actions
# ---------------------------------------------------------------------------

def emulate_binary(cmd):
    """Full binary emulation with behavioral report."""
    filepath = cmd["filepath"]
    rootfs_path = cmd.get("rootfs_path")
    timeout_seconds = cmd.get("timeout_seconds", 60)
    max_instructions = cmd.get("max_instructions", 0)
    limit = cmd.get("limit", 200)

    os_type, arch, fmt_desc = _detect_binary_format(filepath)
    if os_type is None:
        return {"error": f"Cannot detect binary format: {fmt_desc}"}

    rootfs, err = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}

    api_calls = []
    memory_writes = []
    file_activity = []
    registry_activity = []
    network_activity = []

    def _api_hook(ql, address, params, retval, api_name):
        """Collect API/syscall calls."""
        if len(api_calls) < limit * 2:  # Collect extra, trim later
            entry = {
                "api": api_name or "unknown",
                "address": _hex(address),
                "params": {},
                "retval": _hex(retval),
            }
            if params:
                for k, v in list(params.items())[:5]:
                    entry["params"][k] = str(v)[:200] if v is not None else None
            api_calls.append(entry)

            # Classify activity from API name
            api_lower = (api_name or "").lower()
            if any(k in api_lower for k in ("createfile", "writefile", "readfile", "deletefile",
                                             "open", "write", "read", "fopen", "fwrite")):
                if len(file_activity) < limit:
                    file_activity.append({"api": api_name, "params": entry["params"]})
            elif any(k in api_lower for k in ("regopen", "regset", "regquery", "regcreate", "regdelete")):
                if len(registry_activity) < limit:
                    registry_activity.append({"api": api_name, "params": entry["params"]})
            elif any(k in api_lower for k in ("socket", "connect", "send", "recv", "wsastartup",
                                               "bind", "listen", "accept", "getaddrinfo",
                                               "internetopen", "httpopen", "urldownload")):
                if len(network_activity) < limit:
                    network_activity.append({"api": api_name, "params": entry["params"]})

    try:
        ql = Qiling(
            [filepath],
            rootfs,
            verbose=QL_VERBOSE.DISABLED,
        )
    except Exception as e:
        return {"error": f"Failed to initialize Qiling: {e}"}

    # Set up syscall/API interception
    ql.os.set_api("*", _api_hook, QL_INTERCEPT.CALL)

    try:
        if max_instructions > 0:
            ql.run(count=max_instructions, timeout=timeout_seconds * 1000000)
        else:
            ql.run(timeout=timeout_seconds * 1000000)
    except Exception:
        # Emulation may raise on exit or unhandled API -- expected
        pass

    return {
        "status": "completed",
        "format": fmt_desc,
        "os_type": os_type,
        "architecture": arch,
        "total_api_calls": len(api_calls),
        "api_calls": _safe_slice(api_calls, limit),
        "file_activity": _safe_slice(file_activity, limit),
        "registry_activity": _safe_slice(registry_activity, limit),
        "network_activity": _safe_slice(network_activity, limit),
    }


def emulate_shellcode(cmd):
    """Multi-architecture shellcode emulation."""
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
        with open(filepath, "rb") as f:
            sc_data = f.read()
    else:
        return {"error": "No shellcode provided (no shellcode_hex or filepath)."}

    rootfs, err = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}

    api_calls = []

    def _api_hook(ql, address, params, retval, api_name):
        if len(api_calls) < limit * 2:
            entry = {
                "api": api_name or "unknown",
                "address": _hex(address),
                "params": {},
                "retval": _hex(retval),
            }
            if params:
                for k, v in list(params.items())[:5]:
                    entry["params"][k] = str(v)[:200] if v is not None else None
            api_calls.append(entry)

    try:
        ql = Qiling(
            code=sc_data,
            rootfs=rootfs,
            ostype=os_type,
            archtype=arch,
            verbose=QL_VERBOSE.DISABLED,
        )
    except Exception as e:
        return {"error": f"Failed to initialize Qiling for shellcode: {e}"}

    ql.os.set_api("*", _api_hook, QL_INTERCEPT.CALL)

    try:
        if max_instructions > 0:
            ql.run(count=max_instructions, timeout=timeout_seconds * 1000000)
        else:
            ql.run(timeout=timeout_seconds * 1000000)
    except Exception:
        pass

    return {
        "status": "completed",
        "os_type": os_type,
        "architecture": arch,
        "shellcode_size": len(sc_data),
        "shellcode_sha256": hashlib.sha256(sc_data).hexdigest(),
        "total_api_calls": len(api_calls),
        "api_calls": _safe_slice(api_calls, limit),
    }


def trace_execution(cmd):
    """Instruction-level execution tracing."""
    filepath = cmd["filepath"]
    rootfs_path = cmd.get("rootfs_path")
    start_address = cmd.get("start_address")
    end_address = cmd.get("end_address")
    max_instructions = cmd.get("max_instructions", 1000)
    timeout_seconds = cmd.get("timeout_seconds", 30)
    limit = cmd.get("limit", 500)

    os_type, arch, fmt_desc = _detect_binary_format(filepath)
    if os_type is None:
        return {"error": f"Cannot detect binary format: {fmt_desc}"}

    rootfs, err = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}

    instructions = []
    unique_addresses = set()

    def _code_hook(ql, address, size):
        if len(instructions) >= limit:
            ql.emu_stop()
            return
        # Read the bytes at this address
        try:
            insn_bytes = ql.mem.read(address, size)
            instructions.append({
                "address": _hex(address),
                "size": size,
                "bytes": insn_bytes.hex(),
            })
            unique_addresses.add(address)
        except Exception:
            instructions.append({
                "address": _hex(address),
                "size": size,
                "bytes": None,
            })

    try:
        ql = Qiling(
            [filepath],
            rootfs,
            verbose=QL_VERBOSE.DISABLED,
        )
    except Exception as e:
        return {"error": f"Failed to initialize Qiling: {e}"}

    ql.hook_code(_code_hook)

    begin = int(start_address, 0) if start_address else None
    end = int(end_address, 0) if end_address else None

    try:
        kwargs = {"timeout": timeout_seconds * 1000000, "count": max_instructions}
        if begin is not None:
            kwargs["begin"] = begin
        if end is not None:
            kwargs["end"] = end
        ql.run(**kwargs)
    except Exception:
        pass

    return {
        "status": "completed",
        "format": fmt_desc,
        "total_instructions_traced": len(instructions),
        "unique_addresses": len(unique_addresses),
        "instructions": _safe_slice(instructions, limit),
    }


def hook_api_calls(cmd):
    """Targeted API/syscall hooking with argument capture."""
    filepath = cmd["filepath"]
    rootfs_path = cmd.get("rootfs_path")
    target_apis = cmd.get("target_apis", [])
    timeout_seconds = cmd.get("timeout_seconds", 60)
    max_instructions = cmd.get("max_instructions", 0)
    limit = cmd.get("limit", 200)

    os_type, arch, fmt_desc = _detect_binary_format(filepath)
    if os_type is None:
        return {"error": f"Cannot detect binary format: {fmt_desc}"}

    rootfs, err = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}

    captured_calls = []

    try:
        ql = Qiling(
            [filepath],
            rootfs,
            verbose=QL_VERBOSE.DISABLED,
        )
    except Exception as e:
        return {"error": f"Failed to initialize Qiling: {e}"}

    # If specific APIs requested, hook each one; otherwise hook all
    if target_apis:
        for api_name in target_apis:
            def _make_hook(name):
                def _hook(ql, address, params, retval, api_name_actual):
                    if len(captured_calls) < limit:
                        entry = {
                            "api": api_name_actual or name,
                            "address": _hex(address),
                            "params": {},
                            "retval": _hex(retval),
                        }
                        if params:
                            for k, v in list(params.items())[:8]:
                                entry["params"][k] = str(v)[:500] if v is not None else None
                        captured_calls.append(entry)
                return _hook
            try:
                ql.os.set_api(api_name, _make_hook(api_name), QL_INTERCEPT.CALL)
            except Exception:
                # API may not exist in the emulated environment
                pass
    else:
        def _global_hook(ql, address, params, retval, api_name):
            if len(captured_calls) < limit:
                entry = {
                    "api": api_name or "unknown",
                    "address": _hex(address),
                    "params": {},
                    "retval": _hex(retval),
                }
                if params:
                    for k, v in list(params.items())[:8]:
                        entry["params"][k] = str(v)[:500] if v is not None else None
                captured_calls.append(entry)
        ql.os.set_api("*", _global_hook, QL_INTERCEPT.CALL)

    try:
        kwargs = {"timeout": timeout_seconds * 1000000}
        if max_instructions > 0:
            kwargs["count"] = max_instructions
        ql.run(**kwargs)
    except Exception:
        pass

    return {
        "status": "completed",
        "format": fmt_desc,
        "target_apis": target_apis if target_apis else ["* (all)"],
        "total_captured": len(captured_calls),
        "captured_calls": _safe_slice(captured_calls, limit),
    }


def dump_unpacked(cmd):
    """Dynamic unpacking: run binary until OEP, then dump memory."""
    filepath = cmd["filepath"]
    rootfs_path = cmd.get("rootfs_path")
    output_path = cmd["output_path"]
    dump_address = cmd.get("dump_address")
    dump_size = cmd.get("dump_size")
    timeout_seconds = cmd.get("timeout_seconds", 120)
    max_instructions = cmd.get("max_instructions", 0)

    os_type, arch, fmt_desc = _detect_binary_format(filepath)
    if os_type is None:
        return {"error": f"Cannot detect binary format: {fmt_desc}"}

    rootfs, err = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}

    try:
        ql = Qiling(
            [filepath],
            rootfs,
            verbose=QL_VERBOSE.DISABLED,
        )
    except Exception as e:
        return {"error": f"Failed to initialize Qiling: {e}"}

    # If a specific dump address is provided, hook it to trigger dump
    dump_triggered = {"done": False}

    if dump_address:
        addr = int(dump_address, 0)
        def _dump_hook(ql):
            if not dump_triggered["done"]:
                dump_triggered["done"] = True
                ql.emu_stop()
        ql.hook_address(_dump_hook, addr)

    try:
        kwargs = {"timeout": timeout_seconds * 1000000}
        if max_instructions > 0:
            kwargs["count"] = max_instructions
        ql.run(**kwargs)
    except Exception:
        pass

    # Dump memory
    try:
        if dump_address and dump_size:
            addr = int(dump_address, 0)
            size = int(dump_size, 0) if isinstance(dump_size, str) else dump_size
            data = ql.mem.read(addr, size)
        else:
            # Dump the main mapped region (image base + size)
            # Find the largest mapped region that looks like the PE image
            maps = ql.mem.get_mapinfo()
            best_region = None
            best_size = 0
            for start, end, perms, label, _path in maps:
                region_size = end - start
                if region_size > best_size:
                    best_size = region_size
                    best_region = (start, region_size)
            if best_region:
                data = ql.mem.read(best_region[0], best_region[1])
            else:
                return {"error": "No mapped memory regions found to dump."}

        with open(output_path, "wb") as f:
            f.write(data)

        return {
            "status": "success",
            "input_file": filepath,
            "output_file": output_path,
            "output_size": len(data),
            "dump_address": dump_address or _hex(best_region[0]) if not dump_address and best_region else dump_address,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    except Exception as e:
        return {"error": f"Memory dump failed: {e}"}


def resolve_api_hashes(cmd):
    """Resolve API hash values by emulating hash computation routines."""
    filepath = cmd["filepath"]
    rootfs_path = cmd.get("rootfs_path")
    hash_values = cmd.get("hash_values", [])
    hash_algorithm = cmd.get("hash_algorithm", "ror13")
    timeout_seconds = cmd.get("timeout_seconds", 30)

    os_type, arch, fmt_desc = _detect_binary_format(filepath)
    if os_type is None:
        # Default to Windows x86 for hash resolution
        os_type, arch = "windows", "x86"

    rootfs, err = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}

    # Compute hashes for known DLL exports
    def _ror13(name):
        """ROR13 hash (commonly used by shellcode)."""
        h = 0
        for c in name:
            h = ((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF
            h = (h + ord(c)) & 0xFFFFFFFF
        return h

    def _crc32(name):
        """CRC32 hash."""
        import binascii
        return binascii.crc32(name.encode()) & 0xFFFFFFFF

    def _djb2(name):
        """DJB2 hash."""
        h = 5381
        for c in name:
            h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
        return h

    def _fnv1a(name):
        """FNV-1a hash (32-bit)."""
        h = 0x811C9DC5
        for c in name:
            h = (h ^ ord(c)) & 0xFFFFFFFF
            h = (h * 0x01000193) & 0xFFFFFFFF
        return h

    hash_funcs = {
        "ror13": _ror13,
        "crc32": _crc32,
        "djb2": _djb2,
        "fnv1a": _fnv1a,
    }

    hash_func = hash_funcs.get(hash_algorithm)
    if not hash_func:
        return {"error": f"Unknown hash algorithm: {hash_algorithm}. Supported: {list(hash_funcs.keys())}"}

    # Convert input hash values to integers
    target_hashes = set()
    for hv in hash_values:
        if isinstance(hv, str):
            target_hashes.add(int(hv, 0))
        else:
            target_hashes.add(int(hv))

    # Scan common DLL exports in rootfs
    resolved = []
    dll_dirs = []
    sys32 = os.path.join(rootfs, "Windows", "System32")
    if os.path.isdir(sys32):
        dll_dirs.append(sys32)
    syswow = os.path.join(rootfs, "Windows", "SysWOW64")
    if os.path.isdir(syswow):
        dll_dirs.append(syswow)

    # Also check common DLL names directly
    common_dlls = [
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
        "ws2_32.dll", "wininet.dll", "shell32.dll", "msvcrt.dll",
        "ole32.dll", "oleaut32.dll", "urlmon.dll", "crypt32.dll",
    ]

    # Use pefile from the venv if available, otherwise try manual parsing
    try:
        import pefile as _pefile

        checked_dlls = set()
        for dll_dir in dll_dirs:
            for dll_name in os.listdir(dll_dir):
                if not dll_name.lower().endswith(".dll"):
                    continue
                dll_path = os.path.join(dll_dir, dll_name)
                if dll_name.lower() in checked_dlls:
                    continue
                checked_dlls.add(dll_name.lower())

                try:
                    pe = _pefile.PE(dll_path, fast_load=True)
                    pe.parse_data_directories(
                        directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
                    )
                    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                        pe.close()
                        continue
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            func_name = exp.name.decode("utf-8", errors="replace")
                            # Try both "FunctionName" and "dll.FunctionName"
                            for name_variant in [func_name, f"{dll_name}.{func_name}"]:
                                h = hash_func(name_variant)
                                if h in target_hashes:
                                    resolved.append({
                                        "hash_value": _hex(h),
                                        "dll": dll_name,
                                        "function": func_name,
                                        "name_form": name_variant,
                                    })
                    pe.close()
                except Exception:
                    continue

                # Early exit if all hashes resolved
                resolved_hashes = {int(r["hash_value"], 16) for r in resolved}
                if resolved_hashes >= target_hashes:
                    break
    except ImportError:
        return {
            "status": "partial",
            "error": "pefile not available in Qiling venv; cannot scan DLL exports.",
            "resolved": [],
            "unresolved": [_hex(h) for h in target_hashes],
        }

    resolved_hashes = {int(r["hash_value"], 16) for r in resolved}
    unresolved = [_hex(h) for h in target_hashes if h not in resolved_hashes]

    return {
        "status": "completed",
        "hash_algorithm": hash_algorithm,
        "total_input": len(target_hashes),
        "total_resolved": len(resolved),
        "total_unresolved": len(unresolved),
        "resolved": resolved,
        "unresolved": unresolved,
    }


def memory_search(cmd):
    """Run binary then search process memory for patterns."""
    filepath = cmd["filepath"]
    rootfs_path = cmd.get("rootfs_path")
    search_patterns = cmd.get("search_patterns", [])
    search_hex = cmd.get("search_hex")
    max_instructions = cmd.get("max_instructions", 500000)
    timeout_seconds = cmd.get("timeout_seconds", 60)
    context_bytes = cmd.get("context_bytes", 32)
    limit = cmd.get("limit", 50)

    os_type, arch, fmt_desc = _detect_binary_format(filepath)
    if os_type is None:
        return {"error": f"Cannot detect binary format: {fmt_desc}"}

    rootfs, err = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}

    try:
        ql = Qiling(
            [filepath],
            rootfs,
            verbose=QL_VERBOSE.DISABLED,
        )
    except Exception as e:
        return {"error": f"Failed to initialize Qiling: {e}"}

    # Run for N instructions to let the binary unpack/initialize
    try:
        kwargs = {"timeout": timeout_seconds * 1000000}
        if max_instructions > 0:
            kwargs["count"] = max_instructions
        ql.run(**kwargs)
    except Exception:
        pass

    # Search memory
    matches = []

    # Build search needles
    needles = []
    for pat in search_patterns:
        needles.append(("string", pat, pat.encode("utf-8")))
        needles.append(("string_wide", pat, pat.encode("utf-16-le")))
    if search_hex:
        needles.append(("hex", search_hex, bytes.fromhex(search_hex)))

    try:
        maps = ql.mem.get_mapinfo()
        for start, end, perms, label, _path in maps:
            if len(matches) >= limit:
                break
            try:
                region_data = ql.mem.read(start, end - start)
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
                    # Extract context
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
        "status": "completed",
        "format": fmt_desc,
        "search_patterns": search_patterns,
        "search_hex": search_hex,
        "instructions_executed": max_instructions,
        "memory_regions_scanned": len(maps) if 'maps' in dir() else 0,
        "total_matches": len(matches),
        "matches": _safe_slice(matches, limit),
    }


def download_rootfs(cmd):
    """Download Qiling rootfs files for a specific OS/architecture."""
    os_type = cmd.get("os_type", "windows")
    arch = cmd.get("architecture", "x86")
    output_dir = cmd.get("output_dir", "/app/qiling-rootfs")

    import urllib.request
    import zipfile
    import tempfile

    rootfs_map = {
        ("windows", "x86"): "x86_windows",
        ("windows", "x8664"): "x8664_windows",
        ("linux", "x86"): "x86_linux",
        ("linux", "x8664"): "x8664_linux",
        ("linux", "arm"): "arm_linux",
        ("linux", "arm64"): "arm64_linux",
        ("linux", "mips"): "mips32_linux",
        ("macos", "x8664"): "x8664_macos",
    }

    dir_name = rootfs_map.get((os_type, arch))
    if not dir_name:
        return {"error": f"No rootfs available for {os_type}/{arch}. Supported: {list(rootfs_map.keys())}"}

    target_dir = os.path.join(output_dir, dir_name)
    if os.path.isdir(target_dir) and os.listdir(target_dir):
        return {
            "status": "already_exists",
            "rootfs_path": target_dir,
            "message": f"Rootfs for {os_type}/{arch} already exists at {target_dir}",
        }

    url = "https://github.com/qilingframework/qiling/archive/refs/heads/master.zip"
    prefix = f"qiling-master/examples/rootfs/{dir_name}/"

    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = tmp.name
            urllib.request.urlretrieve(url, tmp_path)

        os.makedirs(target_dir, exist_ok=True)
        extracted_count = 0

        with zipfile.ZipFile(tmp_path, "r") as zf:
            for member in zf.namelist():
                if member.startswith(prefix) and not member.endswith("/"):
                    rel_path = member[len(prefix):]
                    if rel_path:
                        dest = os.path.join(target_dir, rel_path)
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with zf.open(member) as src, open(dest, "wb") as dst:
                            dst.write(src.read())
                        extracted_count += 1

        os.remove(tmp_path)

        return {
            "status": "success",
            "rootfs_path": target_dir,
            "os_type": os_type,
            "architecture": arch,
            "files_extracted": extracted_count,
        }
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return {"error": f"Failed to download rootfs: {e}"}


# ---------------------------------------------------------------------------
#  Main dispatcher
# ---------------------------------------------------------------------------

# Import Qiling intercept constant after imports are available
try:
    from qiling.const import QL_INTERCEPT
except ImportError:
    # Fallback for older Qiling versions
    class QL_INTERCEPT:
        CALL = 0
        EXIT = 1


def main():
    cmd = json.loads(sys.stdin.read())
    action = cmd.get("action")

    try:
        if action == "emulate_binary":
            result = emulate_binary(cmd)
        elif action == "emulate_shellcode":
            result = emulate_shellcode(cmd)
        elif action == "trace_execution":
            result = trace_execution(cmd)
        elif action == "hook_api_calls":
            result = hook_api_calls(cmd)
        elif action == "dump_unpacked":
            result = dump_unpacked(cmd)
        elif action == "resolve_api_hashes":
            result = resolve_api_hashes(cmd)
        elif action == "memory_search":
            result = memory_search(cmd)
        elif action == "download_rootfs":
            result = download_rootfs(cmd)
        else:
            result = {"error": f"Unknown action: {action}"}
    except Exception as e:
        result = {"error": f"{type(e).__name__}: {e}", "traceback": traceback.format_exc()[:1000]}

    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
