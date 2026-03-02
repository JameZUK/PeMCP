#!/usr/bin/env python
"""Standalone Qiling Framework runner -- invoked via subprocess from Arkana.

Reads a JSON command from stdin, runs the requested Qiling emulation,
and writes a JSON result to stdout.

This script is executed inside the qiling venv (/app/qiling-venv)
which has unicorn 1.x, keeping the main env free to use unicorn 2.x
for angr's native unicorn bridge.
"""
import json
import os
import shutil
import sys
import struct
import hashlib
import traceback

from qiling import Qiling
from qiling.const import QL_VERBOSE

try:
    from qiling.const import QL_ARCH, QL_OS
except ImportError:
    QL_ARCH = None
    QL_OS = None

# Qiling's string→enum lookup for ostype/archtype is case-sensitive and
# varies between versions.  Map our lowercase strings to the actual enum
# constants so shellcode emulation works regardless of Qiling version.
_ARCH_MAP = {
    "x86": "X86",
    "x8664": "X8664",
    "arm": "ARM",
    "arm64": "ARM64",
    "mips": "MIPS",
}

_OS_MAP = {
    "windows": "WINDOWS",
    "linux": "LINUX",
    "macos": "MACOS",
    "freebsd": "FREEBSD",
}


def _ql_arch(arch_str):
    """Convert our architecture string to a Qiling QL_ARCH enum value."""
    if QL_ARCH is not None:
        name = _ARCH_MAP.get(arch_str, arch_str.upper())
        return QL_ARCH[name]
    return arch_str


def _ql_os(os_str):
    """Convert our OS string to a Qiling QL_OS enum value."""
    if QL_OS is not None:
        name = _OS_MAP.get(os_str, os_str.upper())
        return QL_OS[name]
    return os_str


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _validate_file_path(filepath):
    """Validate that a file path exists and is a regular file.

    Defense-in-depth: the parent MCP tool layer enforces path sandboxing,
    but direct invocation of this runner (e.g. during development) would
    bypass those checks.
    """
    if not filepath:
        raise ValueError("No file path provided")
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


def _setup_api_hooks(ql, os_type, api_calls_list, limit):
    """Set up API/syscall interception appropriate for the target OS.

    Qiling uses different hook mechanisms per OS:
    - Windows: ql.os.set_api("*", callback, QL_INTERCEPT.CALL)
      callback signature: (ql, address, params)
    - POSIX:   ql.os.set_syscall("*", callback, QL_INTERCEPT.CALL)
      callback signature: (ql, syscall_name, *args)

    set_api("*") on a POSIX target raises AttributeError because the
    ELF/Mach-O loader has no 'is_driver' attribute.
    """
    if os_type == "windows":
        def _win_api_hook(ql, address, params):
            if len(api_calls_list) < limit * 2:
                entry = {
                    "api": "unknown",
                    "address": _hex(address),
                    "params": {},
                    "retval": None,
                }
                if isinstance(params, dict):
                    for k, v in list(params.items())[:5]:
                        entry["params"][k] = str(v)[:200] if v is not None else None
                    # Try to extract API name from params or function context
                    entry["api"] = params.get("__name__", "unknown") if isinstance(params, dict) else "unknown"
                api_calls_list.append(entry)
        try:
            ql.os.set_api("*", _win_api_hook, QL_INTERCEPT.CALL)
        except Exception:
            pass  # Fallback: no API capture if hooking fails
    else:
        # POSIX: hook syscalls instead of API calls
        def _posix_syscall_hook(ql, *args):
            if len(api_calls_list) < limit * 2:
                # args[0] is typically the syscall number or name
                syscall_id = args[0] if args else "unknown"
                entry = {
                    "api": str(syscall_id),
                    "address": _hex(ql.arch.regs.arch_pc) if hasattr(ql.arch.regs, 'arch_pc') else None,
                    "params": {},
                    "retval": None,
                }
                # Remaining args are syscall parameters
                for i, a in enumerate(args[1:6]):
                    entry["params"][f"arg{i}"] = str(a)[:200] if a is not None else None
                api_calls_list.append(entry)
        try:
            ql.os.set_syscall("*", _posix_syscall_hook, QL_INTERCEPT.CALL)
        except Exception:
            pass  # Fallback: no syscall capture if hooking fails


def _setup_syscall_trace(ql, os_type, api_calls, timeline, syscall_filter, limit):
    """Set up ENTER+EXIT hooks for full syscall/API timeline with return values.

    Captures both arguments (on entry) and return values (on exit) for a
    structured timeline. Also populates api_calls for backward-compatible
    activity classification. Falls back to standard CALL hooks if
    ENTER/EXIT intercepts aren't available in this Qiling version.
    """
    filter_lower = [f.lower() for f in syscall_filter] if syscall_filter else []
    seq = [0]
    max_timeline = limit * 3

    def _read_retval(ql):
        """Read the return value register (RAX for 64-bit, EAX for 32-bit)."""
        try:
            if hasattr(ql.arch.regs, 'rax'):
                return ql.arch.regs.rax
            elif hasattr(ql.arch.regs, 'eax'):
                return ql.arch.regs.eax
        except Exception:
            pass
        return None

    if os_type == "windows":
        def _win_enter(ql, address, params):
            api_name = "unknown"
            args = {}
            if isinstance(params, dict):
                api_name = params.get("__name__", "unknown")
                for k, v in list(params.items())[:8]:
                    if not k.startswith("__"):
                        args[k] = str(v)[:200] if v is not None else None

            # Always populate api_calls for activity classification
            if len(api_calls) < limit * 2:
                api_calls.append({
                    "api": api_name,
                    "address": _hex(address),
                    "params": args,
                    "retval": None,
                })

            # Apply filter for timeline
            if filter_lower and not any(f in api_name.lower() for f in filter_lower):
                return

            if len(timeline) < max_timeline:
                timeline.append({
                    "seq": seq[0],
                    "api": api_name,
                    "type": "win_api",
                    "address": _hex(address),
                    "args": args,
                    "return_value": None,
                })
                seq[0] += 1

        def _win_exit(ql, *_args):
            retval_hex = _hex(_read_retval(ql))
            for entry in reversed(timeline):
                if entry.get("return_value") is None:
                    entry["return_value"] = retval_hex
                    break
            if api_calls and api_calls[-1].get("retval") is None:
                api_calls[-1]["retval"] = retval_hex

        try:
            ql.os.set_api("*", _win_enter, QL_INTERCEPT.ENTER)
            ql.os.set_api("*", _win_exit, QL_INTERCEPT.EXIT)
        except Exception:
            # ENTER/EXIT not available — fall back to CALL hooks
            _setup_api_hooks(ql, os_type, api_calls, limit)

    else:
        # POSIX syscall hooks
        def _posix_enter(ql, *args):
            syscall_name = str(args[0]) if args else "unknown"
            if filter_lower and not any(f in syscall_name.lower() for f in filter_lower):
                return

            sc_args = {}
            for i, a in enumerate(args[1:6]):
                sc_args[f"arg{i}"] = str(a)[:200] if a is not None else None

            pc = None
            try:
                pc = _hex(ql.arch.regs.arch_pc)
            except Exception:
                pass

            if len(api_calls) < limit * 2:
                api_calls.append({
                    "api": syscall_name,
                    "address": pc,
                    "params": sc_args,
                    "retval": None,
                })

            if len(timeline) < max_timeline:
                timeline.append({
                    "seq": seq[0],
                    "syscall": syscall_name,
                    "type": "posix_syscall",
                    "address": pc,
                    "args": sc_args,
                    "return_value": None,
                })
                seq[0] += 1

        def _posix_exit(ql, *args):
            # Try args first (some Qiling versions pass retval), else read register
            retval = None
            if args and isinstance(args[0], int):
                retval = args[0]
            else:
                retval = _read_retval(ql)
            retval_hex = _hex(retval)

            for entry in reversed(timeline):
                if entry.get("return_value") is None:
                    entry["return_value"] = retval_hex
                    break
            if api_calls and api_calls[-1].get("retval") is None:
                api_calls[-1]["retval"] = retval_hex

        try:
            ql.os.set_syscall("*", _posix_enter, QL_INTERCEPT.ENTER)
            ql.os.set_syscall("*", _posix_exit, QL_INTERCEPT.EXIT)
        except Exception:
            _setup_api_hooks(ql, os_type, api_calls, limit)


# Windows memory protection flags
_WIN_PROTECT_FLAGS = {
    0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY", 0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY", 0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY",
}


def _safe_int(val, default=0):
    """Parse a string or int value to int, returning default on failure."""
    if val is None:
        return default
    if isinstance(val, int):
        return val
    try:
        return int(val, 0) if isinstance(val, str) and val.startswith("0x") else int(val)
    except (ValueError, TypeError):
        return default


def _analyze_memory_activity(api_calls, limit):
    """Post-hoc analysis of captured API calls for memory allocation patterns.

    Returns structured memory operation timeline and flags suspicious patterns
    like RWX allocations, protection changes to executable, guard pages, and
    large allocations that may indicate injection or unpacking.
    """
    memory_ops = []
    anomalies = []

    for call in api_calls:
        api = (call.get("api") or "").lower()
        params = call.get("params", {})

        if "virtualalloc" in api and "free" not in api:
            size = _safe_int(params.get("dwSize") or params.get("RegionSize", "0"))
            protect = _safe_int(params.get("flProtect") or params.get("Protect", "0"))
            addr = params.get("lpAddress") or params.get("BaseAddress", "0")

            protect_name = _WIN_PROTECT_FLAGS.get(protect & 0xFF, hex(protect))
            entry = {
                "api": call.get("api", "VirtualAlloc"),
                "address": str(addr),
                "size": size,
                "protection": protect_name,
            }
            memory_ops.append(entry)

            if protect & 0x40:  # PAGE_EXECUTE_READWRITE
                anomalies.append({
                    "type": "RWX_ALLOCATION",
                    "severity": "high",
                    "api": call.get("api"),
                    "size": size,
                    "detail": f"Allocated {size} bytes with RWX — common in shellcode injection and unpacking",
                })
            if size > 1048576:  # > 1 MB
                anomalies.append({
                    "type": "LARGE_ALLOCATION",
                    "severity": "medium",
                    "api": call.get("api"),
                    "size": size,
                    "detail": f"Large allocation ({size} bytes) — may indicate process hollowing or payload staging",
                })

        elif "virtualprotect" in api:
            new_protect = _safe_int(params.get("flNewProtect") or params.get("NewProtect", "0"))
            addr = params.get("lpAddress") or params.get("BaseAddress", "0")
            size = _safe_int(params.get("dwSize") or params.get("RegionSize", "0"))

            protect_name = _WIN_PROTECT_FLAGS.get(new_protect & 0xFF, hex(new_protect))
            entry = {
                "api": call.get("api", "VirtualProtect"),
                "address": str(addr),
                "size": size,
                "new_protection": protect_name,
            }
            memory_ops.append(entry)

            if new_protect & 0x40:
                anomalies.append({
                    "type": "RWX_PROTECTION_CHANGE",
                    "severity": "high",
                    "api": call.get("api"),
                    "detail": "Protection changed to RWX — often precedes shellcode execution",
                })
            elif new_protect & 0xF0:  # any executable flag
                anomalies.append({
                    "type": "EXECUTE_PROTECTION_CHANGE",
                    "severity": "medium",
                    "api": call.get("api"),
                    "detail": f"Protection changed to executable ({protect_name}) — may indicate unpacking",
                })
            if new_protect & 0x100:  # PAGE_GUARD
                anomalies.append({
                    "type": "GUARD_PAGE",
                    "severity": "medium",
                    "api": call.get("api"),
                    "detail": "Guard page set — can be used for anti-debug single-step tracking",
                })

        elif "heapalloc" in api or "heapcreate" in api:
            size = _safe_int(params.get("dwBytes") or params.get("dwInitialSize", "0"))
            memory_ops.append({
                "api": call.get("api", api),
                "size": size,
            })

        elif "virtualfree" in api:
            addr = params.get("lpAddress", "0")
            memory_ops.append({
                "api": call.get("api", "VirtualFree"),
                "address": str(addr),
            })

        elif api in ("mmap", "mmap2"):
            # POSIX memory mapping
            memory_ops.append({
                "api": api,
                "params_raw": {k: str(v)[:100] for k, v in list(params.items())[:6]},
            })

        elif api == "mprotect":
            memory_ops.append({
                "api": "mprotect",
                "params_raw": {k: str(v)[:100] for k, v in list(params.items())[:6]},
            })

        if len(memory_ops) >= limit * 2:
            break

    # Detect allocation→execute sequences
    alloc_apis = [op for op in memory_ops if "alloc" in op.get("api", "").lower()]
    protect_apis = [op for op in memory_ops if "protect" in op.get("api", "").lower()]
    if alloc_apis and protect_apis:
        exec_changes = [p for p in protect_apis
                        if _safe_int(p.get("new_protection", "0x0"), 0) & 0xF0]
        if exec_changes:
            anomalies.append({
                "type": "ALLOC_THEN_EXECUTE_SEQUENCE",
                "severity": "high",
                "detail": (f"Detected {len(alloc_apis)} allocation(s) followed by "
                           f"{len(exec_changes)} protection change(s) to executable — "
                           "classic injection/unpacking pattern"),
            })

    return {
        "memory_operations": memory_ops[:limit],
        "anomalies": anomalies[:limit],
        "summary": {
            "total_memory_operations": len(memory_ops),
            "total_anomalies": len(anomalies),
            "anomaly_types": sorted(set(a["type"] for a in anomalies)),
        },
    }


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


def _check_windows_dlls(rootfs_dir):
    """Check whether Windows DLL files are present in the rootfs.

    Returns (has_dlls: bool, dll_warning: str|None).
    """
    sys32 = os.path.join(rootfs_dir, "Windows", "System32")
    if not os.path.isdir(sys32):
        return False, (
            "Windows DLLs missing: no Windows/System32/ directory found in rootfs. "
            "Windows PE emulation requires real DLL files (ntdll.dll, kernel32.dll, "
            "user32.dll, advapi32.dll, ws2_32.dll, msvcrt.dll, etc.) copied from a "
            "Windows installation. Without them, Qiling cannot resolve imports and "
            "emulation will fail or produce no API call data. "
            "To fix: copy DLLs from C:\\Windows\\SysWOW64\\ (for 32-bit PE) or "
            "C:\\Windows\\System32\\ (for 64-bit PE) into "
            "qiling-rootfs/<arch>_windows/Windows/System32/ on the Docker host. "
            "The directory is automatically mounted into the container."
        )
    dlls = [f for f in os.listdir(sys32)
            if f.lower().endswith(".dll") and os.path.isfile(os.path.join(sys32, f))]
    if not dlls:
        return False, (
            "Windows DLLs missing: Windows/System32/ exists but contains no .dll files. "
            "Windows PE emulation requires real DLL files (ntdll.dll, kernel32.dll, "
            "user32.dll, advapi32.dll, ws2_32.dll, msvcrt.dll, etc.) copied from a "
            "Windows installation. Without them, Qiling cannot resolve imports and "
            "emulation will fail or produce no API call data. "
            "To fix: copy DLLs from C:\\Windows\\SysWOW64\\ (for 32-bit PE) or "
            "C:\\Windows\\System32\\ (for 64-bit PE) into this directory on the "
            "Docker host. The qiling-rootfs/ directory is automatically mounted."
        )
    # Check for the essential minimum set
    essential = {"ntdll.dll", "kernel32.dll"}
    present = {f.lower() for f in dlls}
    missing_essential = essential - present
    if missing_essential:
        return True, (
            f"Essential Windows DLLs missing: {', '.join(sorted(missing_essential))}. "
            f"Found {len(dlls)} DLLs but ntdll.dll and kernel32.dll are required "
            f"at minimum. Copy them from a Windows installation."
        )
    return True, None


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
        return None, f"No rootfs mapping for {os_type}/{arch}", None

    rootfs = os.path.join(rootfs_path, dir_name)
    if os.path.isdir(rootfs):
        # Windows rootfs needs registry hive stubs that can't be legally
        # distributed.  Generate them on first use if missing.
        dll_warning = None
        if os_type == "windows":
            _ensure_windows_registry(rootfs)
            _, dll_warning = _check_windows_dlls(rootfs)
        return rootfs, None, dll_warning
    return None, (
        f"Rootfs directory not found: {rootfs}. "
        f"The rootfs is pre-populated in the Docker image at build time. "
        f"If it is missing, rebuild the image or mount your own rootfs files "
        f"at /app/qiling-rootfs/{dir_name}/ via the qiling-rootfs/ host directory. "
        f"For Windows PE emulation you also need real Windows DLL files "
        f"(ntdll.dll, kernel32.dll, etc.) copied from a Windows installation "
        f"into {dir_name}/Windows/System32/. "
        f"See docs/QILING_ROOTFS.md for setup instructions."
    ), None


def _cleanup_staged_binary(staged_path):
    """Remove the staged binary copy from the rootfs.  Best-effort."""
    if staged_path:
        try:
            os.remove(staged_path)
        except OSError:
            pass


def _init_qiling_for_binary(filepath, rootfs_path):
    """Detect binary format, validate rootfs/DLLs, and create a Qiling instance.

    Qiling requires the binary to live *inside* the rootfs so it can map
    host paths to virtual guest paths.  We copy the sample into a staging
    directory inside the rootfs before creating the Qiling instance.

    Returns (ql, os_type, arch, fmt_desc, dll_warning, staged_path) on success.
    Returns (None, os_type, arch, fmt_desc, error_dict, None) on failure,
    where error_dict is a dict with 'error' (and optionally 'traceback') keys.
    Callers must call ``_cleanup_staged_binary(staged_path)`` in a finally
    block after emulation completes.
    """
    os_type, arch, fmt_desc = _detect_binary_format(filepath)
    if os_type is None:
        return None, None, None, fmt_desc, {"error": f"Cannot detect binary format: {fmt_desc}"}, None

    rootfs, err, dll_warning = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return None, os_type, arch, fmt_desc, {"error": err}, None

    # Pre-validate: for Windows binaries, fail fast if essential DLLs are missing
    if os_type == "windows":
        has_dlls, dll_msg = _check_windows_dlls(rootfs)
        if not has_dlls:
            return None, os_type, arch, fmt_desc, {
                "error": (
                    f"Cannot initialize Qiling for {fmt_desc}: {dll_msg}\n\n"
                    "Use qiling_setup_check() to see exactly which DLLs are missing "
                    "and get copy commands to fix the issue."
                ),
            }, None

    # Stage the binary inside the rootfs so Qiling can resolve paths
    staging_dir = os.path.join(rootfs, "_arkana_samples")
    os.makedirs(staging_dir, exist_ok=True)
    staged_path = os.path.join(staging_dir, os.path.basename(filepath))
    try:
        shutil.copy2(filepath, staged_path)
    except OSError as e:
        return None, os_type, arch, fmt_desc, {
            "error": f"Failed to stage binary into rootfs: {e}",
        }, None

    try:
        ql = Qiling(
            [staged_path],
            rootfs,
            ostype=_ql_os(os_type),
            archtype=_ql_arch(arch),
            verbose=QL_VERBOSE.DISABLED,
        )
    except Exception as e:
        _cleanup_staged_binary(staged_path)
        err_msg = f"Failed to initialize Qiling: {type(e).__name__}: {e}"
        if dll_warning:
            err_msg += f"\n\nNote: {dll_warning}"
        tb = traceback.format_exc()
        return None, os_type, arch, fmt_desc, {
            "error": err_msg,
            "traceback": tb[:2000],
        }, None

    return ql, os_type, arch, fmt_desc, dll_warning, staged_path


# ---------------------------------------------------------------------------
#  Actions
# ---------------------------------------------------------------------------

def emulate_binary(cmd):
    """Full binary emulation with behavioral report."""
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
    dll_warning = init_result

    try:
        api_calls = []
        file_activity = []
        registry_activity = []
        network_activity = []
        syscall_timeline = []

        # Set up hooks — enhanced ENTER+EXIT for tracing, or standard CALL
        if trace_syscalls:
            _setup_syscall_trace(ql, os_type, api_calls, syscall_timeline,
                                syscall_filter, limit)
        else:
            _setup_api_hooks(ql, os_type, api_calls, limit)

        try:
            if max_instructions > 0:
                ql.run(count=max_instructions, timeout=timeout_seconds * 1000000)
            else:
                ql.run(timeout=timeout_seconds * 1000000)
        except Exception:
            # Emulation may raise on exit or unhandled API -- expected
            pass

        # Post-hoc activity classification from captured calls
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
            "format": fmt_desc,
            "os_type": os_type,
            "architecture": arch,
            "total_api_calls": len(api_calls),
            "api_calls": _safe_slice(api_calls, limit),
            "file_activity": _safe_slice(file_activity, limit),
            "registry_activity": _safe_slice(registry_activity, limit),
            "network_activity": _safe_slice(network_activity, limit),
        }

        # Add syscall timeline when tracing is enabled
        if trace_syscalls and syscall_timeline:
            result["syscall_timeline"] = _safe_slice(syscall_timeline, limit)
            result["total_syscalls_traced"] = len(syscall_timeline)
            # Summarize by API/syscall name
            counts = {}
            for entry in syscall_timeline:
                name = entry.get("api") or entry.get("syscall", "unknown")
                counts[name] = counts.get(name, 0) + 1
            result["syscall_summary"] = dict(sorted(counts.items(), key=lambda x: -x[1])[:20])
            if syscall_filter:
                result["syscall_filter_applied"] = syscall_filter

        # Add memory allocation analysis when tracking is enabled
        if track_memory:
            result["memory_activity"] = _analyze_memory_activity(api_calls, limit)

        if dll_warning:
            result["warning"] = dll_warning
        return result
    finally:
        _cleanup_staged_binary(staged_path)


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
        _validate_file_path(filepath)
        with open(filepath, "rb") as f:
            sc_data = f.read()
    else:
        return {"error": "No shellcode provided (no shellcode_hex or filepath)."}

    rootfs, err, dll_warning = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}

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

    _setup_api_hooks(ql, os_type, api_calls, limit)

    try:
        if max_instructions > 0:
            ql.run(count=max_instructions, timeout=timeout_seconds * 1000000)
        else:
            ql.run(timeout=timeout_seconds * 1000000)
    except Exception:
        pass

    result = {
        "status": "completed",
        "os_type": os_type,
        "architecture": arch,
        "shellcode_size": len(sc_data),
        "shellcode_sha256": hashlib.sha256(sc_data).hexdigest(),
        "total_api_calls": len(api_calls),
        "api_calls": _safe_slice(api_calls, limit),
    }
    if dll_warning:
        result["warning"] = dll_warning
    return result


def trace_execution(cmd):
    """Instruction-level execution tracing."""
    filepath = cmd["filepath"]
    _validate_file_path(filepath)
    rootfs_path = cmd.get("rootfs_path")
    start_address = cmd.get("start_address")
    end_address = cmd.get("end_address")
    max_instructions = cmd.get("max_instructions", 1000)
    timeout_seconds = cmd.get("timeout_seconds", 30)
    limit = cmd.get("limit", 500)

    ql, os_type, arch, fmt_desc, init_result, staged_path = _init_qiling_for_binary(filepath, rootfs_path)
    if ql is None:
        return init_result
    dll_warning = init_result

    try:
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

        result = {
            "status": "completed",
            "format": fmt_desc,
            "total_instructions_traced": len(instructions),
            "unique_addresses": len(unique_addresses),
            "instructions": _safe_slice(instructions, limit),
        }
        if dll_warning:
            result["warning"] = dll_warning
        return result
    finally:
        _cleanup_staged_binary(staged_path)


def hook_api_calls(cmd):
    """Targeted API/syscall hooking with argument capture."""
    filepath = cmd["filepath"]
    _validate_file_path(filepath)
    rootfs_path = cmd.get("rootfs_path")
    target_apis = cmd.get("target_apis", [])
    timeout_seconds = cmd.get("timeout_seconds", 60)
    max_instructions = cmd.get("max_instructions", 0)
    limit = cmd.get("limit", 200)

    ql, os_type, arch, fmt_desc, init_result, staged_path = _init_qiling_for_binary(filepath, rootfs_path)
    if ql is None:
        return init_result
    dll_warning = init_result

    try:
        captured_calls = []

        # If specific APIs requested, hook each; otherwise hook all.
        # For specific APIs on Windows, use set_api per name.
        # For the wildcard case, use _setup_api_hooks which handles OS differences.
        if target_apis and os_type == "windows":
            for api_name in target_apis:
                def _make_hook(name):
                    def _hook(ql, address, params):
                        if len(captured_calls) < limit:
                            entry = {
                                "api": name,
                                "address": _hex(address),
                                "params": {},
                                "retval": None,
                            }
                            if isinstance(params, dict):
                                for k, v in list(params.items())[:8]:
                                    entry["params"][k] = str(v)[:500] if v is not None else None
                            captured_calls.append(entry)
                    return _hook
                try:
                    ql.os.set_api(api_name, _make_hook(api_name), QL_INTERCEPT.CALL)
                except Exception:
                    pass  # API may not exist in the emulated environment
        else:
            _setup_api_hooks(ql, os_type, captured_calls, limit)

        try:
            kwargs = {"timeout": timeout_seconds * 1000000}
            if max_instructions > 0:
                kwargs["count"] = max_instructions
            ql.run(**kwargs)
        except Exception:
            pass

        result = {
            "status": "completed",
            "format": fmt_desc,
            "target_apis": target_apis if target_apis else ["* (all)"],
            "total_captured": len(captured_calls),
            "captured_calls": _safe_slice(captured_calls, limit),
        }
        if dll_warning:
            result["warning"] = dll_warning
        return result
    finally:
        _cleanup_staged_binary(staged_path)


def dump_unpacked(cmd):
    """Dynamic unpacking: run binary until OEP, then dump memory."""
    filepath = cmd["filepath"]
    _validate_file_path(filepath)
    rootfs_path = cmd.get("rootfs_path")
    output_path = cmd["output_path"]
    dump_address = cmd.get("dump_address")
    dump_size = cmd.get("dump_size")
    timeout_seconds = cmd.get("timeout_seconds", 120)
    max_instructions = cmd.get("max_instructions", 0)

    ql, os_type, arch, fmt_desc, init_result, staged_path = _init_qiling_for_binary(filepath, rootfs_path)
    if ql is None:
        return init_result
    dll_warning = init_result

    try:
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

            result = {
                "status": "success",
                "input_file": filepath,
                "output_file": output_path,
                "output_size": len(data),
                "dump_address": dump_address or _hex(best_region[0]) if not dump_address and best_region else dump_address,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            if dll_warning:
                result["warning"] = dll_warning
            return result
        except Exception as e:
            err_msg = f"Memory dump failed: {e}"
            if dll_warning:
                err_msg += f"\n\nNote: {dll_warning}"
            return {"error": err_msg}
    finally:
        _cleanup_staged_binary(staged_path)


def resolve_api_hashes(cmd):
    """Resolve API hash values by emulating hash computation routines."""
    filepath = cmd["filepath"]
    _validate_file_path(filepath)
    rootfs_path = cmd.get("rootfs_path")
    hash_values = cmd.get("hash_values", [])
    hash_algorithm = cmd.get("hash_algorithm", "ror13")
    timeout_seconds = cmd.get("timeout_seconds", 30)

    os_type, arch, fmt_desc = _detect_binary_format(filepath)
    if os_type is None:
        # Default to Windows x86 for hash resolution
        os_type, arch = "windows", "x86"

    rootfs, err, dll_warning = _find_rootfs(os_type, arch, rootfs_path)
    if err:
        return {"error": err}

    # API hash resolution absolutely requires DLLs — warn prominently
    if dll_warning:
        has_dlls, _ = _check_windows_dlls(rootfs)
        if not has_dlls:
            return {
                "error": (
                    "Cannot resolve API hashes: no Windows DLL files found in rootfs. "
                    "This tool works by computing hashes of exported function names from "
                    "real DLL files and matching them against your input hashes. Without "
                    "DLLs, there are no exports to hash against. "
                    "To fix: copy DLL files from a Windows installation into "
                    "qiling-rootfs/<arch>_windows/Windows/System32/ on the Docker host. "
                    "Key DLLs: kernel32.dll, ntdll.dll, user32.dll, advapi32.dll, "
                    "ws2_32.dll, wininet.dll, shell32.dll, msvcrt.dll, ole32.dll, "
                    "crypt32.dll. The more DLLs you provide, the more hashes can be resolved."
                ),
            }

    # Read optional seed and case_handling from IPC command
    custom_seed = cmd.get("hash_seed")  # None means use default
    case_handling = cmd.get("case_handling")  # 'lower', 'upper', or None

    # Default seeds per algorithm
    _DEFAULT_SEEDS = {"ror13": 0, "crc32": 0, "djb2": 5381, "fnv1a": 0x811C9DC5}

    # Compute hashes for known DLL exports — with configurable seeds
    def _ror13(name, seed=None):
        h = (seed if seed is not None else _DEFAULT_SEEDS["ror13"]) & 0xFFFFFFFF
        for c in name:
            h = ((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF
            h = (h + ord(c)) & 0xFFFFFFFF
        return h

    def _crc32(name, seed=None):
        import binascii
        return binascii.crc32(name.encode()) & 0xFFFFFFFF

    def _djb2(name, seed=None):
        h = (seed if seed is not None else _DEFAULT_SEEDS["djb2"]) & 0xFFFFFFFF
        for c in name:
            h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
        return h

    def _fnv1a(name, seed=None):
        h = (seed if seed is not None else _DEFAULT_SEEDS["fnv1a"]) & 0xFFFFFFFF
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

    hash_func_raw = hash_funcs.get(hash_algorithm)
    if not hash_func_raw:
        return {"error": f"Unknown hash algorithm: {hash_algorithm}. Supported: {list(hash_funcs.keys())}"}

    # Wrap with seed and case handling
    def hash_func(name):
        if case_handling == "lower":
            name = name.lower()
        elif case_handling == "upper":
            name = name.upper()
        return hash_func_raw(name, seed=custom_seed)

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
    _validate_file_path(filepath)
    rootfs_path = cmd.get("rootfs_path")
    search_patterns = cmd.get("search_patterns", [])
    search_hex = cmd.get("search_hex")
    max_instructions = cmd.get("max_instructions", 500000)
    timeout_seconds = cmd.get("timeout_seconds", 60)
    context_bytes = cmd.get("context_bytes", 32)
    limit = cmd.get("limit", 50)

    ql, os_type, arch, fmt_desc, init_result, staged_path = _init_qiling_for_binary(filepath, rootfs_path)
    if ql is None:
        return init_result
    dll_warning = init_result

    try:
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

        result = {
            "status": "completed",
            "format": fmt_desc,
            "search_patterns": search_patterns,
            "search_hex": search_hex,
            "instructions_executed": max_instructions,
            "memory_regions_scanned": len(maps) if 'maps' in locals() else 0,
            "total_matches": len(matches),
            "matches": _safe_slice(matches, limit),
        }
        if dll_warning:
            result["warning"] = dll_warning
        return result
    finally:
        _cleanup_staged_binary(staged_path)


# ---------------------------------------------------------------------------
#  Windows rootfs helpers (registry hive stubs)
# ---------------------------------------------------------------------------

# Import the canonical implementation from the shared script.
# Both the Dockerfile and this runner use the same code.
from create_registry_hives import create_minimal_registry_hive as _create_minimal_registry_hive


def _ensure_windows_registry(target_dir):
    """Create minimal Windows registry hive stubs if they don't exist.

    Returns the number of hive files created (0 if all already existed).
    """
    reg_dir = os.path.join(target_dir, "Windows", "registry")
    os.makedirs(reg_dir, exist_ok=True)

    # Qiling's RegHive opens ALL six hives; a missing one raises
    # FileNotFoundError → "Windows registry hive not found".
    hive_names = ["NTUSER.DAT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM", "HARDWARE"]
    created = 0
    for name in hive_names:
        path = os.path.join(reg_dir, name)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(_create_minimal_registry_hive())
            created += 1
    return created


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

    # Redirect stdout → stderr while Qiling runs.
    # Qiling's emulator and internal helpers print log/debug messages
    # directly to stdout which would corrupt the JSON result that the
    # parent process expects on stdout.  Sending those to stderr keeps
    # the JSON channel clean (same pattern as unipacker_runner.py).
    real_stdout = sys.stdout
    sys.stdout = sys.stderr

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
        else:
            result = {"error": f"Unknown action: {action}"}
    except Exception as e:
        result = {"error": f"{type(e).__name__}: {e}", "traceback": traceback.format_exc()[:1000]}
    finally:
        sys.stdout = real_stdout

    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
