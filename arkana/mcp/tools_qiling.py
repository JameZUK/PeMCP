"""MCP tools powered by the Qiling Framework (cross-platform binary emulation).

Qiling runs in an isolated venv (/app/qiling-venv) with unicorn 1.x,
keeping the main env free to use unicorn 2.x for angr.  All tools
invoke the runner script via subprocess, following the same pattern
as the speakeasy and unipacker integrations.
"""
import asyncio
import json
import os

from typing import Dict, Any, Optional, List

from arkana.config import (
    state, logger, Context,
    _QILING_VENV_PYTHON, _QILING_RUNNER, _QILING_DEFAULT_ROOTFS,
    _check_qiling_available,
)
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp.tools_new_libs import _subprocess_progress_reporter


_MAX_INSTRUCTIONS_LIMIT = 10_000_000

def _validate_max_instructions(max_instructions: int) -> int:
    """Validate and clamp max_instructions parameter."""
    if max_instructions < 0:
        raise ValueError(f"max_instructions must be non-negative, got {max_instructions}")
    if max_instructions > _MAX_INSTRUCTIONS_LIMIT:
        raise ValueError(f"max_instructions too large (max {_MAX_INSTRUCTIONS_LIMIT:,}), got {max_instructions:,}")
    return max_instructions


_MAX_TIMEOUT_SECONDS = 600  # 10 minutes

_VALID_OS_TYPES = frozenset({"windows", "linux", "macos"})
_VALID_ARCHITECTURES = frozenset({"x86", "x8664", "arm", "arm64", "mips"})


def _validate_timeout(timeout_seconds: int) -> int:
    """Validate timeout_seconds parameter."""
    if timeout_seconds < 1:
        raise ValueError(f"timeout_seconds must be positive, got {timeout_seconds}")
    if timeout_seconds > _MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds too large (max {_MAX_TIMEOUT_SECONDS}), got {timeout_seconds}")
    return timeout_seconds


# L7-v14: _subprocess_progress_reporter imported from tools_new_libs (single source)

# ---------------------------------------------------------------------------
#  Subprocess helper (mirrors _run_speakeasy / _run_unipacker pattern)
# ---------------------------------------------------------------------------

# Qiling-specific error enrichment (applied to subprocess results, not exceptions)
_QILING_ERROR_HINTS = {
    "windows api implementation error": (
        "This usually means Windows DLL files are missing or incomplete in the rootfs. "
        "Qiling needs real Windows DLLs (ntdll.dll, kernel32.dll, etc.) to emulate PE files. "
        "Run qiling_setup_check() to diagnose, then copy DLLs from a Windows machine."
    ),
    "dll not found": (
        "A required DLL could not be found in the rootfs. Copy the missing DLL from a "
        "Windows installation into qiling-rootfs/<arch>_windows/Windows/System32/. "
        "Run qiling_setup_check() for specific guidance."
    ),
    "registry hive": (
        "Windows registry hive files are missing or corrupt. "
        "The runner normally auto-creates these. Try running qiling_setup_check() to diagnose."
    ),
}


def _enrich_qiling_error(error_msg: str) -> str:
    """Append actionable hints to known Qiling error patterns."""
    msg_lower = error_msg.lower()
    for pattern, hint in _QILING_ERROR_HINTS.items():
        if pattern in msg_lower:
            return f"{error_msg}\n\nHint: {hint}"
    return error_msg


async def _run_qiling(cmd: dict, timeout_seconds: int) -> dict:
    """Invoke the qiling runner subprocess in the isolated venv."""
    proc = await asyncio.create_subprocess_exec(
        str(_QILING_VENV_PYTHON), str(_QILING_RUNNER),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    input_data = json.dumps(cmd).encode()
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=input_data),
            timeout=timeout_seconds + 60,  # buffer beyond emulation timeout
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass  # Best-effort cleanup; process may already be dead
        return {"error": f"Qiling emulation timed out after {timeout_seconds}s"}

    if proc.returncode != 0:
        err_msg = stderr.decode(errors="replace")[:500]
        return {"error": f"Qiling runner failed (exit {proc.returncode}): {err_msg}"}

    try:
        result = json.loads(stdout.decode())
    except json.JSONDecodeError:
        return {"error": f"Invalid JSON from Qiling runner: {stdout.decode(errors='replace')[:500]}"}

    # Enrich error results with actionable hints
    if isinstance(result, dict) and "error" in result:
        result["error"] = _enrich_qiling_error(result["error"])

    return result


def _check_qiling(tool_name: str):
    """Validate that Qiling is available, raising RuntimeError with rootfs guidance if not."""
    if not _check_qiling_available():
        raise RuntimeError(
            f"[{tool_name}] Qiling Framework is not available. "
            "It requires the Qiling venv (/app/qiling-venv) to be set up. "
            "This is included in the Docker image."
        )
    # Check rootfs exists and provide specific guidance
    rootfs = str(_QILING_DEFAULT_ROOTFS)
    if not os.path.isdir(rootfs):
        raise RuntimeError(
            f"[{tool_name}] Qiling rootfs directory not found at {rootfs}. "
            "Create it or set QILING_ROOTFS environment variable. "
            "Use qiling_setup_check() to diagnose the issue."
        )


def _rootfs_path() -> str:
    """Return the default rootfs path."""
    return str(_QILING_DEFAULT_ROOTFS)


# Essential DLLs needed for Windows PE emulation
_ESSENTIAL_DLLS = {
    "x86_windows": [
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "advapi32.dll", "ws2_32.dll", "msvcrt.dll", "ole32.dll",
    ],
    "x8664_windows": [
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "advapi32.dll", "ws2_32.dll", "msvcrt.dll", "ole32.dll",
    ],
}

_ROOTFS_ARCH_DIRS = {
    "x86_windows": "x86_windows/Windows/System32",
    "x8664_windows": "x8664_windows/Windows/System32",
    "x86_linux": "x86_linux",
    "x8664_linux": "x8664_linux",
}


# ===================================================================
#  Tool 1: emulate_binary_with_qiling
# ===================================================================

@tool_decorator
async def emulate_binary_with_qiling(
    ctx: Context,
    timeout_seconds: int = 60,
    max_instructions: int = 0,
    limit: int = 20,
    trace_syscalls: bool = False,
    syscall_filter: Optional[List[str]] = None,
    track_memory: bool = False,
) -> Dict[str, Any]:
    """
    Emulates the loaded binary (PE, ELF, or Mach-O) using the Qiling Framework
    with full OS emulation.  Returns a behavioral report: API/syscall calls,
    file activity, registry activity, and network activity.

    ---compact: full OS emulation with syscall/API tracing | PE/ELF/Mach-O | needs: qiling, file

    This is a cross-platform emulator — unlike Speakeasy (Windows-only), Qiling
    can emulate Linux ELF and macOS Mach-O binaries as well.

    Rootfs requirements (OS-specific files needed for emulation):
    - Linux ELF: Works out of the box — rootfs is pre-populated in the Docker image.
    - Windows PE: Requires real Windows DLL files (ntdll.dll, kernel32.dll, etc.)
      copied from a Windows installation into the rootfs.  Without DLLs, Qiling
      cannot resolve imports and emulation will fail or produce no API calls.
      To set up: copy DLLs from C:\\Windows\\SysWOW64\\ (for 32-bit PE) or
      C:\\Windows\\System32\\ (for 64-bit PE) into qiling-rootfs/x86_windows/Windows/System32/
      or qiling-rootfs/x8664_windows/Windows/System32/ on the host.  The directory
      is auto-mounted into the container at /app/qiling-rootfs/.
    - macOS Mach-O: Requires macOS system libraries (rarely needed).

    If emulation fails with "rootfs not found" or "DLL not found", the user
    needs to provide the required files.  See docs/QILING_ROOTFS.md for details.

    Args:
        timeout_seconds: Max emulation time in seconds (default 60).
        max_instructions: Max CPU instructions to emulate (0 = unlimited, use timeout only).
        limit: Max entries per activity category to return.
        trace_syscalls: If True, enables detailed syscall-level tracing using
            ENTER+EXIT hooks. Returns a structured syscall timeline with arguments
            and return values, plus a frequency summary. Supports both Windows
            API calls (ntdll stubs) and Linux syscalls (int 0x80 / syscall).
        syscall_filter: When trace_syscalls is True, optionally filter the timeline
            to only include calls matching these substrings (case-insensitive).
            E.g. ['CreateFile', 'VirtualAlloc', 'connect'] to trace only those APIs.
            If empty/None, all calls are traced.
        track_memory: If True, analyzes captured API calls for memory allocation
            patterns. Returns memory_activity with operations timeline, anomalies
            (RWX allocations, protection changes to executable, guard pages, large
            allocations), and alloc-then-execute sequence detection.
    """
    await ctx.info("Emulating binary with Qiling Framework")
    _check_qiling("emulate_binary_with_qiling")
    _check_pe_loaded("emulate_binary_with_qiling")
    _validate_max_instructions(max_instructions)
    _validate_timeout(timeout_seconds)

    progress_task = asyncio.create_task(
        _subprocess_progress_reporter(ctx, "emulate_binary_with_qiling", timeout_seconds))
    try:
        result = await _run_qiling({
            "action": "emulate_binary",
            "filepath": state.filepath,
            "rootfs_path": _rootfs_path(),
            "timeout_seconds": timeout_seconds,
            "max_instructions": max_instructions,
            "limit": limit,
            "trace_syscalls": trace_syscalls,
            "syscall_filter": syscall_filter or [],
            "track_memory": track_memory,
        }, timeout_seconds)
    finally:
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "emulate_binary_with_qiling", "the 'limit' parameter")


# ===================================================================
#  Tool 2: emulate_shellcode_with_qiling
# ===================================================================

@tool_decorator
async def emulate_shellcode_with_qiling(
    ctx: Context,
    shellcode_hex: Optional[str] = None,
    os_type: str = "windows",
    architecture: str = "x86",
    timeout_seconds: int = 30,
    max_instructions: int = 0,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    Emulates shellcode using the Qiling Framework with multi-architecture support.
    Supports x86, x86_64, ARM, ARM64, and MIPS — far broader than Speakeasy's
    x86/x64-only shellcode emulation.

    ---compact: emulate shellcode multi-arch | x86/x64/ARM/MIPS | needs: qiling

    If no shellcode_hex is provided, uses the loaded file as raw shellcode.

    Rootfs requirements:
    - Shellcode emulation still requires a rootfs directory for the target OS.
    - Linux: Pre-populated in Docker image — works immediately.
    - Windows: Requires real DLL files for full API hooking.  Without DLLs,
      shellcode runs but Windows API calls cannot be intercepted (you'll see
      0 API calls in the output).  Copy DLLs from a Windows machine into
      qiling-rootfs/x86_windows/Windows/System32/ (32-bit) or
      qiling-rootfs/x8664_windows/Windows/System32/ (64-bit) on the host.

    Args:
        shellcode_hex: Hex-encoded shellcode bytes. If None, uses loaded file data.
        os_type: Target OS ('windows', 'linux', 'macos'). Default: 'windows'.
        architecture: Target architecture ('x86', 'x8664', 'arm', 'arm64', 'mips'). Default: 'x86'.
        timeout_seconds: Max emulation time in seconds.
        max_instructions: Max CPU instructions to emulate (0 = unlimited).
        limit: Max API calls to return.
    """
    await ctx.info(f"Emulating shellcode with Qiling ({os_type}/{architecture})")
    _check_qiling("emulate_shellcode_with_qiling")
    _validate_max_instructions(max_instructions)
    _validate_timeout(timeout_seconds)
    _MAX_SHELLCODE_HEX = 20_000_000  # 20MB hex = 10MB shellcode
    if shellcode_hex and len(shellcode_hex) > _MAX_SHELLCODE_HEX:
        raise ValueError(f"shellcode_hex too large ({len(shellcode_hex)} chars). Maximum is {_MAX_SHELLCODE_HEX}.")
    if os_type not in _VALID_OS_TYPES:
        raise ValueError(f"Invalid os_type '{os_type}'. Must be one of: {', '.join(sorted(_VALID_OS_TYPES))}")
    if architecture not in _VALID_ARCHITECTURES:
        raise ValueError(f"Invalid architecture '{architecture}'. Must be one of: {', '.join(sorted(_VALID_ARCHITECTURES))}")

    progress_task = asyncio.create_task(
        _subprocess_progress_reporter(ctx, "emulate_shellcode_with_qiling", timeout_seconds))
    try:
        result = await _run_qiling({
            "action": "emulate_shellcode",
            "filepath": state.filepath,
            "shellcode_hex": shellcode_hex,
            "os_type": os_type,
            "architecture": architecture,
            "rootfs_path": _rootfs_path(),
            "timeout_seconds": timeout_seconds,
            "max_instructions": max_instructions,
            "limit": limit,
        }, timeout_seconds)
    finally:
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "emulate_shellcode_with_qiling", "the 'limit' parameter")


# ===================================================================
#  Tool 3: qiling_trace_execution
# ===================================================================

@tool_decorator
async def qiling_trace_execution(
    ctx: Context,
    start_address: Optional[str] = None,
    end_address: Optional[str] = None,
    max_instructions: int = 1000,
    timeout_seconds: int = 30,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Traces execution of the loaded binary at the instruction level using Qiling.
    Returns an instruction trace with addresses, sizes, and raw bytes for each
    executed instruction.  Complements angr's static CFG with actual dynamic
    execution paths.

    ---compact: instruction-level execution trace | dynamic path coverage | needs: qiling, file

    Rootfs requirements: Same as emulate_binary_with_qiling.  Linux ELF works
    out of the box.  Windows PE requires real DLLs in the rootfs — copy them
    from a Windows installation into qiling-rootfs/<arch>_windows/Windows/System32/.

    Args:
        start_address: Hex address to begin tracing from (default: entry point).
        end_address: Hex address to stop tracing at (optional).
        max_instructions: Maximum instructions to trace (default 1000).
        timeout_seconds: Max emulation time in seconds.
        limit: Max instruction entries to return.
    """
    await ctx.info("Tracing execution with Qiling")
    _check_qiling("qiling_trace_execution")
    _check_pe_loaded("qiling_trace_execution")
    _validate_max_instructions(max_instructions)
    _validate_timeout(timeout_seconds)

    progress_task = asyncio.create_task(
        _subprocess_progress_reporter(ctx, "qiling_trace_execution", timeout_seconds))
    try:
        result = await _run_qiling({
            "action": "trace_execution",
            "filepath": state.filepath,
            "rootfs_path": _rootfs_path(),
            "start_address": start_address,
            "end_address": end_address,
            "max_instructions": max_instructions,
            "timeout_seconds": timeout_seconds,
            "limit": limit,
        }, timeout_seconds)
    finally:
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "qiling_trace_execution", "the 'limit' parameter")


# ===================================================================
#  Tool 4: qiling_hook_api_calls
# ===================================================================

@tool_decorator
async def qiling_hook_api_calls(
    ctx: Context,
    target_apis: Optional[List[str]] = None,
    timeout_seconds: int = 60,
    max_instructions: int = 0,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    Runs the loaded binary under Qiling and hooks specific API/syscall calls
    to capture arguments and return values.  More targeted than full emulation
    — specify exactly which APIs you're interested in for faster, less noisy output.

    ---compact: hook specific APIs during emulation | capture args + return values | needs: qiling, file

    If no target_apis are specified, hooks ALL API calls (equivalent to
    emulate_binary_with_qiling but with more detailed argument capture).

    Rootfs requirements: Same as emulate_binary_with_qiling.  Linux ELF works
    out of the box.  Windows PE requires real DLLs — without them, API hooking
    cannot function because Qiling cannot resolve import tables.  Copy DLLs
    from a Windows installation into qiling-rootfs/<arch>_windows/Windows/System32/.

    Args:
        target_apis: List of API names to hook (e.g. ['CreateFileW', 'VirtualAlloc', 'connect']).
                     If None/empty, hooks all API calls.
        timeout_seconds: Max emulation time in seconds.
        max_instructions: Max CPU instructions to emulate (0 = unlimited).
        limit: Max captured calls to return.
    """
    apis_desc = ", ".join(target_apis[:5]) if target_apis else "all APIs"
    await ctx.info(f"Hooking API calls with Qiling: {apis_desc}")
    _check_qiling("qiling_hook_api_calls")
    _check_pe_loaded("qiling_hook_api_calls")
    _validate_max_instructions(max_instructions)
    _validate_timeout(timeout_seconds)

    progress_task = asyncio.create_task(
        _subprocess_progress_reporter(ctx, "qiling_hook_api_calls", timeout_seconds))
    try:
        result = await _run_qiling({
            "action": "hook_api_calls",
            "filepath": state.filepath,
            "rootfs_path": _rootfs_path(),
            "target_apis": target_apis or [],
            "timeout_seconds": timeout_seconds,
            "max_instructions": max_instructions,
            "limit": limit,
        }, timeout_seconds)
    finally:
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "qiling_hook_api_calls", "the 'limit' parameter")


# ===================================================================
#  Tool 5: qiling_dump_unpacked_binary
# ===================================================================

@tool_decorator
async def qiling_dump_unpacked_binary(
    ctx: Context,
    output_path: Optional[str] = None,
    dump_address: Optional[str] = None,
    dump_size: Optional[int] = None,
    timeout_seconds: int = 120,
    max_instructions: int = 0,
    smart_unpack: bool = True,
) -> Dict[str, Any]:
    """
    Dynamically unpacks the loaded binary by emulating it with Qiling until it
    self-unpacks, then dumps the process memory.  Handles custom/unknown packers
    that unipacker's YARA-based approach cannot identify.

    ---compact: dynamic unpack via emulation + memory dump | smart VirtualAlloc tracking | needs: qiling, PE

    If dump_address is specified, Qiling will stop emulation when that address is
    reached (e.g., the Original Entry Point) and dump from that address.  Otherwise,
    when smart_unpack is True (default), it hooks VirtualAlloc/VirtualAllocEx to
    track memory allocations during emulation, then scans tracked regions for PE
    headers (MZ + PE signature) and dumps the best candidate.  This is much more
    reliable than the fallback of dumping the largest mapped region, especially
    for packers that allocate+decrypt+execute in heap memory (e.g. TA505).

    Falls back to dumping the largest mapped region if smart_unpack finds no PE
    headers, or if smart_unpack is disabled.

    Rootfs requirements: Same as emulate_binary_with_qiling.  Windows PE unpacking
    requires real DLLs in the rootfs because most packers call Windows APIs
    (VirtualAlloc, VirtualProtect, LoadLibrary) during unpacking.  Copy DLLs
    from a Windows installation into qiling-rootfs/<arch>_windows/Windows/System32/.

    Args:
        output_path: Where to save the unpacked binary. Default: <original>_qiling_unpacked.exe.
        dump_address: Hex address to stop at and dump from (e.g., OEP). Optional.
        dump_size: Number of bytes to dump from dump_address. Required if dump_address is set.
        timeout_seconds: Max emulation time in seconds.
        max_instructions: Max CPU instructions to emulate (0 = unlimited).
        smart_unpack: If True (default), hooks VirtualAlloc to track allocations
            and scans for PE headers in allocated regions after emulation. More
            reliable than the largest-region fallback for most packers.
    """
    await ctx.info("Dynamically unpacking with Qiling")
    _check_qiling("qiling_dump_unpacked_binary")
    _check_pe_loaded("qiling_dump_unpacked_binary")
    _validate_max_instructions(max_instructions)
    _validate_timeout(timeout_seconds)

    if not output_path:
        base, ext = os.path.splitext(state.filepath)
        output_path = f"{base}_qiling_unpacked{ext}"

    # Validate output path against sandbox
    state.check_path_allowed(os.path.realpath(output_path))

    progress_task = asyncio.create_task(
        _subprocess_progress_reporter(ctx, "qiling_dump_unpacked_binary", timeout_seconds))
    try:
        result = await _run_qiling({
            "action": "dump_unpacked",
            "filepath": state.filepath,
            "rootfs_path": _rootfs_path(),
            "output_path": output_path,
            "dump_address": dump_address,
            "dump_size": dump_size,
            "timeout_seconds": timeout_seconds,
            "max_instructions": max_instructions,
            "smart_unpack": smart_unpack,
        }, timeout_seconds)
    finally:
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
    await ctx.report_progress(100, 100)

    if result.get("status") == "success":
        result["hint"] = "Use open_file() to load the unpacked binary for further analysis."

    return await _check_mcp_response_size(ctx, result, "qiling_dump_unpacked_binary")


# ===================================================================
#  Tool 6: qiling_resolve_api_hashes
# ===================================================================

@tool_decorator
async def qiling_resolve_api_hashes(
    ctx: Context,
    hash_values: List[str] = None,
    hash_algorithm: str = "ror13",
    seed: Optional[int] = None,
    case_handling: Optional[str] = None,
    family_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Resolves API hash values by computing hashes of known DLL export function
    names and matching them against the provided hash values.  Commonly used for
    analyzing shellcode and malware that dynamically resolves APIs via hashing.

    ---compact: resolve API hashes to function names | ror13, crc32, djb2, fnv1a, auto | needs: qiling

    Supports multiple hash algorithms commonly found in malware:
    - auto: Try ALL algorithms and return any matches (best when algorithm is unknown)
    - ror13: Rotate-right-13 (most common in shellcode)
    - crc32: CRC32 hash
    - djb2: DJB2 hash (Daniel J. Bernstein)
    - fnv1a: FNV-1a 32-bit hash

    Uses Qiling rootfs DLLs when available for comprehensive resolution. Falls
    back to the bundled API name database (~800 curated + ~10K extended names)
    when rootfs DLLs are absent.

    Args:
        hash_values: List of hash values to resolve (hex strings, e.g. ['0x6A4ABC5B']).
        hash_algorithm: Hash algorithm to use ('auto', 'ror13', 'crc32', 'djb2', 'fnv1a').
            'auto' tries all algorithms and returns the best matches.
        seed: Custom seed/initial value for the hash algorithm. None uses standard
            default (e.g. 5381 for djb2). Use for malware variants with modified seeds.
        case_handling: Transform API names before hashing: 'lower', 'upper', or None.
        family_hint: Malware family name. Reads algorithm, seed, and case from the
            malware_signatures.yaml knowledge base automatically.
    """
    if hash_values is None:
        hash_values = []
    _MAX_HASH_VALUES = 1000
    if len(hash_values) > _MAX_HASH_VALUES:
        raise ValueError(f"Too many hash_values ({len(hash_values)}). Maximum is {_MAX_HASH_VALUES}.")

    # Apply family_hint overrides from KB
    if family_hint:
        try:
            from arkana.mcp.tools_malware_identify import _get_families
            for fam in _get_families():
                if fam.get("family", "").lower() == family_hint.lower():
                    api_hash_meta = fam.get("api_hash") or {}
                    if isinstance(api_hash_meta, dict):
                        kb_algo = api_hash_meta.get("algorithm", "").replace("_modified", "")
                        if kb_algo and hash_algorithm == "ror13":
                            hash_algorithm = kb_algo
                        if seed is None and "seed" in api_hash_meta:
                            seed = api_hash_meta["seed"]
                        if case_handling is None:
                            cs = api_hash_meta.get("case_sensitive", True)
                            if not cs:
                                case_handling = "lower"
                    break
        except Exception:
            logger.debug("qiling_resolve_api_hashes: KB lookup failed for '%s'",
                         family_hint, exc_info=True)

    if not hash_values:
        return {"error": "No hash values provided. Pass a list of hex hash values to resolve."}

    # --- Auto mode: try all algorithms using bundled DB (no subprocess needed) ---
    if hash_algorithm == "auto":
        from arkana.mcp._helpers_api_hashes import (
            get_all_api_names, build_hash_lookup, HASH_ALGORITHMS, DEFAULT_SEEDS,
        )
        await ctx.info(f"Auto-resolving {len(hash_values)} hashes — trying all {len(HASH_ALGORITHMS)} algorithms...")
        api_names = get_all_api_names(include_extended=True)

        target_hashes = set()
        for hv in hash_values:
            target_hashes.add(int(hv, 0) if isinstance(hv, str) else int(hv))

        all_resolved = []
        resolved_set = set()  # Track which hashes have been resolved
        for algo_name in HASH_ALGORITHMS:
            algo_seed = seed if seed is not None else DEFAULT_SEEDS.get(algo_name)
            for ch in (case_handling, None) if case_handling else (None, "lower"):
                lookup = build_hash_lookup(api_names, algo_name,
                                           seed=algo_seed, case_handling=ch)
                for h in target_hashes:
                    if h in lookup and h not in resolved_set:
                        all_resolved.append({
                            "hash_value": hex(h),
                            "function": lookup[h],
                            "algorithm": algo_name,
                            "seed": algo_seed,
                            "case_handling": ch,
                            "source": "bundled_db_auto",
                        })
                        resolved_set.add(h)

        unresolved = [hex(h) for h in target_hashes if h not in resolved_set]
        result = {
            "status": "completed",
            "hash_algorithm": "auto",
            "algorithms_tried": list(HASH_ALGORITHMS.keys()),
            "total_input": len(target_hashes),
            "total_resolved": len(all_resolved),
            "total_unresolved": len(unresolved),
            "resolved": all_resolved,
            "unresolved": unresolved,
        }
        await ctx.report_progress(100, 100)
        return await _check_mcp_response_size(ctx, result, "qiling_resolve_api_hashes")

    # --- Single algorithm mode (original flow) ---
    await ctx.info(f"Resolving {len(hash_values)} API hashes ({hash_algorithm}"
                   f"{f', seed={seed}' if seed is not None else ''})")
    _check_qiling("qiling_resolve_api_hashes")

    # Build the IPC command with optional seed/case
    ipc_cmd = {
        "action": "resolve_api_hashes",
        "filepath": state.filepath or "",
        "rootfs_path": _rootfs_path(),
        "hash_values": hash_values,
        "hash_algorithm": hash_algorithm,
    }
    if seed is not None:
        ipc_cmd["hash_seed"] = seed
    if case_handling:
        ipc_cmd["case_handling"] = case_handling

    progress_task = asyncio.create_task(
        _subprocess_progress_reporter(ctx, "qiling_resolve_api_hashes", 60))
    try:
        result = await _run_qiling(ipc_cmd, 60)
    finally:
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass

    # Fallback: if Qiling resolved nothing (missing rootfs), use bundled DB
    qiling_resolved = result.get("total_resolved", 0) if isinstance(result, dict) else 0
    used_fallback = False
    if qiling_resolved == 0 and isinstance(result, dict):
        try:
            from arkana.mcp._helpers_api_hashes import (
                get_all_api_names, build_hash_lookup,
            )
            await ctx.info("No rootfs DLLs — falling back to bundled API database")
            api_names = get_all_api_names(include_extended=True)
            lookup = build_hash_lookup(api_names, hash_algorithm,
                                       seed=seed, case_handling=case_handling)

            target_hashes = set()
            for hv in hash_values:
                target_hashes.add(int(hv, 0) if isinstance(hv, str) else int(hv))

            fallback_resolved = []
            for h in target_hashes:
                if h in lookup:
                    fallback_resolved.append({
                        "hash_value": hex(h),
                        "dll": "unknown",
                        "function": lookup[h],
                        "name_form": lookup[h],
                        "source": "bundled_db",
                    })

            unresolved = [hex(h) for h in target_hashes
                          if h not in {int(r["hash_value"], 16) for r in fallback_resolved}]
            result = {
                "status": "completed",
                "hash_algorithm": hash_algorithm,
                "seed": seed,
                "source": "bundled_api_db (rootfs DLLs not found)",
                "total_input": len(target_hashes),
                "total_resolved": len(fallback_resolved),
                "total_unresolved": len(unresolved),
                "resolved": fallback_resolved,
                "unresolved": unresolved,
            }
            used_fallback = True
        except Exception:
            logger.debug("qiling_resolve_api_hashes: bundled DB fallback failed", exc_info=True)

    if isinstance(result, dict) and not used_fallback:
        if seed is not None:
            result["seed"] = seed
        if case_handling:
            result["case_handling"] = case_handling
    if family_hint and isinstance(result, dict):
        result["family_hint"] = family_hint

    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "qiling_resolve_api_hashes")


# ===================================================================
#  Tool 7: qiling_memory_search
# ===================================================================

@tool_decorator
async def qiling_memory_search(
    ctx: Context,
    search_patterns: Optional[List[str]] = None,
    search_hex: Optional[str] = None,
    max_instructions: int = 500000,
    timeout_seconds: int = 60,
    context_bytes: int = 32,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    Runs the loaded binary under Qiling for a specified number of instructions,
    then searches all process memory for string patterns or hex byte sequences.

    ---compact: emulate then search memory for strings/hex | find decrypted configs | needs: qiling, file

    Useful for finding decrypted configuration blobs, C2 URLs, encryption keys,
    or other data that only appears in memory after the binary has run and
    unpacked/decrypted itself.

    Rootfs requirements: Same as emulate_binary_with_qiling.  The binary must
    actually run for memory search to find anything useful — Windows PE files
    need real DLLs in the rootfs to execute beyond the first few instructions.
    Copy DLLs from a Windows installation into
    qiling-rootfs/<arch>_windows/Windows/System32/.

    Args:
        search_patterns: List of string patterns to search for (e.g. ['http://', 'cmd.exe']).
                         Both ASCII and UTF-16LE encodings are searched automatically.
        search_hex: Hex byte pattern to search for (e.g. 'deadbeef').
        max_instructions: Instructions to execute before searching (default 500000).
        timeout_seconds: Max emulation time in seconds.
        context_bytes: Bytes of context to include around each match.
        limit: Max matches to return.
    """
    await ctx.info("Running binary and searching memory with Qiling")
    _check_qiling("qiling_memory_search")
    _check_pe_loaded("qiling_memory_search")
    _validate_max_instructions(max_instructions)
    _validate_timeout(timeout_seconds)

    if context_bytes < 0 or context_bytes > 1_000_000:
        raise ValueError(f"context_bytes must be 0-1000000, got {context_bytes}")

    if not search_patterns and not search_hex:
        return {"error": "No search criteria provided. Specify search_patterns (strings) and/or search_hex (bytes)."}

    progress_task = asyncio.create_task(
        _subprocess_progress_reporter(ctx, "qiling_memory_search", timeout_seconds))
    try:
        result = await _run_qiling({
            "action": "memory_search",
            "filepath": state.filepath,
            "rootfs_path": _rootfs_path(),
            "search_patterns": search_patterns or [],
            "search_hex": search_hex,
            "max_instructions": max_instructions,
            "timeout_seconds": timeout_seconds,
            "context_bytes": context_bytes,
            "limit": limit,
        }, timeout_seconds)
    finally:
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "qiling_memory_search", "the 'limit' parameter")


# ===================================================================
#  Tool 8: qiling_setup_check
# ===================================================================

@tool_decorator
async def qiling_setup_check(
    ctx: Context,
) -> Dict[str, Any]:
    """
    [Phase: utility] Checks the Qiling Framework setup status: venv availability,
    rootfs directory structure, and essential DLLs for each architecture.

    ---compact: verify qiling venv + rootfs + DLL setup | diagnose emulation failures

    When to use: When Qiling emulation fails or before first use to verify the
    environment is properly configured. Provides specific copy commands for
    missing DLLs.

    Args:
        ctx: The MCP Context object.
    """
    await ctx.info("Checking Qiling setup status")

    result: Dict[str, Any] = {}

    # Check venv
    venv_available = _check_qiling_available()
    result["venv_available"] = venv_available
    result["venv_python"] = str(_QILING_VENV_PYTHON)
    result["runner_script"] = str(_QILING_RUNNER)

    if not venv_available:
        result["error"] = (
            "Qiling venv is not set up. The Docker image includes it by default. "
            "If running locally, create a venv at /app/qiling-venv with: "
            "python3 -m venv /app/qiling-venv && "
            "/app/qiling-venv/bin/pip install qiling 'unicorn<2'"
        )
        return result

    # Check rootfs
    rootfs = str(_QILING_DEFAULT_ROOTFS)
    result["rootfs_path"] = rootfs
    result["rootfs_exists"] = os.path.isdir(rootfs)

    if not os.path.isdir(rootfs):
        result["error"] = f"Rootfs directory not found at {rootfs}. Create it or set QILING_ROOTFS env var."
        return result

    # Check each architecture directory
    arch_status = {}
    for arch_key, rel_path in _ROOTFS_ARCH_DIRS.items():
        arch_dir = os.path.join(rootfs, rel_path)
        exists = os.path.isdir(arch_dir)
        entry: Dict[str, Any] = {"path": arch_dir, "exists": exists}

        if exists and arch_key in _ESSENTIAL_DLLS:
            present = []
            missing = []
            for dll in _ESSENTIAL_DLLS[arch_key]:
                dll_path = os.path.join(arch_dir, dll)
                if os.path.isfile(dll_path):
                    present.append(dll)
                else:
                    missing.append(dll)
            entry["present_dlls"] = present
            entry["missing_dlls"] = missing
            if missing:
                # Generate copy commands
                if "x86" in arch_key and "64" not in arch_key:
                    src_dir = r"C:\Windows\SysWOW64"
                else:
                    src_dir = r"C:\Windows\System32"
                entry["fix_command"] = (
                    f"Copy from a Windows machine: "
                    f"cp {src_dir}\\{{{','.join(missing)}}} → {arch_dir}/"
                )

        arch_status[arch_key] = entry

    result["architectures"] = arch_status

    # Determine loaded binary's architecture needs
    if state.pe_data:
        mode = state.pe_data.get("mode", "").lower()
        if "pe32+" in mode or "pe64" in mode or "x64" in mode:
            result["loaded_binary_arch"] = "x8664_windows"
        elif "pe32" in mode or "pe" in mode:
            result["loaded_binary_arch"] = "x86_windows"
        elif "elf64" in mode:
            result["loaded_binary_arch"] = "x8664_linux"
        elif "elf" in mode:
            result["loaded_binary_arch"] = "x86_linux"

        needed_arch = result.get("loaded_binary_arch")
        if needed_arch and needed_arch in arch_status:
            arch_info = arch_status[needed_arch]
            if not arch_info["exists"]:
                result["warning"] = f"Directory for {needed_arch} does not exist. Emulation will fail."
            elif arch_info.get("missing_dlls"):
                result["warning"] = (
                    f"Missing essential DLLs for {needed_arch}: "
                    f"{', '.join(arch_info['missing_dlls'])}. "
                    "Emulation may fail or produce incomplete results."
                )

    return result
