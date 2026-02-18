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

from pemcp.config import (
    state, logger, Context,
    _QILING_VENV_PYTHON, _QILING_RUNNER, _QILING_DEFAULT_ROOTFS,
    _check_qiling_available,
)
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size


# ---------------------------------------------------------------------------
#  Subprocess helper (mirrors _run_speakeasy / _run_unipacker pattern)
# ---------------------------------------------------------------------------

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
        return json.loads(stdout.decode())
    except json.JSONDecodeError:
        return {"error": f"Invalid JSON from Qiling runner: {stdout.decode(errors='replace')[:500]}"}


def _check_qiling(tool_name: str):
    """Validate that Qiling is available, raising RuntimeError if not."""
    if not _check_qiling_available():
        raise RuntimeError(
            f"[{tool_name}] Qiling Framework is not available. "
            "It requires the Qiling venv (/app/qiling-venv) to be set up. "
            "This is included in the Docker image."
        )


def _rootfs_path() -> str:
    """Return the default rootfs path."""
    return str(_QILING_DEFAULT_ROOTFS)


# ===================================================================
#  Tool 1: emulate_binary_with_qiling
# ===================================================================

@tool_decorator
async def emulate_binary_with_qiling(
    ctx: Context,
    timeout_seconds: int = 60,
    max_instructions: int = 0,
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Emulates the loaded binary (PE, ELF, or Mach-O) using the Qiling Framework
    with full OS emulation.  Returns a behavioral report: API/syscall calls,
    file activity, registry activity, and network activity.

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

    If emulation fails with "rootfs not found" or "DLL not found", use
    download_qiling_rootfs first, then provide Windows DLLs as described above.

    Args:
        timeout_seconds: Max emulation time in seconds (default 60).
        max_instructions: Max CPU instructions to emulate (0 = unlimited, use timeout only).
        limit: Max entries per activity category to return.
    """
    await ctx.info("Emulating binary with Qiling Framework")
    _check_qiling("emulate_binary_with_qiling")
    _check_pe_loaded("emulate_binary_with_qiling")

    result = await _run_qiling({
        "action": "emulate_binary",
        "filepath": state.filepath,
        "rootfs_path": _rootfs_path(),
        "timeout_seconds": timeout_seconds,
        "max_instructions": max_instructions,
        "limit": limit,
    }, timeout_seconds)
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
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Emulates shellcode using the Qiling Framework with multi-architecture support.
    Supports x86, x86_64, ARM, ARM64, and MIPS — far broader than Speakeasy's
    x86/x64-only shellcode emulation.

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
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Traces execution of the loaded binary at the instruction level using Qiling.
    Returns an instruction trace with addresses, sizes, and raw bytes for each
    executed instruction.  Complements angr's static CFG with actual dynamic
    execution paths.

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
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Runs the loaded binary under Qiling and hooks specific API/syscall calls
    to capture arguments and return values.  More targeted than full emulation
    — specify exactly which APIs you're interested in for faster, less noisy output.

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

    result = await _run_qiling({
        "action": "hook_api_calls",
        "filepath": state.filepath,
        "rootfs_path": _rootfs_path(),
        "target_apis": target_apis or [],
        "timeout_seconds": timeout_seconds,
        "max_instructions": max_instructions,
        "limit": limit,
    }, timeout_seconds)
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
) -> Dict[str, Any]:
    """
    Dynamically unpacks the loaded binary by emulating it with Qiling until it
    self-unpacks, then dumps the process memory.  Handles custom/unknown packers
    that unipacker's YARA-based approach cannot identify.

    If dump_address is specified, Qiling will stop emulation when that address is
    reached (e.g., the Original Entry Point) and dump from that address.  Otherwise,
    it runs until timeout and dumps the largest mapped memory region.

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
    """
    await ctx.info("Dynamically unpacking with Qiling")
    _check_qiling("qiling_dump_unpacked_binary")
    _check_pe_loaded("qiling_dump_unpacked_binary")

    if not output_path:
        base, ext = os.path.splitext(state.filepath)
        output_path = f"{base}_qiling_unpacked{ext}"

    # Validate output path against sandbox
    state.check_path_allowed(os.path.abspath(output_path))

    result = await _run_qiling({
        "action": "dump_unpacked",
        "filepath": state.filepath,
        "rootfs_path": _rootfs_path(),
        "output_path": output_path,
        "dump_address": dump_address,
        "dump_size": dump_size,
        "timeout_seconds": timeout_seconds,
        "max_instructions": max_instructions,
    }, timeout_seconds)

    if result.get("status") == "success":
        result["hint"] = "Use open_file() to load the unpacked binary for further analysis."

    return await _check_mcp_response_size(ctx, result, "qiling_dump_unpacked_binary")


# ===================================================================
#  Tool 6: qiling_resolve_api_hashes
# ===================================================================

@tool_decorator
async def qiling_resolve_api_hashes(
    ctx: Context,
    hash_values: List[str] = [],
    hash_algorithm: str = "ror13",
) -> Dict[str, Any]:
    """
    Resolves API hash values by computing hashes of known DLL export function
    names and matching them against the provided hash values.  Commonly used for
    analyzing shellcode and malware that dynamically resolves APIs via hashing.

    Supports multiple hash algorithms commonly found in malware:
    - ror13: Rotate-right-13 (most common in shellcode)
    - crc32: CRC32 hash
    - djb2: DJB2 hash (Daniel J. Bernstein)
    - fnv1a: FNV-1a 32-bit hash

    Rootfs requirements: This tool scans DLL export tables to build a hash lookup
    database.  It REQUIRES real Windows DLL files in the rootfs to work — without
    DLLs there are no exports to hash against and no hashes can be resolved.
    Copy DLLs from C:\\Windows\\System32\\ (64-bit) or C:\\Windows\\SysWOW64\\
    (32-bit) into qiling-rootfs/<arch>_windows/Windows/System32/ on the host.
    The more DLLs you provide, the more hashes can be resolved.

    Args:
        hash_values: List of hash values to resolve (hex strings, e.g. ['0x6A4ABC5B']).
        hash_algorithm: Hash algorithm to use ('ror13', 'crc32', 'djb2', 'fnv1a').
    """
    await ctx.info(f"Resolving {len(hash_values)} API hashes ({hash_algorithm})")
    _check_qiling("qiling_resolve_api_hashes")

    if not hash_values:
        return {"error": "No hash values provided. Pass a list of hex hash values to resolve."}

    result = await _run_qiling({
        "action": "resolve_api_hashes",
        "filepath": state.filepath or "",
        "rootfs_path": _rootfs_path(),
        "hash_values": hash_values,
        "hash_algorithm": hash_algorithm,
    }, 60)
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
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Runs the loaded binary under Qiling for a specified number of instructions,
    then searches all process memory for string patterns or hex byte sequences.

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

    if not search_patterns and not search_hex:
        return {"error": "No search criteria provided. Specify search_patterns (strings) and/or search_hex (bytes)."}

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
    return await _check_mcp_response_size(ctx, result, "qiling_memory_search", "the 'limit' parameter")


# ===================================================================
#  Tool 8: download_qiling_rootfs
# ===================================================================

@tool_decorator
async def download_qiling_rootfs(
    ctx: Context,
    os_type: str = "windows",
    architecture: str = "x86",
) -> Dict[str, Any]:
    """
    Downloads Qiling Framework rootfs files (OS-specific system files and
    directory structure) required for binary emulation.  Downloads from the
    official Qiling GitHub repository.

    The Docker image pre-populates rootfs at build time, but this tool can be
    used to fetch additional OS/architecture combinations on demand.

    IMPORTANT — Windows DLLs are NOT included in the download:
    The Qiling rootfs repository provides directory structure and registry
    stubs, but does NOT include Windows DLL files (ntdll.dll, kernel32.dll,
    etc.) because they cannot be legally redistributed.  After running this
    tool for a Windows target, the user must manually copy DLLs from a real
    Windows installation:

      For 32-bit PE analysis:
        Copy C:\\Windows\\SysWOW64\\*.dll into
        qiling-rootfs/x86_windows/Windows/System32/ on the host
        (SysWOW64 contains the 32-bit DLLs despite the name)

      For 64-bit PE analysis:
        Copy C:\\Windows\\System32\\*.dll into
        qiling-rootfs/x8664_windows/Windows/System32/ on the host

    The qiling-rootfs/ directory next to run.sh or docker-compose.yml is
    automatically mounted into the container.  Alternatively, use --rootfs
    or PEMCP_ROOTFS to specify a custom path.

    Minimum DLLs for basic Windows emulation:
      ntdll.dll, kernel32.dll, user32.dll, advapi32.dll, ws2_32.dll, msvcrt.dll
    More DLLs = better emulation coverage.

    Linux rootfs works immediately — no additional files needed.

    Supported combinations:
    - windows/x86, windows/x8664
    - linux/x86, linux/x8664, linux/arm, linux/arm64, linux/mips
    - macos/x8664

    Args:
        os_type: Target OS ('windows', 'linux', 'macos').
        architecture: Target architecture ('x86', 'x8664', 'arm', 'arm64', 'mips').
    """
    await ctx.info(f"Downloading Qiling rootfs for {os_type}/{architecture}")
    _check_qiling("download_qiling_rootfs")

    result = await _run_qiling({
        "action": "download_rootfs",
        "os_type": os_type,
        "architecture": architecture,
        "output_dir": _rootfs_path(),
    }, 300)  # Download may take a while
    return await _check_mcp_response_size(ctx, result, "download_qiling_rootfs")
