"""Interactive emulation debugger — 20 MCP tools for step-through debugging.

Built on top of Qiling Framework via a persistent subprocess (JSONL protocol).
Unlike existing Qiling tools which are fire-and-forget, debug sessions persist
across multiple MCP calls, enabling interactive stepping, breakpoints,
watchpoints, memory inspection, and snapshot-based state exploration.

Architecture:
    MCP Client → tools_debug.py → debug_runner.py (persistent subprocess)
                  (session mgr)    (Qiling + Capstone)
"""
import asyncio
import json
import re
import os
import threading
import time
from typing import Any, Dict, List, Optional

from arkana.config import (
    state, logger, Context,
    _QILING_VENV_PYTHON, _QILING_DEFAULT_ROOTFS, _check_qiling_available,
)
from arkana.imports import _DEBUG_RUNNER
from arkana.constants import (
    MAX_DEBUG_SESSIONS, DEBUG_SESSION_TTL, DEBUG_COMMAND_TIMEOUT,
    MAX_DEBUG_SNAPSHOTS, MAX_DEBUG_INSTRUCTIONS, MAX_DEBUG_MEMORY_READ,
    MAX_DEBUG_BREAKPOINTS, MAX_DEBUG_WATCHPOINTS, MAX_DEBUG_WATCHPOINT_SIZE,
    MAX_DEBUG_CAPTURED_OUTPUT, MAX_DEBUG_PENDING_INPUT, MAX_DEBUG_API_TRACE,
    MAX_DEBUG_SEARCH_MATCHES, MAX_DEBUG_USER_STUBS, MAX_DEBUG_STUB_WRITE_SIZE,
    MAX_DEBUG_STUB_WRITES,
)
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size


# ---------------------------------------------------------------------------
#  Validation helpers
# ---------------------------------------------------------------------------

def _check_qiling(tool_name: str):
    """Validate that Qiling is available, raising RuntimeError if not."""
    if not _check_qiling_available():
        raise RuntimeError(
            f"[{tool_name}] Qiling Framework is not available. "
            "It requires the Qiling venv (/app/qiling-venv) to be set up. "
            "This is included in the Docker image."
        )
    rootfs = str(_QILING_DEFAULT_ROOTFS)
    if not os.path.isdir(rootfs):
        raise RuntimeError(
            f"[{tool_name}] Qiling rootfs directory not found at {rootfs}. "
            "Create it or set QILING_ROOTFS environment variable. "
            "Use qiling_setup_check() to diagnose the issue."
        )


def _validate_address(addr_str: str, param_name: str = "address") -> str:
    """Validate and normalise an address string."""
    if not addr_str or not isinstance(addr_str, str):
        raise ValueError(f"'{param_name}' is required and must be a non-empty string")
    addr_str = addr_str.strip()
    if len(addr_str) > 40:
        raise ValueError(f"'{param_name}' too long (max 40 chars)")
    # Validate parseable
    try:
        if addr_str.startswith(("0x", "0X")):
            int(addr_str, 16)
        else:
            int(addr_str)
    except ValueError:
        raise ValueError(f"Invalid {param_name}: '{addr_str}'. Must be hex (0x...) or decimal.")
    return addr_str


# ---------------------------------------------------------------------------
#  Debug Session
# ---------------------------------------------------------------------------

class _DebugSession:
    """Wraps a single persistent debug subprocess."""

    def __init__(self, session_id: str, proc: asyncio.subprocess.Process,
                 arch: str, os_type: str, filepath: str):
        self.session_id = session_id
        self.proc = proc
        self.arch = arch
        self.os_type = os_type
        self.filepath = filepath
        self.created_at = time.time()
        self.last_active = time.time()
        self.pc: Optional[str] = None
        self.status = "paused"  # paused | running | exited | error
        self.instructions_executed = 0
        self.stub_io = False
        self.crt_stubs = False
        self.api_trace_enabled = False
        self._cmd_lock = asyncio.Lock()
        # Drain stderr in background to prevent pipe deadlock
        self._stderr_task: Optional[asyncio.Task] = None
        try:
            loop = asyncio.get_running_loop()
            self._stderr_task = loop.create_task(self._drain_stderr())
        except RuntimeError:
            pass  # No event loop (e.g. in tests)

    async def _drain_stderr(self) -> None:
        """Read and discard stderr to prevent pipe buffer deadlock."""
        try:
            while True:
                line = await self.proc.stderr.readline()
                if not line:
                    break
                logger.debug("debug_runner stderr: %s", line.decode(errors="replace").rstrip())
        except Exception:
            pass

    async def send_command(self, cmd: dict, timeout: int = DEBUG_COMMAND_TIMEOUT) -> dict:
        """Send JSONL command, read JSONL response."""
        async with self._cmd_lock:
            if self.proc.returncode is not None:
                return {"error": "Debug session has exited unexpectedly"}
            line = json.dumps(cmd) + "\n"
            self.proc.stdin.write(line.encode())
            await self.proc.stdin.drain()
            try:
                resp_line = await asyncio.wait_for(
                    self.proc.stdout.readline(), timeout=timeout
                )
            except asyncio.TimeoutError:
                return {"error": f"Debug command timed out after {timeout}s"}
            if not resp_line:
                return {"error": "Debug subprocess closed unexpectedly"}
            self.last_active = time.time()
            try:
                return json.loads(resp_line.decode())
            except json.JSONDecodeError as e:
                return {"error": f"Invalid JSON response from debug subprocess: {e}"}

    def is_alive(self) -> bool:
        return self.proc.returncode is None

    async def kill(self) -> None:
        if self.is_alive():
            try:
                self.proc.kill()
                await self.proc.wait()
            except Exception:
                pass
        if self._stderr_task and not self._stderr_task.done():
            self._stderr_task.cancel()

    def kill_sync(self) -> None:
        """Synchronous kill for use in reaper thread."""
        if self.is_alive():
            try:
                self.proc.kill()
            except Exception:
                pass


# ---------------------------------------------------------------------------
#  Debug Session Manager
# ---------------------------------------------------------------------------

class _DebugSessionManager:
    """Manages debug subprocess lifecycle for a single AnalyzerState."""

    def __init__(self):
        self._sessions: Dict[str, _DebugSession] = {}
        self._lock = threading.Lock()
        self._counter = 0

    async def create_session(self, filepath: str, rootfs_path: str = None,
                             stub_io: bool = True,
                             stub_crt: bool = True) -> _DebugSession:
        """Spawn a new debug subprocess and initialise Qiling."""
        # Evict oldest session under lock (sync portion only)
        old_to_kill = None
        with self._lock:
            if len(self._sessions) >= MAX_DEBUG_SESSIONS:
                oldest_id = min(self._sessions, key=lambda k: self._sessions[k].last_active)
                old_to_kill = self._sessions.pop(oldest_id)
                logger.debug("Debug session evicted: %s", oldest_id)
            self._counter += 1
            session_id = f"debug-{self._counter}"

        # Kill evicted session outside lock (async)
        if old_to_kill:
            await old_to_kill.kill()

        proc = await asyncio.create_subprocess_exec(
            str(_QILING_VENV_PYTHON), str(_DEBUG_RUNNER),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        session = _DebugSession(session_id, proc, "", "", filepath)

        # Send init command
        init_cmd = {
            "action": "init",
            "filepath": filepath,
            "rootfs_path": rootfs_path or str(_QILING_DEFAULT_ROOTFS),
            "stub_io": stub_io,
            "stub_crt": stub_crt,
        }
        result = await session.send_command(init_cmd, timeout=120)

        if "error" in result:
            await session.kill()
            raise RuntimeError(result["error"])

        session.arch = result.get("architecture", "")
        session.os_type = result.get("os_type", "")
        session.pc = result.get("pc")
        session.stub_io = result.get("stub_io", False)
        session.crt_stubs = result.get("crt_stubs", False)
        session.api_trace_enabled = result.get("api_trace_enabled", False)
        session.status = "paused"

        with self._lock:
            self._sessions[session_id] = session
        return session

    async def destroy_session(self, session_id: str) -> None:
        """Stop and remove a debug session."""
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return
        try:
            await session.send_command({"action": "stop"}, timeout=10)
        except Exception:
            pass
        await session.kill()

    async def get_session(self, session_id: Optional[str] = None) -> _DebugSession:
        """Get a session by ID, or the most recent one if ID is None."""
        with self._lock:
            if not self._sessions:
                raise RuntimeError(
                    "No active debug session. Use debug_start to create one."
                )
            if session_id:
                session = self._sessions.get(session_id)
                if session is None:
                    available = list(self._sessions.keys())
                    raise RuntimeError(
                        f"Debug session '{session_id}' not found. "
                        f"Available sessions: {available}"
                    )
                return session
            # Return most recently active session
            return max(self._sessions.values(), key=lambda s: s.last_active)

    def cleanup_all(self) -> None:
        """Synchronously kill all debug subprocesses. Called by session reaper."""
        with self._lock:
            for session in self._sessions.values():
                session.kill_sync()
            self._sessions.clear()

    @property
    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def list_sessions(self) -> List[Dict[str, Any]]:
        """Return metadata for all active sessions."""
        with self._lock:
            result = []
            for sid, s in self._sessions.items():
                result.append({
                    "session_id": sid,
                    "filepath": s.filepath,
                    "architecture": s.arch,
                    "os_type": s.os_type,
                    "pc": s.pc,
                    "status": s.status,
                    "instructions_executed": s.instructions_executed,
                    "created_at": s.created_at,
                    "last_active": s.last_active,
                    "is_alive": s.is_alive(),
                })
            return result


_debug_manager_lock = threading.Lock()


def _get_debug_manager() -> _DebugSessionManager:
    """Get or create the debug session manager for the current state."""
    with _debug_manager_lock:
        if not hasattr(state, '_debug_manager') or state._debug_manager is None:
            state._debug_manager = _DebugSessionManager()
        return state._debug_manager


def _update_session_from_result(session: _DebugSession, result: dict) -> None:
    """Update session metadata from a command result."""
    if "pc" in result:
        session.pc = result["pc"]
    if "instructions_executed" in result:
        session.instructions_executed = result["instructions_executed"]
    stop_reason = result.get("stop_reason", "")
    if stop_reason in ("exited",):
        session.status = "exited"
    elif "error" in result and "stop_reason" not in result:
        session.status = "error"
    else:
        session.status = "paused"


# ---------------------------------------------------------------------------
#  MCP Tools — Session Lifecycle
# ---------------------------------------------------------------------------

@tool_decorator
async def debug_start(
    ctx: Context,
    rootfs_path: str = "",
    stub_io: bool = True,
    stub_crt: bool = True,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Start an interactive debug session for the loaded binary.

    Creates a persistent emulation environment using Qiling Framework.
    The binary is loaded and paused at entry point, ready for stepping.

    CRT stubs (enabled by default) hook ~47 Windows APIs needed for MSVC CRT
    initialization (GetSystemTimeAsFileTime, GetCurrentProcessId, GetProcessHeap,
    critical sections, TLS/FLS, etc.) to prevent crashes before user code runs.

    I/O stubs (enabled by default) hook Windows console APIs (WriteConsoleA,
    ReadConsoleA, GetStdHandle, etc.) to prevent crashes from printf/cout/cin
    and capture all console output. Use debug_get_output to read captured text
    and debug_set_input to queue input for ReadConsole.

    API call tracing is enabled by default — all Windows API calls are logged
    with arguments and return values. Use debug_get_api_trace to view the trace.

    Use debug_stub_api to add custom stubs for additional APIs at runtime.

    Args:
        rootfs_path: Custom rootfs path (optional, uses default if empty)
        stub_io: Install console I/O stubs to prevent crashes (default True)
        stub_crt: Install CRT initialization stubs to prevent crashes (default True)
        session_id: Ignored (auto-generated). Use debug_status to see session IDs.

    Returns:
        Session ID, entry point address, architecture, registers, and first instructions.
    """
    _check_qiling("debug_start")
    _check_pe_loaded("debug_start")

    # Validate rootfs_path against the path sandbox
    if rootfs_path:
        import os as _os
        resolved_rootfs = _os.path.realpath(rootfs_path)
        if not _os.path.isdir(resolved_rootfs):
            return {"error": f"rootfs_path does not exist or is not a directory: {rootfs_path}"}
        state.check_path_allowed(resolved_rootfs)

    mgr = _get_debug_manager()
    await ctx.info("Starting debug session...")

    session = await mgr.create_session(
        filepath=state.filepath,
        rootfs_path=rootfs_path or None,
        stub_io=stub_io,
        stub_crt=stub_crt,
    )

    await ctx.report_progress(100, 100)

    return {
        "session_id": session.session_id,
        "filepath": session.filepath,
        "architecture": session.arch,
        "os_type": session.os_type,
        "pc": session.pc,
        "status": session.status,
        "stub_io": session.stub_io,
        "crt_stubs": session.crt_stubs,
        "api_trace_enabled": session.api_trace_enabled,
        "note": "Debug session started. Binary loaded and paused at entry point. "
                "Use debug_step, debug_continue, debug_set_breakpoint to control execution. "
                "Use debug_get_output for captured console I/O, debug_get_api_trace for API calls, "
                "debug_search_memory to search emulated memory. "
                "Use debug_stub_api to add custom API stubs at runtime.",
    }


@tool_decorator
async def debug_stop(
    ctx: Context,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Stop and destroy a debug session.

    Cleans up the emulation subprocess and frees resources.

    Args:
        session_id: Session to stop (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)
    sid = session.session_id
    await mgr.destroy_session(sid)

    return {
        "status": "ok",
        "session_id": sid,
        "note": "Debug session stopped and cleaned up.",
    }


@tool_decorator
async def debug_status(
    ctx: Context,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Check the status of debug sessions.

    Args:
        session_id: Specific session to check (lists all if empty)
    """
    mgr = _get_debug_manager()

    if session_id:
        session = await mgr.get_session(session_id)
        return {
            "session_id": session.session_id,
            "filepath": session.filepath,
            "architecture": session.arch,
            "os_type": session.os_type,
            "pc": session.pc,
            "status": session.status,
            "instructions_executed": session.instructions_executed,
            "is_alive": session.is_alive(),
            "created_at": session.created_at,
            "last_active": session.last_active,
            "idle_seconds": int(time.time() - session.last_active),
        }

    sessions = mgr.list_sessions()
    return {
        "total_sessions": len(sessions),
        "max_sessions": MAX_DEBUG_SESSIONS,
        "sessions": sessions,
    }


# ---------------------------------------------------------------------------
#  MCP Tools — Execution Control
# ---------------------------------------------------------------------------

@tool_decorator
async def debug_step(
    ctx: Context,
    count: int = 1,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Execute N instructions (single-step).

    Args:
        count: Number of instructions to execute (1-10000, default 1)
        session_id: Session to step (uses most recent if empty)

    Returns:
        Updated PC, registers, next instructions, and stop reason.
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    count = max(1, min(count, 10000))
    await ctx.info(f"Stepping {count} instruction(s)...")

    result = await session.send_command({"action": "step", "count": count})
    if "error" in result and "stop_reason" not in result:
        return result

    _update_session_from_result(session, result)
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "debug_step")


@tool_decorator
async def debug_step_over(
    ctx: Context,
    max_instructions: int = 1_000_000,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Step over a call instruction.

    If the current instruction is a CALL, sets a temporary breakpoint
    after it and continues. Otherwise, steps 1 instruction.

    Args:
        max_instructions: Safety limit for call execution (default 1M)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    max_instructions = max(1, min(max_instructions, MAX_DEBUG_INSTRUCTIONS))
    await ctx.info("Stepping over...")

    result = await session.send_command({
        "action": "step_over",
        "max_instructions": max_instructions,
    })
    if "error" in result and "stop_reason" not in result:
        return result

    _update_session_from_result(session, result)
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "debug_step_over")


@tool_decorator
async def debug_continue(
    ctx: Context,
    max_instructions: int = 10_000_000,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Continue execution until breakpoint, watchpoint, or limit.

    Args:
        max_instructions: Max instructions before stopping (default 10M)
        session_id: Session to use (uses most recent if empty)

    Returns:
        Stop reason (breakpoint_hit, watchpoint_hit, max_instructions_reached, exited),
        updated registers and PC.
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    max_instructions = max(1, min(max_instructions, MAX_DEBUG_INSTRUCTIONS))
    await ctx.info(f"Continuing execution (limit: {max_instructions:,} instructions)...")

    result = await session.send_command({
        "action": "continue",
        "max_instructions": max_instructions,
    })
    if "error" in result and "stop_reason" not in result:
        return result

    _update_session_from_result(session, result)
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "debug_continue")


@tool_decorator
async def debug_run_until(
    ctx: Context,
    address: str = "",
    max_instructions: int = 10_000_000,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Run until a specific address is reached.

    Sets a temporary breakpoint at the target address and continues.

    Args:
        address: Target address (hex, e.g. "0x401000")
        max_instructions: Safety limit (default 10M)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    address = _validate_address(address, "address")
    max_instructions = max(1, min(max_instructions, MAX_DEBUG_INSTRUCTIONS))
    await ctx.info(f"Running until {address}...")

    result = await session.send_command({
        "action": "run_until",
        "address": address,
        "max_instructions": max_instructions,
    })
    if "error" in result and "stop_reason" not in result:
        return result

    _update_session_from_result(session, result)
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "debug_run_until")


# ---------------------------------------------------------------------------
#  MCP Tools — Breakpoints & Watchpoints
# ---------------------------------------------------------------------------

@tool_decorator
async def debug_set_breakpoint(
    ctx: Context,
    address: str = "",
    api_name: str = "",
    conditions: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Set a breakpoint at an address or API function.

    Supports three types:
    - Address breakpoint: stops when PC reaches the address
    - API breakpoint: stops when a Windows API function is called
    - Conditional: adds register/memory conditions to address/API breakpoints

    Args:
        address: Address to break at (hex, e.g. "0x401000")
        api_name: Windows API name (e.g. "CreateFileA", "VirtualAlloc")
        conditions: JSON array of conditions, e.g. '[{"type":"register","register":"eax","operator":"==","value":"0x1"}]'
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if not address and not api_name:
        return {"error": "Must provide 'address' or 'api_name' for breakpoint"}

    if address:
        address = _validate_address(address, "address")

    if api_name:
        if len(api_name) > 128:
            return {"error": "api_name too long (max 128 chars)"}
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', api_name):
            return {"error": "api_name must be alphanumeric/underscore"}

    parsed_conditions = []
    if conditions:
        try:
            parsed_conditions = json.loads(conditions)
            if not isinstance(parsed_conditions, list):
                return {"error": "'conditions' must be a JSON array"}
        except json.JSONDecodeError as e:
            return {"error": f"Invalid conditions JSON: {e}"}

    cmd = {"action": "set_breakpoint", "conditions": parsed_conditions}
    if address:
        cmd["address"] = address
    if api_name:
        cmd["api_name"] = api_name

    result = await session.send_command(cmd)
    return result


@tool_decorator
async def debug_set_watchpoint(
    ctx: Context,
    address: str = "",
    size: int = 4,
    type: str = "write",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Set a memory watchpoint.

    Stops execution when memory in the watched range is read or written.

    Args:
        address: Start address of watched region (hex)
        size: Size of watched region in bytes (1 to 1MB, default 4)
        type: "read", "write", or "readwrite" (default "write")
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    address = _validate_address(address, "address")
    size = max(1, min(size, MAX_DEBUG_WATCHPOINT_SIZE))
    if type not in ("read", "write", "readwrite"):
        return {"error": f"Invalid watchpoint type: {type}. Must be 'read', 'write', or 'readwrite'"}

    result = await session.send_command({
        "action": "set_watchpoint",
        "address": address,
        "size": size,
        "type": type,
    })
    return result


@tool_decorator
async def debug_remove_breakpoint(
    ctx: Context,
    breakpoint_id: int = 0,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Remove a breakpoint by ID.

    Args:
        breakpoint_id: ID of the breakpoint to remove (from debug_set_breakpoint)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if breakpoint_id <= 0:
        return {"error": "breakpoint_id must be a positive integer"}

    return await session.send_command({
        "action": "remove_breakpoint",
        "breakpoint_id": breakpoint_id,
    })


@tool_decorator
async def debug_remove_watchpoint(
    ctx: Context,
    watchpoint_id: int = 0,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Remove a watchpoint by ID.

    Args:
        watchpoint_id: ID of the watchpoint to remove (from debug_set_watchpoint)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if watchpoint_id <= 0:
        return {"error": "watchpoint_id must be a positive integer"}

    return await session.send_command({
        "action": "remove_watchpoint",
        "watchpoint_id": watchpoint_id,
    })


@tool_decorator
async def debug_list_breakpoints(
    ctx: Context,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] List all breakpoints and watchpoints in a debug session.

    Args:
        session_id: Session to query (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    return await session.send_command({"action": "list_breakpoints"})


# ---------------------------------------------------------------------------
#  MCP Tools — State Inspection / Modification
# ---------------------------------------------------------------------------

@tool_decorator
async def debug_read_state(
    ctx: Context,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Read the full execution state of a debug session.

    Returns registers, program counter, next instructions (disassembled),
    stack top values, memory map summary, and breakpoint/watchpoint counts.

    Args:
        session_id: Session to query (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    result = await session.send_command({"action": "read_state"})
    if "error" not in result:
        _update_session_from_result(session, result)
    return await _check_mcp_response_size(ctx, result, "debug_read_state")


@tool_decorator
async def debug_read_memory(
    ctx: Context,
    address: str = "",
    length: int = 256,
    format: str = "hex",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Read memory at a specific address.

    Args:
        address: Memory address to read from (hex)
        length: Number of bytes to read (1 to 1MB, default 256)
        format: "hex" for raw hex dump, "disasm" for hex + disassembly (default "hex")
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    address = _validate_address(address, "address")
    length = max(1, min(length, MAX_DEBUG_MEMORY_READ))

    result = await session.send_command({
        "action": "read_memory",
        "address": address,
        "length": length,
        "format": format,
    })
    return await _check_mcp_response_size(ctx, result, "debug_read_memory", "the 'length' parameter")


@tool_decorator
async def debug_write_memory(
    ctx: Context,
    address: str = "",
    hex_bytes: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Write bytes to memory at a specific address.

    Args:
        address: Memory address to write to (hex)
        hex_bytes: Hex string of bytes to write (e.g. "90909090" for NOPs)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    address = _validate_address(address, "address")
    if not hex_bytes:
        return {"error": "hex_bytes is required"}
    if len(hex_bytes) > 4_194_304:  # 2MB hex = 1MB data
        return {"error": "hex_bytes too large (max 2MB hex string / 1MB data)"}

    return await session.send_command({
        "action": "write_memory",
        "address": address,
        "hex_bytes": hex_bytes,
    })


@tool_decorator
async def debug_write_register(
    ctx: Context,
    register: str = "",
    value: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Write a value to a CPU register.

    Args:
        register: Register name (e.g. "eax", "rip", "pc")
        value: Value to write (hex or decimal, e.g. "0x401000")
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if not register:
        return {"error": "register name is required"}
    if not value:
        return {"error": "value is required"}

    return await session.send_command({
        "action": "write_register",
        "register": register,
        "value": value,
    })


# ---------------------------------------------------------------------------
#  MCP Tools — Snapshots
# ---------------------------------------------------------------------------

@tool_decorator
async def debug_snapshot_save(
    ctx: Context,
    name: str = "",
    note: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Save a snapshot of the current execution state.

    Snapshots capture all registers, memory, and CPU state. Use them to
    explore alternative execution paths or recover from mistakes.

    Args:
        name: Human-readable snapshot name (optional)
        note: Description of what this snapshot represents (optional)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    result = await session.send_command({
        "action": "snapshot_save",
        "name": name,
        "note": note,
    })

    if "error" not in result:
        total = result.get("total_snapshots", 0)
        if total >= MAX_DEBUG_SNAPSHOTS:
            result["warning"] = (
                f"Snapshot limit ({MAX_DEBUG_SNAPSHOTS}) reached. "
                "Delete old snapshots to free memory."
            )
    return result


@tool_decorator
async def debug_snapshot_restore(
    ctx: Context,
    snapshot_id: int = 0,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Restore execution state from a saved snapshot.

    Restores all registers, memory, and CPU state to the snapshot point.

    Args:
        snapshot_id: ID of the snapshot to restore (from debug_snapshot_save)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if snapshot_id <= 0:
        return {"error": "snapshot_id must be a positive integer"}

    result = await session.send_command({
        "action": "snapshot_restore",
        "snapshot_id": snapshot_id,
    })
    if "error" not in result:
        _update_session_from_result(session, result)
    return await _check_mcp_response_size(ctx, result, "debug_snapshot_restore")


@tool_decorator
async def debug_snapshot_list(
    ctx: Context,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] List all saved snapshots in a debug session.

    Args:
        session_id: Session to query (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    return await session.send_command({"action": "snapshot_list"})


@tool_decorator
async def debug_snapshot_diff(
    ctx: Context,
    snapshot_id_a: int = 0,
    snapshot_id_b: int = 0,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Compare two snapshots to see what changed.

    Shows register differences and memory regions that changed between
    two saved snapshots. Useful for understanding execution effects.

    Args:
        snapshot_id_a: First snapshot ID
        snapshot_id_b: Second snapshot ID
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if snapshot_id_a <= 0 or snapshot_id_b <= 0:
        return {"error": "Both snapshot_id_a and snapshot_id_b must be positive integers"}
    if snapshot_id_a == snapshot_id_b:
        return {"error": "Cannot diff a snapshot with itself"}

    result = await session.send_command({
        "action": "snapshot_diff",
        "snapshot_id_a": snapshot_id_a,
        "snapshot_id_b": snapshot_id_b,
    })
    return await _check_mcp_response_size(ctx, result, "debug_snapshot_diff")


# ---------------------------------------------------------------------------
#  MCP Tools — I/O Stubs
# ---------------------------------------------------------------------------

@tool_decorator
async def debug_set_input(
    ctx: Context,
    data: str = "",
    encoding: str = "utf-8",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Queue input data for stubbed console input (ReadConsoleA).

    When I/O stubs are enabled (stub_io=True on debug_start), ReadConsoleA
    consumes data from this input queue instead of crashing. Queue input
    before stepping through code that reads from stdin/cin/scanf.

    Args:
        data: Input data to queue (string or hex-encoded bytes)
        encoding: "utf-8" (default) or "hex" (hex-encoded bytes)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if not data:
        return {"error": "data is required"}
    if encoding not in ("utf-8", "hex"):
        return {"error": f"Invalid encoding: {encoding}. Must be 'utf-8' or 'hex'"}

    return await session.send_command({
        "action": "set_input",
        "data": data,
        "encoding": encoding,
    })


@tool_decorator
async def debug_get_output(
    ctx: Context,
    clear: bool = False,
    offset: int = 0,
    limit: int = 100,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Retrieve captured console output from I/O stubs.

    When I/O stubs are enabled, all text written via WriteConsoleA/W
    (covering printf, puts, cout, etc.) is captured. This tool returns
    the captured output buffer.

    Args:
        clear: Clear the buffer after reading (default False)
        offset: Start offset for pagination (default 0)
        limit: Max entries to return (1-1000, default 100)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    offset = max(0, offset)
    limit = max(1, min(limit, 1000))

    result = await session.send_command({
        "action": "get_output",
        "offset": offset,
        "limit": limit,
        "clear": clear,
    })
    return await _check_mcp_response_size(ctx, result, "debug_get_output", "'limit' parameter")


# ---------------------------------------------------------------------------
#  MCP Tools — API Call Tracing
# ---------------------------------------------------------------------------

@tool_decorator
async def debug_get_api_trace(
    ctx: Context,
    offset: int = 0,
    limit: int = 100,
    filter: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Retrieve the API call trace log.

    All Windows API calls are logged with function name, arguments, and
    return value. Use this to see what the binary is doing at the API level
    without setting individual breakpoints.

    Args:
        offset: Start offset for pagination (default 0)
        limit: Max entries to return (1-1000, default 100)
        filter: Optional API name filter (case-insensitive substring match)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    offset = max(0, offset)
    limit = max(1, min(limit, 1000))

    cmd = {
        "action": "get_api_trace",
        "offset": offset,
        "limit": limit,
    }
    if filter:
        cmd["filter"] = filter

    result = await session.send_command(cmd)
    return await _check_mcp_response_size(ctx, result, "debug_get_api_trace", "'limit' parameter")


@tool_decorator
async def debug_clear_api_trace(
    ctx: Context,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Clear the API call trace buffer.

    Args:
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    return await session.send_command({"action": "clear_api_trace"})


@tool_decorator
async def debug_set_trace_filter(
    ctx: Context,
    apis: str = "",
    enabled: bool = True,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Configure API trace filtering.

    By default all API calls are traced. Use this to whitelist specific APIs
    or disable/enable tracing entirely.

    Args:
        apis: Comma-separated API names to whitelist (empty = trace all)
        enabled: Enable or disable tracing (default True)
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    cmd: Dict[str, Any] = {
        "action": "set_trace_filter",
        "enabled": enabled,
    }

    if apis:
        api_list = [a.strip() for a in apis.split(",") if a.strip()]
        cmd["apis"] = api_list
    else:
        cmd["apis"] = []  # Empty list = clear filter (trace all)

    return await session.send_command(cmd)


# ---------------------------------------------------------------------------
#  MCP Tools — Memory Search
# ---------------------------------------------------------------------------

@tool_decorator
async def debug_search_memory(
    ctx: Context,
    pattern: str = "",
    pattern_type: str = "string",
    max_matches: int = 100,
    context_bytes: int = 32,
    region_filter: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Search emulated memory for strings or byte patterns.

    Searches across all mapped memory regions. For string patterns, searches
    both UTF-8 and UTF-16LE encodings. For hex patterns, supports ?? wildcards.

    Use cases: finding decrypted strings, config data, C2 URLs, encryption keys
    after stepping through decryption/unpacking routines.

    Args:
        pattern: Search pattern (string text or hex bytes)
        pattern_type: "string" (UTF-8 + UTF-16LE, default) or "hex" (with ?? wildcards)
        max_matches: Maximum matches to return (1-100, default 100)
        context_bytes: Bytes of context around each match (0-256, default 32)
        region_filter: Only search regions whose label contains this substring
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if not pattern:
        return {"error": "pattern is required"}
    if pattern_type not in ("string", "hex"):
        return {"error": f"Invalid pattern_type: {pattern_type}. Must be 'string' or 'hex'"}

    max_matches = max(1, min(max_matches, MAX_DEBUG_SEARCH_MATCHES))
    context_bytes = max(0, min(context_bytes, 256))

    await ctx.info(f"Searching memory for {pattern_type} pattern...")

    cmd: Dict[str, Any] = {
        "action": "search_memory",
        "pattern": pattern,
        "pattern_type": pattern_type,
        "max_matches": max_matches,
        "context_bytes": context_bytes,
    }
    if region_filter:
        cmd["region_filter"] = region_filter

    result = await session.send_command(cmd)
    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "debug_search_memory", "'max_matches' parameter")


# ---------------------------------------------------------------------------
#  MCP Tools — API Stubs
# ---------------------------------------------------------------------------

@tool_decorator
async def debug_stub_api(
    ctx: Context,
    api_name: str = "",
    return_value: str = "0x0",
    num_params: int = 0,
    writes: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Create a custom API stub at runtime.

    When the binary calls the specified Windows API, the stub intercepts it:
    sets the return value, optionally writes data to output pointer parameters,
    and returns cleanly. Useful for stubbing APIs that Qiling doesn't handle.

    CRT stubs (~47 APIs) are installed by default. Use this for additional APIs
    that crash during emulation (e.g. custom DLL imports, rare Win32 APIs).

    Args:
        api_name: Windows API function name (e.g. "GetVersionExW", "CreateMutexA")
        return_value: Return value as hex (e.g. "0x1") or "void" for no return (default "0x0")
        num_params: Number of STDCALL parameters (0-20, for x86 stack cleanup)
        writes: JSON array of pointer writes, e.g. '[{"param_index": 0, "data_hex": "0100", "size": 2}]'
        session_id: Session to use (uses most recent if empty)

    Returns:
        Stub creation result with patching status.
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if not api_name:
        return {"error": "api_name is required"}
    if len(api_name) > 128:
        return {"error": "api_name too long (max 128 chars)"}

    num_params = max(0, min(num_params, 20))

    cmd: Dict[str, Any] = {
        "action": "stub_api",
        "api_name": api_name,
        "return_value": return_value,
        "num_params": num_params,
    }

    if writes:
        try:
            parsed_writes = json.loads(writes)
            if not isinstance(parsed_writes, list):
                return {"error": "'writes' must be a JSON array"}
            if len(parsed_writes) > MAX_DEBUG_STUB_WRITES:
                return {"error": f"Too many write operations (max {MAX_DEBUG_STUB_WRITES})"}
            for i, w in enumerate(parsed_writes):
                if not isinstance(w, dict):
                    return {"error": f"writes[{i}] must be an object"}
                dh = w.get("data_hex", "")
                if dh and len(dh) // 2 > MAX_DEBUG_STUB_WRITE_SIZE:
                    return {"error": f"writes[{i}].data_hex too large (max {MAX_DEBUG_STUB_WRITE_SIZE} bytes)"}
            cmd["writes"] = parsed_writes
        except json.JSONDecodeError as e:
            return {"error": f"Invalid writes JSON: {e}"}

    result = await session.send_command(cmd)
    return result


@tool_decorator
async def debug_list_stubs(
    ctx: Context,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] List all installed API stubs in a debug session.

    Shows three categories: builtin I/O stubs (console APIs), builtin CRT
    stubs (MSVC initialization APIs), and user-defined stubs (created via
    debug_stub_api).

    Args:
        session_id: Session to query (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    result = await session.send_command({"action": "list_stubs"})
    return await _check_mcp_response_size(ctx, result, "debug_list_stubs")


@tool_decorator
async def debug_remove_stub(
    ctx: Context,
    api_name: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Remove a user-defined API stub.

    Only user-defined stubs (created via debug_stub_api) can be removed.
    Builtin I/O and CRT stubs cannot be removed — restart the session
    with stub_io=False or stub_crt=False to disable them.

    Args:
        api_name: Name of the API stub to remove
        session_id: Session to use (uses most recent if empty)
    """
    mgr = _get_debug_manager()
    session = await mgr.get_session(session_id or None)

    if not api_name:
        return {"error": "api_name is required"}

    result = await session.send_command({
        "action": "remove_stub",
        "api_name": api_name,
    })
    return result
