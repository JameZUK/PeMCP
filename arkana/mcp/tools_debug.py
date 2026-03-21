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
import os
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
        self._cmd_lock = asyncio.Lock()

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
        self._lock = asyncio.Lock()
        self._counter = 0

    async def create_session(self, filepath: str, rootfs_path: str = None) -> _DebugSession:
        """Spawn a new debug subprocess and initialise Qiling."""
        async with self._lock:
            if len(self._sessions) >= MAX_DEBUG_SESSIONS:
                # Evict oldest session
                oldest_id = min(self._sessions, key=lambda k: self._sessions[k].last_active)
                old = self._sessions.pop(oldest_id)
                await old.kill()
                logger.debug("Debug session evicted: %s", oldest_id)

            self._counter += 1
            session_id = f"debug-{self._counter}"

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
            }
            result = await session.send_command(init_cmd, timeout=120)

            if "error" in result:
                await session.kill()
                raise RuntimeError(result["error"])

            session.arch = result.get("architecture", "")
            session.os_type = result.get("os_type", "")
            session.pc = result.get("pc")
            session.status = "paused"
            self._sessions[session_id] = session
            return session

    async def destroy_session(self, session_id: str) -> None:
        """Stop and remove a debug session."""
        async with self._lock:
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
        async with self._lock:
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
        for session in self._sessions.values():
            session.kill_sync()
        self._sessions.clear()

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    def list_sessions(self) -> List[Dict[str, Any]]:
        """Return metadata for all active sessions."""
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


def _get_debug_manager() -> _DebugSessionManager:
    """Get or create the debug session manager for the current state."""
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
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Start an interactive debug session for the loaded binary.

    Creates a persistent emulation environment using Qiling Framework.
    The binary is loaded and paused at entry point, ready for stepping.

    Args:
        rootfs_path: Custom rootfs path (optional, uses default if empty)
        session_id: Ignored (auto-generated). Use debug_status to see session IDs.

    Returns:
        Session ID, entry point address, architecture, registers, and first instructions.
    """
    _check_qiling("debug_start")
    _check_pe_loaded("debug_start")

    mgr = _get_debug_manager()
    await ctx.info("Starting debug session...")

    session = await mgr.create_session(
        filepath=state.filepath,
        rootfs_path=rootfs_path or None,
    )

    await ctx.report_progress(100, 100)

    return {
        "session_id": session.session_id,
        "filepath": session.filepath,
        "architecture": session.arch,
        "os_type": session.os_type,
        "pc": session.pc,
        "status": session.status,
        "note": "Debug session started. Binary loaded and paused at entry point. "
                "Use debug_step, debug_continue, debug_set_breakpoint, etc. to control execution.",
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
