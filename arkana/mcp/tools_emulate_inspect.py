"""Post-emulation memory inspection — persistent Qiling/Speakeasy sessions.

Unlike fire-and-forget emulation tools (emulate_binary_with_qiling, etc.)
which destroy the emulator after returning results, these tools keep the
emulator subprocess alive after run() completes.  This allows unlimited
memory queries (search, read, memory map) on the same emulation state
without re-running the binary.

Architecture:
    MCP Client → tools_emulate_inspect.py → qiling_emulate_runner.py   (Qiling)
                  (session manager)         speakeasy_emulate_runner.py (Speakeasy)

Session lifecycle:
    emulate_and_inspect()      → runs emulation, keeps session alive
    emulation_read_memory()    → reads from the live emulator
    emulation_search_memory()  → searches emulated memory
    emulation_memory_map()     → lists mapped memory regions
    close_emulation_session()  → destroys the session
"""
import asyncio
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional

from arkana.config import (
    state, logger, Context,
    _QILING_VENV_PYTHON, _QILING_DEFAULT_ROOTFS, _check_qiling_available,
    _SPEAKEASY_VENV_PYTHON, _check_speakeasy_available,
    _QILING_EMULATE_RUNNER, _SPEAKEASY_EMULATE_RUNNER,
)
from arkana.constants import (
    MAX_EMULATION_SESSIONS, EMULATION_SESSION_TTL, EMULATION_COMMAND_TIMEOUT,
    EMULATION_RUN_TIMEOUT, MAX_EMULATION_MEMORY_READ, MAX_EMULATION_SEARCH_MATCHES,
    EMULATION_SEARCH_CONTEXT_BYTES,
)
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size


# ---------------------------------------------------------------------------
#  Emulation Session
# ---------------------------------------------------------------------------

class _EmulationSession:
    """Wraps a single persistent emulation subprocess (Qiling or Speakeasy)."""

    def __init__(self, session_id: str, proc: asyncio.subprocess.Process,
                 engine: str, filepath: str):
        self.session_id = session_id
        self.proc = proc
        self.engine = engine  # "qiling" or "speakeasy"
        self.filepath = filepath
        self.created_at = time.time()
        self.last_active = time.time()
        self.status = "initializing"  # initializing | completed | error | exited
        self.emulation_result: Optional[Dict] = None
        self._desynchronised = False
        self._evicted = False
        self._cmd_lock = asyncio.Lock()
        self._stderr_task: Optional[asyncio.Task] = None
        try:
            loop = asyncio.get_running_loop()
            self._stderr_task = loop.create_task(self._drain_stderr())
        except RuntimeError:
            pass

    async def _drain_stderr(self) -> None:
        """Read and discard stderr to prevent pipe buffer deadlock."""
        try:
            while True:
                line = await self.proc.stderr.readline()
                if not line:
                    break
                logger.debug("emulate_runner stderr: %s", line.decode(errors="replace").rstrip())
        except Exception as e:
            logger.debug("emulate_runner stderr drain error: %s", e)

    async def send_command(self, cmd: dict, timeout: int = EMULATION_COMMAND_TIMEOUT) -> dict:
        """Send JSONL command, read JSONL response."""
        async with self._cmd_lock:
            if self._evicted:
                return {"error": "Emulation session was evicted. Use emulate_and_inspect() to create a new one."}
            if self._desynchronised:
                return {"error": "Emulation session is desynchronised — close and recreate it."}
            if self.proc.returncode is not None:
                return {"error": "Emulation subprocess has exited unexpectedly."}

            line = json.dumps(cmd) + "\n"
            self.proc.stdin.write(line.encode())
            await self.proc.stdin.drain()
            try:
                resp_line = await asyncio.wait_for(
                    self.proc.stdout.readline(), timeout=timeout
                )
            except asyncio.TimeoutError:
                self._desynchronised = True
                self.status = "error"
                try:
                    self.proc.kill()
                except Exception:
                    pass
                return {"error": f"Emulation command timed out after {timeout}s — session killed."}
            if not resp_line:
                return {"error": "Emulation subprocess closed unexpectedly."}
            self.last_active = time.time()
            try:
                return json.loads(resp_line.decode())
            except json.JSONDecodeError as e:
                return {"error": f"Invalid JSON response from emulation subprocess: {e}"}

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
            try:
                if self.proc.pid is not None:
                    os.waitpid(self.proc.pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                pass
        if self._stderr_task and not self._stderr_task.done():
            self._stderr_task.cancel()


# ---------------------------------------------------------------------------
#  Emulation Session Manager
# ---------------------------------------------------------------------------

class _EmulationSessionManager:
    """Manages emulation subprocess lifecycle for a single AnalyzerState."""

    def __init__(self):
        self._sessions: Dict[str, _EmulationSession] = {}
        self._lock = threading.Lock()
        self._counter = 0

    async def create_session(self, engine: str, filepath: str,
                             emulate_cmd: dict) -> _EmulationSession:
        """Spawn a persistent runner subprocess and run emulation."""
        # Determine the runner script and Python interpreter
        if engine == "qiling":
            python_path = str(_QILING_VENV_PYTHON)
            runner_path = str(_QILING_EMULATE_RUNNER)
        elif engine == "speakeasy":
            python_path = str(_SPEAKEASY_VENV_PYTHON)
            runner_path = str(_SPEAKEASY_EMULATE_RUNNER)
        else:
            raise ValueError(f"Unknown emulation engine: {engine}")

        # Evict oldest session if at capacity
        old_to_kill = None
        with self._lock:
            if len(self._sessions) >= MAX_EMULATION_SESSIONS:
                oldest_id = min(self._sessions, key=lambda k: self._sessions[k].last_active)
                old_to_kill = self._sessions.pop(oldest_id)
                old_to_kill._evicted = True
                logger.debug("Emulation session evicted: %s", oldest_id)
            self._counter += 1
            session_id = f"emu-{self._counter}"

        if old_to_kill:
            await old_to_kill.kill()

        proc = await asyncio.create_subprocess_exec(
            python_path, runner_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        session = _EmulationSession(session_id, proc, engine, filepath)

        # Send the emulation command — this runs the binary and returns the behavioral report
        try:
            result = await session.send_command(emulate_cmd, timeout=EMULATION_RUN_TIMEOUT + 30)
        except Exception:
            await session.kill()
            raise

        if "error" in result:
            await session.kill()
            raise RuntimeError(result["error"])

        session.emulation_result = result
        session.status = "completed"

        with self._lock:
            self._sessions[session_id] = session
        return session

    async def destroy_session(self, session_id: str) -> None:
        """Stop and remove an emulation session."""
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return
        try:
            await session.send_command({"action": "stop"}, timeout=10)
        except Exception:
            pass
        await session.kill()

    async def get_session(self, session_id: Optional[str] = None) -> _EmulationSession:
        """Get a session by ID, or the most recent one."""
        # Reap expired sessions
        expired = []
        now = time.time()
        with self._lock:
            for sid, sess in list(self._sessions.items()):
                if now - sess.last_active > EMULATION_SESSION_TTL:
                    expired.append(self._sessions.pop(sid))
        for sess in expired:
            sess.kill_sync()
            logger.debug("Emulation session expired (TTL): %s", sess.session_id)

        with self._lock:
            if not self._sessions:
                raise RuntimeError(
                    "No active emulation session. Use emulate_and_inspect() to create one."
                )
            if session_id:
                session = self._sessions.get(session_id)
                if session is None:
                    available = list(self._sessions.keys())
                    raise RuntimeError(
                        f"Emulation session '{session_id}' not found. "
                        f"Available sessions: {available}"
                    )
                return session
            return max(self._sessions.values(), key=lambda s: s.last_active)

    def cleanup_all(self) -> None:
        """Synchronously kill all emulation subprocesses."""
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
                    "engine": s.engine,
                    "filepath": s.filepath,
                    "status": s.status,
                    "created_at": s.created_at,
                    "last_active": s.last_active,
                    "is_alive": s.is_alive(),
                })
            return result


_emulation_manager_lock = threading.Lock()


def _get_emulation_manager() -> _EmulationSessionManager:
    """Get or create the emulation session manager for the current state."""
    with _emulation_manager_lock:
        if not hasattr(state, '_emulation_manager') or state._emulation_manager is None:
            state._emulation_manager = _EmulationSessionManager()
        return state._emulation_manager


# ---------------------------------------------------------------------------
#  MCP Tools — Session Lifecycle
# ---------------------------------------------------------------------------

@tool_decorator
async def emulate_and_inspect(
    ctx: Context,
    engine: str = "qiling",
    file_path: str = "",
    shellcode_hex: str = "",
    architecture: str = "x86",
    os_type: str = "windows",
    rootfs_path: str = "",
    timeout_seconds: int = 60,
    max_instructions: int = 0,
    limit: int = 200,
) -> Dict[str, Any]:
    """[Phase: dynamic] Emulate a binary or shellcode, then keep the session
    alive for post-emulation memory inspection.

    Unlike fire-and-forget tools (emulate_binary_with_qiling, etc.), this tool
    keeps the emulator subprocess alive after run() completes. Use
    emulation_read_memory, emulation_search_memory, and emulation_memory_map
    to inspect the emulated memory. Call close_emulation_session when done.

    Supports both Qiling and Speakeasy engines.

    Args:
        engine: "qiling" or "speakeasy" (default "qiling")
        file_path: Path to binary or shellcode file. For PE files with Speakeasy,
            the file is loaded as a PE module.
        shellcode_hex: Hex-encoded shellcode bytes. If provided, emulates shellcode
            instead of a binary file.
        architecture: "x86" or "x8664" (default "x86"). Used for shellcode.
        os_type: "windows" or "linux" (default "windows"). Qiling only.
        rootfs_path: Custom rootfs path for Qiling (uses default if empty).
        timeout_seconds: Emulation timeout (default 60).
        max_instructions: Max instructions (0 = unlimited).
        limit: Max API calls to return (default 200).

    Returns:
        Emulation results (API calls, activity) plus session_id for memory queries.
    """
    if engine == "qiling":
        _check_qiling_available()
    elif engine == "speakeasy":
        _check_speakeasy_available()
    else:
        return {"error": f"Unknown engine: {engine}. Use 'qiling' or 'speakeasy'."}

    mgr = _get_emulation_manager()

    # Build the emulation command for the runner
    if shellcode_hex or (not file_path and not shellcode_hex):
        if not shellcode_hex:
            # Use loaded file as shellcode
            _check_pe_loaded(ctx, "emulate_and_inspect")
            file_path = state.filepath

        if engine == "qiling":
            emulate_cmd = {
                "action": "emulate_shellcode",
                "shellcode_hex": shellcode_hex if shellcode_hex else None,
                "filepath": file_path if not shellcode_hex else None,
                "os_type": os_type,
                "architecture": architecture,
                "rootfs_path": rootfs_path or str(_QILING_DEFAULT_ROOTFS),
                "timeout_seconds": timeout_seconds,
                "max_instructions": max_instructions,
                "limit": limit,
            }
        else:
            emulate_cmd = {
                "action": "emulate_shellcode",
                "shellcode_hex": shellcode_hex if shellcode_hex else None,
                "filepath": file_path if not shellcode_hex else None,
                "architecture": architecture,
                "timeout_seconds": timeout_seconds,
                "limit": limit,
            }
    else:
        if engine == "qiling":
            emulate_cmd = {
                "action": "emulate_binary",
                "filepath": file_path,
                "rootfs_path": rootfs_path or str(_QILING_DEFAULT_ROOTFS),
                "timeout_seconds": timeout_seconds,
                "max_instructions": max_instructions,
                "limit": limit,
            }
        else:
            emulate_cmd = {
                "action": "emulate_pe",
                "filepath": file_path,
                "timeout_seconds": timeout_seconds,
                "limit": limit,
            }

    await ctx.info(f"Starting {engine} emulation (timeout: {timeout_seconds}s)...")

    try:
        session = await mgr.create_session(engine, file_path or "shellcode", emulate_cmd)
    except RuntimeError as e:
        return {"error": str(e)}

    result = session.emulation_result or {}
    result["session_id"] = session.session_id
    result["engine"] = engine

    await ctx.report_progress(100, 100)
    return await _check_mcp_response_size(ctx, result, "emulate_and_inspect")


@tool_decorator
async def emulation_session_status(
    ctx: Context,
) -> Dict[str, Any]:
    """[Phase: utility] List all active emulation inspect sessions.

    Returns metadata for all sessions: ID, engine, filepath, status, timing.
    """
    mgr = _get_emulation_manager()
    sessions = mgr.list_sessions()
    return {
        "total_sessions": len(sessions),
        "max_sessions": MAX_EMULATION_SESSIONS,
        "sessions": sessions,
    }


@tool_decorator
async def close_emulation_session(
    ctx: Context,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: utility] Close an emulation inspect session and release resources.

    Args:
        session_id: Session to close (uses most recent if empty).
    """
    mgr = _get_emulation_manager()
    session = await mgr.get_session(session_id or None)
    sid = session.session_id
    await mgr.destroy_session(sid)
    return {"status": "ok", "session_id": sid, "message": f"Emulation session {sid} closed."}


# ---------------------------------------------------------------------------
#  MCP Tools — Memory Inspection
# ---------------------------------------------------------------------------

@tool_decorator
async def emulation_read_memory(
    ctx: Context,
    address: str = "",
    length: int = 256,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Read memory from a completed emulation session.

    Reads raw bytes at a virtual address in the emulated process. The emulator
    must have been started with emulate_and_inspect().

    Args:
        address: Memory address to read (hex, e.g. "0x401000").
        length: Number of bytes to read (1 to 1MB, default 256).
        session_id: Session to query (uses most recent if empty).

    Returns:
        Hex dump and ASCII representation of the memory region.
    """
    mgr = _get_emulation_manager()
    session = await mgr.get_session(session_id or None)

    if not address:
        return {"error": "'address' is required."}
    length = max(1, min(length, MAX_EMULATION_MEMORY_READ))

    result = await session.send_command({
        "action": "read_memory",
        "address": address,
        "length": length,
    })
    if "error" in result:
        return result

    result["session_id"] = session.session_id
    return await _check_mcp_response_size(ctx, result, "emulation_read_memory")


@tool_decorator
async def emulation_search_memory(
    ctx: Context,
    search_patterns: Optional[List[str]] = None,
    search_hex: str = "",
    context_bytes: int = 32,
    limit: int = 50,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Search emulated memory for strings or hex patterns.

    Searches all mapped memory regions in the emulated process. For string
    patterns, searches both UTF-8 and UTF-16LE encodings. The emulator must
    have been started with emulate_and_inspect().

    Args:
        search_patterns: List of string patterns to search for.
        search_hex: Hex byte pattern to search for (e.g. "4D5A9000").
        context_bytes: Bytes of context around each match (0-256, default 32).
        limit: Max matches to return (default 50).
        session_id: Session to query (uses most recent if empty).

    Returns:
        List of matches with addresses, types, context hex, and region info.
    """
    mgr = _get_emulation_manager()
    session = await mgr.get_session(session_id or None)

    context_bytes = max(0, min(context_bytes, 256))
    limit = max(1, min(limit, MAX_EMULATION_SEARCH_MATCHES))

    cmd = {
        "action": "search_memory",
        "search_patterns": search_patterns or [],
        "context_bytes": context_bytes,
        "limit": limit,
    }
    if search_hex:
        cmd["search_hex"] = search_hex

    result = await session.send_command(cmd)
    if "error" in result:
        return result

    result["session_id"] = session.session_id
    return await _check_mcp_response_size(ctx, result, "emulation_search_memory")


@tool_decorator
async def emulation_memory_map(
    ctx: Context,
    session_id: str = "",
) -> Dict[str, Any]:
    """[Phase: dynamic] Get the memory map of a completed emulation session.

    Returns all mapped memory regions with start/end addresses, sizes,
    permissions, and labels. The emulator must have been started with
    emulate_and_inspect().

    Args:
        session_id: Session to query (uses most recent if empty).

    Returns:
        List of memory regions with metadata.
    """
    mgr = _get_emulation_manager()
    session = await mgr.get_session(session_id or None)

    result = await session.send_command({"action": "memory_map"})
    if "error" in result:
        return result

    result["session_id"] = session.session_id
    return await _check_mcp_response_size(ctx, result, "emulation_memory_map")
