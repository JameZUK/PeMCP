"""Unit tests for the emulation-based debugger (tools_debug.py).

Uses mock subprocesses to test the MCP tool layer without requiring
the actual Qiling venv or debug_runner.py subprocess.
"""
import asyncio
import json
import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch

from arkana.state import AnalyzerState, set_current_state


def _run(coro):
    """Helper to run async functions in tests."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
#  Mock helpers
# ---------------------------------------------------------------------------

class MockContext:
    """Minimal mock for MCP Context."""
    async def warning(self, msg): pass
    async def error(self, msg): pass
    async def info(self, msg): pass
    async def report_progress(self, current, total): pass


class MockStdin:
    """Mock subprocess stdin that records written data."""
    def __init__(self):
        self.written = []

    def write(self, data):
        self.written.append(data)

    async def drain(self):
        pass


class MockStdout:
    """Mock subprocess stdout that yields pre-configured responses."""
    def __init__(self, responses):
        self._responses = iter(responses)

    async def readline(self):
        try:
            resp = next(self._responses)
            if isinstance(resp, dict):
                return (json.dumps(resp) + "\n").encode()
            return resp
        except StopIteration:
            return b""


class MockProcess:
    """Mock asyncio.subprocess.Process."""
    def __init__(self, responses):
        self.stdin = MockStdin()
        self.stdout = MockStdout(responses)
        self.stderr = MagicMock()
        self.returncode = None
        self._killed = False

    def kill(self):
        self._killed = True
        self.returncode = -9

    async def wait(self):
        pass


def _make_init_response(arch="x86", os_type="windows", pc="0x401000"):
    return {
        "status": "ok", "pc": pc, "architecture": arch, "os_type": os_type,
        "format": "PE (32-bit)",
        "registers": {"eax": "0x0", "ebx": "0x0", "eip": pc, "eflags": "0x246"},
        "next_instructions": [{"address": pc, "mnemonic": "push", "op_str": "ebp", "bytes": "55", "size": 1}],
        "memory_map": [{"start": "0x400000", "end": "0x410000", "permissions": "r-x"}],
    }


def _make_step_response(pc="0x401001", insn_count=1, stop_reason="step_completed"):
    return {
        "status": "ok", "pc": pc, "instructions_executed": insn_count,
        "registers": {"eax": "0x0", "eip": pc, "eflags": "0x246"},
        "next_instructions": [{"address": pc, "mnemonic": "mov", "op_str": "ebp, esp", "bytes": "89e5", "size": 2}],
        "stack_top": [{"offset": "0x0", "address": "0xffffd000", "value": "0x0"}],
        "stop_reason": stop_reason,
    }


def _make_continue_response(pc="0x401100", insn_count=5000, stop_reason="breakpoint_hit", bp_id=1):
    resp = _make_step_response(pc=pc, insn_count=insn_count, stop_reason=stop_reason)
    if bp_id is not None:
        resp["breakpoint_id"] = bp_id
    return resp


# ---------------------------------------------------------------------------
#  Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_state():
    s = AnalyzerState()
    s.filepath = "/tmp/test.exe"
    s.pe_data = {"file_hashes": {"sha256": "abc123"}}
    set_current_state(s)
    yield s
    set_current_state(None)


@pytest.fixture
def mock_ctx():
    return MockContext()


# ---------------------------------------------------------------------------
#  Import helpers
# ---------------------------------------------------------------------------

def _import_session_cls():
    from arkana.mcp.tools_debug import _DebugSession
    return _DebugSession


def _import_manager_cls():
    from arkana.mcp.tools_debug import _DebugSessionManager
    return _DebugSessionManager


# ===================================================================
#  1. Session Lifecycle Tests
# ===================================================================

class TestDebugSessionLifecycle:

    def test_send_command_basic(self):
        _DebugSession = _import_session_cls()
        proc = MockProcess([{"status": "ok", "pc": "0x401000"}])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        result = _run(session.send_command({"action": "read_state"}))
        assert result["status"] == "ok"
        assert result["pc"] == "0x401000"
        assert len(proc.stdin.written) == 1

    def test_send_command_exited_process(self):
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        proc.returncode = 1
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        result = _run(session.send_command({"action": "read_state"}))
        assert "error" in result
        assert "exited unexpectedly" in result["error"]

    def test_send_command_empty_response(self):
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        result = _run(session.send_command({"action": "read_state"}))
        assert "error" in result
        assert "closed unexpectedly" in result["error"]

    def test_is_alive(self):
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        assert session.is_alive() is True
        proc.returncode = 0
        assert session.is_alive() is False

    def test_kill(self):
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        _run(session.kill())
        assert proc._killed is True

    def test_kill_sync(self):
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        session.kill_sync()
        assert proc._killed is True

    def test_manager_create_session(self):
        _DebugSessionManager = _import_manager_cls()
        init_resp = _make_init_response()
        mock_proc = MockProcess([init_resp])

        async def _test():
            mgr = _DebugSessionManager()
            with patch("arkana.mcp.tools_debug.asyncio.create_subprocess_exec",
                        new_callable=AsyncMock, return_value=mock_proc):
                session = await mgr.create_session("/tmp/test.exe")
            assert session.session_id == "debug-1"
            assert session.arch == "x86"
            assert session.pc == "0x401000"
            assert mgr.session_count == 1

        _run(_test())

    def test_manager_max_sessions_eviction(self):
        _DebugSessionManager = _import_manager_cls()
        from arkana.constants import MAX_DEBUG_SESSIONS

        async def _test():
            mgr = _DebugSessionManager()
            for i in range(MAX_DEBUG_SESSIONS + 1):
                init_resp = _make_init_response()
                mock_proc = MockProcess([init_resp])
                with patch("arkana.mcp.tools_debug.asyncio.create_subprocess_exec",
                            new_callable=AsyncMock, return_value=mock_proc):
                    s = await mgr.create_session(f"/tmp/test{i}.exe")
                    s.last_active = time.time() - (MAX_DEBUG_SESSIONS - i) * 10
            assert mgr.session_count == MAX_DEBUG_SESSIONS

        _run(_test())

    def test_manager_destroy_session(self):
        _DebugSessionManager = _import_manager_cls()
        init_resp = _make_init_response()
        stop_resp = {"status": "ok"}
        mock_proc = MockProcess([init_resp, stop_resp])

        async def _test():
            mgr = _DebugSessionManager()
            with patch("arkana.mcp.tools_debug.asyncio.create_subprocess_exec",
                        new_callable=AsyncMock, return_value=mock_proc):
                session = await mgr.create_session("/tmp/test.exe")
            await mgr.destroy_session(session.session_id)
            assert mgr.session_count == 0

        _run(_test())

    def test_manager_get_most_recent(self):
        _DebugSessionManager = _import_manager_cls()

        async def _test():
            mgr = _DebugSessionManager()
            for i in range(2):
                init_resp = _make_init_response()
                mock_proc = MockProcess([init_resp])
                with patch("arkana.mcp.tools_debug.asyncio.create_subprocess_exec",
                            new_callable=AsyncMock, return_value=mock_proc):
                    s = await mgr.create_session(f"/tmp/test{i}.exe")
                    s.last_active = time.time() + i * 10
            session = await mgr.get_session(None)
            assert session.filepath == "/tmp/test1.exe"

        _run(_test())

    def test_manager_get_no_sessions(self):
        _DebugSessionManager = _import_manager_cls()

        async def _test():
            mgr = _DebugSessionManager()
            with pytest.raises(RuntimeError, match="No active debug session"):
                await mgr.get_session(None)

        _run(_test())

    def test_manager_get_by_id_not_found(self):
        _DebugSessionManager = _import_manager_cls()

        async def _test():
            mgr = _DebugSessionManager()
            init_resp = _make_init_response()
            mock_proc = MockProcess([init_resp])
            with patch("arkana.mcp.tools_debug.asyncio.create_subprocess_exec",
                        new_callable=AsyncMock, return_value=mock_proc):
                await mgr.create_session("/tmp/test.exe")
            with pytest.raises(RuntimeError, match="not found"):
                await mgr.get_session("nonexistent-id")

        _run(_test())

    def test_manager_cleanup_all(self):
        _DebugSession = _import_session_cls()
        _DebugSessionManager = _import_manager_cls()
        mgr = _DebugSessionManager()
        procs = []
        for i in range(3):
            proc = MockProcess([])
            session = _DebugSession(f"test-{i}", proc, "x86", "windows", "/tmp/test.exe")
            mgr._sessions[f"test-{i}"] = session
            procs.append(proc)
        mgr.cleanup_all()
        assert mgr.session_count == 0
        assert all(p._killed for p in procs)

    def test_manager_list_sessions(self):
        _DebugSession = _import_session_cls()
        _DebugSessionManager = _import_manager_cls()
        mgr = _DebugSessionManager()
        proc = MockProcess([])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        session.pc = "0x401000"
        mgr._sessions["test-1"] = session
        listing = mgr.list_sessions()
        assert len(listing) == 1
        assert listing[0]["session_id"] == "test-1"
        assert listing[0]["is_alive"] is True

    def test_send_command_invalid_json_response(self):
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        proc.stdout = MockStdout([b"not valid json\n"])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        result = _run(session.send_command({"action": "read_state"}))
        assert "error" in result
        assert "Invalid JSON" in result["error"]


# ===================================================================
#  2. Execution Control Tests (subprocess-level)
# ===================================================================

class TestDebugExecutionControl:

    def _make_session(self, responses):
        _DebugSession = _import_session_cls()
        proc = MockProcess(responses)
        return _DebugSession("debug-1", proc, "x86", "windows", "/tmp/test.exe")

    def test_step_single(self):
        resp = _make_step_response(pc="0x401001", insn_count=1)
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "step", "count": 1}))
        assert result["pc"] == "0x401001"
        assert result["instructions_executed"] == 1

    def test_step_multiple(self):
        resp = _make_step_response(pc="0x401010", insn_count=10)
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "step", "count": 10}))
        assert result["pc"] == "0x401010"
        assert result["instructions_executed"] == 10

    def test_continue_until_breakpoint(self):
        resp = _make_continue_response(pc="0x401100", insn_count=5000, stop_reason="breakpoint_hit", bp_id=1)
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "continue", "max_instructions": 10_000_000}))
        assert result["stop_reason"] == "breakpoint_hit"
        assert result["breakpoint_id"] == 1

    def test_continue_max_instructions(self):
        resp = _make_step_response(pc="0x402000", insn_count=10_000_000, stop_reason="max_instructions_reached")
        resp["max_instructions"] = 10_000_000
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "continue", "max_instructions": 10_000_000}))
        assert result["stop_reason"] == "max_instructions_reached"

    def test_step_over(self):
        resp = _make_step_response(pc="0x401005", insn_count=100, stop_reason="step_over_completed")
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "step_over"}))
        assert result["stop_reason"] == "step_over_completed"

    def test_run_until(self):
        resp = _make_step_response(pc="0x401500", insn_count=250, stop_reason="address_reached")
        resp["target_address"] = "0x401500"
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "run_until", "address": "0x401500"}))
        assert result["stop_reason"] == "address_reached"


# ===================================================================
#  3. Breakpoint Tests (subprocess-level)
# ===================================================================

class TestDebugBreakpoints:

    def _make_session(self, responses):
        _DebugSession = _import_session_cls()
        proc = MockProcess(responses)
        return _DebugSession("debug-1", proc, "x86", "windows", "/tmp/test.exe")

    def test_set_address_breakpoint(self):
        resp = {"status": "ok", "breakpoint_id": 1, "type": "address",
                "address": "0x401000", "total_breakpoints": 1}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "set_breakpoint", "address": "0x401000"}))
        assert result["breakpoint_id"] == 1
        assert result["type"] == "address"

    def test_set_api_breakpoint(self):
        resp = {"status": "ok", "breakpoint_id": 1, "type": "api",
                "api_name": "CreateFileA", "total_breakpoints": 1}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "set_breakpoint", "api_name": "CreateFileA"}))
        assert result["type"] == "api"

    def test_set_conditional_breakpoint(self):
        resp = {"status": "ok", "breakpoint_id": 1, "type": "address", "total_breakpoints": 1}
        session = self._make_session([resp])
        result = _run(session.send_command({
            "action": "set_breakpoint", "address": "0x401000",
            "conditions": [{"type": "register", "register": "eax", "operator": "==", "value": "0x1"}],
        }))
        assert result["breakpoint_id"] == 1

    def test_remove_breakpoint(self):
        resp = {"status": "ok", "breakpoint_id": 1, "total_breakpoints": 0}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "remove_breakpoint", "breakpoint_id": 1}))
        assert result["total_breakpoints"] == 0

    def test_remove_nonexistent_breakpoint(self):
        resp = {"error": "Breakpoint 999 not found"}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "remove_breakpoint", "breakpoint_id": 999}))
        assert "error" in result

    def test_list_breakpoints(self):
        resp = {"status": "ok", "breakpoints": [
            {"id": 1, "type": "address", "address": "0x401000"},
            {"id": 2, "type": "api", "api_name": "VirtualAlloc"},
        ], "watchpoints": [], "total_breakpoints": 2, "total_watchpoints": 0}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "list_breakpoints"}))
        assert result["total_breakpoints"] == 2

    def test_breakpoint_no_target(self):
        resp = {"error": "Must provide 'address' or 'api_name' for breakpoint"}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "set_breakpoint"}))
        assert "error" in result

    def test_continue_hits_breakpoint(self):
        resp = _make_continue_response(pc="0x401100", insn_count=1234, stop_reason="breakpoint_hit", bp_id=1)
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "continue", "max_instructions": 10_000_000}))
        assert result["stop_reason"] == "breakpoint_hit"
        assert result["breakpoint_id"] == 1


# ===================================================================
#  4. Watchpoint Tests (subprocess-level)
# ===================================================================

class TestDebugWatchpoints:

    def _make_session(self, responses):
        _DebugSession = _import_session_cls()
        proc = MockProcess(responses)
        return _DebugSession("debug-1", proc, "x86", "windows", "/tmp/test.exe")

    def test_set_watchpoint_write(self):
        resp = {"status": "ok", "watchpoint_id": 1, "address": "0x404000",
                "size": 4, "type": "write", "total_watchpoints": 1}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "set_watchpoint", "address": "0x404000", "size": 4, "type": "write"}))
        assert result["watchpoint_id"] == 1

    def test_set_watchpoint_read(self):
        resp = {"status": "ok", "watchpoint_id": 1, "type": "read", "total_watchpoints": 1}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "set_watchpoint", "address": "0x404000", "size": 8, "type": "read"}))
        assert result["type"] == "read"

    def test_remove_watchpoint(self):
        resp = {"status": "ok", "watchpoint_id": 1, "total_watchpoints": 0}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "remove_watchpoint", "watchpoint_id": 1}))
        assert result["total_watchpoints"] == 0

    def test_watchpoint_hit(self):
        resp = {
            "status": "ok", "pc": "0x401234", "instructions_executed": 50,
            "registers": {"eax": "0x0", "eip": "0x401234"}, "next_instructions": [], "stack_top": [],
            "stop_reason": "watchpoint_hit", "watchpoint_id": 1,
            "access_type": "write", "access_address": "0x404010", "access_size": 4, "value_written": "0xDEADBEEF",
        }
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "continue"}))
        assert result["stop_reason"] == "watchpoint_hit"
        assert result["value_written"] == "0xDEADBEEF"

    def test_set_watchpoint_readwrite(self):
        resp = {"status": "ok", "watchpoint_id": 1, "type": "readwrite", "total_watchpoints": 1}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "set_watchpoint", "address": "0x404000", "type": "readwrite"}))
        assert result["type"] == "readwrite"


# ===================================================================
#  5. Inspection / Modification Tests (subprocess-level)
# ===================================================================

class TestDebugInspection:

    def _make_session(self, responses):
        _DebugSession = _import_session_cls()
        proc = MockProcess(responses)
        return _DebugSession("debug-1", proc, "x86", "windows", "/tmp/test.exe")

    def test_read_state(self):
        resp = {
            "status": "ok", "pc": "0x401000", "architecture": "x86", "os_type": "windows",
            "instructions_executed": 42,
            "registers": {"eax": "0x1", "ebx": "0x2", "eip": "0x401000"},
            "next_instructions": [{"address": "0x401000", "mnemonic": "push", "op_str": "ebp"}],
            "stack_top": [{"offset": "0x0", "address": "0xffffd000", "value": "0x0"}],
            "memory_map": [{"start": "0x400000", "end": "0x410000", "permissions": "r-x"}],
            "breakpoint_count": 0, "watchpoint_count": 0, "snapshot_count": 0,
        }
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "read_state"}))
        assert result["pc"] == "0x401000"
        assert result["registers"]["eax"] == "0x1"

    def test_read_memory_hex(self):
        resp = {"status": "ok", "address": "0x401000", "length": 16,
                "hex": "554889e54883ec20488b0500000000", "ascii": "UH..H... H......"}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "read_memory", "address": "0x401000", "length": 16}))
        assert result["hex"].startswith("554889e5")

    def test_read_memory_disasm(self):
        resp = {"status": "ok", "address": "0x401000", "length": 16, "hex": "554889e5",
                "disassembly": [{"address": "0x401000", "mnemonic": "push", "op_str": "rbp"}]}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "read_memory", "address": "0x401000", "format": "disasm"}))
        assert "disassembly" in result

    def test_read_memory_unmapped(self):
        resp = {"error": "Failed to read memory at 0x999999: UC_ERR_READ_UNMAPPED"}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "read_memory", "address": "0x999999"}))
        assert "error" in result

    def test_write_memory(self):
        resp = {"status": "ok", "address": "0x404000", "bytes_written": 4}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "write_memory", "address": "0x404000", "hex_bytes": "DEADBEEF"}))
        assert result["bytes_written"] == 4

    def test_write_register(self):
        resp = {"status": "ok", "register": "eax", "value": "0x12345678"}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "write_register", "register": "eax", "value": "0x12345678"}))
        assert result["register"] == "eax"


# ===================================================================
#  6. Snapshot Tests (subprocess-level)
# ===================================================================

class TestDebugSnapshots:

    def _make_session(self, responses):
        _DebugSession = _import_session_cls()
        proc = MockProcess(responses)
        return _DebugSession("debug-1", proc, "x86", "windows", "/tmp/test.exe")

    def test_snapshot_save(self):
        resp = {"status": "ok", "snapshot_id": 1, "name": "before_decrypt",
                "pc": "0x401000", "instructions_executed": 100, "total_snapshots": 1}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "snapshot_save", "name": "before_decrypt"}))
        assert result["snapshot_id"] == 1

    def test_snapshot_restore(self):
        resp = _make_step_response(pc="0x401000", insn_count=100, stop_reason="snapshot_restored")
        resp["snapshot_id"] = 1
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "snapshot_restore", "snapshot_id": 1}))
        assert result["stop_reason"] == "snapshot_restored"

    def test_snapshot_list(self):
        resp = {"status": "ok", "snapshots": [
            {"id": 1, "name": "entry", "pc": "0x401000"},
            {"id": 2, "name": "after_unpack", "pc": "0x401500"},
        ], "total_snapshots": 2}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "snapshot_list"}))
        assert result["total_snapshots"] == 2

    def test_snapshot_diff_registers(self):
        resp = {
            "status": "ok",
            "snapshot_a": {"id": 1, "name": "before", "pc": "0x401000"},
            "snapshot_b": {"id": 2, "name": "after", "pc": "0x401500"},
            "register_diffs": [{"register": "eax", "snapshot_a": "0x0", "snapshot_b": "0x1"}],
            "memory_diffs": [], "total_register_diffs": 1, "total_memory_diffs": 0,
        }
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "snapshot_diff", "snapshot_id_a": 1, "snapshot_id_b": 2}))
        assert result["total_register_diffs"] == 1

    def test_snapshot_diff_memory(self):
        resp = {
            "status": "ok",
            "snapshot_a": {"id": 1}, "snapshot_b": {"id": 2},
            "register_diffs": [],
            "memory_diffs": [{"address": "0x404000", "size": 4096, "change": "modified"}],
            "total_register_diffs": 0, "total_memory_diffs": 1,
        }
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "snapshot_diff", "snapshot_id_a": 1, "snapshot_id_b": 2}))
        assert result["total_memory_diffs"] == 1
        assert result["memory_diffs"][0]["change"] == "modified"

    def test_snapshot_nonexistent(self):
        resp = {"error": "Snapshot 999 not found"}
        session = self._make_session([resp])
        result = _run(session.send_command({"action": "snapshot_restore", "snapshot_id": 999}))
        assert "error" in result


# ===================================================================
#  7. Error Handling Tests
# ===================================================================

class TestDebugErrorHandling:

    def test_no_file_loaded_error(self, mock_ctx):
        from arkana.mcp.tools_debug import debug_start

        s = AnalyzerState()
        s.filepath = None
        s.pe_data = None
        set_current_state(s)
        try:
            # _check_qiling runs before _check_pe_loaded, and Qiling is not
            # available in the test env, so we patch it to pass.
            with patch("arkana.mcp.tools_debug._check_qiling_available", return_value=True), \
                 patch("os.path.isdir", return_value=True):
                # tool_decorator catches RuntimeError and re-raises with enrichment
                with pytest.raises(RuntimeError, match="No file"):
                    _run(debug_start(mock_ctx))
        finally:
            set_current_state(None)

    def test_qiling_unavailable_error(self, mock_ctx, clean_state):
        from arkana.mcp.tools_debug import debug_start

        # tool_decorator re-raises RuntimeError from _check_qiling
        with pytest.raises(RuntimeError, match="Qiling Framework is not available"):
            _run(debug_start(mock_ctx))

    def test_subprocess_crash_handling(self):
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        proc.returncode = 1
        session = _DebugSession("debug-1", proc, "x86", "windows", "/tmp/test.exe")
        result = _run(session.send_command({"action": "step", "count": 1}))
        assert "error" in result

    def test_validate_address_valid(self):
        from arkana.mcp.tools_debug import _validate_address
        assert _validate_address("0x401000") == "0x401000"
        assert _validate_address("0X401000") == "0X401000"
        assert _validate_address("12345") == "12345"

    def test_validate_address_empty(self):
        from arkana.mcp.tools_debug import _validate_address
        with pytest.raises(ValueError, match="required"):
            _validate_address("")

    def test_validate_address_invalid(self):
        from arkana.mcp.tools_debug import _validate_address
        with pytest.raises(ValueError, match="Invalid"):
            _validate_address("not_a_number")

    def test_validate_address_too_long(self):
        from arkana.mcp.tools_debug import _validate_address
        with pytest.raises(ValueError, match="too long"):
            _validate_address("0x" + "1" * 50)


# ===================================================================
#  8. Update Session From Result Tests
# ===================================================================

class TestUpdateSessionFromResult:

    def test_updates_pc(self):
        from arkana.mcp.tools_debug import _update_session_from_result
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        _update_session_from_result(session, {"pc": "0x401100", "instructions_executed": 50})
        assert session.pc == "0x401100"
        assert session.instructions_executed == 50

    def test_exited_status(self):
        from arkana.mcp.tools_debug import _update_session_from_result
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        _update_session_from_result(session, {"stop_reason": "exited", "pc": "0x401500"})
        assert session.status == "exited"

    def test_error_status(self):
        from arkana.mcp.tools_debug import _update_session_from_result
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        _update_session_from_result(session, {"error": "something broke"})
        assert session.status == "error"

    def test_paused_status(self):
        from arkana.mcp.tools_debug import _update_session_from_result
        _DebugSession = _import_session_cls()
        proc = MockProcess([])
        session = _DebugSession("test-1", proc, "x86", "windows", "/tmp/test.exe")
        _update_session_from_result(session, {"stop_reason": "step_completed", "pc": "0x401001"})
        assert session.status == "paused"


# ===================================================================
#  9. MCP Tool Integration Tests (with tool_decorator)
# ===================================================================

class TestMCPToolIntegration:

    def _setup_session(self, clean_state, responses):
        """Create a manager with a mocked session on the state."""
        _DebugSession = _import_session_cls()
        _DebugSessionManager = _import_manager_cls()
        mgr = _DebugSessionManager()
        proc = MockProcess(responses)
        session = _DebugSession("debug-1", proc, "x86", "windows", "/tmp/test.exe")
        mgr._sessions["debug-1"] = session
        clean_state._debug_manager = mgr
        return session

    def test_debug_status_no_sessions(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_status
        clean_state._debug_manager = _import_manager_cls()()
        result = _run(debug_status(mock_ctx))
        assert result["total_sessions"] == 0

    def test_debug_status_with_session(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_status
        session = self._setup_session(clean_state, [])
        session.pc = "0x401000"
        result = _run(debug_status(mock_ctx, session_id="debug-1"))
        assert result["session_id"] == "debug-1"
        assert result["pc"] == "0x401000"

    def test_debug_step_tool(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_step
        resp = _make_step_response(pc="0x401001", insn_count=1)
        session = self._setup_session(clean_state, [resp])
        result = _run(debug_step(mock_ctx, count=1))
        assert result["pc"] == "0x401001"
        assert session.pc == "0x401001"

    def test_debug_read_memory_tool(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_read_memory
        resp = {"status": "ok", "address": "0x401000", "length": 16, "hex": "554889e54883ec20"}
        self._setup_session(clean_state, [resp])
        result = _run(debug_read_memory(mock_ctx, address="0x401000", length=16))
        assert result["hex"] == "554889e54883ec20"

    def test_debug_write_memory_tool(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_write_memory
        resp = {"status": "ok", "address": "0x404000", "bytes_written": 4}
        self._setup_session(clean_state, [resp])
        result = _run(debug_write_memory(mock_ctx, address="0x404000", hex_bytes="DEADBEEF"))
        assert result["bytes_written"] == 4

    def test_debug_write_register_tool(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_write_register
        resp = {"status": "ok", "register": "eax", "value": "0x42"}
        self._setup_session(clean_state, [resp])
        result = _run(debug_write_register(mock_ctx, register="eax", value="0x42"))
        assert result["register"] == "eax"

    def test_debug_set_breakpoint_tool(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_set_breakpoint
        resp = {"status": "ok", "breakpoint_id": 1, "type": "address", "total_breakpoints": 1}
        self._setup_session(clean_state, [resp])
        result = _run(debug_set_breakpoint(mock_ctx, address="0x401000"))
        assert result["breakpoint_id"] == 1

    def test_debug_set_breakpoint_invalid_conditions(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_set_breakpoint
        self._setup_session(clean_state, [])
        result = _run(debug_set_breakpoint(mock_ctx, address="0x401000", conditions="not json"))
        assert "error" in result
        assert "Invalid conditions JSON" in result["error"]

    def test_debug_set_watchpoint_tool(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_set_watchpoint
        resp = {"status": "ok", "watchpoint_id": 1, "type": "write", "total_watchpoints": 1}
        self._setup_session(clean_state, [resp])
        result = _run(debug_set_watchpoint(mock_ctx, address="0x404000", size=4, type="write"))
        assert result["watchpoint_id"] == 1

    def test_debug_set_watchpoint_invalid_type(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_set_watchpoint
        self._setup_session(clean_state, [])
        result = _run(debug_set_watchpoint(mock_ctx, address="0x404000", type="invalid"))
        assert "error" in result
        assert "Invalid watchpoint type" in result["error"]

    def test_debug_remove_breakpoint_zero_id(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_remove_breakpoint
        self._setup_session(clean_state, [])
        result = _run(debug_remove_breakpoint(mock_ctx, breakpoint_id=0))
        assert "error" in result

    def test_debug_remove_watchpoint_zero_id(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_remove_watchpoint
        self._setup_session(clean_state, [])
        result = _run(debug_remove_watchpoint(mock_ctx, watchpoint_id=0))
        assert "error" in result

    def test_debug_snapshot_save_tool(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_snapshot_save
        resp = {"status": "ok", "snapshot_id": 1, "name": "test", "pc": "0x401000", "total_snapshots": 1}
        self._setup_session(clean_state, [resp])
        result = _run(debug_snapshot_save(mock_ctx, name="test"))
        assert result["snapshot_id"] == 1

    def test_debug_snapshot_restore_zero_id(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_snapshot_restore
        self._setup_session(clean_state, [])
        result = _run(debug_snapshot_restore(mock_ctx, snapshot_id=0))
        assert "error" in result

    def test_debug_snapshot_diff_same_id(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_snapshot_diff
        self._setup_session(clean_state, [])
        result = _run(debug_snapshot_diff(mock_ctx, snapshot_id_a=1, snapshot_id_b=1))
        assert "error" in result
        assert "Cannot diff a snapshot with itself" in result["error"]

    def test_debug_write_memory_empty_hex(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_write_memory
        self._setup_session(clean_state, [])
        result = _run(debug_write_memory(mock_ctx, address="0x404000", hex_bytes=""))
        assert "error" in result

    def test_debug_write_register_empty(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_write_register
        self._setup_session(clean_state, [])
        result = _run(debug_write_register(mock_ctx, register="", value="0x42"))
        assert "error" in result

    def test_debug_list_breakpoints_tool(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_list_breakpoints
        resp = {"status": "ok", "breakpoints": [], "watchpoints": [],
                "total_breakpoints": 0, "total_watchpoints": 0}
        self._setup_session(clean_state, [resp])
        result = _run(debug_list_breakpoints(mock_ctx))
        assert result["total_breakpoints"] == 0

    def test_debug_snapshot_list_tool(self, clean_state, mock_ctx):
        from arkana.mcp.tools_debug import debug_snapshot_list
        resp = {"status": "ok", "snapshots": [], "total_snapshots": 0}
        self._setup_session(clean_state, [resp])
        result = _run(debug_snapshot_list(mock_ctx))
        assert result["total_snapshots"] == 0
