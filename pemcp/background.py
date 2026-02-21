"""Background task management: heartbeat monitoring, progress tracking, async wrappers."""
import datetime
import inspect
import sys
import time
import asyncio
import threading
import logging

from pemcp.config import state, logger
from pemcp.state import (
    get_current_state, set_current_state, get_all_session_states,
    TASK_RUNNING, TASK_COMPLETED, TASK_FAILED,
)

# Global lock and flag for the heartbeat monitor thread (shared across sessions)
_monitor_lock = threading.Lock()
_monitor_started = False


def _console_heartbeat_loop():
    """
    Daemon thread that prints the status of running tasks to the console every 30 seconds.
    This ensures the user knows the script is alive even during heavy blocking operations.
    """
    while True:
        time.sleep(30)

        current_time_str = datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')

        # Collect running tasks from ALL sessions (not just the default state)
        running_entries = []
        for session_state in get_all_session_states():
            for task_id in session_state.get_all_task_ids():
                task = session_state.get_task(task_id)
                if task and task["status"] == TASK_RUNNING:
                    running_entries.append((task_id, task))

        if running_entries:
            # Print a clean status block
            print(f"\n--- [Status Heartbeat {current_time_str}] ---", file=sys.stderr)
            for task_id, task in running_entries:
                # Calculate elapsed time
                try:
                    start_time = datetime.datetime.fromisoformat(task["created_at"])
                    elapsed = datetime.datetime.now(datetime.timezone.utc) - start_time
                    elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
                except Exception:
                    elapsed_str = "?"

                percent = task.get("progress_percent", 0)
                msg = task.get("progress_message", "Processing...")

                print(f" * Task {task_id[:8]}... [{elapsed_str} elapsed] | {percent}%: {msg}", file=sys.stderr)
            print("------------------------------------------\n", file=sys.stderr)

            # Flush stderr to ensure it appears in logs/consoles immediately
            sys.stderr.flush()


def _update_progress(task_id: str, percent: int, message: str):
    """Helper to safely update progress in the global registry."""
    state.update_task(task_id, progress_percent=percent, progress_message=message)


def _log_task_exception(task_id: str):
    """Return a done-callback that logs unhandled exceptions from background tasks."""
    def _callback(t):
        if not t.cancelled() and t.exception() is not None:
            logger.error(f"Background task '{task_id}' failed: {t.exception()}")
    return _callback


async def _run_background_task_wrapper(task_id: str, func, *args, **kwargs):
    """Helper to run a blocking function in a thread and update the registry."""

    # Lazy-start the heartbeat monitor on the first background request
    global _monitor_started
    with _monitor_lock:
        if not _monitor_started:
            monitor_thread = threading.Thread(target=_console_heartbeat_loop, daemon=True)
            monitor_thread.start()
            _monitor_started = True
            logger.info("Console heartbeat monitor started.")

    # Capture the caller's session state so we can propagate it into the worker thread
    _session_state = get_current_state()

    def _thread_wrapper():
        # Propagate session state into this worker thread
        set_current_state(_session_state)
        return func(*args, **kwargs)

    try:
        # Inject the task_id only if the function accepts it (via explicit
        # parameter or **kwargs) to avoid TypeError for functions that don't.
        sig = inspect.signature(func)
        params = sig.parameters
        if 'task_id_for_progress' in params or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
        ):
            kwargs['task_id_for_progress'] = task_id

        result = await asyncio.to_thread(_thread_wrapper)

        state.update_task(task_id, result=result, status=TASK_COMPLETED,
                          progress_percent=100, progress_message="Analysis complete.")
        print(f"\n[*] Task {task_id[:8]} finished successfully.", file=sys.stderr)

    except Exception as e:
        logger.error(f"Background task {task_id} failed: {type(e).__name__}: {e}", exc_info=True)
        state.update_task(task_id, error=str(e), status=TASK_FAILED)
        print(f"\n[!] Task {task_id[:8]} failed: {e}", file=sys.stderr)


def angr_background_worker(filepath: str, task_id: str, mode: str = "auto", arch_hint: str = "amd64",
                           _session_state=None):
    """
    Unified background worker for Angr analysis.  Supports PE, ELF, Mach-O,
    and shellcode (via ``mode='shellcode'``).

    This is the single implementation used by both CLI startup pre-loading
    and the ``open_file`` MCP tool.
    """
    # Propagate the caller's session state so the StateProxy resolves to the
    # correct AnalyzerState inside this thread.
    if _session_state is not None:
        set_current_state(_session_state)

    import angr  # imported here since this only runs when ANGR_AVAILABLE is True

    try:
        _update_progress(task_id, 1, "Loading Angr Project...")

        # 1. Load Project (mode-aware)
        if mode == "shellcode":
            _update_progress(task_id, 5, f"Loading raw shellcode as {arch_hint}...")
            project = angr.Project(
                filepath,
                main_opts={"backend": "blob", "arch": arch_hint},
                auto_load_libs=False,
            )
        else:
            project = angr.Project(filepath, auto_load_libs=False)

        state.set_angr_results(project, None, None, None)
        _update_progress(task_id, 20, "Building Control Flow Graph...")

        # 2. Build CFG (the heaviest step)
        cfg = project.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)
        state.set_angr_results(project, cfg, None, None)
        _update_progress(task_id, 80, "Identifying loops...")

        # 3. Pre-calculate Loops
        loop_finder = project.analyses.LoopFinder(kb=project.kb)
        raw_loops = {}
        for loop in loop_finder.loops:
            try:
                node = cfg.model.get_any_node(loop.entry.addr)
                if node and node.function_address:
                    func_addr = node.function_address
                    if func_addr not in raw_loops:
                        raw_loops[func_addr] = []
                    raw_loops[func_addr].append({
                        "entry": hex(loop.entry.addr),
                        "blocks": len(list(loop.body_nodes)),
                        "subloops": bool(loop.subloops),
                    })
            except Exception:
                continue

        state.set_angr_results(project, cfg, raw_loops, {"resolve_jumps": True, "data_refs": False})

        # 4. Mark Complete
        state.update_task(
            task_id,
            status=TASK_COMPLETED,
            result={"message": "Analysis ready."},
            progress_percent=100,
            progress_message="Background analysis complete.",
        )
        print(f"\n[*] Background Angr Analysis finished.", file=sys.stderr)

    except (OSError, RuntimeError, ValueError) as e:
        logger.error(f"Background Angr analysis failed: {type(e).__name__}: {e}", exc_info=True)
        state.update_task(task_id, status=TASK_FAILED, error=str(e))
        _update_progress(task_id, 0, f"Failed: {e}")
    except Exception as e:
        logger.error(f"Background Angr analysis failed unexpectedly: {type(e).__name__}: {e}", exc_info=True)
        state.update_task(task_id, status=TASK_FAILED, error=str(e))
        _update_progress(task_id, 0, f"Failed: {e}")


def start_angr_background(filepath: str, mode: str = "auto", arch_hint: str = "amd64",
                          task_id: str = "startup-angr", tool_label: str = "startup"):
    """
    Register a background task and launch ``angr_background_worker`` in a
    daemon thread.  Returns the *task_id* so callers can track it.

    This is the single entry-point used by ``main.py`` startup and the
    ``open_file`` MCP tool — no more duplicated worker code.
    """
    # Capture the caller's session state to propagate to the background thread
    _session_state = get_current_state()

    state.set_task(task_id, {
        "status": TASK_RUNNING,
        "progress_percent": 0,
        "progress_message": "Starting background pre-analysis...",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "created_at_epoch": time.time(),
        "tool": tool_label,
    })

    global _monitor_started
    with _monitor_lock:
        if not _monitor_started:
            monitor_thread = threading.Thread(target=_console_heartbeat_loop, daemon=True)
            monitor_thread.start()
            _monitor_started = True

    angr_thread = threading.Thread(
        target=angr_background_worker,
        args=(filepath, task_id, mode, arch_hint),
        kwargs={"_session_state": _session_state},
        daemon=True,
    )
    angr_thread.start()
    logger.info(f"Background Angr analysis thread started (task_id={task_id}).")
    return task_id
