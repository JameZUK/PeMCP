"""Background task management: heartbeat monitoring, progress tracking, async wrappers."""
import concurrent.futures
import datetime
import inspect
import sys
import time
import asyncio
import threading
import logging

from arkana.config import state, logger
from arkana.constants import (
    ANGR_CFG_TIMEOUT, BACKGROUND_TASK_TIMEOUT,
    ANGR_CFG_SOFT_TIMEOUT, BACKGROUND_TASK_SOFT_TIMEOUT,
    OVERTIME_CHECK_INTERVAL, OVERTIME_STALL_KILL, OVERTIME_MAX_RUNTIME,
    CFG_ERROR_RATE_THRESHOLD, CFG_PARTIAL_MIN_FUNCS,
)
from arkana.utils import _safe_env_int
from arkana.state import (
    get_current_state, set_current_state, get_all_session_states,
    TASK_RUNNING, TASK_OVERTIME, TASK_COMPLETED, TASK_FAILED,
)
from arkana.warning_handler import _current_task_var

# Global lock and flag for the heartbeat monitor thread (shared across sessions)
_monitor_lock = threading.Lock()
_monitor_started = False

# Resolve env-configurable error thresholds for CFG degradation detection
_CFG_ERROR_RATE = _safe_env_int("ARKANA_CFG_ERROR_RATE_THRESHOLD", CFG_ERROR_RATE_THRESHOLD, min_val=5)
_CFG_PARTIAL_MIN = _safe_env_int("ARKANA_CFG_PARTIAL_MIN_FUNCS", CFG_PARTIAL_MIN_FUNCS, min_val=10)


class _PartialCFG:
    """Shim for a partially-built CFG, backed by the live angr project KB.

    When the CFG build is interrupted (stall, timeout, or high error rate),
    ``project.kb.functions`` already contains whatever was discovered.
    This wrapper exposes the same interface that tools expect from a full
    ``CFGFast`` result — ``.functions``, ``.model``, ``.functions.callgraph``.

    Since ``.functions`` is a live reference to the project KB, any
    functions discovered by a still-running CFGFast thread appear
    automatically.
    """

    def __init__(self, project):
        self.functions = project.kb.functions
        self.model = None
        try:
            self.model = project.kb.cfgs.get_most_accurate()
        except Exception:
            pass
        self._partial = True

    def __repr__(self):
        try:
            n = len(self.functions)
        except Exception:
            n = "?"
        return f"<_PartialCFG functions={n} model={'yes' if self.model else 'no'}>"


def _accept_partial_cfg(task_id, project, reason, func_count, error_count, bridge=None):
    """Accept a partial CFG result instead of marking the task as FAILED.

    Stores a ``_PartialCFG`` wrapper on state so tools can use whatever
    functions were discovered, and sets ``state._cfg_quality`` metadata.
    """
    partial = _PartialCFG(project)
    state.set_angr_results(project, partial, None, None)

    quality = {
        "status": "partial",
        "reason": reason,
        "functions_discovered": func_count,
        "errors_during_build": error_count,
        "timestamp": time.time(),
    }
    state._cfg_quality = quality

    msg = (
        f"CFG partial: {func_count} functions discovered ({reason}). "
        "Function map and decompilation available for discovered functions. "
        "Use decompile_function_with_angr(address) to decompile any function "
        "(builds a local CFG if not in the partial result)."
    )
    state.update_task(task_id, status=TASK_COMPLETED,
                      result={"message": msg, "cfg_quality": quality},
                      progress_percent=100,
                      progress_message=f"CFG partial ({func_count} funcs)")
    if bridge is not None:
        bridge.info(msg, force=True)
    logger.info("Accepted partial CFG: %s (%d funcs, %d errors)", reason, func_count, error_count)


def _try_salvage_partial(task_id, project, error_msg, bridge=None):
    """Try to salvage a partial CFG after an exception during CFG build/post-processing.

    If enough functions were discovered in project.kb before the crash,
    accepts them as a partial CFG instead of discarding everything.
    Returns True if partial was accepted, False otherwise.
    """
    if project is None:
        return False
    try:
        func_count = len(project.kb.functions)
    except Exception:
        return False
    if func_count < _CFG_PARTIAL_MIN:
        return False

    _accept_partial_cfg(
        task_id, project,
        reason=f"exception after {func_count} funcs: {error_msg[:100]}",
        func_count=func_count,
        error_count=0,
        bridge=bridge,
    )
    return True


def _console_heartbeat_loop():
    """
    Daemon thread that prints the status of running tasks to the console every 30 seconds.
    This ensures the user knows the script is alive even during heavy blocking operations.
    """
    while True:
        time.sleep(30)
        try:
            current_time_str = datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')

            # Collect running/overtime tasks from ALL sessions (not just the default state)
            running_entries = []
            for session_state in get_all_session_states():
                for task_id in session_state.get_all_task_ids():
                    task = session_state.get_task(task_id)
                    if task and task["status"] in (TASK_RUNNING, TASK_OVERTIME):
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
                    suffix = " (OVERTIME)" if task["status"] == TASK_OVERTIME else ""

                    print(f" * Task {task_id[:8]}... [{elapsed_str} elapsed] | {percent}%: {msg}{suffix}", file=sys.stderr)
                print("------------------------------------------\n", file=sys.stderr)

                # Flush stderr to ensure it appears in logs/consoles immediately
                sys.stderr.flush()
        except Exception:
            logger.debug("Heartbeat loop error", exc_info=True)


def _update_progress(task_id: str, percent: int, message: str, bridge=None):
    """Helper to safely update progress in the global registry.

    If a :class:`~arkana.mcp._progress_bridge.ProgressBridge` is provided,
    also push the progress notification to the MCP client in real-time.

    Skips the update if the task is no longer active (e.g. after abort or
    file switch) to prevent confusing progress on dead tasks.
    """
    task = state.get_task(task_id)
    if not task or task.get("status") not in (TASK_RUNNING, TASK_OVERTIME):
        return  # Task is no longer active — skip update
    state.update_task(task_id, progress_percent=percent, progress_message=message,
                      last_progress_epoch=time.time())
    if bridge is not None:
        try:
            bridge.report_progress(percent, 100)
            bridge.info(message)
        except Exception:
            pass  # Never let bridge errors break background work


def _log_task_exception(task_id: str):
    """Return a done-callback that logs unhandled exceptions from background tasks."""
    def _callback(t):
        if not t.cancelled() and t.exception() is not None:
            logger.error("Background task '%s' failed: %s", task_id, t.exception())
    return _callback


def _register_background_task(task_id: str, task_info: dict) -> threading.Event:
    """Register a background task and its cancel event atomically.

    Creates a cancel event, registers it in ``_task_cancel_events``, then
    calls ``state.set_task()``.  Returns the cancel event so callers can
    pass it to ``_run_background_task_wrapper(cancel_event=...)``.

    This closes the race window where ``cancel_all_background_tasks()``
    could fire between ``set_task(RUNNING)`` and cancel event registration
    inside the wrapper.
    """
    _session_state = get_current_state()
    cancel_event = threading.Event()
    _session_state.register_task_infra(task_id, cancel_event)
    state.set_task(task_id, task_info)
    return cancel_event


def _is_task_aborted(task_id: str) -> bool:
    """Check if a task has been marked as aborted."""
    task = state.get_task(task_id)
    return task is not None and task.get("aborted", False)


async def _run_background_task_wrapper(task_id: str, func, *args, ctx=None,
                                       timeout=None, soft_timeout=None,
                                       on_timeout=None, cancel_event=None,
                                       **kwargs):
    """Helper to run a blocking function in a thread and update the registry.

    Parameters
    ----------
    task_id : str
        Unique identifier for this background task.
    func : callable
        The blocking function to run in a worker thread.
    ctx : Context, optional
        If provided, a :class:`ProgressBridge` is created and injected into
        *func* (as ``_progress_bridge`` kwarg) so that the worker can push
        real-time MCP progress notifications in addition to the pollable
        task registry.
    timeout : int or None
        Hard timeout (legacy, used when soft_timeout is disabled).
        Defaults to ``ARKANA_BACKGROUND_TASK_TIMEOUT``.  Pass ``0`` to disable.
    soft_timeout : int or None
        Seconds before the task transitions to OVERTIME (still running).
        Defaults to ``ARKANA_BACKGROUND_TASK_SOFT_TIMEOUT``.  Set to ``0``
        to fall back to the old single hard-timeout behavior.
    on_timeout : callable or None
        Optional callback invoked on stall-kill to capture partial results.
        Should return a dict (or None).
    cancel_event : threading.Event, optional
        Pre-registered cancel event.  When provided, the wrapper uses it
        instead of creating a new one.  Callers should register the event
        in ``_task_cancel_events`` *before* setting the task to RUNNING
        to close the race window with ``cancel_all_background_tasks()``.
    """

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
    captured_gen = _session_state._analysis_generation

    # Use pre-registered cancel event or create one (backward compat)
    if cancel_event is None:
        cancel_event = threading.Event()
        _session_state.register_task_infra(task_id, cancel_event)

    # Create a ProgressBridge if we have a live MCP context
    bridge = None
    if ctx is not None:
        try:
            from arkana.mcp._progress_bridge import ProgressBridge
            bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())
        except Exception:
            logger.debug("Could not create ProgressBridge for background task %s", task_id, exc_info=True)

    def _thread_wrapper():
        # Propagate session state and task context into this worker thread
        set_current_state(_session_state)
        _current_task_var.set(task_id)
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

        # Inject bridge if the function can accept it
        if bridge is not None:
            if '_progress_bridge' in params or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
            ):
                kwargs['_progress_bridge'] = bridge

        # Resolve timeouts
        hard_timeout = timeout if timeout is not None else _safe_env_int(
            "ARKANA_BACKGROUND_TASK_TIMEOUT", BACKGROUND_TASK_TIMEOUT)
        soft_t = soft_timeout if soft_timeout is not None else (
            timeout if timeout is not None else _safe_env_int(
                "ARKANA_BACKGROUND_TASK_SOFT_TIMEOUT", BACKGROUND_TASK_SOFT_TIMEOUT))
        check_interval = _safe_env_int("ARKANA_OVERTIME_CHECK_INTERVAL", OVERTIME_CHECK_INTERVAL, min_val=5)
        stall_kill = _safe_env_int("ARKANA_OVERTIME_STALL_KILL", OVERTIME_STALL_KILL, min_val=10)
        max_runtime = _safe_env_int("ARKANA_OVERTIME_MAX_RUNTIME", OVERTIME_MAX_RUNTIME, min_val=60)

        task_start = time.time()
        coro = asyncio.to_thread(_thread_wrapper)
        task_future = asyncio.ensure_future(coro)

        # --- Backward compat: soft_timeout disabled → old single-timeout ---
        if soft_t <= 0:
            if hard_timeout > 0:
                result = await asyncio.wait_for(asyncio.shield(task_future), timeout=hard_timeout)
            else:
                result = await task_future
            # Generation guard
            if _session_state._analysis_generation != captured_gen:
                logger.info("Task %s completed but file was switched — discarding result", task_id)
                state.update_task(task_id, status=TASK_FAILED,
                                  error="File was switched during analysis.",
                                  progress_message="Discarded — file switched")
                return
            state.update_task(task_id, result=result, status=TASK_COMPLETED,
                              progress_percent=100, progress_message="Analysis complete.")
            if bridge is not None:
                bridge.report_progress(100, 100, force=True)
                bridge.info("Background task complete.", force=True)
            print(f"\n[*] Task {task_id[:8]} finished successfully.", file=sys.stderr)
            return

        # --- Phase 1: Wait for soft timeout ---
        done, _ = await asyncio.wait({task_future}, timeout=soft_t)
        if done:
            # Check cancel before extracting result
            if cancel_event.is_set():
                logger.info("Task %s cancelled before result extraction", task_id)
                return
            result = task_future.result()
            if _session_state._analysis_generation != captured_gen:
                logger.info("Task %s completed but file was switched — discarding result", task_id)
                state.update_task(task_id, status=TASK_FAILED,
                                  error="File was switched during analysis.",
                                  progress_message="Discarded — file switched")
                return
            state.update_task(task_id, result=result, status=TASK_COMPLETED,
                              progress_percent=100, progress_message="Analysis complete.")
            if bridge is not None:
                bridge.report_progress(100, 100, force=True)
                bridge.info("Background task complete.", force=True)
            print(f"\n[*] Task {task_id[:8]} finished successfully.", file=sys.stderr)
            return

        # --- Phase 2: Overtime loop ---
        state.update_task(task_id, status=TASK_OVERTIME,
                          overtime_since_epoch=time.time(),
                          progress_message=f"Overtime — soft timeout ({soft_t}s) exceeded, still running...")
        logger.info("Task %s entered overtime after %ds soft timeout", task_id, soft_t)
        if bridge is not None:
            bridge.info(f"Task entered overtime (soft timeout {soft_t}s exceeded, still running).", force=True)

        while True:
            done, _ = await asyncio.wait({task_future}, timeout=check_interval)
            if done:
                # Task completed during overtime
                if cancel_event.is_set():
                    logger.info("Task %s completed after cancel — discarding", task_id)
                    return
                if _session_state._analysis_generation != captured_gen:
                    logger.info("Task %s completed but file was switched — discarding result", task_id)
                    return
                result = task_future.result()
                state.update_task(task_id, result=result, status=TASK_COMPLETED,
                                  progress_percent=100,
                                  progress_message="Analysis complete (recovered from overtime).")
                if bridge is not None:
                    bridge.report_progress(100, 100, force=True)
                    bridge.info("Background task complete (recovered from overtime).", force=True)
                print(f"\n[*] Task {task_id[:8]} finished (overtime recovery).", file=sys.stderr)
                return

            # Check if cancelled (abort, file switch, or reaper)
            if cancel_event.is_set():
                logger.info("Task %s cancelled during overtime — thread still running but result will be discarded", task_id)
                return

            # Check generation
            if _session_state._analysis_generation != captured_gen:
                logger.info("Task %s: file switched during overtime — discarding", task_id)
                state.update_task(task_id, status=TASK_FAILED,
                                  error="File was switched during analysis.",
                                  progress_message="Discarded — file switched")
                return

            # Check absolute ceiling
            total_elapsed = time.time() - task_start
            if max_runtime > 0 and total_elapsed >= max_runtime:
                partial = None
                if on_timeout is not None:
                    try:
                        partial = on_timeout()
                    except Exception:
                        logger.debug("on_timeout callback failed for task %s", task_id, exc_info=True)
                state.update_task(task_id, status=TASK_FAILED,
                                  error=f"Absolute max runtime ({int(max_runtime)}s) exceeded.",
                                  timed_out=True, partial_result=partial,
                                  progress_message=f"Killed — max runtime {int(max_runtime)}s exceeded")
                print(f"\n[!] Task {task_id[:8]} killed — max runtime exceeded.", file=sys.stderr)
                return

            # Check progress (stall detection)
            task = state.get_task(task_id)
            last_progress = task.get("last_progress_epoch", task_start) if task else task_start
            stalled_for = time.time() - last_progress
            if stalled_for >= stall_kill:
                partial = None
                if on_timeout is not None:
                    try:
                        partial = on_timeout()
                    except Exception:
                        logger.debug("on_timeout callback failed for task %s", task_id, exc_info=True)
                error_msg = (
                    f"Task stalled for {int(stalled_for)}s with no progress. "
                    f"Total runtime: {int(total_elapsed)}s."
                )
                if partial:
                    error_msg += " Partial results are available."
                state.update_task(task_id, status=TASK_FAILED, error=error_msg,
                                  timed_out=True, partial_result=partial,
                                  progress_message=f"Stall-killed after {int(stalled_for)}s no progress")
                if bridge is not None:
                    bridge.info(f"Task stall-killed after {int(stalled_for)}s no progress.", force=True)
                print(f"\n[!] Task {task_id[:8]} stall-killed after {int(stalled_for)}s no progress.", file=sys.stderr)
                return

            # Still progressing — update overtime status
            state.update_task(task_id,
                              progress_message=f"Overtime ({int(total_elapsed)}s elapsed, progressing...)")

    except asyncio.TimeoutError:
        # Only reached in backward-compat mode (soft_t <= 0)
        partial = None
        if on_timeout is not None:
            try:
                partial = on_timeout()
            except Exception:
                logger.debug("on_timeout callback failed for task %s", task_id, exc_info=True)

        error_msg = f"Task timed out after {hard_timeout}s."
        if partial:
            error_msg += " Partial results are available."

        state.update_task(task_id, status=TASK_FAILED, error=error_msg,
                          timed_out=True, partial_result=partial,
                          progress_message=f"Timed out after {hard_timeout}s")
        if bridge is not None:
            bridge.info(f"Task timed out after {hard_timeout}s.", force=True)
        print(f"\n[!] Task {task_id[:8]} timed out after {hard_timeout}s.", file=sys.stderr)

    except Exception as e:
        logger.error("Background task %s failed: %s: %s", task_id, type(e).__name__, e, exc_info=True)
        state.update_task(task_id, error=str(e)[:200], status=TASK_FAILED)  # M4-v10: truncate exception
        print(f"\n[!] Task {task_id[:8]} failed: {str(e)[:200]}", file=sys.stderr)  # H1-v11: truncate stderr

    finally:
        # Clean up cancel event and thread ref
        _session_state.unregister_task_infra(task_id)


def _cfg_stall_monitor(project, task_id, interval=15, _session_state=None):
    """Sample KB function count and error rate periodically during CFGFast.

    Writes snapshots to task metadata so the overtime loop can detect
    stalls and high error rates. Runs until the task leaves RUNNING/OVERTIME.
    """
    # Propagate session state so StateProxy resolves correctly in this thread
    if _session_state is not None:
        set_current_state(_session_state)
    snapshots = []  # list of (timestamp, func_count, error_count)
    baseline_warnings = state.get_warning_count()
    while True:
        task = state.get_task(task_id)
        if not task or task["status"] not in (TASK_RUNNING, TASK_OVERTIME):
            break
        try:
            count = len(project.kb.functions)
        except Exception:
            count = 0
        error_count = max(0, state.get_warning_count() - baseline_warnings)
        now = time.time()
        snapshots.append((now, count, error_count))
        # Keep last 20 snapshots (~5 min at 15s interval)
        if len(snapshots) > 20:
            snapshots = snapshots[-20:]
        state.update_task(
            task_id,
            cfg_func_snapshots=list(snapshots),
            cfg_functions_discovered=count,
            cfg_error_count=error_count,
        )
        time.sleep(interval)


def angr_background_worker(filepath: str, task_id: str, mode: str = "auto", arch_hint: str = "amd64",
                           _session_state=None, _progress_bridge=None, _cancel_event=None):
    """
    Unified background worker for Angr analysis.  Supports PE, ELF, Mach-O,
    and shellcode (via ``mode='shellcode'``).

    Uses progress-adaptive timeout: soft timeout → OVERTIME → stall-kill.

    Parameters
    ----------
    _progress_bridge : ProgressBridge, optional
        If provided, progress updates are also pushed to the MCP client
        in real-time via the bridge (in addition to the pollable task registry).
    _cancel_event : threading.Event, optional
        Cooperative cancellation event.  Checked during the overtime loop
        and before writing results.  Set by ``abort_background_task()`` or
        ``cancel_all_background_tasks()``.
    """
    # Propagate the caller's session state so the StateProxy resolves to the
    # correct AnalyzerState inside this thread.
    if _session_state is not None:
        set_current_state(_session_state)
    _current_task_var.set(task_id)

    import angr  # imported here since this only runs when ANGR_AVAILABLE is True

    # Resolve timeouts
    cfg_hard = _safe_env_int("ARKANA_ANGR_CFG_TIMEOUT", ANGR_CFG_TIMEOUT)
    cfg_soft = _safe_env_int("ARKANA_ANGR_CFG_SOFT_TIMEOUT", ANGR_CFG_SOFT_TIMEOUT)
    check_interval = _safe_env_int("ARKANA_OVERTIME_CHECK_INTERVAL", OVERTIME_CHECK_INTERVAL, min_val=5)
    stall_kill = _safe_env_int("ARKANA_OVERTIME_STALL_KILL", OVERTIME_STALL_KILL, min_val=10)
    max_runtime = _safe_env_int("ARKANA_OVERTIME_MAX_RUNTIME", OVERTIME_MAX_RUNTIME, min_val=60)

    bridge = _progress_bridge  # shorter alias
    my_gen = _session_state._analysis_generation if _session_state else 0
    task_start_time = time.time()

    try:
        _update_progress(task_id, 1, "Loading Angr Project...", bridge=bridge)

        # 1. Load Project (mode-aware)
        if mode == "shellcode":
            _update_progress(task_id, 5, f"Loading raw shellcode as {arch_hint}...", bridge=bridge)
            project = angr.Project(
                filepath,
                main_opts={"backend": "blob", "arch": arch_hint},
                auto_load_libs=False,
            )
        else:
            project = angr.Project(filepath, auto_load_libs=False)

        state.set_angr_results(project, None, None, None)
        _update_progress(task_id, 20, "Building Control Flow Graph...", bridge=bridge)

        # 2. Build CFG (the heaviest step) — with progress-adaptive timeout
        monitor = threading.Thread(
            target=_cfg_stall_monitor,
            args=(project, task_id),
            kwargs={"_session_state": _session_state},
            daemon=True,
        )
        monitor.start()

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        cfg = None
        try:
            future = executor.submit(
                project.analyses.CFGFast,
                normalize=True,
                resolve_indirect_jumps=True,
            )

            # --- Backward compat: soft timeout disabled → old single-timeout ---
            if cfg_soft <= 0:
                try:
                    cfg = future.result(timeout=cfg_hard)
                except concurrent.futures.TimeoutError:
                    _handle_cfg_hard_timeout(task_id, project, cfg_hard, filepath, bridge)
                    return
            else:
                # --- Phase 1: Wait for soft timeout ---
                try:
                    cfg = future.result(timeout=cfg_soft)
                except concurrent.futures.TimeoutError:
                    # Enter overtime
                    try:
                        funcs = len(project.kb.functions)
                    except Exception:
                        funcs = 0
                    state.update_task(task_id, status=TASK_OVERTIME,
                                      overtime_since_epoch=time.time(),
                                      progress_message=f"CFG overtime ({funcs} funcs, still building...)")
                    logger.info("CFG build entered overtime after %ds (%d funcs)", cfg_soft, funcs)
                    if bridge is not None:
                        bridge.info(f"CFG entered overtime ({funcs} funcs, still building).", force=True)

                    # --- Phase 2: Progress-adaptive overtime loop ---
                    last_known_funcs = funcs
                    stall_start = None
                    while True:
                        try:
                            cfg = future.result(timeout=check_interval)
                            break  # Completed during overtime
                        except concurrent.futures.TimeoutError:
                            pass

                        # Check if cancelled (abort or file switch)
                        if _cancel_event is not None and _cancel_event.is_set():
                            logger.info("CFG task %s cancelled during overtime", task_id)
                            state.update_task(task_id, status=TASK_FAILED,
                                              error="Cancelled during overtime.",
                                              progress_message="Cancelled")
                            executor.shutdown(wait=False, cancel_futures=True)
                            return

                        # Check generation
                        if _session_state and _session_state._analysis_generation != my_gen:
                            logger.info("CFG task %s: file switched during overtime — discarding", task_id)
                            state.update_task(task_id, status=TASK_FAILED,
                                              error="File was switched during analysis.",
                                              progress_message="Discarded — file switched")
                            executor.shutdown(wait=False, cancel_futures=True)
                            return

                        try:
                            current_funcs = len(project.kb.functions)
                        except Exception:
                            current_funcs = last_known_funcs

                        # Check error rate from stall monitor snapshots
                        task_data = state.get_task(task_id)
                        cfg_errors = task_data.get("cfg_error_count", 0) if task_data else 0

                        if current_funcs > last_known_funcs:
                            # Progress! Reset stall timer
                            last_known_funcs = current_funcs
                            stall_start = None
                            state.update_task(task_id,
                                              progress_message=f"CFG overtime ({current_funcs} funcs, progressing...)",
                                              cfg_functions_discovered=current_funcs,
                                              last_progress_epoch=time.time())
                        else:
                            # No progress
                            if stall_start is None:
                                stall_start = time.time()
                            stalled_for = time.time() - stall_start
                            if stalled_for >= stall_kill:
                                if current_funcs >= _CFG_PARTIAL_MIN:
                                    # Accept partial CFG instead of discarding
                                    _accept_partial_cfg(
                                        task_id, project,
                                        reason=f"stalled for {int(stalled_for)}s",
                                        func_count=current_funcs,
                                        error_count=cfg_errors,
                                        bridge=bridge,
                                    )
                                else:
                                    error_msg = (
                                        f"CFG stalled for {int(stalled_for)}s ({current_funcs} funcs). "
                                        "Too few functions to accept partial result. "
                                        "Binary may be packed — try auto_unpack_pe()."
                                    )
                                    logger.warning("CFG stall-killed for %s (%d funcs)", filepath, current_funcs)
                                    state.update_task(task_id, status=TASK_FAILED, error=error_msg,
                                                      progress_message=f"CFG stall-killed ({current_funcs} funcs)")
                                    if bridge is not None:
                                        bridge.info(f"CFG stall-killed ({current_funcs} funcs).", force=True)
                                executor.shutdown(wait=False, cancel_futures=True)
                                return

                        # Check for high error rate with slow progress
                        # (catches degraded builds that make progress but produce many errors)
                        if (cfg_errors >= _CFG_ERROR_RATE
                                and current_funcs >= _CFG_PARTIAL_MIN
                                and stall_start is not None):
                            _accept_partial_cfg(
                                task_id, project,
                                reason=f"high error rate ({cfg_errors} errors, progress stalled)",
                                func_count=current_funcs,
                                error_count=cfg_errors,
                                bridge=bridge,
                            )
                            executor.shutdown(wait=False, cancel_futures=True)
                            return

                        # Check absolute ceiling
                        total_elapsed = time.time() - task_start_time
                        if max_runtime > 0 and total_elapsed >= max_runtime:
                            try:
                                f_count = len(project.kb.functions)
                            except Exception:
                                f_count = 0
                            if f_count >= _CFG_PARTIAL_MIN:
                                _accept_partial_cfg(
                                    task_id, project,
                                    reason=f"max runtime ({int(max_runtime)}s) exceeded",
                                    func_count=f_count,
                                    error_count=cfg_errors,
                                    bridge=bridge,
                                )
                            else:
                                error_msg = (
                                    f"Absolute max runtime ({int(max_runtime)}s) exceeded "
                                    f"({f_count} funcs discovered)."
                                )
                                state.update_task(task_id, status=TASK_FAILED, error=error_msg,
                                                  progress_message=f"Max runtime exceeded ({f_count} funcs)")
                            executor.shutdown(wait=False, cancel_futures=True)
                            return

            if cfg is None:
                # Should not reach here, but safety net
                _handle_cfg_hard_timeout(task_id, project, cfg_hard, filepath, bridge)
                return

            # Cancel and generation guard before writing results
            if _cancel_event is not None and _cancel_event.is_set():
                logger.info("CFG task %s cancelled before result write", task_id)
                state.update_task(task_id, status=TASK_FAILED,
                                  error="Cancelled before result write.",
                                  progress_message="Cancelled")
                return
            if _session_state and _session_state._analysis_generation != my_gen:
                logger.info("CFG task %s completed but file switched — discarding", task_id)
                state.update_task(task_id, status=TASK_FAILED,
                                  error="File was switched during analysis.",
                                  progress_message="Discarded — file switched")
                return

            state.set_angr_results(project, cfg, None, None)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        _update_progress(task_id, 80, "Identifying loops...", bridge=bridge)

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
                        "blocks": len(loop.body_nodes),  # L10-v10: body_nodes is already a set
                        "subloops": bool(loop.subloops),
                    })
            except Exception:
                continue

        state.set_angr_results(project, cfg, raw_loops, {"resolve_jumps": True, "data_refs": False})

        # Record CFG quality (full build completed)
        try:
            task_data = state.get_task(task_id)
            cfg_errors = task_data.get("cfg_error_count", 0) if task_data else 0
        except Exception:
            cfg_errors = 0
        try:
            func_count = len(cfg.functions)
        except Exception:
            func_count = 0
        state._cfg_quality = {
            "status": "full",
            "functions_discovered": func_count,
            "errors_during_build": cfg_errors,
            "timestamp": time.time(),
        }

        # 4. Mark Complete
        state.update_task(
            task_id,
            status=TASK_COMPLETED,
            result={"message": "Analysis ready."},
            progress_percent=100,
            progress_message="Background analysis complete.",
        )
        if bridge is not None:
            bridge.report_progress(100, 100, force=True)
            bridge.info("Background Angr analysis complete.", force=True)
        print(f"\n[*] Background Angr Analysis finished.", file=sys.stderr)

    except (OSError, RuntimeError, ValueError) as e:
        logger.error("Background Angr analysis failed: %s: %s", type(e).__name__, e, exc_info=True)
        # Salvage partial CFG if enough functions were discovered before the crash
        if _try_salvage_partial(task_id, project, str(e)[:200], bridge):
            pass  # Accepted as partial — don't mark FAILED
        else:
            state.update_task(task_id, status=TASK_FAILED, error=str(e)[:200],
                              progress_message=f"Failed: {str(e)[:200]}")
    except Exception as e:
        logger.error("Background Angr analysis failed unexpectedly: %s: %s", type(e).__name__, e, exc_info=True)
        if _try_salvage_partial(task_id, project, str(e)[:200], bridge):
            pass
        else:
            state.update_task(task_id, status=TASK_FAILED, error=str(e)[:200],
                              progress_message=f"Failed: {str(e)[:200]}")
    finally:
        # Clean up cancel event and thread ref (mirrors _run_background_task_wrapper)
        if _session_state is not None:
            _session_state.unregister_task_infra(task_id)


def _handle_cfg_hard_timeout(task_id, project, cfg_timeout, filepath, bridge):
    """Handle old-style hard CFG timeout (when soft timeout is disabled).

    Accepts a partial CFG if enough functions were discovered.
    """
    try:
        funcs_found = len(project.kb.functions)
    except Exception:
        funcs_found = 0

    if funcs_found >= _CFG_PARTIAL_MIN:
        _accept_partial_cfg(
            task_id, project,
            reason=f"hard timeout ({cfg_timeout}s)",
            func_count=funcs_found,
            error_count=0,
            bridge=bridge,
        )
        return

    error_msg = (
        f"CFG build timed out after {cfg_timeout}s "
        f"(discovered {funcs_found} functions — too few for partial). "
        "Binary may be packed. Try auto_unpack_pe()."
    )
    logger.warning("Background Angr CFG timed out after %ds for %s", cfg_timeout, filepath)
    state.update_task(
        task_id,
        status=TASK_FAILED,
        error=error_msg,
        progress_message=f"CFG timed out ({funcs_found} functions discovered)",
    )
    if bridge is not None:
        bridge.info(f"CFG timed out after {cfg_timeout}s. {funcs_found} partial functions available.", force=True)
    print(f"\n[!] Background Angr CFG timed out after {cfg_timeout}s ({funcs_found} functions found).", file=sys.stderr)


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

    # Register cancel event BEFORE set_task so cancel_all_background_tasks()
    # can always find it once the task is visible as RUNNING.
    cancel_event = threading.Event()
    _session_state.register_task_infra(task_id, cancel_event)

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
        kwargs={"_session_state": _session_state, "_cancel_event": cancel_event},
        daemon=True,
    )
    # Register thread BEFORE start so cleanup always finds it
    _session_state.set_task_thread(task_id, angr_thread)
    angr_thread.start()

    logger.info("Background Angr analysis thread started (task_id=%s).", task_id)
    return task_id
