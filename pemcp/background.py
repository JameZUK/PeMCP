"""Background task management: heartbeat monitoring, progress tracking, async wrappers."""
import datetime
import sys
import time
import asyncio
import threading
import logging

from pemcp.config import state, logger


def _console_heartbeat_loop():
    """
    Daemon thread that prints the status of running tasks to the console every 30 seconds.
    This ensures the user knows the script is alive even during heavy blocking operations.
    """
    while True:
        time.sleep(30)

        current_time_str = datetime.datetime.now().strftime('%H:%M:%S')

        # Thread-safe snapshot of task IDs and their data
        task_ids = state.get_all_task_ids()

        # Check for running tasks
        running_entries = []
        for task_id in task_ids:
            task = state.get_task(task_id)
            if task and task["status"] == "running":
                running_entries.append((task_id, task))

        if running_entries:
            # Print a clean status block
            print(f"\n--- [Status Heartbeat {current_time_str}] ---")
            for task_id, task in running_entries:
                # Calculate elapsed time
                try:
                    start_time = datetime.datetime.fromisoformat(task["created_at"])
                    elapsed = datetime.datetime.now() - start_time
                    elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
                except Exception:
                    elapsed_str = "?"

                percent = task.get("progress_percent", 0)
                msg = task.get("progress_message", "Processing...")

                print(f" * Task {task_id[:8]}... [{elapsed_str} elapsed] | {percent}%: {msg}")
            print("------------------------------------------\n")

            # Flush stdout to ensure it appears in logs/consoles immediately
            sys.stdout.flush()


def _update_progress(task_id: str, percent: int, message: str):
    """Helper to safely update progress in the global registry."""
    state.update_task(task_id, progress_percent=percent, progress_message=message)


async def _run_background_task_wrapper(task_id: str, func, *args, **kwargs):
    """Helper to run a blocking function in a thread and update the registry."""

    # Lazy-start the heartbeat monitor on the first background request
    if not state.monitor_thread_started:
        monitor_thread = threading.Thread(target=_console_heartbeat_loop, daemon=True)
        monitor_thread.start()
        state.monitor_thread_started = True
        logger.info("Console heartbeat monitor started.")

    try:
        # Inject the task_id into the function if it accepts 'task_id_for_progress'
        kwargs['task_id_for_progress'] = task_id

        result = await asyncio.to_thread(func, *args, **kwargs)

        state.update_task(task_id, result=result, status="completed",
                          progress_percent=100, progress_message="Analysis complete.")
        print(f"\n[*] Task {task_id[:8]} finished successfully.")

    except Exception as e:
        logger.error(f"Background task {task_id} failed: {e}", exc_info=True)
        state.update_task(task_id, error=str(e), status="failed")
        print(f"\n[!] Task {task_id[:8]} failed: {e}")


def _startup_angr_analysis_worker(filepath: str, task_id: str):
    """
    Background thread that performs heavy Angr analysis immediately upon script startup.
    """
    import angr  # imported here since this only runs when ANGR_AVAILABLE is True

    try:
        _update_progress(task_id, 1, "Initializing Angr Project...")

        # 1. Load Project
        project = angr.Project(filepath, auto_load_libs=False)

        # Update Global Project
        state.angr_project = project
        _update_progress(task_id, 10, "Project loaded. Starting CFG generation (Heavy)...")

        # 2. Build CFG (The heaviest step)
        cfg = project.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)

        # Update Global CFG
        state.angr_cfg = cfg
        _update_progress(task_id, 75, "CFG generated. identifying loops...")

        # 3. Pre-calculate Loops
        loop_finder = project.analyses.LoopFinder(kb=project.kb)
        raw_loops = {}
        for loop in loop_finder.loops:
            try:
                node = cfg.model.get_any_node(loop.entry.addr)
                if node and node.function_address:
                    func_addr = node.function_address
                    if func_addr not in raw_loops: raw_loops[func_addr] = []
                    raw_loops[func_addr].append({
                        "entry": hex(loop.entry.addr),
                        "blocks": len(list(loop.body_nodes)),
                        "subloops": bool(loop.subloops)
                    })
            except Exception: continue

        # Update Global Loop Cache
        state.angr_loop_cache = raw_loops
        state.angr_loop_cache_config = {"resolve_jumps": True, "data_refs": False}

        # 4. Mark Complete
        state.update_task(task_id, status="completed",
                          result={"message": "Startup analysis completed successfully."})
        _update_progress(task_id, 100, "Startup pre-analysis complete.")
        print(f"\n[*] Background Startup Analysis finished.")

    except Exception as e:
        logger.error(f"Startup Angr analysis failed: {e}")
        state.update_task(task_id, status="failed", error=str(e))
        _update_progress(task_id, 0, f"Failed: {e}")
