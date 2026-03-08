"""Background auto-enrichment coordinator.

Launches after ``open_file()`` to run triage, classification, similarity
hashing, MITRE mapping, IOC collection, library identification, decompile
sweep, and auto-noting — all in a background daemon thread.

Results are cached on ``AnalyzerState`` so that MCP tools can return them
instantly without re-executing.
"""
import logging
import os
import threading
import time

from typing import Dict, Any, Optional

from arkana.constants import ENRICHMENT_MAX_DECOMPILE, ENRICHMENT_TIMEOUT
from arkana.state import (
    AnalyzerState, TASK_RUNNING, TASK_COMPLETED, TASK_FAILED,
    set_current_state, get_current_state,
)
from arkana.utils import _safe_env_int

logger = logging.getLogger("Arkana")

# Environment overrides
_AUTO_ENRICHMENT_ENABLED = os.environ.get("ARKANA_AUTO_ENRICHMENT", "1") != "0"
_MAX_DECOMPILE = _safe_env_int("ARKANA_ENRICHMENT_MAX_DECOMPILE", ENRICHMENT_MAX_DECOMPILE)

TASK_ID = "auto-enrichment"


def start_enrichment(current_state: AnalyzerState) -> None:
    """Launch the enrichment coordinator as a background daemon thread.

    Safe to call from any context (async or sync).  If enrichment is
    disabled via ``ARKANA_AUTO_ENRICHMENT=0``, this is a no-op.
    """
    if not _AUTO_ENRICHMENT_ENABLED:
        logger.debug("Auto-enrichment disabled via ARKANA_AUTO_ENRICHMENT=0")
        return

    # Resolve StateProxy to concrete AnalyzerState
    if not isinstance(current_state, AnalyzerState):
        current_state = get_current_state()

    # Wait for any previous enrichment thread to acknowledge cancellation
    existing = current_state.get_task(TASK_ID)
    if existing and existing.get("status") == TASK_RUNNING:
        current_state._enrichment_cancel.set()
        # Give old thread up to 5s to notice and exit
        for _ in range(50):
            check = current_state.get_task(TASK_ID)
            if not check or check.get("status") != TASK_RUNNING:
                break
            time.sleep(0.1)

    # Reset cancellation flag for new run
    current_state._enrichment_cancel.clear()

    # H5: Increment generation counter to detect stale workers
    current_state._enrichment_generation += 1
    generation = current_state._enrichment_generation

    current_state.set_task(TASK_ID, {
        "status": TASK_RUNNING,
        "progress_percent": 0,
        "progress_message": "Starting auto-enrichment...",
        "created_at_epoch": time.time(),
        "last_progress_epoch": time.time(),
        "tool": "open_file (auto-enrichment)",
    })

    t = threading.Thread(
        target=_enrichment_worker,
        args=(current_state, generation),
        daemon=True,
        name="arkana-enrichment",
    )
    t.start()
    logger.info("Auto-enrichment background thread started (task_id=%s, gen=%d).", TASK_ID, generation)


def _update(state: AnalyzerState, pct: int, msg: str) -> None:
    """Update enrichment task progress."""
    state.update_task(
        TASK_ID,
        progress_percent=pct,
        progress_message=msg,
        last_progress_epoch=time.time(),
    )


def _cancelled(state: AnalyzerState, generation: int = 0) -> bool:
    """Check if enrichment has been cancelled or superseded by a newer run."""
    if state._enrichment_cancel.is_set():
        return True
    # H5: If generation doesn't match, a newer run has started
    if generation > 0 and state._enrichment_generation != generation:
        return True
    return False


def _enrichment_worker(state: AnalyzerState, generation: int = 0) -> None:
    """Main enrichment coordinator. Runs sequentially through phases."""
    set_current_state(state)

    phases_completed = []
    phases_failed = []

    try:
        # ── Phase 1a: Classify binary purpose ────────────────────────
        if _cancelled(state, generation):
            return
        _update(state, 0, "Classifying binary purpose...")
        try:
            from arkana.mcp.tools_classification import _classify_internal
            result = _classify_internal(state)
            state._cached_classification = result
            phases_completed.append("classify")
        except Exception as e:
            logger.warning("Enrichment: classify failed: %s", e)
            phases_failed.append(("classify", str(e)))

        # ── Phase 1b: Triage report ──────────────────────────────────
        if _cancelled(state, generation):
            return
        _update(state, 2, "Running triage report...")
        try:
            from arkana.mcp.tools_triage import _run_triage_internal

            def _triage_progress(pct, msg=""):
                # Map triage progress (0-100) to enrichment range (2-25)
                mapped = 2 + int(pct * 0.23)
                _update(state, mapped, f"Triage: {msg}" if msg else "Running triage...")

            _run_triage_internal(state, progress_cb=_triage_progress)
            phases_completed.append("triage")
        except Exception as e:
            logger.warning("Enrichment: triage failed: %s", e)
            phases_failed.append(("triage", str(e)))

        # ── Phase 1c: Similarity hashes ──────────────────────────────
        if _cancelled(state, generation):
            return
        _update(state, 25, "Computing similarity hashes...")
        try:
            from arkana.mcp.tools_new_libs import _compute_similarity_internal
            result = _compute_similarity_internal(state)
            if "error" not in result:
                state._cached_similarity_hashes = result
                phases_completed.append("similarity_hashes")
            else:
                phases_failed.append(("similarity_hashes", result["error"]))
        except Exception as e:
            logger.warning("Enrichment: similarity hashes failed: %s", e)
            phases_failed.append(("similarity_hashes", str(e)))

        # ── Phase 2a: MITRE ATT&CK mapping ──────────────────────────
        if _cancelled(state, generation):
            return
        _update(state, 28, "Mapping MITRE ATT&CK techniques...")
        try:
            from arkana.mcp.tools_threat_intel import _map_mitre_internal
            result = _map_mitre_internal(state)
            state._cached_mitre_mapping = result
            phases_completed.append("mitre_attack")
        except Exception as e:
            logger.warning("Enrichment: MITRE mapping failed: %s", e)
            phases_failed.append(("mitre_attack", str(e)))

        # ── Phase 2b: Structured IOCs ────────────────────────────────
        if _cancelled(state, generation):
            return
        _update(state, 30, "Collecting structured IOCs...")
        try:
            from arkana.mcp.tools_ioc import _collect_iocs_internal
            result = _collect_iocs_internal(state)
            state._cached_iocs = result
            phases_completed.append("iocs")
        except Exception as e:
            logger.warning("Enrichment: IOC collection failed: %s", e)
            phases_failed.append(("iocs", str(e)))

        # ── Phase 3: Wait for angr CFG ───────────────────────────────
        if _cancelled(state, generation):
            return
        _update(state, 32, "Waiting for angr CFG...")
        cfg_ready = _wait_for_cfg(state, generation=generation)

        if not cfg_ready:
            _update(state, 35, "Angr CFG not available — skipping angr phases")
            logger.info("Enrichment: skipping angr-dependent phases (CFG not available)")
        else:
            # ── Phase 3a: Library function identification ────────────
            if _cancelled(state, generation):
                return
            _update(state, 35, "Identifying library functions...")
            try:
                from arkana.mcp.tools_angr_disasm import _identify_library_internal
                _identify_library_internal(state)
                phases_completed.append("library_functions")
            except Exception as e:
                logger.warning("Enrichment: library identification failed: %s", e)
                phases_failed.append(("library_functions", str(e)))

            # ── Phase 3b: Decompile sweep ────────────────────────────
            if _cancelled(state, generation):
                return
            _update(state, 40, "Starting decompile sweep...")
            try:
                _decompile_sweep(state, phases_completed, phases_failed, generation=generation)
            except Exception as e:
                logger.warning("Enrichment: decompile sweep failed: %s", e)
                phases_failed.append(("decompile_sweep", str(e)))

            # ── Phase 3c: Auto-note functions ────────────────────────
            if _cancelled(state, generation):
                return
            _update(state, 90, "Auto-noting functions...")
            try:
                _auto_note_sweep(state, generation=generation)
                phases_completed.append("auto_notes")
            except Exception as e:
                logger.warning("Enrichment: auto-note sweep failed: %s", e)
                phases_failed.append(("auto_notes", str(e)))

        # ── Phase 4: Cache save ──────────────────────────────────────
        if _cancelled(state, generation):
            return
        _update(state, 98, "Saving to cache...")
        try:
            _save_enrichment_cache(state)
            phases_completed.append("cache_save")
        except Exception as e:
            logger.warning("Enrichment: cache save failed: %s", e)
            phases_failed.append(("cache_save", str(e)))

        # ── Done ─────────────────────────────────────────────────────
        summary = f"Completed {len(phases_completed)} phases"
        if phases_failed:
            summary += f", {len(phases_failed)} failed: {', '.join(f[0] for f in phases_failed)}"
        state.update_task(
            TASK_ID,
            status=TASK_COMPLETED,
            progress_percent=100,
            progress_message=summary,
            last_progress_epoch=time.time(),
            phases_completed=phases_completed,
            phases_failed=phases_failed,
        )
        logger.info("Auto-enrichment completed: %s", summary)

    except Exception as e:
        logger.error("Auto-enrichment failed: %s", e, exc_info=True)
        state.update_task(
            TASK_ID,
            status=TASK_FAILED,
            progress_percent=0,
            progress_message=f"Failed: {e}",
            last_progress_epoch=time.time(),
        )
    finally:
        # Ensure on-demand flag is cleared
        state._decompile_on_demand_waiting = False


def _wait_for_cfg(state: AnalyzerState, timeout: int = ENRICHMENT_TIMEOUT, generation: int = 0) -> bool:
    """Poll for angr CFG completion. Returns True if CFG is available."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _cancelled(state, generation):
            return False

        # Check if CFG is already available
        proj, cfg = state.get_angr_snapshot()
        if proj is not None and cfg is not None:
            return True

        # Check angr task status
        task = state.get_task("startup-angr")
        if task:
            status = task.get("status", "")
            if status == TASK_COMPLETED:
                # Task completed — check if CFG is now set
                proj, cfg = state.get_angr_snapshot()
                return proj is not None and cfg is not None
            if status == TASK_FAILED:
                return False
        else:
            # No angr task — CFG won't appear
            return False

        time.sleep(0.5)

    return False


def _decompile_sweep(
    state: AnalyzerState,
    phases_completed: list,
    phases_failed: list,
    generation: int = 0,
) -> None:
    """Decompile top-scored functions in priority order."""
    from arkana.mcp.tools_angr_disasm import _build_scored_functions
    from arkana.mcp._input_helpers import _ToolResultCache

    scored = _build_scored_functions(state)
    if not scored:
        return

    # Cache scored functions for other tools
    state._cached_function_scores = scored

    # Import the decompile cache to store results
    from arkana.mcp.tools_angr import _decompile_meta, _get_cached_lines

    max_funcs = min(len(scored), _MAX_DECOMPILE)
    decompiled = 0
    failed = 0

    for i, func_info in enumerate(scored[:max_funcs]):
        if _cancelled(state, generation):
            break

        # Yield to on-demand decompile requests (with 120s timeout)
        if state._decompile_on_demand_waiting:
            wait_deadline = time.time() + 120
            while state._decompile_on_demand_waiting:
                time.sleep(0.1)
                if _cancelled(state, generation) or time.time() > wait_deadline:
                    break

        # Progress: map index to 40-90% range
        pct = 40 + int((i / max_funcs) * 50)
        func_name = func_info.get("name", "unknown")
        _update(state, pct, f"Decompiling {func_name} ({i+1}/{max_funcs})...")

        addr_hex = func_info.get("addr", "")
        try:
            addr_int = int(addr_hex, 16)
        except (ValueError, TypeError):
            continue

        # Skip if already cached (e.g. from a previous session)
        cache_key = (addr_int,)
        if _get_cached_lines(cache_key) is not None:
            continue

        # Acquire decompile lock (with cancellation check)
        acquired = False
        for _ in range(100):  # try for up to 50s
            acquired = state._decompile_lock.acquire(timeout=0.5)
            if acquired:
                break
            if _cancelled(state, generation):
                break
        if not acquired:
            continue
        try:
            proj, cfg = state.get_angr_snapshot()
            if proj is None or cfg is None:
                break

            if addr_int not in cfg.functions:
                continue

            func = cfg.functions[addr_int]
            try:
                dec = proj.analyses.Decompiler(func, cfg=cfg.model)
                if dec.codegen:
                    lines = dec.codegen.text.splitlines()
                    _decompile_meta[cache_key] = {
                        "function_name": func.name,
                        "address": hex(addr_int),
                        "lines": lines,
                    }
                    state._newly_decompiled.append(hex(addr_int))
                    decompiled += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
        finally:
            state._decompile_lock.release()

    if decompiled > 0:
        phases_completed.append(f"decompile_sweep({decompiled})")
    if failed > 0:
        phases_failed.append(("decompile_partial", f"{failed} functions failed"))


def _auto_note_sweep(state: AnalyzerState, generation: int = 0) -> None:
    """Auto-note top functions that have been decompiled."""
    from arkana.mcp.tools_notes import _auto_note_single
    from arkana.mcp.tools_angr import _get_cached_lines

    scored = state._cached_function_scores or []
    noted = 0

    for func_info in scored[:50]:
        if _cancelled(state, generation):
            break

        addr_hex = func_info.get("addr", "")
        try:
            addr_int = int(addr_hex, 16)
        except (ValueError, TypeError):
            continue

        # Only auto-note functions that were decompiled
        cache_key = (addr_int,)
        if _get_cached_lines(cache_key) is None:
            continue

        # Skip if already noted
        existing = state.get_notes(category="function", address=addr_hex)
        if existing:
            continue

        try:
            _auto_note_single(addr_hex)
            noted += 1
        except Exception as e:
            logger.debug("Enrichment: auto_note failed for %s: %s", addr_hex, e)

    if noted:
        # Persist notes to cache
        try:
            from arkana.mcp.tools_notes import _persist_notes_to_cache
            _persist_notes_to_cache()
        except Exception:
            logger.debug("Enrichment: note cache persistence failed", exc_info=True)

    logger.debug("Enrichment: auto-noted %d functions", noted)


def _save_enrichment_cache(state: AnalyzerState) -> None:
    """Persist enrichment results to the disk cache.

    Enrichment data lives on state attributes (``_cached_triage``, etc.) and
    on ``_decompile_meta`` at runtime.  For disk persistence we temporarily
    inject these into ``state.pe_data``, write the blob, then pop the keys
    so data exists in only one place in memory.
    """
    try:
        from arkana.config import analysis_cache

        if state.pe_data is None:
            return

        # Keys we'll temporarily add to pe_data for serialization
        _enrichment_keys = []

        try:
            # Store cached results in pe_data for cache persistence
            if state._cached_triage:
                state.pe_data['_cached_triage'] = state._cached_triage
                _enrichment_keys.append('_cached_triage')
            if state._cached_classification:
                state.pe_data['_cached_classification'] = state._cached_classification
                _enrichment_keys.append('_cached_classification')
            if state._cached_similarity_hashes:
                state.pe_data['_cached_similarity_hashes'] = state._cached_similarity_hashes
                _enrichment_keys.append('_cached_similarity_hashes')
            if state._cached_mitre_mapping:
                state.pe_data['_cached_mitre_mapping'] = state._cached_mitre_mapping
                _enrichment_keys.append('_cached_mitre_mapping')
            if state._cached_iocs:
                state.pe_data['_cached_iocs'] = state._cached_iocs
                _enrichment_keys.append('_cached_iocs')
            if state._cached_function_scores:
                state.pe_data['_cached_function_scores'] = state._cached_function_scores
                _enrichment_keys.append('_cached_function_scores')

            # Save decompiled functions (metadata + code lines) for cache restore
            try:
                from arkana.mcp.tools_angr import _decompile_meta
                if _decompile_meta:
                    decompiled_funcs = []
                    # Snapshot to avoid RuntimeError: dict changed size during iteration
                    for key, meta in dict(_decompile_meta).items():
                        if isinstance(key, tuple) and key:
                            decompiled_funcs.append({
                                "addr_int": key[0],
                                "function_name": meta.get("function_name", ""),
                                "address": meta.get("address", ""),
                                "lines": meta.get("lines"),
                            })
                    if decompiled_funcs:
                        state.pe_data['_decompiled_functions'] = decompiled_funcs
                        _enrichment_keys.append('_decompiled_functions')
            except ImportError:
                pass

            sha = state.pe_data.get("file_hashes", {}).get("sha256")
            if sha and state.filepath:
                analysis_cache.put(sha, state.pe_data, state.filepath)

                # Also save session metadata
                analysis_cache.update_session_data(
                    sha,
                    notes=state.get_all_notes_snapshot(),
                    tool_history=state.get_tool_history_snapshot(),
                    artifacts=state.get_all_artifacts_snapshot(),
                    renames=state.get_all_renames_snapshot(),
                    custom_types=state.get_all_types_snapshot(),
                    triage_status=state.get_all_triage_snapshot(),
                )
        finally:
            # Always clean up injected keys — even if cache.put() throws
            for key in _enrichment_keys:
                state.pe_data.pop(key, None)

    except Exception as e:
        logger.warning("Enrichment: cache save failed: %s", e)
