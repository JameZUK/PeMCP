"""Background auto-enrichment coordinator.

Launches after ``open_file()`` to run triage, classification, similarity
hashing, MITRE mapping, IOC collection, library identification, decompile
sweep, and auto-noting — all in a background daemon thread.

Results are cached on ``AnalyzerState`` so that MCP tools can return them
instantly without re-executing.
"""
import datetime
import logging
import os
import threading
import time

from typing import Dict, Any, Optional

# Interval between periodic saves during the decompile sweep (seconds).
_SWEEP_SAVE_INTERVAL = 60

# Minimum interval between async (on-demand) saves (seconds).
_ASYNC_SAVE_INTERVAL = 30

# Per-state lock is used for throttled async saves (state._async_save_lock).

from arkana.constants import ENRICHMENT_MAX_DECOMPILE, ENRICHMENT_TIMEOUT, MAX_ENRICHMENT_BLOCKS
from arkana.state import (
    AnalyzerState, TASK_RUNNING, TASK_OVERTIME, TASK_COMPLETED, TASK_FAILED,
    set_current_state, get_current_state,
)
from arkana.utils import _safe_env_int

logger = logging.getLogger("Arkana")

# Timeout for on-demand decompile yield (seconds)
_ON_DEMAND_YIELD_TIMEOUT = 120

# Environment overrides
_AUTO_ENRICHMENT_ENABLED = os.environ.get("ARKANA_AUTO_ENRICHMENT", "1") != "0"
_MAX_DECOMPILE = _safe_env_int("ARKANA_ENRICHMENT_MAX_DECOMPILE", ENRICHMENT_MAX_DECOMPILE, min_val=0)
_MAX_ENRICHMENT_BLOCKS = _safe_env_int("ARKANA_MAX_ENRICHMENT_BLOCKS", MAX_ENRICHMENT_BLOCKS, min_val=10)

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

    # Atomically cancel previous run and increment generation to prevent
    # a race where two threads see the same generation.
    previous_was_running = False
    with current_state._enrichment_gen_lock:
        existing = current_state.get_task(TASK_ID)
        if existing and existing.get("status") == TASK_RUNNING:
            current_state._enrichment_cancel.set()
            previous_was_running = True

        current_state._enrichment_generation += 1
        generation = current_state._enrichment_generation

    # Wait for previous thread to notice cancellation (outside lock to avoid blocking)
    if previous_was_running:
        for _ in range(50):
            check = current_state.get_task(TASK_ID)
            if not check or check.get("status") != TASK_RUNNING:
                break
            time.sleep(0.1)

    # Reset cancellation flag for new run INSIDE the lock to prevent a
    # 3rd concurrent start_enrichment() from having its cancel signal wiped.
    with current_state._enrichment_gen_lock:
        # Only clear if we are still the latest generation
        if current_state._enrichment_generation == generation:
            current_state._enrichment_cancel.clear()
        else:
            # A newer start_enrichment() call already superseded us
            return

    current_state.set_task(TASK_ID, {
        "status": TASK_RUNNING,
        "progress_percent": 0,
        "progress_message": "Starting auto-enrichment...",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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
    # Register in standard background task infra BEFORE starting the thread
    # so abort_background_task() and cancel_all_background_tasks() work.
    # Reuse _enrichment_cancel as the cancel event so both mechanisms are unified.
    current_state.register_task_infra(TASK_ID, current_state._enrichment_cancel, thread=t)
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
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
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
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
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
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
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
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
            return
        _update(state, 26, "Mapping MITRE ATT&CK techniques...")
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
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
            return
        _update(state, 27, "Collecting structured IOCs...")
        try:
            from arkana.mcp.tools_ioc import _collect_iocs_internal
            result = _collect_iocs_internal(state)
            state._cached_iocs = result
            phases_completed.append("iocs")
        except Exception as e:
            logger.warning("Enrichment: IOC collection failed: %s", e)
            phases_failed.append(("iocs", str(e)))

        # ── Phase 2c: Malware family identification ──────────────
        # Runs after IOCs so _cached_iocs evidence is available for matching.
        if _cancelled(state, generation):
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
            return
        _update(state, 28, "Identifying malware family...")
        try:
            from arkana.mcp.tools_malware_identify import _identify_family_internal
            result = _identify_family_internal(state)
            if result and not result.get("error"):
                state._cached_malware_family = result
                phases_completed.append("malware_family")
        except Exception as e:
            logger.warning("Enrichment: malware family ID failed: %s", e)
            phases_failed.append(("malware_family", str(e)))

        # ── Phase 2d: API hash detection ──────────────────────────
        if _cancelled(state, generation):
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
            return
        _update(state, 29, "Scanning for API hashes...")
        try:
            from arkana.mcp.tools_pe_extended import _scan_api_hashes_internal
            result = _scan_api_hashes_internal(state)
            if result and result.get("resolved_count", 0) > 0:
                state._cached_api_hashes = result
                phases_completed.append("api_hashes")
        except Exception as e:
            logger.warning("Enrichment: API hash scan failed: %s", e)
            phases_failed.append(("api_hashes", str(e)))

        # ── Phase 2e: C2 indicator matching ───────────────────────
        if _cancelled(state, generation):
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
            return
        _update(state, 30, "Matching C2 indicators...")
        try:
            from arkana.mcp.tools_malware_detect import _match_c2_internal
            result = _match_c2_internal(state)
            if result and (result.get("indicators") or result.get("matches")):
                state._cached_c2_indicators = result
                phases_completed.append("c2_indicators")
        except Exception as e:
            logger.warning("Enrichment: C2 indicator matching failed: %s", e)
            phases_failed.append(("c2_indicators", str(e)))

        # ── Phase 2f: DGA indicator detection ─────────────────────
        if _cancelled(state, generation):
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
            return
        _update(state, 31, "Detecting DGA indicators...")
        try:
            from arkana.mcp.tools_malware_detect import _detect_dga_internal
            result = _detect_dga_internal(state)
            if result and (result.get("indicators") or result.get("dga_score", 0) > 0):
                state._cached_dga_indicators = result
                phases_completed.append("dga_indicators")
        except Exception as e:
            logger.warning("Enrichment: DGA detection failed: %s", e)
            phases_failed.append(("dga_indicators", str(e)))

        # ── Phase 2g: Crypto constant detection ───────────────────
        if _cancelled(state, generation):
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
            return
        _update(state, 32, "Detecting crypto constants...")
        try:
            from arkana.mcp.tools_pe_extended import _detect_crypto_internal
            result = _detect_crypto_internal(state)
            if result and result.get("crypto_constants"):
                state._cached_crypto_constants = result
                phases_completed.append("crypto_constants")
        except Exception as e:
            logger.warning("Enrichment: crypto detection failed: %s", e)
            phases_failed.append(("crypto_constants", str(e)))

        # ── Incremental save: persist fast-phase results ──────────────
        try:
            _save_enrichment_cache(state)
            logger.debug("Enrichment: incremental save after fast phases")
        except Exception as e:
            logger.warning("Enrichment: incremental save failed: %s", e)

        # ── Phase 3: Wait for angr CFG ───────────────────────────────
        if _cancelled(state, generation):
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
            return
        _update(state, 33, "Waiting for angr CFG...")
        cfg_ready = _wait_for_cfg(state, generation=generation)

        if not cfg_ready:
            _update(state, 35, "Angr CFG not available — skipping angr phases")
            logger.info("Enrichment: skipping angr-dependent phases (CFG not available)")
        else:
            # ── Phase 3a: Library function identification ────────────
            if _cancelled(state, generation):
                state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
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
                state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
                return
            _update(state, 40, "Starting decompile sweep...")
            try:
                _decompile_sweep(state, phases_completed, phases_failed, generation=generation)
            except Exception as e:
                logger.warning("Enrichment: decompile sweep failed: %s", e)
                phases_failed.append(("decompile_sweep", str(e)))

            # ── Phase 3c: Auto-note functions ────────────────────────
            if _cancelled(state, generation):
                state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
                return
            _update(state, 90, "Auto-noting functions...")
            try:
                _auto_note_sweep(state, generation=generation)
                phases_completed.append("auto_notes")
            except Exception as e:
                logger.warning("Enrichment: auto-note sweep failed: %s", e)
                phases_failed.append(("auto_notes", str(e)))

        # ── Phase 3d: BSim auto-index ──────────────────────────────
        if _cancelled(state, generation):
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
            return
        try:
            _bsim_auto_index(state, generation=generation)
            phases_completed.append("bsim_index")
        except Exception as e:
            logger.debug("Enrichment: BSim auto-index skipped: %s", e)
            # Not added to phases_failed — BSim indexing is optional/best-effort

        # ── Phase 4: Cache save ──────────────────────────────────────
        if _cancelled(state, generation):
            state.update_task(TASK_ID, status=TASK_FAILED, progress_message="Cancelled")
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
            progress_message=f"Failed: {str(e)[:200]}",  # M4-v10: truncate exception
            last_progress_epoch=time.time(),
        )
    finally:
        # M11-v10: Removed unconditional counter reset — the counter is self-balancing
        # (each increment in tools_angr.py has a matching decrement). Resetting here
        # corrupts the counter if an on-demand decompile is in flight.
        # Clean up standard background task infra entries
        state.unregister_task_infra(TASK_ID)


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
            # TASK_OVERTIME: CFG is still building — keep waiting
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
    from arkana.mcp.tools_angr import _set_decompile_meta, _get_cached_lines, _make_decompile_key

    max_funcs = min(len(scored), _MAX_DECOMPILE)
    decompiled = 0
    failed = 0
    skipped_large = 0
    last_save_time = time.time()

    for i, func_info in enumerate(scored[:max_funcs]):
        if _cancelled(state, generation):
            break

        # Yield to on-demand decompile requests (with 120s timeout)
        if state._decompile_on_demand_count > 0:
            wait_deadline = time.time() + _ON_DEMAND_YIELD_TIMEOUT
            while state._decompile_on_demand_count > 0:
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
        cache_key = _make_decompile_key(addr_int)
        if _get_cached_lines(cache_key) is not None:
            continue

        # Skip very large functions that can block angr's Decompiler for
        # minutes (uninterruptible C extension call).  These can still be
        # decompiled on-demand via decompile_function_with_angr.
        block_count = func_info.get("blocks", 0)
        if block_count > _MAX_ENRICHMENT_BLOCKS:
            skipped_large += 1
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
                from arkana.mcp._angr_helpers import _safe_decompile, DECOMPILE_FALLBACK_NOTE
                dec, used_fallback = _safe_decompile(proj, func, cfg.model)
                if dec.codegen:
                    lines = dec.codegen.text.splitlines()
                    meta = {
                        "function_name": func.name,
                        "address": hex(addr_int),
                        "lines": lines,
                    }
                    if used_fallback:
                        meta["note"] = DECOMPILE_FALLBACK_NOTE
                    _set_decompile_meta(cache_key, meta)
                    # Reclaim KB decompiler artifacts now that text is cached
                    if proj is not None:
                        from arkana.mcp._angr_helpers import _cleanup_kb_decompile_artifacts
                        _cleanup_kb_decompile_artifacts(proj, addr_int)
                    state._newly_decompiled.append(hex(addr_int))
                    decompiled += 1

                    # Periodic save: persist progress every _SWEEP_SAVE_INTERVAL seconds
                    now = time.time()
                    if now - last_save_time >= _SWEEP_SAVE_INTERVAL:
                        try:
                            _save_enrichment_cache(state)
                            last_save_time = now
                            logger.debug("Enrichment: periodic sweep save (%d decompiled)", decompiled)
                        except Exception:
                            pass  # Best-effort; don't abort sweep
                else:
                    failed += 1
            except Exception:
                failed += 1
        finally:
            state._decompile_lock.release()

    if decompiled > 0:
        suffix = f", {skipped_large} skipped (>{_MAX_ENRICHMENT_BLOCKS} blocks)" if skipped_large else ""
        phases_completed.append(f"decompile_sweep({decompiled}{suffix})")
    if failed > 0:
        phases_failed.append(("decompile_partial", f"{failed} functions failed"))


def _auto_note_sweep(state: AnalyzerState, generation: int = 0) -> None:
    """Auto-note top functions that have been decompiled."""
    from arkana.mcp.tools_notes import _auto_note_single
    from arkana.mcp.tools_angr import _get_cached_lines, _make_decompile_key

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
        cache_key = _make_decompile_key(addr_int)
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

    # Notes are persisted via the project overlay flush daemon — no
    # explicit cache write needed (cache wrapper v2 strips user state).
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

        # Build a separate dict for serialization instead of mutating pe_data.
        # Snapshot all cached fields under _pe_lock to avoid TOCTOU races —
        # CPython's GIL makes individual reads atomic, but we need a consistent
        # set of fields that all correspond to the same pe_data generation.
        with state._pe_lock:
            serializable = dict(state.pe_data)
            cached_triage = state._cached_triage
            cached_classification = state._cached_classification
            cached_similarity_hashes = state._cached_similarity_hashes
            cached_mitre_mapping = state._cached_mitre_mapping
            cached_iocs = state._cached_iocs
            cached_function_scores = state._cached_function_scores
            cached_malware_family = state._cached_malware_family
            cached_api_hashes = state._cached_api_hashes
            cached_c2_indicators = state._cached_c2_indicators
            cached_dga_indicators = state._cached_dga_indicators
            cached_crypto_constants = state._cached_crypto_constants

        if cached_triage:
            serializable['_cached_triage'] = cached_triage
        if cached_classification:
            serializable['_cached_classification'] = cached_classification
        if cached_similarity_hashes:
            serializable['_cached_similarity_hashes'] = cached_similarity_hashes
        if cached_mitre_mapping:
            serializable['_cached_mitre_mapping'] = cached_mitre_mapping
        if cached_iocs:
            serializable['_cached_iocs'] = cached_iocs
        if cached_function_scores:
            serializable['_cached_function_scores'] = cached_function_scores
        if cached_malware_family:
            serializable['_cached_malware_family'] = cached_malware_family
        if cached_api_hashes:
            serializable['_cached_api_hashes'] = cached_api_hashes
        if cached_c2_indicators:
            serializable['_cached_c2_indicators'] = cached_c2_indicators
        if cached_dga_indicators:
            serializable['_cached_dga_indicators'] = cached_dga_indicators
        if cached_crypto_constants:
            serializable['_cached_crypto_constants'] = cached_crypto_constants

        # Save decompiled functions (metadata + code lines) for cache restore
        # Only save entries belonging to the current session (key[0] == session UUID)
        try:
            from arkana.mcp.tools_angr import _decompile_meta, _decompile_meta_lock
            session_uuid = state._state_uuid
            with _decompile_meta_lock:
                decompiled_funcs = []
                for key, meta in _decompile_meta.items():
                    if isinstance(key, tuple) and len(key) >= 2 and key[0] == session_uuid:
                        decompiled_funcs.append({
                            "addr_int": key[1],
                            "function_name": meta.get("function_name", ""),
                            "address": meta.get("address", ""),
                            "lines": meta.get("lines"),
                        })
            if decompiled_funcs:
                serializable['_decompiled_functions'] = decompiled_funcs
        except ImportError:
            pass

        sha = serializable.get("file_hashes", {}).get("sha256")
        if sha and state.filepath:
            # M5-v8: Pass session data directly to put() instead of calling
            # put() then update_session_data() — avoids redundant gzip
            # decompress + recompress cycle (double I/O).
            analysis_cache.put(
                sha, serializable, state.filepath,
                notes=state.get_all_notes_snapshot(),
                tool_history=state.get_tool_history_snapshot(),
                artifacts=state.get_all_artifacts_snapshot(),
                renames=state.get_all_renames_snapshot(),
                custom_types=state.get_all_types_snapshot(),
                triage_status=state.get_all_triage_snapshot(),
            )

    except Exception as e:
        logger.warning("Enrichment: cache save failed: %s", e)


def save_decompile_cache_async(state: AnalyzerState) -> None:
    """Trigger a throttled, non-blocking cache save after an on-demand decompile.

    Called from ``tools_angr.decompile_function_with_angr`` and
    ``state_api.trigger_decompile`` so that newly-decompiled functions are
    persisted to disk without waiting for the enrichment pipeline to finish.

    Throttled to at most one save per ``_ASYNC_SAVE_INTERVAL`` seconds.
    Runs in a daemon thread so the caller is never blocked.
    """
    # Quick guard: nothing to save if no PE data or no file hash
    if state.pe_data is None:
        return
    sha = state.pe_data.get("file_hashes", {}).get("sha256")
    if not sha:
        return

    now = time.time()
    # Use the async_save_lock for an atomic check-and-update of the throttle
    # timestamp to prevent TOCTOU races where multiple threads pass the
    # interval check simultaneously.
    if not state._async_save_lock.acquire(blocking=False):
        return  # Another save is already running
    try:
        if now - state._last_decompile_save_time < _ASYNC_SAVE_INTERVAL:
            state._async_save_lock.release()
            return
        state._last_decompile_save_time = now
    except BaseException:
        state._async_save_lock.release()
        raise

    # Lock is held — run save in a daemon thread and release when done.
    def _bg_save():
        try:
            _save_enrichment_cache(state)
            logger.debug("Async decompile cache save completed")
        except Exception as e:
            logger.debug("Async decompile cache save failed: %s", e)
        finally:
            state._async_save_lock.release()

    try:
        t = threading.Thread(target=_bg_save, daemon=True, name="arkana-async-save")
        t.start()
    except Exception:
        # Release the lock if thread creation/start fails to prevent deadlock
        state._async_save_lock.release()
        raise


# ---------------------------------------------------------------------------
#  BSim auto-index (Phase 3d)
# ---------------------------------------------------------------------------

def _bsim_auto_index(state: AnalyzerState, *, generation: int = 0) -> None:
    """Index the loaded binary's functions into the BSim signature DB.

    Skips if:
    - BSim auto-index is disabled (ARKANA_BSIM_AUTO_INDEX=0)
    - angr is not available
    - The binary is already indexed (same SHA256 in DB)
    - No CFG is available
    """
    from arkana.utils import _safe_env_int

    # Check config — env var overrides constant
    enabled = _safe_env_int("ARKANA_BSIM_AUTO_INDEX", 1, min_val=0, max_val=1)
    if not enabled:
        logger.debug("BSim auto-index disabled via ARKANA_BSIM_AUTO_INDEX=0")
        return

    try:
        from arkana.imports import ANGR_AVAILABLE
        if not ANGR_AVAILABLE:
            return

        from arkana.mcp._bsim_features import (
            _db_write_lock,
            extract_function_features,
            is_binary_indexed,
            is_trivial_function,
            register_binary,
            store_functions_batch,
            update_binary_function_count,
        )
    except ImportError:
        return

    filepath = state.filepath
    if not filepath:
        return

    # Compute SHA256
    import hashlib
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
    except OSError:
        return
    file_hash = sha256.hexdigest()

    # Skip if already indexed
    if is_binary_indexed(file_hash):
        logger.debug("BSim auto-index: %s already in DB, skipping", os.path.basename(filepath))
        return

    # Need angr project + CFG
    project, cfg = state.get_angr_snapshot()
    if cfg is None or project is None:
        return

    _update(state, 93, "BSim auto-indexing...")
    logger.info("BSim auto-index: indexing %s", os.path.basename(filepath))

    all_funcs = [
        f for f in cfg.functions.values()
        if not is_trivial_function(f)
    ]
    all_funcs.sort(key=lambda f: f.addr)
    total = len(all_funcs)
    if total == 0:
        return

    arch = "unknown"
    try:
        arch = project.arch.name
    except Exception:
        pass

    file_size = 0
    try:
        file_size = os.path.getsize(filepath)
    except OSError:
        pass

    _BATCH_SIZE = 50
    indexed_count = 0

    with _db_write_lock:
        binary_id, conn = register_binary(
            sha256=file_hash,
            filename=os.path.basename(filepath),
            architecture=arch,
            file_size=file_size,
            source="user",
        )

    try:
        batch = []
        for func in all_funcs:
            # Check cancellation periodically
            if _cancelled(state, generation):
                break
            try:
                feat = extract_function_features(project, cfg, func, include_vex=False)
                batch.append(feat)
                indexed_count += 1
            except Exception:
                pass

            if len(batch) >= _BATCH_SIZE:
                with _db_write_lock:
                    store_functions_batch(conn, binary_id, batch)
                batch.clear()

        with _db_write_lock:
            if batch:
                store_functions_batch(conn, binary_id, batch)
                batch.clear()
            update_binary_function_count(conn, binary_id, indexed_count)
    finally:
        conn.close()

    logger.info("BSim auto-index: indexed %d/%d functions for %s",
                indexed_count, total, os.path.basename(filepath))
