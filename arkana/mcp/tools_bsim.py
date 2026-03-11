"""MCP tools for BSim-inspired function similarity analysis.

Provides 5 tools for extracting function feature vectors, comparing functions
across binaries, and managing a persistent function signature database.
"""

import asyncio
import datetime
import hashlib
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from arkana.config import state, logger, Context, ANGR_AVAILABLE
from arkana.constants import BSIM_DEFAULT_THRESHOLD, BSIM_BACKGROUND_TIMEOUT
from arkana.mcp.server import (
    tool_decorator,
    _check_angr_ready,
    _check_mcp_response_size,
)
from arkana.mcp._angr_helpers import (
    _ensure_project_and_cfg,
    _parse_addr,
    _resolve_function_address,
    _raise_on_error_dict,
)
from arkana.mcp._bsim_features import (
    _db_write_lock,
    compute_similarity,
    extract_function_features,
    is_trivial_function,
    list_indexed_binaries,
    query_similar_functions,
    register_binary,
    store_functions_batch,
    update_binary_function_count,
)
from arkana.background import _update_progress, _run_background_task_wrapper, _log_task_exception
from arkana.utils import _safe_env_int

if ANGR_AVAILABLE:
    import angr


# ---------------------------------------------------------------------------
#  Tool 1: extract_function_features
# ---------------------------------------------------------------------------

@tool_decorator
async def extract_function_features_tool(
    ctx: Context,
    function_address: str = "",
    limit: int = 20,
    include_vex: bool = False,
) -> Dict[str, Any]:
    """Extract BSim-style feature vectors from functions in the loaded binary.

    Features include CFG structure, API calls, VEX IR profile, string
    references, constants, and size metrics.  These vectors enable
    architecture-independent function similarity matching.

    Args:
        function_address: Hex address of a specific function (e.g. '0x401000').
                         If empty, extracts features from multiple functions.
        limit: Maximum number of functions to extract (default 20, ignored if
               function_address is specified).
        include_vex: Include full VEX IR operation histogram (verbose, may
                    exceed response limits for many functions).

    Returns:
        dict with 'functions' list of feature vectors and metadata.
    """
    _check_angr_ready("extract_function_features")

    def _extract(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()
        project, cfg = state.get_angr_snapshot()
        if cfg is None:
            return {"error": "CFG not available. Wait for background analysis to complete."}

        results = []

        if function_address:
            addr = _parse_addr(function_address)
            func, _ = _resolve_function_address(addr)
            feat = extract_function_features(project, cfg, func, include_vex=include_vex)
            # Remove internal-only key from response
            feat.pop("_vex_histogram", None)
            feat["address"] = hex(feat["address"])
            results.append(feat)
        else:
            all_funcs = [
                f for f in cfg.functions.values()
                if not is_trivial_function(f)
            ]
            # Sort by address for deterministic output
            all_funcs.sort(key=lambda f: f.addr)
            selected = all_funcs[:limit]

            for func in selected:
                try:
                    feat = extract_function_features(
                        project, cfg, func, include_vex=include_vex,
                    )
                    feat.pop("_vex_histogram", None)
                    feat["address"] = hex(feat["address"])
                    results.append(feat)
                except Exception as e:
                    logger.debug(
                        "Feature extraction failed for %#x: %s", func.addr, e
                    )

        return {
            "status": "success",
            "binary": os.path.basename(state.filepath or "unknown"),
            "functions": results,
            "count": len(results),
            "include_vex": include_vex,
        }

    result = await asyncio.to_thread(_extract)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(
        ctx, result, "extract_function_features", "the 'limit' parameter"
    )


# ---------------------------------------------------------------------------
#  Tool 2: find_similar_functions
# ---------------------------------------------------------------------------

@tool_decorator
async def find_similar_functions(
    ctx: Context,
    function_address: str,
    file_path_b: str,
    metrics: str = "combined",
    threshold: float = BSIM_DEFAULT_THRESHOLD,
    limit: int = 10,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """Compare a function against all functions in another binary.

    Loads the second binary, extracts features from all its non-trivial
    functions, and scores pairwise similarity against the target function.
    Returns ranked matches above the threshold.

    Args:
        function_address: Hex address of the source function (e.g. '0x401000').
        file_path_b: Path to the second binary to compare against.
        metrics: Scoring metric — 'combined' (default), 'cfg_structural',
                'api_calls', 'vex_profile', 'string_refs', 'constants',
                'size_metrics'.
        threshold: Minimum similarity score to include (0.0-1.0, default 0.5).
        limit: Maximum matches to return (default 10).
        run_in_background: Queue as background task (default True).

    Returns:
        dict with ranked matches or task_id for background execution.
    """
    _check_angr_ready("find_similar_functions")

    abs_path_b = os.path.abspath(file_path_b)
    state.check_path_allowed(abs_path_b)
    if not os.path.isfile(abs_path_b):
        raise ValueError(f"File not found: {abs_path_b}")

    source_addr = _parse_addr(function_address)

    bsim_timeout = _safe_env_int("ARKANA_BSIM_BACKGROUND_TIMEOUT", BSIM_BACKGROUND_TIMEOUT)

    _partial_compare = {}  # shared state for on_timeout callback

    def _compare(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()
        project_a, cfg_a = state.get_angr_snapshot()
        if cfg_a is None:
            return {"error": "CFG not available."}

        # Extract source function features
        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Extracting source function features...", bridge=_progress_bridge)

        func_a, _ = _resolve_function_address(source_addr)
        features_a = extract_function_features(project_a, cfg_a, func_a, include_vex=False)

        # Load second binary
        if task_id_for_progress:
            _update_progress(task_id_for_progress, 10, "Loading second binary...", bridge=_progress_bridge)

        proj_b = None
        cfg_b = None
        try:
            proj_b = angr.Project(abs_path_b, auto_load_libs=False)
            cfg_b = proj_b.analyses.CFGFast(normalize=True)

            if task_id_for_progress:
                _update_progress(task_id_for_progress, 40, "Extracting features from second binary...", bridge=_progress_bridge)

            # Extract features from all non-trivial functions in binary B
            funcs_b = [
                f for f in cfg_b.functions.values()
                if not is_trivial_function(f)
            ]

            matches = []
            total = len(funcs_b)
            _partial_compare['total'] = total
            for i, func_b in enumerate(funcs_b):
                try:
                    features_b = extract_function_features(proj_b, cfg_b, func_b, include_vex=False)
                    scores = compute_similarity(features_a, features_b, metrics)
                    score_key = metrics if metrics in scores else "combined"
                    if scores.get(score_key, 0) >= threshold:
                        matches.append({
                            "address": hex(func_b.addr),
                            "name": func_b.name or f"sub_{func_b.addr:x}",
                            "scores": {k: round(v, 4) if isinstance(v, float) else v for k, v in scores.items()},
                        })
                except Exception as e:
                    logger.debug("Comparison failed for %#x: %s", func_b.addr, e)

                _partial_compare['compared'] = i + 1
                _partial_compare['matches'] = len(matches)
                if task_id_for_progress and i % 50 == 0:
                    pct = 40 + int(50 * i / max(total, 1))
                    _update_progress(task_id_for_progress, pct, f"Compared {i}/{total} functions...", bridge=_progress_bridge)

            if task_id_for_progress:
                _update_progress(task_id_for_progress, 95, "Sorting results...", bridge=_progress_bridge)

            matches.sort(key=lambda m: m["scores"].get("combined", 0), reverse=True)
            matches = matches[:limit]

            result = {
                "status": "success",
                "source_function": hex(func_a.addr),
                "source_name": func_a.name or f"sub_{func_a.addr:x}",
                "target_binary": os.path.basename(abs_path_b),
                "functions_compared": total,
                "matches_found": len(matches),
                "threshold": threshold,
                "metrics": metrics,
                "matches": matches,
            }

            return result
        finally:
            # CFFI cleanup — ensure angr Project is freed even on timeout/exception
            try:
                if proj_b is not None and hasattr(proj_b, 'close'):
                    proj_b.close()
            except Exception:
                pass
            del cfg_b, proj_b

    def _on_timeout_compare():
        return {
            "functions_compared": _partial_compare.get('compared', 0),
            "total_functions": _partial_compare.get('total', 0),
            "matches_found": _partial_compare.get('matches', 0),
            "message": f"Timed out after comparing {_partial_compare.get('compared', 0)}/{_partial_compare.get('total', 0)} functions.",
            "hint": "Try: use 'limit' parameter, raise threshold, or increase ARKANA_BSIM_BACKGROUND_TIMEOUT.",
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing function similarity comparison...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "find_similar_functions",
        })
        task = asyncio.create_task(
            _run_background_task_wrapper(task_id, _compare, ctx=ctx,
                                         timeout=bsim_timeout, on_timeout=_on_timeout_compare)
        )
        task.add_done_callback(_log_task_exception(task_id))
        return {
            "status": "queued",
            "task_id": task_id,
            "message": "Function similarity comparison queued. Use check_task_status() to monitor.",
        }

    await ctx.info("Running function similarity comparison (foreground)...")
    result = await asyncio.to_thread(_compare)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(
        ctx, result, "find_similar_functions", "the 'limit' parameter"
    )


# ---------------------------------------------------------------------------
#  Tool 3: build_function_signature_db
# ---------------------------------------------------------------------------

@tool_decorator
async def build_function_signature_db(
    ctx: Context,
    limit: int = 0,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """Index all non-trivial functions from the loaded binary into the signature DB.

    Extracts feature vectors and stores them in a persistent SQLite database
    at ~/.arkana/bsim/signatures.db.  Subsequent calls to query_signature_db
    can search across all indexed binaries.

    Args:
        limit: Maximum functions to index (0 = all non-trivial functions).
        run_in_background: Queue as background task (default True).

    Returns:
        dict with indexing results or task_id for background execution.
    """
    _check_angr_ready("build_function_signature_db")

    bsim_timeout = _safe_env_int("ARKANA_BSIM_BACKGROUND_TIMEOUT", BSIM_BACKGROUND_TIMEOUT)
    _BATCH_SIZE = 50

    _partial_build = {}  # shared state for on_timeout callback

    def _build(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()
        project, cfg = state.get_angr_snapshot()
        if cfg is None:
            return {"error": "CFG not available. Wait for background analysis to complete."}

        filepath = state.filepath
        if not filepath:
            return {"error": "No file loaded."}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Computing file hash...", bridge=_progress_bridge)

        # Compute SHA256 of the file
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        file_size = os.path.getsize(filepath)

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 10, "Enumerating functions...", bridge=_progress_bridge)

        # Collect non-trivial functions
        all_funcs = [
            f for f in cfg.functions.values()
            if not is_trivial_function(f)
        ]
        all_funcs.sort(key=lambda f: f.addr)
        if limit > 0:
            all_funcs = all_funcs[:limit]

        total = len(all_funcs)
        if task_id_for_progress:
            _update_progress(task_id_for_progress, 15, f"Extracting features from {total} functions...", bridge=_progress_bridge)

        # Detect architecture
        arch = "unknown"
        try:
            arch = project.arch.name
        except Exception:
            pass

        # Streaming inserts: register binary, then write features in batches
        # to avoid accumulating all features in memory at once.
        # Lock is held only for DB writes, not during feature extraction.
        indexed_count = 0
        binary_basename = os.path.basename(filepath)
        _partial_build['total'] = total
        _partial_build['binary'] = binary_basename

        # Hold lock only for the register_binary DB write
        with _db_write_lock:
            binary_id, conn = register_binary(
                sha256=file_hash,
                filename=binary_basename,
                architecture=arch,
                file_size=file_size,
            )

        try:
            batch: List[Dict[str, Any]] = []
            for i, func in enumerate(all_funcs):
                try:
                    # include_vex=False: the internal _vex_histogram key is
                    # always populated regardless; include_vex only controls
                    # whether the verbose histogram appears in the response dict.
                    feat = extract_function_features(project, cfg, func, include_vex=False)
                    batch.append(feat)
                    indexed_count += 1
                except Exception as e:
                    logger.debug("Feature extraction failed for %#x: %s", func.addr, e)

                # Flush batch to DB periodically — re-acquire lock for write
                if len(batch) >= _BATCH_SIZE:
                    with _db_write_lock:
                        store_functions_batch(conn, binary_id, batch)
                    batch.clear()

                _partial_build['indexed'] = indexed_count

                if task_id_for_progress and i % 25 == 0:
                    pct = 15 + int(75 * i / max(total, 1))
                    _update_progress(task_id_for_progress, pct, f"Extracted {i}/{total} functions...", bridge=_progress_bridge)

            # Flush remaining batch and update count — hold lock for final writes
            with _db_write_lock:
                if batch:
                    store_functions_batch(conn, binary_id, batch)
                    batch.clear()
                update_binary_function_count(conn, binary_id, indexed_count)

            if task_id_for_progress:
                _update_progress(task_id_for_progress, 95, "Finalizing...", bridge=_progress_bridge)
        finally:
            conn.close()

        return {
            "status": "success",
            "binary": binary_basename,
            "sha256": file_hash,
            "architecture": arch,
            "functions_indexed": indexed_count,
            "functions_skipped": total - indexed_count,
            "binary_id": binary_id,
            "db_path": "~/.arkana/bsim/signatures.db",
        }

    def _on_timeout_build():
        return {
            "functions_indexed": _partial_build.get('indexed', 0),
            "total_functions": _partial_build.get('total', 0),
            "binary": _partial_build.get('binary', 'unknown'),
            "message": f"Timed out after indexing {_partial_build.get('indexed', 0)}/{_partial_build.get('total', 0)} functions. "
                       "Partial results were saved to the signature DB.",
            "hint": "Try: use 'limit' parameter to index fewer functions, or increase ARKANA_BSIM_BACKGROUND_TIMEOUT.",
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        state.set_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing signature DB build...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "build_function_signature_db",
        })
        task = asyncio.create_task(
            _run_background_task_wrapper(task_id, _build, ctx=ctx,
                                         timeout=bsim_timeout, on_timeout=_on_timeout_build)
        )
        task.add_done_callback(_log_task_exception(task_id))
        return {
            "status": "queued",
            "task_id": task_id,
            "message": "Signature DB build queued. Use check_task_status() to monitor.",
        }

    await ctx.info("Building signature database (foreground)...")
    result = await asyncio.to_thread(_build)
    _raise_on_error_dict(result)
    return result


# ---------------------------------------------------------------------------
#  Tool 4: query_signature_db
# ---------------------------------------------------------------------------

@tool_decorator
async def query_signature_db(
    ctx: Context,
    function_address: str,
    threshold: float = 0.6,
    metrics: str = "combined",
    limit: int = 10,
) -> Dict[str, Any]:
    """Search the signature database for functions similar to one in the loaded binary.

    Uses two-phase matching: SQL pre-filter on structural features (eliminates
    ~80-90% of candidates), then full feature vector scoring on the remainder.
    Searches across all previously indexed binaries.

    Args:
        function_address: Hex address of the function to search for (e.g. '0x401000').
        threshold: Minimum similarity score (0.0-1.0, default 0.6).
        metrics: Scoring metric — 'combined', 'cfg_structural', 'api_calls', etc.
        limit: Maximum matches to return (default 10).

    Returns:
        dict with ranked matches from the signature database.
    """
    _check_angr_ready("query_signature_db")
    addr = _parse_addr(function_address)

    def _query():
        _ensure_project_and_cfg()
        project, cfg = state.get_angr_snapshot()
        if cfg is None:
            return {"error": "CFG not available."}

        func, _ = _resolve_function_address(addr)
        features = extract_function_features(project, cfg, func, include_vex=False)

        matches = query_similar_functions(
            target_features=features,
            threshold=threshold,
            metrics=metrics,
            limit=limit,
        )

        return {
            "status": "success",
            "source_function": hex(func.addr),
            "source_name": func.name or f"sub_{func.addr:x}",
            "threshold": threshold,
            "metrics": metrics,
            "matches_found": len(matches),
            "matches": matches,
        }

    result = await asyncio.to_thread(_query)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(
        ctx, result, "query_signature_db", "the 'limit' parameter"
    )


# ---------------------------------------------------------------------------
#  Tool 5: list_signature_dbs
# ---------------------------------------------------------------------------

@tool_decorator
async def list_signature_dbs(
    ctx: Context,
) -> Dict[str, Any]:
    """List all binaries indexed in the function signature database.

    Returns metadata for each indexed binary: SHA256, filename, architecture,
    function count, and indexing date.  No angr dependency — reads only
    SQLite metadata.

    Returns:
        dict with list of indexed binaries and summary statistics.
    """
    binaries = list_indexed_binaries()
    total_functions = sum(b.get("function_count", 0) for b in binaries)
    return {
        "status": "success",
        "binaries": binaries,
        "total_binaries": len(binaries),
        "total_functions": total_functions,
        "db_path": "~/.arkana/bsim/signatures.db",
    }
