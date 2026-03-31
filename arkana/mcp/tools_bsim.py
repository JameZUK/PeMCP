"""MCP tools for BSim-inspired function similarity analysis.

Provides 5 tools for extracting function feature vectors, comparing functions
across binaries, and managing a persistent function signature database.
"""

import asyncio
import datetime
import hashlib
import os
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional

from arkana.config import state, logger, Context, ANGR_AVAILABLE
from arkana.constants import (
    BSIM_DEFAULT_THRESHOLD, BSIM_BACKGROUND_TIMEOUT, BSIM_MIN_BLOCKS_FOR_MATCH,
    BSIM_DEFAULT_CONFIDENCE_THRESHOLD, MAX_TOOL_LIMIT,
)
from arkana.mcp.server import (
    tool_decorator,
    _check_angr_ready,
    _check_pe_loaded,
    _check_mcp_response_size,
)
from arkana.mcp._angr_helpers import (
    _ensure_project_and_cfg,
    _parse_addr,
    _resolve_function_address,
    _raise_on_error_dict,
)
from arkana.mcp._bsim_features import (
    ANGR_PSEUDO_APIS,
    _db_write_lock,
    compute_confidence,
    compute_feature_idf,
    compute_similarity,
    extract_function_features,
    get_db_path,
    is_binary_indexed,
    is_trivial_function,
    list_indexed_binaries,
    query_similar_functions,
    register_binary,
    store_functions_batch,
    update_binary_function_count,
    _row_to_features,
    _get_connection,
    _safe_json_loads,
)
from arkana.background import _update_progress, _run_background_task_wrapper, _log_task_exception, _register_background_task
from arkana.utils import _safe_env_int

if ANGR_AVAILABLE:
    import angr

    # ANGR_PSEUDO_APIS imported from _bsim_features — used in transfer_annotations
    # API overlap guard to filter out angr internal pseudo-API names.


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

    ---compact: extract CFG/API/VEX/string feature vectors for similarity matching | needs: angr

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
    limit = max(1, min(limit, MAX_TOOL_LIMIT))

    def _extract(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()
        project, cfg = state.get_angr_snapshot()
        if cfg is None:
            return {"error": "CFG not available. Wait for background analysis to complete."}

        results = []

        failed_count = 0
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
                    failed_count += 1
                    logger.debug(
                        "Feature extraction failed for %#x: %s", func.addr, e
                    )

        result = {
            "status": "success",
            "binary": os.path.basename(state.filepath or "unknown"),
            "functions": results,
            "count": len(results),
            "include_vex": include_vex,
        }
        if failed_count > 0:
            result["warnings"] = [
                f"{failed_count} function(s) failed feature extraction"
            ]
        return result

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

    ---compact: find similar functions in another binary via feature vectors | background | needs: angr

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
    limit = max(1, min(limit, MAX_TOOL_LIMIT))

    abs_path_b = os.path.abspath(file_path_b)
    state.check_path_allowed(abs_path_b)
    if not os.path.isfile(abs_path_b):
        raise ValueError(f"File not found: {abs_path_b}")

    # M-4: Guard against excessively large comparison files
    _MAX_COMPARISON_FILE_SIZE = 200 * 1024 * 1024  # 200 MB
    file_size_b = os.path.getsize(abs_path_b)
    if file_size_b > _MAX_COMPARISON_FILE_SIZE:
        return {"error": f"Second binary too large ({file_size_b} bytes). Max {_MAX_COMPARISON_FILE_SIZE} bytes."}

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
        _cancel = _register_background_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing function similarity comparison...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "find_similar_functions",
        })
        task = asyncio.create_task(
            _run_background_task_wrapper(task_id, _compare, ctx=ctx,
                                         cancel_event=_cancel, timeout=bsim_timeout, on_timeout=_on_timeout_compare)
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

    ---compact: index function signatures into persistent SQLite DB | background | needs: angr

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

        # Hold lock only for the register_binary DB write.
        # The returned connection is held open for the duration of batch
        # inserts for efficiency — closed in the finally block below.
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
        _cancel = _register_background_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing signature DB build...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "build_function_signature_db",
        })
        task = asyncio.create_task(
            _run_background_task_wrapper(task_id, _build, ctx=ctx,
                                         cancel_event=_cancel, timeout=bsim_timeout, on_timeout=_on_timeout_build)
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

    ---compact: query signature DB for similar functions across indexed binaries | needs: angr

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
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    addr = _parse_addr(function_address)

    def _query():
        _ensure_project_and_cfg()
        project, cfg = state.get_angr_snapshot()
        if cfg is None:
            return {"error": "CFG not available."}

        func, _ = _resolve_function_address(addr)
        features = extract_function_features(project, cfg, func, include_vex=False)

        # Extract architecture for pre-filter selectivity
        arch = None
        try:
            arch = project.arch.name
        except Exception:
            pass

        # Compute IDF weights for confidence scoring
        idf = compute_feature_idf()

        matches = query_similar_functions(
            target_features=features,
            threshold=threshold,
            metrics=metrics,
            limit=limit,
            source_architecture=arch,
            idf_weights=idf,
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

    ---compact: list indexed binaries in signature DB with function counts

    Returns metadata for each indexed binary: SHA256, filename, architecture,
    function count, and indexing date.  No angr dependency — reads only
    SQLite metadata.

    Returns:
        dict with list of indexed binaries and summary statistics.
    """
    binaries = list_indexed_binaries()
    total_functions = sum(b.get("function_count", 0) for b in binaries)
    library_count = sum(1 for b in binaries if b.get("source") == "library")
    user_count = sum(1 for b in binaries if b.get("source") != "library")
    return {
        "status": "success",
        "binaries": binaries,
        "total_binaries": len(binaries),
        "total_functions": total_functions,
        "library_entries": library_count,
        "user_entries": user_count,
        "db_path": "~/.arkana/bsim/signatures.db",
    }


# ---------------------------------------------------------------------------
#  Tool 6: triage_binary_similarity
# ---------------------------------------------------------------------------

@tool_decorator
async def triage_binary_similarity(
    ctx: Context,
    threshold: float = 0.7,
    limit: int = 10,
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """Compare loaded binary against all indexed binaries in the signature DB.
    ---compact: whole-binary similarity triage against signature DB | background | needs: angr

    Compares ALL non-trivial functions in the loaded binary against the
    signature DB, then aggregates function-level matches into per-binary
    overlap scores.  Answers: "Is this binary related to anything I've
    seen before?  What family/library is it?"

    Results include shared function count, overlap ratio, average similarity,
    and average confidence per indexed binary.

    Args:
        threshold: Minimum function similarity to count as a match (0.0-1.0, default 0.7).
        limit: Maximum indexed binaries to return (default 10).
        run_in_background: Queue as background task (default True).

    Returns:
        dict with ranked binary matches or task_id for background execution.
    """
    _check_angr_ready("triage_binary_similarity")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    bsim_timeout = _safe_env_int("ARKANA_BSIM_BACKGROUND_TIMEOUT", BSIM_BACKGROUND_TIMEOUT)

    _partial_triage = {}

    def _triage(task_id_for_progress=None, _progress_bridge=None):
        _ensure_project_and_cfg()
        project, cfg = state.get_angr_snapshot()
        if cfg is None:
            return {"error": "CFG not available. Wait for background analysis to complete."}

        filepath = state.filepath
        if not filepath:
            return {"error": "No file loaded."}

        db = get_db_path()
        if not db.exists():
            return {"error": "Signature DB is empty. Index some binaries first with build_function_signature_db."}

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 5, "Enumerating functions...", bridge=_progress_bridge)

        # Collect non-trivial functions from loaded binary
        all_funcs = [
            f for f in cfg.functions.values()
            if not is_trivial_function(f)
        ]
        all_funcs.sort(key=lambda f: f.addr)
        total = len(all_funcs)
        _partial_triage['total'] = total

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 10, f"Extracting features from {total} functions...", bridge=_progress_bridge)

        # Compute IDF for confidence scoring
        idf = compute_feature_idf()

        # Extract architecture
        arch = None
        try:
            arch = project.arch.name
        except Exception:
            pass

        # For each function, find best matches in the DB
        # Aggregate by binary_sha256
        binary_matches: Dict[str, Dict[str, Any]] = {}  # sha256 -> aggregation
        functions_matched = 0

        for i, func in enumerate(all_funcs):
            try:
                features = extract_function_features(project, cfg, func, include_vex=False)
                matches = query_similar_functions(
                    target_features=features,
                    threshold=threshold,
                    metrics="combined",
                    limit=3,  # Top 3 per function to avoid O(N²) explosion
                    source_architecture=arch,
                    idf_weights=idf,
                )

                if matches:
                    functions_matched += 1
                    for match in matches:
                        sha = match["binary_sha256"]
                        if sha not in binary_matches:
                            binary_matches[sha] = {
                                "binary_sha256": sha,
                                "binary_filename": match["binary_filename"],
                                "architecture": match.get("architecture", ""),
                                "source": match.get("source", "user"),
                                "library_name": match.get("library_name"),
                                "shared_functions": [],
                                "similarity_sum": 0.0,
                                "confidence_sum": 0.0,
                            }
                        entry = binary_matches[sha]
                        func_name = func.name or f"sub_{func.addr:x}"
                        # Avoid double-counting the same source function
                        if not any(sf["source_address"] == hex(func.addr) for sf in entry["shared_functions"]):
                            entry["shared_functions"].append({
                                "source_address": hex(func.addr),
                                "source_name": func_name,
                                "match_name": match["name"],
                                "similarity": match["scores"].get("combined", 0),
                                "confidence": match.get("confidence", 0),
                            })
                            entry["similarity_sum"] += match["scores"].get("combined", 0)
                            entry["confidence_sum"] += match.get("confidence", 0)

            except Exception as e:
                logger.debug("Triage feature extraction failed for %#x: %s", func.addr, e)

            _partial_triage['processed'] = i + 1
            if task_id_for_progress and i % 25 == 0:
                pct = 10 + int(80 * i / max(total, 1))
                _update_progress(
                    task_id_for_progress, pct,
                    f"Compared {i}/{total} functions ({len(binary_matches)} binaries matched)...",
                    bridge=_progress_bridge,
                )

        if task_id_for_progress:
            _update_progress(task_id_for_progress, 92, "Aggregating results...", bridge=_progress_bridge)

        # Build ranked result list
        results = []
        for sha, entry in binary_matches.items():
            count = len(entry["shared_functions"])
            avg_sim = entry["similarity_sum"] / count if count else 0
            avg_conf = entry["confidence_sum"] / count if count else 0
            # Only include top matches in response to keep size manageable
            top_matches = sorted(
                entry["shared_functions"],
                key=lambda m: m.get("confidence", 0) * m.get("similarity", 0),
                reverse=True,
            )[:5]
            results.append({
                "binary_sha256": sha,
                "binary_filename": entry["binary_filename"],
                "architecture": entry.get("architecture", ""),
                "source": entry.get("source", "user"),
                "library_name": entry.get("library_name"),
                "shared_function_count": count,
                "shared_function_ratio": round(count / max(total, 1), 3),
                "avg_similarity": round(avg_sim, 4),
                "avg_confidence": round(avg_conf, 2),
                "significance": round(avg_sim * avg_conf * count, 2),
                "top_matches": top_matches,
            })

        # Sort by significance (confidence × similarity × count)
        results.sort(key=lambda r: r["significance"], reverse=True)
        results = results[:limit]

        return {
            "status": "success",
            "binary": os.path.basename(filepath),
            "total_functions_analyzed": total,
            "functions_with_matches": functions_matched,
            "indexed_binaries_matched": len(results),
            "threshold": threshold,
            "results": results,
        }

    def _on_timeout_triage():
        return {
            "functions_processed": _partial_triage.get('processed', 0),
            "total_functions": _partial_triage.get('total', 0),
            "message": "Triage timed out. Partial results may be available.",
            "hint": "Try: raise threshold, or increase ARKANA_BSIM_BACKGROUND_TIMEOUT.",
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        _cancel = _register_background_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": "Initializing binary similarity triage...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "triage_binary_similarity",
        })
        task = asyncio.create_task(
            _run_background_task_wrapper(task_id, _triage, ctx=ctx,
                                         cancel_event=_cancel, timeout=bsim_timeout, on_timeout=_on_timeout_triage)
        )
        task.add_done_callback(_log_task_exception(task_id))
        return {
            "status": "queued",
            "task_id": task_id,
            "message": "Binary similarity triage queued. Use check_task_status() to monitor.",
        }

    await ctx.info("Running binary similarity triage (foreground)...")
    result = await asyncio.to_thread(_triage)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(
        ctx, result, "triage_binary_similarity", "the 'limit' parameter"
    )


# ---------------------------------------------------------------------------
#  Tool 7: seed_signature_db
# ---------------------------------------------------------------------------

@tool_decorator
async def seed_signature_db(
    ctx: Context,
    library_path: str,
    library_name: str = "",
    run_in_background: bool = True,
) -> Dict[str, Any]:
    """Index library files into the signature DB for known-code identification.
    ---compact: index library files (.lib/.a/.obj/.so) into signature DB | background | needs: angr

    Accepts a path to a library file or directory of library files.
    Extracts function features via angr and stores them tagged as
    'library' entries in the signature DB.  Used to seed the DB with
    known libraries (CRT, OpenSSL, zlib, etc.) so BSim can identify
    library code in analyzed binaries.

    Args:
        library_path: Path to a .lib, .a, .obj, .so, .dll file or directory
                     containing such files.
        library_name: Human-readable name (e.g. 'OpenSSL 1.1.1').
                     Defaults to filename.
        run_in_background: Queue as background task (default True).

    Returns:
        dict with indexing results or task_id for background execution.
    """
    if not ANGR_AVAILABLE:
        return {"error": "angr is required for library indexing but is not available."}

    abs_path = os.path.abspath(library_path)
    state.check_path_allowed(abs_path)
    if not os.path.exists(abs_path):
        raise ValueError(f"Path not found: {abs_path}")

    # Collect files to index
    _LIB_EXTENSIONS = {'.lib', '.a', '.obj', '.o', '.so', '.dll', '.dylib'}
    files_to_index: List[str] = []
    if os.path.isdir(abs_path):
        for root, _dirs, filenames in os.walk(abs_path):
            for fn in filenames:
                if any(fn.lower().endswith(ext) for ext in _LIB_EXTENSIONS):
                    files_to_index.append(os.path.join(root, fn))
    elif os.path.isfile(abs_path):
        files_to_index.append(abs_path)
    else:
        raise ValueError(f"Not a file or directory: {abs_path}")

    if not files_to_index:
        return {"error": f"No library files found at {abs_path}. Supported: {', '.join(sorted(_LIB_EXTENSIONS))}"}

    bsim_timeout = _safe_env_int("ARKANA_BSIM_BACKGROUND_TIMEOUT", BSIM_BACKGROUND_TIMEOUT)
    _BATCH_SIZE = 50
    _partial_seed = {}

    def _seed(task_id_for_progress=None, _progress_bridge=None):
        total_files = len(files_to_index)
        total_indexed = 0
        total_functions = 0
        errors = []
        _partial_seed['total_files'] = total_files

        for fi, fpath in enumerate(files_to_index):
            if task_id_for_progress:
                pct = int(95 * fi / max(total_files, 1))
                _update_progress(
                    task_id_for_progress, pct,
                    f"Indexing file {fi+1}/{total_files}: {os.path.basename(fpath)}...",
                    bridge=_progress_bridge,
                )

            try:
                proj = angr.Project(fpath, auto_load_libs=False)
                cfg_lib = proj.analyses.CFGFast(normalize=True)

                funcs = [
                    f for f in cfg_lib.functions.values()
                    if not is_trivial_function(f)
                ]

                if not funcs:
                    logger.debug("No non-trivial functions in %s, skipping", fpath)
                    continue

                # Compute hash
                sha = hashlib.sha256()
                with open(fpath, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha.update(chunk)
                file_hash = sha.hexdigest()
                file_size = os.path.getsize(fpath)

                arch = "unknown"
                try:
                    arch = proj.arch.name
                except Exception:
                    pass

                lib_label = library_name or os.path.basename(fpath)

                with _db_write_lock:
                    binary_id, conn = register_binary(
                        sha256=file_hash,
                        filename=os.path.basename(fpath),
                        architecture=arch,
                        file_size=file_size,
                        source="library",
                        library_name=lib_label,
                    )

                try:
                    batch: List[Dict[str, Any]] = []
                    func_count = 0
                    for func in funcs:
                        try:
                            feat = extract_function_features(proj, cfg_lib, func, include_vex=False)
                            batch.append(feat)
                            func_count += 1
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
                        update_binary_function_count(conn, binary_id, func_count)
                finally:
                    conn.close()

                total_indexed += 1
                total_functions += func_count
                _partial_seed['indexed'] = total_indexed
                _partial_seed['functions'] = total_functions

                # Cleanup angr project
                try:
                    if hasattr(proj, 'close'):
                        proj.close()
                except Exception:
                    pass
                del cfg_lib, proj

            except Exception as e:
                errors.append(f"{os.path.basename(fpath)}: {str(e)[:100]}")
                logger.debug("Failed to index library %s: %s", fpath, e, exc_info=True)

        result = {
            "status": "success",
            "files_found": total_files,
            "files_indexed": total_indexed,
            "total_functions_indexed": total_functions,
            "library_name": library_name or os.path.basename(abs_path),
            "source_tag": "library",
        }
        if errors:
            result["errors"] = errors[:20]  # Cap error list
        return result

    def _on_timeout_seed():
        return {
            "files_indexed": _partial_seed.get('indexed', 0),
            "total_files": _partial_seed.get('total_files', 0),
            "functions_indexed": _partial_seed.get('functions', 0),
            "message": "Library indexing timed out. Partial results were saved.",
        }

    if run_in_background:
        task_id = str(uuid.uuid4())
        _cancel = _register_background_task(task_id, {
            "status": "running",
            "progress_percent": 0,
            "progress_message": f"Initializing library indexing ({len(files_to_index)} files)...",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_at_epoch": time.time(),
            "tool": "seed_signature_db",
        })
        task = asyncio.create_task(
            _run_background_task_wrapper(task_id, _seed, ctx=ctx,
                                         cancel_event=_cancel, timeout=bsim_timeout, on_timeout=_on_timeout_seed)
        )
        task.add_done_callback(_log_task_exception(task_id))
        return {
            "status": "queued",
            "task_id": task_id,
            "files_to_index": len(files_to_index),
            "message": "Library indexing queued. Use check_task_status() to monitor.",
        }

    await ctx.info(f"Indexing {len(files_to_index)} library files (foreground)...")
    result = await asyncio.to_thread(_seed)
    _raise_on_error_dict(result)
    return result


# ---------------------------------------------------------------------------
#  Tool 8: transfer_annotations
# ---------------------------------------------------------------------------

@tool_decorator
async def transfer_annotations(
    ctx: Context,
    source_binary_sha256: str,
    threshold: float = 0.85,
    min_confidence: float = 3.0,
    require_api_overlap: bool = True,
    min_api_overlap: int = 2,
    preview: bool = True,
) -> Dict[str, Any]:
    """Transfer renames and notes from a matched binary to the loaded binary.
    ---compact: transfer renames/notes from similar binary via function matching | needs: angr

    For each function in the loaded binary, finds the best match in the
    specified source binary (from the signature DB).  Transfers function
    renames and notes from high-confidence matches.

    Use preview=True (default) to see what would be transferred before
    applying.  Set preview=False to apply the transfers.

    Args:
        source_binary_sha256: SHA256 of the source binary in the signature DB.
        threshold: Minimum similarity for transfer (0.0-1.0, default 0.85).
        min_confidence: Minimum confidence for transfer (default 1.0).
        require_api_overlap: If True (default), only transfer when both functions
            share at least one API call. Prevents false positives from purely
            structural matches.
        min_api_overlap: Minimum number of shared real API calls required when
            require_api_overlap is True (default 2). Higher values are stricter.
        preview: If True, show transfers without applying (default True).

    Returns:
        dict with transfer summary and details.
    """
    _check_angr_ready("transfer_annotations")
    _check_pe_loaded("transfer_annotations")

    def _transfer():
        _ensure_project_and_cfg()
        project, cfg = state.get_angr_snapshot()
        if cfg is None:
            return {"error": "CFG not available."}

        db = get_db_path()
        if not db.exists():
            return {"error": "Signature DB is empty."}

        # Verify source binary exists in DB
        conn = _get_connection(db)
        try:
            source_row = conn.execute(
                "SELECT id, filename FROM binaries WHERE sha256 = ?",
                (source_binary_sha256,),
            ).fetchone()
            if not source_row:
                return {"error": f"Binary {source_binary_sha256[:16]}... not found in signature DB."}
            source_binary_id = source_row["id"]
            source_filename = source_row["filename"]

            # Load all functions from source binary
            source_rows = conn.execute(
                "SELECT * FROM functions WHERE binary_id = ?", (source_binary_id,)
            ).fetchall()
        finally:
            conn.close()

        if not source_rows:
            return {"error": f"No functions found for binary {source_binary_sha256[:16]}... in DB."}

        # Build feature vectors for source functions
        source_features = []
        for row in source_rows:
            feat = _row_to_features(row)
            feat["_db_name"] = row["name"]
            feat["_db_address"] = row["address"]
            source_features.append(feat)

        # Compute IDF
        idf = compute_feature_idf()

        # Match loaded binary functions against source
        all_funcs = [
            f for f in cfg.functions.values()
            if not is_trivial_function(f)
        ]
        all_funcs.sort(key=lambda f: f.addr)

        transfers = []
        for func in all_funcs:
            try:
                features = extract_function_features(project, cfg, func, include_vex=False)

                best_match = None
                best_score = 0.0
                best_confidence = 0.0

                for sf in source_features:
                    scores = compute_similarity(features, sf, "combined")
                    sim = scores.get("combined", 0)
                    if sim < threshold:
                        continue
                    conf = compute_confidence(features, sf, scores, idf)
                    significance = sim * conf
                    if significance > best_score:
                        best_score = significance
                        best_match = sf
                        best_confidence = conf

                if best_match and best_confidence >= min_confidence:
                    # API overlap guard: reject purely structural matches
                    if require_api_overlap:
                        target_apis = set(features.get("api_calls", {}).get("names", []))
                        match_apis = set(best_match.get("api_calls", {}).get("names", []))
                        shared_apis = target_apis & match_apis
                        # Filter out angr pseudo-APIs that match everywhere
                        shared_apis -= ANGR_PSEUDO_APIS
                        if len(shared_apis) < min_api_overlap:
                            continue  # Insufficient real shared APIs — structural match only

                    source_name = best_match.get("_db_name", "")
                    current_name = func.name or f"sub_{func.addr:x}"

                    # Only transfer if source has a meaningful name
                    if (source_name
                            and not source_name.startswith("sub_")
                            and source_name != current_name):
                        entry = {
                            "address": hex(func.addr),
                            "current_name": current_name,
                            "new_name": source_name,
                            "similarity": round(best_score / max(best_confidence, 0.01), 4),
                            "confidence": best_confidence,
                        }
                        # Include shared API info when overlap guard is active
                        if require_api_overlap:
                            entry["shared_apis"] = sorted(shared_apis)[:10]
                        transfers.append(entry)
            except Exception as e:
                logger.debug("Transfer matching failed for %#x: %s", func.addr, e)

        # Apply transfers if not preview
        applied = 0
        if not preview and transfers:
            for t in transfers:
                try:
                    state.rename_function(t["address"], t["new_name"])
                    applied += 1
                except Exception as e:
                    logger.debug("Failed to apply rename at %s: %s", t["address"], e)

        return {
            "status": "success",
            "source_binary": source_filename,
            "source_sha256": source_binary_sha256[:16] + "...",
            "functions_analyzed": len(all_funcs),
            "transfers_found": len(transfers),
            "transfers_applied": applied if not preview else 0,
            "preview": preview,
            "transfers": transfers[:50],  # Cap for response size
            "hint": "Set preview=False to apply these renames." if preview and transfers else None,
        }

    result = await asyncio.to_thread(_transfer)
    _raise_on_error_dict(result)
    return await _check_mcp_response_size(
        ctx, result, "transfer_annotations", "threshold or min_confidence"
    )


# ---------------------------------------------------------------------------
#  Tool 9: validate_signature_db
# ---------------------------------------------------------------------------

@tool_decorator
async def validate_signature_db(
    ctx: Context,
) -> Dict[str, Any]:
    """Run diagnostics on the signature database.
    ---compact: validate signature DB health | self-match test, feature stats, integrity

    Reports DB statistics, runs a self-match sanity test (random functions
    should find themselves at similarity ~1.0), and checks feature
    distribution health.

    Returns:
        dict with DB stats, sanity test results, and health indicators.
    """
    import random

    def _validate():
        db = get_db_path()
        if not db.exists():
            return {
                "status": "empty",
                "message": "Signature DB does not exist. Use build_function_signature_db or seed_signature_db to create it.",
            }

        conn = _get_connection(db)
        try:
            # Basic stats
            total_binaries = conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0]
            total_functions = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]

            # Source breakdown
            library_count = 0
            user_count = 0
            try:
                library_count = conn.execute(
                    "SELECT COUNT(*) FROM binaries WHERE source = 'library'"
                ).fetchone()[0]
                user_count = total_binaries - library_count
            except sqlite3.OperationalError:
                user_count = total_binaries  # Old schema without source column

            # Per-binary stats
            binary_stats = conn.execute(
                "SELECT filename, function_count, architecture, "
                "COALESCE(source, 'user') as source, library_name "
                "FROM binaries ORDER BY function_count DESC LIMIT 20"
            ).fetchall()

            # Feature distribution
            avg_blocks = conn.execute(
                "SELECT AVG(block_count) FROM functions"
            ).fetchone()[0] or 0
            avg_instr = conn.execute(
                "SELECT AVG(instruction_count) FROM functions"
            ).fetchone()[0] or 0
            trivial_count = conn.execute(
                "SELECT COUNT(*) FROM functions WHERE block_count < ?",
                (BSIM_MIN_BLOCKS_FOR_MATCH,),
            ).fetchone()[0]

            # Self-match sanity test: pick up to 10 random functions, query for self
            sanity_results = []
            if total_functions > 0:
                sample_rows = conn.execute(
                    "SELECT * FROM functions ORDER BY RANDOM() LIMIT 10"
                ).fetchall()
                for row in sample_rows:
                    feat = _row_to_features(row)
                    scores = compute_similarity(feat, feat, "combined")
                    sanity_results.append({
                        "name": row["name"],
                        "self_similarity": round(scores.get("combined", 0), 4),
                        "pass": scores.get("combined", 0) >= 0.95,
                    })

            sanity_pass = all(r["pass"] for r in sanity_results) if sanity_results else True

            # Health indicators
            health = []
            if total_functions == 0:
                health.append("DB is empty — no functions indexed")
            if trivial_count > total_functions * 0.5 and total_functions > 0:
                health.append(f"{trivial_count}/{total_functions} functions have < {BSIM_MIN_BLOCKS_FOR_MATCH} blocks (trivial)")
            if not sanity_pass:
                health.append("SELF-MATCH FAILURE: some functions don't match themselves")
            if avg_blocks < 2:
                health.append(f"Low avg block count ({avg_blocks:.1f}) — may indicate extraction issues")
            if not health:
                health.append("All checks passed")

            return {
                "status": "success",
                "stats": {
                    "total_binaries": total_binaries,
                    "total_functions": total_functions,
                    "library_entries": library_count,
                    "user_entries": user_count,
                    "avg_block_count": round(avg_blocks, 1),
                    "avg_instruction_count": round(avg_instr, 1),
                    "trivial_functions": trivial_count,
                },
                "binaries": [dict(r) for r in binary_stats],
                "sanity_test": {
                    "samples_tested": len(sanity_results),
                    "all_passed": sanity_pass,
                    "results": sanity_results,
                },
                "health": health,
            }
        finally:
            conn.close()

    return await asyncio.to_thread(_validate)
