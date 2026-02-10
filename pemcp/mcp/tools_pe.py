"""MCP tools for PE data retrieval - summary, full results, dynamic per-key tools, open/close, and reanalysis."""
import os
import json
import asyncio
import datetime
import hashlib
import threading
from typing import Dict, Any, Optional, List
from pathlib import Path

from pemcp.config import (
    state, logger, Context, pefile, analysis_cache,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    FLOSS_MIN_LENGTH_DEFAULT,
    Actual_DebugLevel_Floss, Actual_StringType_Floss,
    DEFAULT_PEID_DB_PATH,
)
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.parsers.pe import _parse_pe_to_dict, _parse_file_hashes
from pemcp.parsers.strings import _extract_strings_from_data, _perform_unified_string_sifting
from pemcp.parsers.floss import _parse_floss_analysis
from pemcp.background import _console_heartbeat_loop, _update_progress
from pemcp.mock import MockPE

if ANGR_AVAILABLE:
    import angr


@tool_decorator
async def open_file(
    ctx: Context,
    file_path: str,
    mode: str = "auto",
    analyses_to_skip: Optional[List[str]] = None,
    start_angr_background: bool = True,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """
    Opens and analyses a binary file, making it available for all other tools.
    Supports PE, ELF, Mach-O, and raw shellcode. Auto-detection is the default.
    This replaces any previously loaded file. Progress is reported during analysis.

    Previously analysed files are cached in ~/.pemcp/cache/ (keyed by SHA256).
    Set use_cache=False to force a fresh analysis and ignore any cached results.

    Args:
        ctx: The MCP Context object.
        file_path: (str) Absolute or relative path to the file to analyse.
        mode: (str) Analysis mode — 'auto' (default, detects from magic bytes), 'pe', 'elf', 'macho', or 'shellcode'.
        analyses_to_skip: (Optional[List[str]]) List of analyses to skip: 'peid', 'yara', 'capa', 'floss'.
        start_angr_background: (bool) If True (default) and angr is available, start background CFG analysis.
        use_cache: (bool) If True (default), check the disk cache for previous analysis results.

    Returns:
        A dictionary with status, filepath, detected format, and summary of what was loaded.
    """
    abs_path = str(Path(file_path).resolve())

    if not os.path.isfile(abs_path):
        raise RuntimeError(f"[open_file] File not found: {abs_path}")

    # Auto-detect format from magic bytes
    if mode == "auto":
        with open(abs_path, 'rb') as f:
            magic = f.read(4)
        if magic[:2] == b'MZ':
            mode = "pe"
        elif magic == b'\x7fELF':
            mode = "elf"
        elif magic in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                       b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                       b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
            mode = "macho"
        else:
            mode = "pe"  # fallback to PE, pefile will report errors if invalid
        await ctx.info(f"Auto-detected format: {mode}")

    await ctx.info(f"Opening file: {abs_path} (mode: {mode})")

    skip_list = [s.lower() for s in (analyses_to_skip or [])]

    # Close any previously loaded file
    if state.pe_object:
        try:
            state.pe_object.close()
        except Exception:
            pass
        state.pe_object = None
        state.pe_data = None
        state.filepath = None
        state.angr_project = None
        state.angr_cfg = None

    _loaded_from_cache = False

    try:
        # --- Early hash for cache lookup ---
        await ctx.report_progress(2, 100)

        def _read_and_hash():
            with open(abs_path, 'rb') as f:
                data = f.read()
            return data, hashlib.sha256(data).hexdigest()

        _raw_file_data, _file_sha256 = await asyncio.to_thread(_read_and_hash)

        # --- Check cache (all modes) ---
        if use_cache:
            cached = analysis_cache.get(_file_sha256, abs_path)
            if cached is not None:
                cached_mode = cached.get("mode", "")
                # Only use cache if the requested mode matches the cached mode
                if mode == cached_mode or (mode == "pe" and cached_mode not in ("shellcode", "elf", "macho")):
                    state.filepath = abs_path
                    state.pe_data = cached
                    state.loaded_from_cache = True
                    # Still need a pe_object for tools that access it directly
                    if mode == "shellcode" or mode in ("elf", "macho"):
                        state.pe_object = MockPE(_raw_file_data)
                    else:
                        state.pe_object = await asyncio.to_thread(
                            lambda: pefile.PE(abs_path, fast_load=False)
                        )
                    _loaded_from_cache = True
                    await ctx.info(f"Analysis loaded from cache (SHA256: {_file_sha256[:16]}...)")
                    await ctx.report_progress(95, 100)

        if not _loaded_from_cache:
            state.loaded_from_cache = False

            if mode == "shellcode":
                await ctx.report_progress(5, 100)
                await ctx.info("Loading raw shellcode...")

                def _load_shellcode():
                    state.pe_object = MockPE(_raw_file_data)
                    state.filepath = abs_path
                    state.pe_data = {
                        "filepath": abs_path,
                        "mode": "shellcode",
                        "file_hashes": _parse_file_hashes(_raw_file_data),
                        "basic_ascii_strings": [
                            {"offset": hex(o), "string": s}
                            for o, s in _extract_strings_from_data(_raw_file_data, 5)
                        ],
                        "floss_analysis": {"status": "Pending..."},
                    }

                await asyncio.to_thread(_load_shellcode)
                await ctx.report_progress(30, 100)

                if "floss" not in skip_list and FLOSS_AVAILABLE:
                    await ctx.info("Running FLOSS analysis on shellcode...")

                    def _run_floss():
                        state.pe_data['floss_analysis'] = _parse_floss_analysis(
                            abs_path, FLOSS_MIN_LENGTH_DEFAULT, 0,
                            Actual_DebugLevel_Floss.NONE, "auto",
                            [], [], [], True,
                        )
                        _perform_unified_string_sifting(state.pe_data)

                    await asyncio.to_thread(_run_floss)

                await ctx.report_progress(95, 100)

                # Store in cache
                sha = state.pe_data.get("file_hashes", {}).get("sha256")
                if sha:
                    analysis_cache.put(sha, state.pe_data, abs_path)

            elif mode in ("elf", "macho"):
                # ELF / Mach-O mode — lightweight load with hashes and strings
                await ctx.report_progress(5, 100)
                format_label = "ELF" if mode == "elf" else "Mach-O"
                await ctx.info(f"Loading {format_label} binary...")

                def _load_non_pe():
                    state.pe_object = MockPE(_raw_file_data)
                    state.filepath = abs_path
                    state.pe_data = {
                        "filepath": abs_path,
                        "mode": mode,
                        "format": format_label,
                        "file_hashes": _parse_file_hashes(_raw_file_data),
                        "basic_ascii_strings": [
                            {"offset": hex(o), "string": s}
                            for o, s in _extract_strings_from_data(_raw_file_data, 5)
                        ],
                        "note": (
                            f"This is a {format_label} binary. PE-specific tools (imports, exports, sections, etc.) "
                            f"are not applicable. Use the format-specific tools instead: "
                            + (
                                "elf_analyze, elf_dwarf_info" if mode == "elf"
                                else "macho_analyze"
                            )
                            + ". Angr-based tools (decompilation, CFG, symbolic execution) work on all formats."
                        ),
                    }

                await asyncio.to_thread(_load_non_pe)
                await ctx.report_progress(50, 100)
                await ctx.info(f"{format_label} binary loaded. Use format-specific tools or angr tools for analysis.")
                await ctx.report_progress(95, 100)

                # Store in cache
                sha = state.pe_data.get("file_hashes", {}).get("sha256")
                if sha:
                    analysis_cache.put(sha, state.pe_data, abs_path)

            else:
                # PE mode
                await ctx.report_progress(5, 100)
                await ctx.info("Loading PE file...")

                def _load_pe():
                    return pefile.PE(abs_path, fast_load=False)

                pe_obj = await asyncio.to_thread(_load_pe)
                state.filepath = abs_path
                state.pe_object = pe_obj

                await ctx.report_progress(15, 100)
                await ctx.info("Analysing PE structures, signatures, and strings...")

                # Use a shared progress state for the callback
                _progress_state = {"last": 15}

                def _progress_cb(step: int, total: int, message: str) -> None:
                    # Map 0-100 analysis progress to 15-95 of overall progress
                    mapped = 15 + int(step * 0.8)
                    _progress_state["last"] = mapped

                def _run_analysis():
                    return _parse_pe_to_dict(
                        pe_obj, abs_path,
                        str(DEFAULT_PEID_DB_PATH), None, None, None,
                        False, False, False,
                        floss_min_len_arg=FLOSS_MIN_LENGTH_DEFAULT,
                        floss_verbose_level_arg=0,
                        floss_script_debug_level_arg=Actual_DebugLevel_Floss.NONE,
                        floss_format_hint_arg="auto",
                        floss_disabled_types_arg=[],
                        floss_only_types_arg=[],
                        floss_functions_to_analyze_arg=[],
                        floss_quiet_mode_arg=True,
                        analyses_to_skip=skip_list,
                        progress_callback=_progress_cb,
                    )

                state.pe_data = await asyncio.to_thread(_run_analysis)
                await ctx.report_progress(95, 100)

                # Store in cache
                sha = state.pe_data.get("file_hashes", {}).get("sha256")
                if sha:
                    await ctx.info("Caching analysis results...")
                    analysis_cache.put(sha, state.pe_data, abs_path)

        # Start background angr analysis if requested
        if start_angr_background and ANGR_AVAILABLE and state.filepath:
            task_id = "startup-angr"

            state.set_task(task_id, {
                "status": "running",
                "progress_percent": 0,
                "progress_message": "Starting background pre-analysis...",
                "created_at": datetime.datetime.now().isoformat(),
                "tool": "open_file_angr_auto",
            })

            if not state.monitor_thread_started:
                monitor_thread = threading.Thread(target=_console_heartbeat_loop, daemon=True)
                monitor_thread.start()
                state.monitor_thread_started = True

            def _angr_worker(fpath, tid):
                try:
                    _update_progress(tid, 1, "Loading Angr Project...")
                    if mode == "shellcode":
                        proj = angr.Project(fpath, main_opts={'backend': 'blob', 'arch': 'amd64'}, auto_load_libs=False)
                    else:
                        proj = angr.Project(fpath, auto_load_libs=False)
                    state.angr_project = proj
                    _update_progress(tid, 20, "Building Control Flow Graph...")
                    cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)
                    state.angr_cfg = cfg
                    _update_progress(tid, 80, "Identifying loops...")
                    loop_finder = proj.analyses.LoopFinder(kb=proj.kb)
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
                    state.angr_loop_cache = raw_loops
                    state.angr_loop_cache_config = {"resolve_jumps": True, "data_refs": False}
                    state.update_task(tid, status="completed",
                                      result={"message": "Analysis ready."},
                                      progress_percent=100,
                                      progress_message="Background analysis complete.")
                except Exception as ex:
                    state.update_task(tid, status="failed", error=str(ex))
                    _update_progress(tid, 0, f"Failed: {ex}")

            angr_thread = threading.Thread(
                target=_angr_worker,
                args=(abs_path, task_id),
                daemon=True,
            )
            angr_thread.start()
            await ctx.info("Background Angr analysis started. Use check_task_status('startup-angr') to monitor.")

        await ctx.report_progress(100, 100)
        await ctx.info(f"File loaded successfully: {abs_path}")

        result = {
            "status": "success",
            "filepath": abs_path,
            "mode": mode,
            "loaded_from_cache": _loaded_from_cache,
            "analyses_skipped": skip_list if skip_list else "none",
            "angr_background": "started" if (start_angr_background and ANGR_AVAILABLE) else "not started",
        }
        if mode in ("elf", "macho"):
            format_label = "ELF" if mode == "elf" else "Mach-O"
            result["suggested_tools"] = (
                ["elf_analyze", "elf_dwarf_info"] if mode == "elf"
                else ["macho_analyze"]
            ) + ["detect_binary_format", "decompile_function_with_angr", "get_function_cfg"]
            result["note"] = f"{format_label} binary loaded. PE-specific tools are not applicable. Use the suggested tools for analysis."
        return result

    except Exception as e:
        # Clean up on failure
        state.filepath = None
        state.pe_data = None
        state.pe_object = None
        logger.error(f"open_file failed for '{abs_path}': {e}", exc_info=True)
        raise RuntimeError(f"[open_file] Failed to load '{abs_path}': {e}") from e


@tool_decorator
async def close_file(ctx: Context) -> Dict[str, str]:
    """
    Closes the currently loaded file and clears all analysis data from memory.
    After calling this, a new file must be opened with open_file before using analysis tools.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary confirming the file was closed.
    """
    if state.filepath is None:
        return {"status": "no_file", "message": "No file was loaded."}

    closed_path = state.filepath

    if state.pe_object:
        try:
            state.pe_object.close()
        except Exception:
            pass

    state.pe_object = None
    state.pe_data = None
    state.filepath = None
    state.loaded_from_cache = False
    state.angr_project = None
    state.angr_cfg = None
    state.angr_loop_cache = None
    state.angr_loop_cache_config = None

    await ctx.info(f"Closed file: {closed_path}")
    return {"status": "success", "message": f"File '{closed_path}' closed and analysis data cleared."}


@tool_decorator
async def reanalyze_loaded_pe_file(
    ctx: Context,
    peid_db_path: Optional[str] = None,
    yara_rules_path: Optional[str] = None,
    capa_rules_dir: Optional[str] = None,
    capa_sigs_dir: Optional[str] = None,
    analyses_to_skip: Optional[List[str]] = None,
    skip_capa_analysis: Optional[bool] = None,
    skip_floss_analysis: Optional[bool] = None,
    pre_analyze_angr: bool = False,
    floss_min_length: Optional[int] = None,
    floss_verbose_level: Optional[int] = None,
    floss_script_debug_level_for_floss_loggers: Optional[str] = None,
    floss_format: Optional[str] = None,
    floss_no_static: Optional[bool] = None,
    floss_no_stack: Optional[bool] = None,
    floss_no_tight: Optional[bool] = None,
    floss_no_decoded: Optional[bool] = None,
    floss_only_static: Optional[bool] = None,
    floss_only_stack: Optional[bool] = None,
    floss_only_tight: Optional[bool] = None,
    floss_only_decoded: Optional[bool] = None,
    floss_functions: Optional[List[str]] = None,
    floss_quiet: Optional[bool] = None,
    verbose_mcp_output: bool = False,
    skip_full_peid_scan: bool = False,
    peid_scan_all_sigs_heuristically: bool = False
    ) -> Dict[str, Any]:
    """
    Re-triggers a full or partial analysis of the PE file that was pre-loaded at server startup.
    Allows skipping heavy analyses (PEiD, YARA, Capa, FLOSS) via 'analyses_to_skip' list or specific flags.
    The analysis results are updated globally. FLOSS specific parameters can also be provided.

    If 'pre_analyze_angr' is True, it will also build the Angr Control Flow Graph (CFG) to speed up
    subsequent decompilation and graph queries.
    """

    if state.filepath is None or not os.path.exists(state.filepath):
        raise RuntimeError(
            "[reanalyze_loaded_pe_file] No PE file was pre-loaded at server startup, "
            "or the file path is no longer valid. Cannot re-analyze."
        )

    await ctx.info(f"Request to re-analyze pre-loaded PE: {state.filepath}")

    if pre_analyze_angr:
        if ANGR_AVAILABLE:
            await ctx.info("Angr pre-analysis requested. Building CFG (this may take time)...")
            def _build_cfg():
                state.angr_project = angr.Project(state.filepath, auto_load_libs=False)
                state.angr_cfg = state.angr_project.analyses.CFGFast(normalize=True)
            try:
                await asyncio.to_thread(_build_cfg)
                await ctx.info("Angr CFG generation complete. Future Angr calls will be fast.")
            except Exception as e:
                await ctx.error(f"Angr pre-analysis failed: {e}")
        else:
            await ctx.warning("Angr pre-analysis requested but 'angr' library is not installed.")

    normalized_analyses_to_skip = []
    if analyses_to_skip:
        normalized_analyses_to_skip = [analysis.lower() for analysis in analyses_to_skip]

    if skip_capa_analysis is True and "capa" not in normalized_analyses_to_skip:
        normalized_analyses_to_skip.append("capa")
        await ctx.info("Capa analysis will be skipped due to 'skip_capa_analysis=True'.")
    elif skip_capa_analysis is False and "capa" in normalized_analyses_to_skip:
        normalized_analyses_to_skip.remove("capa")
        await ctx.info("Capa analysis will be performed as 'skip_capa_analysis=False'.")

    if skip_floss_analysis is True and "floss" not in normalized_analyses_to_skip:
        normalized_analyses_to_skip.append("floss")
        await ctx.info("FLOSS analysis will be skipped due to 'skip_floss_analysis=True'.")
    elif skip_floss_analysis is False and "floss" in normalized_analyses_to_skip:
        normalized_analyses_to_skip.remove("floss")
        await ctx.info("FLOSS analysis will be performed as 'skip_floss_analysis=False'.")

    if normalized_analyses_to_skip:
        await ctx.info(f"Final list of analyses to skip during re-analysis: {', '.join(normalized_analyses_to_skip) if normalized_analyses_to_skip else 'None'}")

    current_peid_db_path = str(Path(peid_db_path).resolve()) if peid_db_path and Path(peid_db_path).exists() else str(DEFAULT_PEID_DB_PATH)
    current_yara_rules_path = str(Path(yara_rules_path).resolve()) if yara_rules_path and Path(yara_rules_path).exists() else None

    current_capa_rules_dir_to_use = None
    if "capa" not in normalized_analyses_to_skip and CAPA_AVAILABLE:
        if capa_rules_dir and Path(capa_rules_dir).is_dir() and os.listdir(Path(capa_rules_dir)):
            current_capa_rules_dir_to_use = str(Path(capa_rules_dir).resolve())
        else:
            if capa_rules_dir: await ctx.warning(f"Provided capa_rules_dir '{capa_rules_dir}' is invalid/empty. Capa will use its default logic.")
            current_capa_rules_dir_to_use = capa_rules_dir

    current_capa_sigs_dir_to_use = None
    if "capa" not in normalized_analyses_to_skip and CAPA_AVAILABLE:
        if capa_sigs_dir and Path(capa_sigs_dir).is_dir():
            current_capa_sigs_dir_to_use = str(Path(capa_sigs_dir).resolve())
        else:
            current_capa_sigs_dir_to_use = capa_sigs_dir

    mcp_floss_min_len = floss_min_length if floss_min_length is not None else FLOSS_MIN_LENGTH_DEFAULT
    mcp_floss_verbose_level = floss_verbose_level if floss_verbose_level is not None else 0

    mcp_floss_script_debug_level_enum_val = Actual_DebugLevel_Floss.NONE
    if floss_script_debug_level_for_floss_loggers:
        floss_debug_map = {
            "NONE": Actual_DebugLevel_Floss.NONE, "DEFAULT": Actual_DebugLevel_Floss.DEFAULT,
            "DEBUG": Actual_DebugLevel_Floss.DEFAULT,
            "TRACE": Actual_DebugLevel_Floss.TRACE, "SUPERTRACE": Actual_DebugLevel_Floss.SUPERTRACE
        }
        mcp_floss_script_debug_level_enum_val = floss_debug_map.get(floss_script_debug_level_for_floss_loggers.upper(), Actual_DebugLevel_Floss.NONE)

    mcp_floss_format_hint = floss_format if floss_format is not None else "auto"

    mcp_floss_disabled_types = []
    if floss_no_static: mcp_floss_disabled_types.append(Actual_StringType_Floss.STATIC)
    if floss_no_stack: mcp_floss_disabled_types.append(Actual_StringType_Floss.STACK)
    if floss_no_tight: mcp_floss_disabled_types.append(Actual_StringType_Floss.TIGHT)
    if floss_no_decoded: mcp_floss_disabled_types.append(Actual_StringType_Floss.DECODED)

    mcp_floss_only_types = []
    if floss_only_static: mcp_floss_only_types.append(Actual_StringType_Floss.STATIC)
    if floss_only_stack: mcp_floss_only_types.append(Actual_StringType_Floss.STACK)
    if floss_only_tight: mcp_floss_only_types.append(Actual_StringType_Floss.TIGHT)
    if floss_only_decoded: mcp_floss_only_types.append(Actual_StringType_Floss.DECODED)

    mcp_floss_functions_to_analyze = []
    if floss_functions:
        for func_str in floss_functions:
            try: mcp_floss_functions_to_analyze.append(int(func_str, 0))
            except ValueError: await ctx.warning(f"Invalid FLOSS function address '{func_str}', skipping.")

    mcp_floss_quiet_mode = floss_quiet if floss_quiet is not None else (not verbose_mcp_output)

    def perform_analysis_in_thread():
        temp_pe_obj = None
        try:
            temp_pe_obj = pefile.PE(state.filepath, fast_load=False)

            new_parsed_data = _parse_pe_to_dict(
                temp_pe_obj, state.filepath, current_peid_db_path, current_yara_rules_path,
                current_capa_rules_dir_to_use,
                current_capa_sigs_dir_to_use,
                verbose_mcp_output, skip_full_peid_scan, peid_scan_all_sigs_heuristically,
                floss_min_len_arg=mcp_floss_min_len,
                floss_verbose_level_arg=mcp_floss_verbose_level,
                floss_script_debug_level_arg=mcp_floss_script_debug_level_enum_val,
                floss_format_hint_arg=mcp_floss_format_hint,
                floss_disabled_types_arg=mcp_floss_disabled_types,
                floss_only_types_arg=mcp_floss_only_types,
                floss_functions_to_analyze_arg=mcp_floss_functions_to_analyze,
                floss_quiet_mode_arg=mcp_floss_quiet_mode,
                analyses_to_skip=normalized_analyses_to_skip
            )
            return temp_pe_obj, new_parsed_data
        except Exception as e_thread:
            if temp_pe_obj:
                temp_pe_obj.close()
            logger.error(f"Error during threaded re-analysis of {state.filepath}: {e_thread}", exc_info=verbose_mcp_output)
            raise

    try:
        new_pe_obj_from_thread, new_parsed_data_from_thread = await asyncio.to_thread(perform_analysis_in_thread)

        if state.pe_object:
            state.pe_object.close()

        state.pe_object = new_pe_obj_from_thread
        state.pe_data = new_parsed_data_from_thread

        # Update cache with fresh results
        sha256 = state.pe_data.get("file_hashes", {}).get("sha256")
        if sha256:
            analysis_cache.put(sha256, state.pe_data, state.filepath)

        await ctx.info(f"Successfully re-analyzed PE: {state.filepath}")
        skipped_msg_part = f" (Skipped: {', '.join(normalized_analyses_to_skip) if normalized_analyses_to_skip else 'None'})"

        msg = f"File '{state.filepath}' re-analyzed{skipped_msg_part}."
        if pre_analyze_angr and ANGR_AVAILABLE:
            msg += " Angr CFG pre-built."

        return {"status":"success", "message": msg, "filepath":state.filepath}

    except asyncio.CancelledError:
        await ctx.warning(f"Re-analysis task for {state.filepath} was cancelled by MCP framework.")
        logger.info(f"Re-analysis of {state.filepath} cancelled. Global PE data remains from previous successful load/analysis.")
        raise
    except Exception as e_outer:
        await ctx.error(f"Error re-analyzing PE '{state.filepath}': {str(e_outer)}");
        logger.error(f"MCP: Error re-analyzing PE '{state.filepath}': {str(e_outer)}", exc_info=verbose_mcp_output)
        raise RuntimeError(f"Failed to re-analyze PE file '{state.filepath}': {str(e_outer)}") from e_outer


@tool_decorator
async def get_analyzed_file_summary(ctx: Context, limit: int) -> Dict[str, Any]:
    """
    Retrieves a high-level summary of the pre-loaded and analyzed PE file.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. Limits the number of top-level key-value pairs returned. Must be positive.

    Returns:
        A dictionary containing summary information.
    Raises:
        RuntimeError: If no PE file is currently loaded.
        ValueError: If limit is not a positive integer.
    """
    await ctx.info(f"Request for analyzed file summary. Limit: {limit}")
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")

    _check_pe_loaded("get_analyzed_file_summary")

    floss_analysis_summary = state.pe_data.get('floss_analysis', {})
    floss_strings_summary = floss_analysis_summary.get('strings', {})

    full_summary = {
        "filepath":state.filepath,"pefile_version_used":state.pefile_version,
        "has_dos_header":'dos_header'in state.pe_data and state.pe_data['dos_header']is not None and"error"not in state.pe_data['dos_header'],
        "has_nt_headers":'nt_headers'in state.pe_data and state.pe_data['nt_headers']is not None and"error"not in state.pe_data['nt_headers'],
        "section_count":len(state.pe_data.get('sections',[])),
        "import_dll_count":len(state.pe_data.get('imports',[])),
        "export_symbol_count":len(state.pe_data.get('exports',{}).get('symbols',[])),
        "peid_ep_match_count":len(state.pe_data.get('peid_matches',{}).get('ep_matches',[])),
        "peid_heuristic_match_count":len(state.pe_data.get('peid_matches',{}).get('heuristic_matches',[])),
        "peid_status": state.pe_data.get('peid_matches',{}).get('status',"Not run/Skipped"),
        "yara_match_count":len([m for m in state.pe_data.get('yara_matches',[])if isinstance(m, dict) and "error" not in m and "status" not in m]),
        "yara_status": state.pe_data.get('yara_matches',[{}])[0].get('status', "Run/No Matches or Not Run/Skipped") if state.pe_data.get('yara_matches') and isinstance(state.pe_data.get('yara_matches'), list) and state.pe_data.get('yara_matches')[0] else "Not run/Skipped",
        "capa_status": state.pe_data.get('capa_analysis',{}).get('status',"Not run/Skipped"),
        "capa_capability_count": len(state.pe_data.get('capa_analysis',{}).get('results',{}).get('rules',{})) if state.pe_data.get('capa_analysis',{}).get('status')=="Analysis complete (adapted workflow)" else 0,
        "floss_status": floss_analysis_summary.get('status', "Not run/Skipped"),
        "floss_static_string_count": len(floss_strings_summary.get('static_strings', [])),
        "floss_stack_string_count": len(floss_strings_summary.get('stack_strings', [])),
        "floss_tight_string_count": len(floss_strings_summary.get('tight_strings', [])),
        "floss_decoded_string_count": len(floss_strings_summary.get('decoded_strings', [])),
        "has_embedded_signature":state.pe_data.get('digital_signature',{}).get('embedded_signature_present',False)
    }
    await ctx.info(f"Summary for {state.filepath} generated.")
    return dict(list(full_summary.items())[:limit])


@tool_decorator
async def get_full_analysis_results(ctx: Context, limit: int) -> Dict[str, Any]:
    """
    Retrieves the complete analysis results for the pre-loaded PE file.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. Limits the number of top-level key-value pairs. Must be positive.

    Returns:
        A potentially large dictionary containing all parsed PE structures, hashes, scan results, etc.
    Raises:
        RuntimeError: If no PE file is currently loaded.
        ValueError: If limit is not a positive integer, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request for full PE analysis. Limit: {limit}")
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")

    _check_pe_loaded("get_full_analysis_results")

    # Prepare the data according to the client's limit on top-level keys
    data_to_send = dict(list(state.pe_data.items())[:limit])

    # Now check the size of this potentially limited data
    limit_info = "the 'limit' parameter (to request fewer top-level keys) or use more specific data retrieval tools"
    return await _check_mcp_response_size(ctx, data_to_send, "get_full_analysis_results", limit_info)

def _create_mcp_tool_for_key(key_name: str, tool_description: str):
    async def _tool_func(ctx: Context, limit: int, offset: Optional[int] = 0) -> Any:
        await ctx.info(f"Request for '{key_name}'. Limit: {limit}, Offset: {offset}")
        if not (isinstance(limit, int) and limit > 0):
            raise ValueError(f"Parameter 'limit' for '{key_name}' must be a positive integer.")

        _check_pe_loaded(f"get_{key_name}_info")

        original_data = state.pe_data.get(key_name)
        if original_data is None:
            await ctx.warning(f"Data for '{key_name}' not found in analyzed results. Returning empty structure.")
            # For empty structure, size check is trivial but let's be consistent
            return await _check_mcp_response_size(ctx, {}, f"get_{key_name}_info")


        # Apply offset first if data is a list
        processed_data = original_data
        if isinstance(original_data, list) and offset is not None:
            if not (isinstance(offset, int) and offset >= 0):
                await ctx.warning(f"Invalid 'offset' value '{offset}' for '{key_name}'. Using offset 0.")
                offset = 0
            if offset > 0:
                processed_data = original_data[offset:]
        elif offset != 0 and offset is not None: # Offset provided but not applicable
            await ctx.warning(f"Parameter 'offset' is provided but not applicable for data type '{type(original_data).__name__}' of key '{key_name}'. Ignoring offset.")

        # Apply limit
        data_to_send: Any
        if isinstance(processed_data, list):
            data_to_send = processed_data[:limit]
        elif isinstance(processed_data, dict): # Offset doesn't apply to dicts in this simple way
            try:
                data_to_send = dict(list(processed_data.items())[:limit])
            except Exception as e_dict_limit:
                await ctx.warning(f"Could not apply generic dictionary limit for '{key_name}': {e_dict_limit}. Will check size of full data for this key.")
                data_to_send = processed_data # Send full dict if limiting failed, size check will catch if too big
        else: # For other types, limit might not be directly applicable in this way
            await ctx.info(f"Data for key '{key_name}' is type '{type(processed_data).__name__}'. 'limit' parameter acknowledged but not directly used for slicing this type.")
            data_to_send = processed_data

        limit_info_str = f"the 'limit' or 'offset' parameters for data key '{key_name}'"
        return await _check_mcp_response_size(ctx, data_to_send, f"get_{key_name}_info", limit_info_str)

    _tool_func.__name__ = f"get_{key_name}_info"
    doc = f"""Retrieves the '{key_name}' portion of the PE analysis results for the pre-loaded file.

Prerequisites:
- A PE file must have been successfully pre-loaded at server startup.

Args:
    ctx: The MCP Context object.
    limit: (int) Mandatory. Limits the number of items returned. Must be a positive integer.
           For lists, it's the number of elements. For dictionaries, it's the number of top-level key-value pairs.
    offset: (Optional[int], default 0) Specifies the starting index for lists. Ignored for dictionaries.

Returns:
    The data associated with '{key_name}'. Structure depends on the key:
    - {tool_description}
    The return type is typically a dictionary or a list of dictionaries.

Raises:
    RuntimeError: If no PE file is currently loaded.
    ValueError: If limit is not a positive integer, or if the response size exceeds the server limit.
"""
    _tool_func.__doc__ = doc
    return tool_decorator(_tool_func)

TOOL_DEFINITIONS = {
    "file_hashes":"Cryptographic hashes (MD5, SHA1, SHA256, ssdeep) for the entire loaded PE file. Output is a dictionary.",
    "dos_header":"Detailed breakdown of the DOS_HEADER structure from the PE file. Output is a dictionary.",
    "nt_headers":"Detailed breakdown of NT_HEADERS, including File Header and Optional Header. Output is a dictionary.",
    "data_directories":"Information on all Data Directories (e.g., import, export, resource tables), including their RVAs and sizes. Output is a list of dictionaries.",
    "sections":"Detailed information for each section in the PE file (name, RVA, size, characteristics, entropy, hashes). Output is a list of dictionaries.",
    "imports":"List of imported DLLs and, for each DLL, the imported symbols (functions/ordinals). Output is a list of dictionaries.",
    "exports":"Information on exported symbols from the PE file, including name, RVA, ordinal, and any forwarders. Output is a dictionary.",
    "resources_summary":"A summary list of resources found in the PE file, detailing type, ID/name, language, RVA, and size. Output is a list of dictionaries.",
    "version_info":"Version information extracted from the PE file's version resource (e.g., FileVersion, ProductName). Output is a dictionary.",
    "debug_info":"Details from the debug directory, which may include PDB paths or CodeView information. Output is a list of dictionaries.",
    "digital_signature":"Information about the PE file's Authenticode digital signature, including certificate details and validation status (if 'cryptography' and 'signify' libs are available). Output is a dictionary.",
    "peid_matches":"Results from PEiD-like signature scanning, indicating potential packers or compilers. Includes entry-point and heuristic matches. Output is a dictionary.",
    "yara_matches":"Results from YARA scanning, listing any matched rules, tags, metadata, and string identifiers. Output is a list of dictionaries.",
    # "floss_analysis" will have its own dedicated tool due to complexity.
    "rich_header":"Decoded Microsoft Rich Header information, often indicating compiler/linker versions. Output is a dictionary.",
    "delay_load_imports":"Information on delay-loaded imported DLLs and their symbols. Output is a list of dictionaries.",
    "tls_info":"Details from the Thread Local Storage (TLS) directory, including any callback function addresses. Output is a dictionary.",
    "load_config":"Information from the Load Configuration directory, including flags like Control Flow Guard (CFG) status. Output is a dictionary.",
    "com_descriptor":"Information from the .NET COM Descriptor (IMAGE_COR20_HEADER) if the PE is a .NET assembly. Output is a dictionary.",
    "overlay_data":"Information about any data appended to the end of the PE file (overlay), including offset, size, and hashes. Output is a dictionary.",
    "base_relocations":"Details of base relocations within the PE file. Output is a list of dictionaries.",
    "bound_imports":"Information on bound imports, if present. Output is a list of dictionaries.",
    "exception_data":"Data from the exception directory (e.g., RUNTIME_FUNCTION entries for x64). Output is a list of dictionaries.",
    "coff_symbols":"COFF (Common Object File Format) symbol table entries, if present. Output is a list of dictionaries.",
    "checksum_verification":"Verification of the PE file's checksum against the value in the Optional Header. Output is a dictionary.",
    "pefile_warnings":"Any warnings generated by the 'pefile' library during parsing. Output is a list of strings."
}
for key, desc in TOOL_DEFINITIONS.items(): globals()[f"get_{key}_info"] = _create_mcp_tool_for_key(key, desc)
