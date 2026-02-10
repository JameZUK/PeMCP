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
from pemcp.background import _console_heartbeat_loop, _update_progress, start_angr_background as start_angr_background_fn
from pemcp.mock import MockPE

if ANGR_AVAILABLE:
    import angr


def _build_quick_indicators(pe_data: Dict[str, Any]) -> Dict[str, Any]:
    """Build quick-look indicators from pe_data for the open_file response."""
    indicators: Dict[str, Any] = {}

    # File hashes
    hashes = pe_data.get('file_hashes', {})
    indicators["sha256"] = hashes.get('sha256')
    indicators["md5"] = hashes.get('md5')

    # Section stats
    sections = pe_data.get('sections', [])
    indicators["section_count"] = len(sections)
    max_ent = 0.0
    for sec in sections:
        if isinstance(sec, dict):
            ent = sec.get('entropy', 0.0)
            if isinstance(ent, (int, float)) and ent > max_ent:
                max_ent = ent
    indicators["max_section_entropy"] = round(max_ent, 3)
    indicators["high_entropy"] = max_ent > 7.0

    # Import count
    imports = pe_data.get('imports', [])
    total_funcs = 0
    dll_count = 0
    for dll_entry in imports:
        if isinstance(dll_entry, dict):
            dll_count += 1
            total_funcs += len(dll_entry.get('symbols', []))
    indicators["import_dll_count"] = dll_count
    indicators["import_function_count"] = total_funcs
    indicators["minimal_imports"] = total_funcs < 10

    # PEiD packer detection
    peid = pe_data.get('peid_matches', {})
    ep_matches = peid.get('ep_matches', []) if isinstance(peid, dict) else []
    heuristic = peid.get('heuristic_matches', []) if isinstance(peid, dict) else []
    packer_names = [m.get('name', m.get('match', '?')) for m in (ep_matches + heuristic) if isinstance(m, dict)]
    indicators["peid_detections"] = packer_names[:3] if packer_names else []

    # Digital signature
    sig_data = pe_data.get('digital_signature', {})
    if isinstance(sig_data, dict):
        indicators["is_signed"] = sig_data.get('embedded_signature_present', False)
    else:
        indicators["is_signed"] = False

    # Packing likelihood
    indicators["likely_packed"] = bool(packer_names) or max_ent > 7.2 or total_funcs < 10

    # Capa high-severity count
    capa_high = 0
    capa_data = pe_data.get('capa_analysis', {})
    if isinstance(capa_data, dict) and isinstance(capa_data.get('results'), dict):
        for rule_details in capa_data['results'].get('rules', {}).values():
            meta = rule_details.get('meta', {})
            ns = meta.get('namespace', '').split('/')[0]
            if ns in ('anti-analysis', 'collection', 'credential-access', 'defense-evasion',
                       'execution', 'impact', 'persistence', 'privilege-escalation', 'c2'):
                capa_high += 1
    indicators["capa_high_severity_count"] = capa_high

    return indicators


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

    # Enforce path sandboxing (configured via --allowed-paths)
    state.check_path_allowed(abs_path)

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
            start_angr_background_fn(
                abs_path,
                mode=mode,
                tool_label="open_file_angr_auto",
            )
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
        elif mode == "pe" and state.pe_data:
            # Quick indicators for PE files — instant first-look data
            result["quick_indicators"] = _build_quick_indicators(state.pe_data)
            result["suggested_next"] = "Call get_triage_report for comprehensive automated analysis."
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

PE_DATA_KEYS = {
    "file_hashes": "Cryptographic hashes (MD5, SHA1, SHA256, ssdeep).",
    "dos_header": "DOS_HEADER structure.",
    "nt_headers": "NT_HEADERS (File Header + Optional Header).",
    "data_directories": "Data Directory entries (import, export, resource tables, etc.).",
    "sections": "Section details (name, RVA, size, characteristics, entropy, hashes).",
    "imports": "Imported DLLs and their symbols (functions/ordinals).",
    "exports": "Exported symbols (name, RVA, ordinal, forwarders).",
    "resources_summary": "Resource entries (type, ID/name, language, RVA, size).",
    "version_info": "Version resource (FileVersion, ProductName, etc.).",
    "debug_info": "Debug directory (PDB paths, CodeView info).",
    "digital_signature": "Authenticode signature and certificate details.",
    "peid_matches": "PEiD packer/compiler signature matches.",
    "yara_matches": "YARA rule match results.",
    "rich_header": "Microsoft Rich Header (compiler/linker versions).",
    "delay_load_imports": "Delay-loaded imported DLLs and symbols.",
    "tls_info": "TLS directory details including callback addresses.",
    "load_config": "Load Configuration directory (CFG, security cookie, etc.).",
    "com_descriptor": ".NET COM Descriptor (IMAGE_COR20_HEADER).",
    "overlay_data": "Overlay data appended after the PE (offset, size, hashes).",
    "base_relocations": "Base relocation entries.",
    "bound_imports": "Bound import entries.",
    "exception_data": "Exception directory (RUNTIME_FUNCTION entries for x64).",
    "coff_symbols": "COFF symbol table entries.",
    "checksum_verification": "PE checksum verification result.",
    "pefile_warnings": "Warnings from the pefile library during parsing.",
}


@tool_decorator
async def get_pe_data(
    ctx: Context,
    key: str,
    limit: int = 50,
    offset: Optional[int] = 0,
) -> Any:
    """
    Retrieves a specific portion of the PE analysis results by key name.
    This is the unified data retrieval tool for all PE structure data.

    Use key='list' to discover all available data keys and their descriptions.

    Args:
        ctx: The MCP Context object.
        key: (str) The data key to retrieve (e.g. 'imports', 'sections', 'file_hashes').
             Use 'list' to see all available keys.
        limit: (int) Max items to return. For lists: element count. For dicts: key count. Default 50.
        offset: (Optional[int]) Starting index for list data. Ignored for dicts. Default 0.

    Returns:
        The requested analysis data, or a list of available keys when key='list'.
    """
    if key == "list":
        _check_pe_loaded("get_pe_data")
        available = {}
        for k, desc in PE_DATA_KEYS.items():
            val = state.pe_data.get(k)
            if val is not None:
                if isinstance(val, list):
                    available[k] = {"description": desc, "type": "list", "count": len(val)}
                elif isinstance(val, dict):
                    available[k] = {"description": desc, "type": "dict", "keys": len(val)}
                else:
                    available[k] = {"description": desc, "type": type(val).__name__}
            else:
                available[k] = {"description": desc, "status": "not_available"}
        return available

    await ctx.info(f"Request for PE data key '{key}'. Limit: {limit}, Offset: {offset}")

    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")

    _check_pe_loaded("get_pe_data")

    if key not in PE_DATA_KEYS:
        return {
            "error": f"Unknown key '{key}'.",
            "available_keys": list(PE_DATA_KEYS.keys()),
            "hint": "Use key='list' for detailed descriptions of each key.",
        }

    original_data = state.pe_data.get(key)
    if original_data is None:
        await ctx.warning(f"Data for '{key}' not found in analyzed results. It may have been skipped.")
        return await _check_mcp_response_size(ctx, {}, "get_pe_data")

    # Apply offset for lists
    processed_data = original_data
    if isinstance(original_data, list) and offset is not None:
        if not (isinstance(offset, int) and offset >= 0):
            await ctx.warning(f"Invalid 'offset' value '{offset}'. Using offset 0.")
            offset = 0
        if offset > 0:
            processed_data = original_data[offset:]

    # Apply limit
    data_to_send: Any
    if isinstance(processed_data, list):
        data_to_send = processed_data[:limit]
    elif isinstance(processed_data, dict):
        try:
            data_to_send = dict(list(processed_data.items())[:limit])
        except Exception:
            data_to_send = processed_data
    else:
        data_to_send = processed_data

    limit_info_str = f"the 'limit' or 'offset' parameters for data key '{key}'"
    return await _check_mcp_response_size(ctx, data_to_send, "get_pe_data", limit_info_str)
