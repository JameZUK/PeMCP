"""MCP tools for PE data retrieval - summary, full results, dynamic per-key tools, open/close, and reanalysis."""
import os
import json
import asyncio
import datetime
import hashlib
from dataclasses import dataclass, field

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
from pemcp.mcp.tools_config import build_path_info
from pemcp.mcp._format_helpers import detect_format_from_magic
from pemcp.parsers.pe import _parse_pe_to_dict, _parse_file_hashes
from pemcp.parsers.strings import _extract_strings_from_data, _perform_unified_string_sifting

# Upper bound on the 'limit' parameter to prevent excessive memory allocation
_MAX_LIMIT = 100_000
from pemcp.parsers.floss import _parse_floss_analysis
from pemcp.background import _console_heartbeat_loop, _update_progress, start_angr_background as start_angr_background_fn
from pemcp.mock import MockPE

def _safe_env_int(key: str, default: int) -> int:
    """Read an environment variable as int with fallback to default."""
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        logger.warning("Invalid value for %s=%r, using default %d", key, val, default)
        return default

# Limit concurrent heavy analyses (open_file with full PE parsing, FLOSS, etc.).
# This is a global semaphore shared across all HTTP sessions.  In multi-tenant
# deployments, one user's analysis can block another if the limit is reached.
# Increase via PEMCP_MAX_CONCURRENT_ANALYSES for high-concurrency environments.
_analysis_semaphore = asyncio.Semaphore(_safe_env_int("PEMCP_MAX_CONCURRENT_ANALYSES", 3))

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
    packer_names = [
        m.get('name', m.get('match', '?')) if isinstance(m, dict) else str(m)
        for m in (ep_matches + heuristic)
        if isinstance(m, (dict, str))
    ]
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

    When a previously analysed file is reopened, the response includes a
    'session_context' field with restored notes and prior tool history. If
    session_context is present, call get_analysis_digest() FIRST to review
    what was learned in previous sessions before repeating analysis steps.

    Args:
        ctx: The MCP Context object.
        file_path: (str) Absolute or relative path to the file to analyse.
        mode: (str) Analysis mode — 'auto' (default, detects from magic bytes), 'pe', 'elf', 'macho', or 'shellcode'.
        analyses_to_skip: (Optional[List[str]]) List of analyses to skip: 'peid', 'yara', 'capa', 'floss'.
        start_angr_background: (bool) If True (default) and angr is available, start background CFG analysis.
        use_cache: (bool) If True (default), check the disk cache for previous analysis results.

    Returns:
        A dictionary with status, filepath, detected format, summary of what was
        loaded, and (if available) session_context with restored notes and history.
    """
    abs_path = str(Path(file_path).resolve())

    # Enforce path sandboxing (configured via --allowed-paths)
    state.check_path_allowed(abs_path)

    if not os.path.isfile(abs_path):
        raise RuntimeError(f"[open_file] File not found: {abs_path}")

    # Reject files that are too large to analyze safely in memory
    MAX_FILE_SIZE = _safe_env_int("PEMCP_MAX_FILE_SIZE_MB", 256) * 1024 * 1024
    file_size = os.path.getsize(abs_path)
    if file_size > MAX_FILE_SIZE:
        raise RuntimeError(
            f"[open_file] File is too large ({file_size / (1024*1024):.1f} MB). "
            f"Maximum allowed size is {MAX_FILE_SIZE // (1024*1024)} MB. "
            "Set PEMCP_MAX_FILE_SIZE_MB environment variable to change this limit."
        )

    # Auto-detect format from magic bytes
    if mode == "auto":
        with open(abs_path, 'rb') as f:
            magic = f.read(4)
        mode = detect_format_from_magic(magic)
        if mode == "unknown":
            mode = "pe"  # fallback to PE, pefile will report errors if invalid
            await ctx.warning(
                f"Unrecognized file format (magic: {magic.hex()}). Falling back to PE mode. "
                "Use mode='shellcode', 'elf', or 'macho' to specify explicitly."
            )
        await ctx.info(f"Auto-detected format: {mode}")

    await ctx.info(f"Opening file: {abs_path} (mode: {mode})")

    skip_list = [s.lower() for s in (analyses_to_skip or [])]

    # Close any previously loaded file — use atomic reset methods
    if state.pe_object or state.filepath:
        state.close_pe()
        state.reset_angr()
        state.pe_data = None
        state.filepath = None

    _loaded_from_cache = False

    acquired = False
    try:
        await _analysis_semaphore.acquire()
        acquired = True
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
                            lambda: pefile.PE(data=_raw_file_data, fast_load=False)
                        )
                    _loaded_from_cache = True

                    # Restore notes and previous session history from cache
                    session_meta = analysis_cache.get_session_metadata(_file_sha256)
                    if session_meta:
                        state.notes = session_meta.get("notes", [])
                        state.previous_session_history = session_meta.get("tool_history", [])

                    await ctx.info(f"Analysis loaded from cache (SHA256: {_file_sha256[:16]}...)")
                    await ctx.report_progress(95, 100)

        if not _loaded_from_cache:
            state.loaded_from_cache = False

            if mode == "shellcode":
                await ctx.report_progress(5, 100)
                await ctx.info("Loading raw shellcode...")

                def _load_shellcode():
                    # Build the complete dict locally, then assign atomically
                    # to avoid concurrent readers seeing a partially-written dict.
                    pe_data = {
                        "filepath": abs_path,
                        "mode": "shellcode",
                        "file_hashes": _parse_file_hashes(_raw_file_data),
                        "basic_ascii_strings": [
                            {"offset": hex(o), "string": s}
                            for o, s in _extract_strings_from_data(_raw_file_data, 5)
                        ],
                        "floss_analysis": {"status": "Pending..."},
                    }
                    state.pe_object = MockPE(_raw_file_data)
                    state.filepath = abs_path
                    state.pe_data = pe_data

                await asyncio.to_thread(_load_shellcode)
                await ctx.report_progress(30, 100)

                if "floss" not in skip_list and FLOSS_AVAILABLE:
                    await ctx.info("Running FLOSS analysis on shellcode...")

                    def _run_floss():
                        # Build an updated copy and assign atomically to
                        # prevent concurrent readers from seeing partial state.
                        updated = dict(state.pe_data)
                        updated['floss_analysis'] = _parse_floss_analysis(
                            abs_path, FLOSS_MIN_LENGTH_DEFAULT, 0,
                            Actual_DebugLevel_Floss.NONE, "auto",
                            [], [], [], True,
                        )
                        _perform_unified_string_sifting(updated)
                        state.pe_data = updated

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
                    return pefile.PE(data=_raw_file_data, fast_load=False)

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

                _PE_ANALYSIS_TIMEOUT = _safe_env_int("PEMCP_ANALYSIS_TIMEOUT", 600)
                try:
                    state.pe_data = await asyncio.wait_for(
                        asyncio.to_thread(_run_analysis),
                        timeout=_PE_ANALYSIS_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    raise RuntimeError(
                        f"[open_file] PE analysis timed out after {_PE_ANALYSIS_TIMEOUT}s. "
                        "The file may be malformed or excessively complex. "
                        "Set PEMCP_ANALYSIS_TIMEOUT env var to increase the limit."
                    )

                # Rank strings with StringSifter (PE mode)
                await asyncio.to_thread(_perform_unified_string_sifting, state.pe_data)

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

        path_info = build_path_info(abs_path)
        result = {
            "status": "success",
            "filepath": abs_path,
            "internal_path": path_info["internal_path"],
            "external_path": path_info["external_path"],
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

        # Include session context when loading from cache with prior data
        cached_notes = getattr(state, "notes", []) or []
        prev_history = getattr(state, "previous_session_history", []) or []
        if cached_notes or prev_history:
            result["session_context"] = {
                "notes_count": len(cached_notes),
                "recent_notes": cached_notes[-5:],
                "previous_tools_run": [h["tool_name"] for h in prev_history[-20:]],
                "previous_tools_count": len(prev_history),
                "last_analyzed": prev_history[-1]["timestamp"] if prev_history else None,
                "hint": (
                    "Previous analysis data restored. "
                    "Call get_analysis_digest() to see what was learned, "
                    "or get_session_summary() for full session context. "
                    "Use add_note() and auto_note_function() to record new findings."
                ),
            }

        return result

    except Exception as e:
        # Clean up on failure — close any PE object that was created to
        # prevent resource leaks, then preserve an error record so clients
        # can distinguish "no file ever loaded" from "last open attempt failed".
        state.filepath = None
        state.pe_data = None
        state.close_pe()
        logger.error("open_file failed for '%s': %s", abs_path, e, exc_info=True)
        raise RuntimeError(f"[open_file] Failed to load '{abs_path}': {e}") from e
    finally:
        if acquired:
            _analysis_semaphore.release()


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
    closed_path_info = build_path_info(closed_path)

    # Persist notes and tool history to cache before clearing state
    sha = (state.pe_data or {}).get("file_hashes", {}).get("sha256") if state.pe_data else None
    if sha:
        analysis_cache.update_session_data(
            sha,
            notes=state.get_all_notes_snapshot(),
            tool_history=state.get_tool_history_snapshot(),
        )

    # Use atomic reset methods (safe for shared references from default state)
    state.close_pe()
    state.reset_angr()
    state.pe_data = None
    state.filepath = None
    state.loaded_from_cache = False
    state.clear_notes()
    state.clear_tool_history()
    state.previous_session_history = []

    await ctx.info(f"Closed file: {closed_path}")
    return {
        "status": "success",
        "message": f"File '{closed_path}' closed and analysis data cleared.",
        "internal_path": closed_path_info["internal_path"],
        "external_path": closed_path_info["external_path"],
    }


@dataclass
class _FlossConfig:
    """Groups FLOSS-related parameters for reanalysis to reduce function complexity."""
    min_length: int = 4
    verbose_level: int = 0
    debug_level: Any = None  # Actual_DebugLevel_Floss enum
    format_hint: str = "auto"
    disabled_types: list = field(default_factory=list)
    only_types: list = field(default_factory=list)
    functions_to_analyze: list = field(default_factory=list)
    quiet_mode: bool = True


def _build_floss_config(
    *,
    floss_min_length: Optional[int],
    floss_verbose_level: Optional[int],
    floss_script_debug_level: Optional[str],
    floss_format: Optional[str],
    floss_no_static: Optional[bool],
    floss_no_stack: Optional[bool],
    floss_no_tight: Optional[bool],
    floss_no_decoded: Optional[bool],
    floss_only_static: Optional[bool],
    floss_only_stack: Optional[bool],
    floss_only_tight: Optional[bool],
    floss_only_decoded: Optional[bool],
    floss_functions: Optional[List[str]],
    floss_quiet: Optional[bool],
    verbose_mcp_output: bool,
) -> _FlossConfig:
    """Convert individual FLOSS MCP parameters into a compact config object."""
    debug_level = Actual_DebugLevel_Floss.NONE
    if floss_script_debug_level:
        debug_map = {
            "NONE": Actual_DebugLevel_Floss.NONE,
            "DEFAULT": Actual_DebugLevel_Floss.DEFAULT,
            "DEBUG": Actual_DebugLevel_Floss.DEFAULT,
            "TRACE": Actual_DebugLevel_Floss.TRACE,
            "SUPERTRACE": Actual_DebugLevel_Floss.SUPERTRACE,
        }
        debug_level = debug_map.get(floss_script_debug_level.upper(), Actual_DebugLevel_Floss.NONE)

    disabled = []
    if floss_no_static: disabled.append(Actual_StringType_Floss.STATIC)
    if floss_no_stack: disabled.append(Actual_StringType_Floss.STACK)
    if floss_no_tight: disabled.append(Actual_StringType_Floss.TIGHT)
    if floss_no_decoded: disabled.append(Actual_StringType_Floss.DECODED)

    only = []
    if floss_only_static: only.append(Actual_StringType_Floss.STATIC)
    if floss_only_stack: only.append(Actual_StringType_Floss.STACK)
    if floss_only_tight: only.append(Actual_StringType_Floss.TIGHT)
    if floss_only_decoded: only.append(Actual_StringType_Floss.DECODED)

    funcs: List[int] = []
    if floss_functions:
        for func_str in floss_functions:
            try:
                funcs.append(int(func_str, 0))
            except ValueError:
                pass  # Invalid addresses logged by caller

    return _FlossConfig(
        min_length=floss_min_length if floss_min_length is not None else FLOSS_MIN_LENGTH_DEFAULT,
        verbose_level=floss_verbose_level if floss_verbose_level is not None else 0,
        debug_level=debug_level,
        format_hint=floss_format if floss_format is not None else "auto",
        disabled_types=disabled,
        only_types=only,
        functions_to_analyze=funcs,
        quiet_mode=floss_quiet if floss_quiet is not None else (not verbose_mcp_output),
    )


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
                proj = angr.Project(state.filepath, auto_load_libs=False)
                cfg = proj.analyses.CFGFast(normalize=True)
                state.set_angr_results(proj, cfg, None, None)
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
    if peid_db_path:
        state.check_path_allowed(current_peid_db_path)
    current_yara_rules_path = str(Path(yara_rules_path).resolve()) if yara_rules_path and Path(yara_rules_path).exists() else None
    if yara_rules_path and current_yara_rules_path:
        state.check_path_allowed(current_yara_rules_path)

    current_capa_rules_dir_to_use = None
    if "capa" not in normalized_analyses_to_skip and CAPA_AVAILABLE:
        if capa_rules_dir and Path(capa_rules_dir).is_dir() and os.listdir(Path(capa_rules_dir)):
            current_capa_rules_dir_to_use = str(Path(capa_rules_dir).resolve())
            state.check_path_allowed(current_capa_rules_dir_to_use)
        else:
            if capa_rules_dir: await ctx.warning(f"Provided capa_rules_dir '{capa_rules_dir}' is invalid/empty. Capa will use its default logic.")
            current_capa_rules_dir_to_use = capa_rules_dir

    current_capa_sigs_dir_to_use = None
    if "capa" not in normalized_analyses_to_skip and CAPA_AVAILABLE:
        if capa_sigs_dir and Path(capa_sigs_dir).is_dir():
            current_capa_sigs_dir_to_use = str(Path(capa_sigs_dir).resolve())
            state.check_path_allowed(current_capa_sigs_dir_to_use)
        else:
            current_capa_sigs_dir_to_use = capa_sigs_dir

    # Build FLOSS config from individual parameters
    floss_cfg = _build_floss_config(
        floss_min_length=floss_min_length,
        floss_verbose_level=floss_verbose_level,
        floss_script_debug_level=floss_script_debug_level_for_floss_loggers,
        floss_format=floss_format,
        floss_no_static=floss_no_static,
        floss_no_stack=floss_no_stack,
        floss_no_tight=floss_no_tight,
        floss_no_decoded=floss_no_decoded,
        floss_only_static=floss_only_static,
        floss_only_stack=floss_only_stack,
        floss_only_tight=floss_only_tight,
        floss_only_decoded=floss_only_decoded,
        floss_functions=floss_functions,
        floss_quiet=floss_quiet,
        verbose_mcp_output=verbose_mcp_output,
    )

    # Log any invalid FLOSS function addresses
    if floss_functions:
        for func_str in floss_functions:
            try:
                int(func_str, 0)
            except ValueError:
                await ctx.warning(f"Invalid FLOSS function address '{func_str}', skipping.")

    def perform_analysis_in_thread():
        temp_pe_obj = None
        try:
            temp_pe_obj = pefile.PE(state.filepath, fast_load=False)

            new_parsed_data = _parse_pe_to_dict(
                temp_pe_obj, state.filepath, current_peid_db_path, current_yara_rules_path,
                current_capa_rules_dir_to_use,
                current_capa_sigs_dir_to_use,
                verbose_mcp_output, skip_full_peid_scan, peid_scan_all_sigs_heuristically,
                floss_min_len_arg=floss_cfg.min_length,
                floss_verbose_level_arg=floss_cfg.verbose_level,
                floss_script_debug_level_arg=floss_cfg.debug_level,
                floss_format_hint_arg=floss_cfg.format_hint,
                floss_disabled_types_arg=floss_cfg.disabled_types,
                floss_only_types_arg=floss_cfg.only_types,
                floss_functions_to_analyze_arg=floss_cfg.functions_to_analyze,
                floss_quiet_mode_arg=floss_cfg.quiet_mode,
                analyses_to_skip=normalized_analyses_to_skip
            )
            return temp_pe_obj, new_parsed_data
        except Exception as e_thread:
            if temp_pe_obj:
                temp_pe_obj.close()
            logger.error("Error during threaded re-analysis of %s: %s", state.filepath, e_thread, exc_info=verbose_mcp_output)
            raise

    try:
        new_pe_obj_from_thread, new_parsed_data_from_thread = await asyncio.to_thread(perform_analysis_in_thread)

        if state.pe_object:
            state.pe_object.close()

        state.pe_object = new_pe_obj_from_thread
        state.pe_data = new_parsed_data_from_thread

        # Rank strings with StringSifter
        _perform_unified_string_sifting(state.pe_data)

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
        logger.info("Re-analysis of %s cancelled. Global PE data remains from previous successful load/analysis.", state.filepath)
        raise
    except Exception as e_outer:
        await ctx.error(f"Error re-analyzing PE '{state.filepath}': {str(e_outer)}");
        logger.error("MCP: Error re-analyzing PE '%s': %s", state.filepath, e_outer, exc_info=verbose_mcp_output)
        raise RuntimeError(f"Failed to re-analyze PE file '{state.filepath}': {str(e_outer)}") from e_outer


@tool_decorator
async def get_analyzed_file_summary(ctx: Context, limit: int = 50) -> Dict[str, Any]:
    """
    Retrieves a high-level summary of the pre-loaded and analyzed PE file.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        limit: (int) Limits the number of top-level key-value pairs returned. Must be positive. Default 50.

    Returns:
        A dictionary containing summary information.
    Raises:
        RuntimeError: If no PE file is currently loaded.
        ValueError: If limit is not a positive integer.
    """
    await ctx.info(f"Request for analyzed file summary. Limit: {limit}")
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    limit = min(limit, _MAX_LIMIT)

    _check_pe_loaded("get_analyzed_file_summary")

    floss_analysis_summary = state.pe_data.get('floss_analysis', {})
    floss_strings_summary = floss_analysis_summary.get('strings', {})

    dos = state.pe_data.get('dos_header')
    nt = state.pe_data.get('nt_headers')
    peid = state.pe_data.get('peid_matches', {})
    yara_matches = state.pe_data.get('yara_matches', [])
    capa = state.pe_data.get('capa_analysis', {})

    # Determine YARA status safely
    yara_status = "Not run/Skipped"
    if yara_matches and isinstance(yara_matches, list) and isinstance(yara_matches[0], dict):
        yara_status = yara_matches[0].get('status', "Run/No Matches or Not Run/Skipped")

    # Determine capa capability count
    capa_count = 0
    if capa.get('status') == "Analysis complete (adapted workflow)":
        capa_count = len(capa.get('results', {}).get('rules', {}))

    full_summary = {
        "filepath": state.filepath,
        "pefile_version_used": state.pefile_version,
        "has_dos_header": dos is not None and "error" not in (dos or {}),
        "has_nt_headers": nt is not None and "error" not in (nt or {}),
        "section_count": len(state.pe_data.get('sections', [])),
        "import_dll_count": len(state.pe_data.get('imports', [])),
        "export_symbol_count": len(state.pe_data.get('exports', {}).get('symbols', [])),
        "peid_ep_match_count": len(peid.get('ep_matches', [])),
        "peid_heuristic_match_count": len(peid.get('heuristic_matches', [])),
        "peid_status": peid.get('status', "Not run/Skipped"),
        "yara_match_count": len([
            m for m in yara_matches
            if isinstance(m, dict) and "error" not in m and "status" not in m
        ]),
        "yara_status": yara_status,
        "capa_status": capa.get('status', "Not run/Skipped"),
        "capa_capability_count": capa_count,
        "floss_status": floss_analysis_summary.get('status', "Not run/Skipped"),
        "floss_static_string_count": len(floss_strings_summary.get('static_strings', [])),
        "floss_stack_string_count": len(floss_strings_summary.get('stack_strings', [])),
        "floss_tight_string_count": len(floss_strings_summary.get('tight_strings', [])),
        "floss_decoded_string_count": len(floss_strings_summary.get('decoded_strings', [])),
        "has_embedded_signature": state.pe_data.get('digital_signature', {}).get(
            'embedded_signature_present', False
        ),
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
    limit = min(limit, _MAX_LIMIT)

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
    limit = min(limit, _MAX_LIMIT)

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


# ---- Focused Imports (AI-friendly filtered view) ----

@tool_decorator
async def get_focused_imports(
    ctx: Context,
    category: str = "all",
    min_risk: str = "MEDIUM",
    include_benign_summary: bool = True,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Returns only the security-relevant imports, categorized by threat behavior.
    Filters out benign imports (GetLastError, HeapAlloc, etc.) that waste context.

    Designed for AI analysts who need to quickly understand what suspicious
    capabilities a binary imports without reading thousands of benign entries.

    Use get_pe_data(key='imports') if you need the full raw import table.

    Args:
        ctx: The MCP Context object.
        category: (str) Filter to a specific category: 'all' (default),
            'process_injection', 'credential_theft', 'privilege_escalation',
            'anti_analysis', 'networking', 'process_manipulation', 'persistence',
            'execution', 'registry', 'crypto', 'file_io', 'memory'.
        min_risk: (str) Minimum risk level to include: 'CRITICAL', 'HIGH', or 'MEDIUM' (default).
        include_benign_summary: (bool) If True (default), include a one-line count of filtered-out imports.
        limit: (int) Max suspicious imports to return. Default 100.

    Returns:
        A dictionary with filtered imports, category counts, and optional benign summary.
    """
    from pemcp.mcp._category_maps import CATEGORIZED_IMPORTS_DB, RISK_ORDER, CATEGORY_DESCRIPTIONS

    _check_pe_loaded("get_focused_imports")
    imports_data = state.pe_data.get('imports', [])

    min_risk_val = RISK_ORDER.get(min_risk.upper(), 2)
    found: List[Dict[str, str]] = []
    total_imports = 0
    total_dlls = 0
    benign_dll_names: set = set()

    if isinstance(imports_data, list):
        for dll_entry in imports_data:
            if not isinstance(dll_entry, dict):
                continue
            dll_name = dll_entry.get('dll_name', 'Unknown')
            total_dlls += 1
            dll_had_suspicious = False
            for sym in dll_entry.get('symbols', []):
                total_imports += 1
                func_name = sym.get('name', '') if isinstance(sym, dict) else ''
                if not func_name:
                    continue
                # Check against categorized DB (substring match like triage)
                for api_name, (risk, cat) in CATEGORIZED_IMPORTS_DB.items():
                    if api_name in func_name:
                        risk_val = RISK_ORDER.get(risk, 3)
                        if risk_val <= min_risk_val:
                            if category == "all" or cat == category:
                                found.append({
                                    "dll": dll_name,
                                    "function": func_name,
                                    "risk": risk,
                                    "category": cat,
                                })
                                dll_had_suspicious = True
                        break
            if not dll_had_suspicious:
                benign_dll_names.add(dll_name)

    # Sort by risk severity then category
    found.sort(key=lambda x: (RISK_ORDER.get(x['risk'], 3), x.get('category', ''), x.get('function', '')))
    found = found[:limit]

    # Build category counts
    by_category: Dict[str, int] = {}
    for imp in found:
        cat = imp['category']
        by_category[cat] = by_category.get(cat, 0) + 1

    result: Dict[str, Any] = {
        "filtered_imports": found,
        "by_category": by_category,
        "total_suspicious": len(found),
        "total_imports": total_imports,
        "total_dlls": total_dlls,
    }

    if include_benign_summary:
        benign_count = total_imports - len(found)
        top_benign = sorted(benign_dll_names)[:5]
        benign_list = ', '.join(top_benign)
        if len(benign_dll_names) > 5:
            benign_list += f", ... (+{len(benign_dll_names) - 5} more)"
        result["benign_summary"] = (
            f"Filtered out {benign_count:,} benign imports from "
            f"{len(benign_dll_names)} DLLs ({benign_list})"
        )

    return await _check_mcp_response_size(ctx, result, "get_focused_imports")
