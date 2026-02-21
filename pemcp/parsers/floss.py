"""FLOSS advanced string extraction and analysis."""
import re
import json
import logging
import datetime

from pathlib import Path
from typing import Dict, Any, Optional, List, Set

from pemcp.config import (
    logger, state,
    FLOSS_AVAILABLE, FLOSS_SETUP_OK, FLOSS_ANALYSIS_OK,
    FLOSS_IMPORT_ERROR_SETUP, FLOSS_IMPORT_ERROR_ANALYSIS,
    Actual_DebugLevel_Floss, Actual_StringType_Floss,
    FLOSS_TRACE_LEVEL_CONST, FLOSS_LOGGERS_LIST,
)

if FLOSS_ANALYSIS_OK:
    import viv_utils
    from vivisect import VivWorkspace
    from floss.utils import get_static_strings, set_vivisect_log_level, get_imagebase
    from floss.identify import (
        find_decoding_function_features, get_top_functions, get_function_fvas,
        get_tight_function_fvas, append_unique, get_functions_with_tightloops
    )
    from floss.stackstrings import extract_stackstrings
    from floss.tightstrings import extract_tightstrings
    from floss.string_decoder import decode_strings
    from floss.results import ResultDocument, Metadata as FlossMetadata, Analysis as FlossAnalysis
else:
    VivWorkspace = None  # type: ignore


# --- FLOSS Analysis Helper Functions ---
def _setup_floss_logging(script_verbose_level: int, floss_internal_verbose_level: int):
    """
    Configures FLOSS internal loggers based on script's verbosity settings.
    script_verbose_level: Corresponds to FLOSS DebugLevel (NONE, DEFAULT, TRACE, SUPERTRACE)
    floss_internal_verbose_level: Corresponds to FLOSS's own -v, -vv flags (0, 1, 2)
                                   This is primarily for the verbosity of string output, not general logging.
                                   The script's general --verbose controls FLOSS's internal loggers.
    """
    if not FLOSS_SETUP_OK: # If basic FLOSS logging components aren't even available
        logger.debug("FLOSS setup not OK, skipping FLOSS logger configuration.")
        return

    # Determine the overall logging level for FLOSS components
    # This maps the script's --verbose/--debug type flags to FLOSS's internal logger levels
    floss_log_level_setting = logging.WARNING # Default to WARNING to keep FLOSS quiet unless specified
    if script_verbose_level >= Actual_DebugLevel_Floss.SUPERTRACE: # e.g. script --floss-debug-level SUPERTRACE
        floss_log_level_setting = FLOSS_TRACE_LEVEL_CONST # Show TRACE and above from FLOSS
    elif script_verbose_level >= Actual_DebugLevel_Floss.TRACE: # e.g. script --floss-debug-level TRACE
        floss_log_level_setting = FLOSS_TRACE_LEVEL_CONST
    elif script_verbose_level >= Actual_DebugLevel_Floss.DEFAULT: # e.g. script --floss-debug-level DEBUG
        floss_log_level_setting = logging.DEBUG
    elif script_verbose_level > Actual_DebugLevel_Floss.NONE : # A general verbose flag for the script might imply INFO for FLOSS
        floss_log_level_setting = logging.INFO


    logger.info(f"Setting FLOSS-related loggers to: {logging.getLevelName(floss_log_level_setting)}")
    for logger_name_floss in FLOSS_LOGGERS_LIST:
        # Special handling for very verbose loggers in FLOSS if needed
        if logger_name_floss in ("floss.api_hooks", "floss.function_argument_getter") and \
           script_verbose_level < Actual_DebugLevel_Floss.SUPERTRACE:
            logging.getLogger(logger_name_floss).setLevel(logging.WARNING) # Keep these quieter unless SUPERTRACE
        else:
            logging.getLogger(logger_name_floss).setLevel(floss_log_level_setting)

    # Configure Vivisect log level based on FLOSS debug level
    if FLOSS_ANALYSIS_OK: # set_vivisect_log_level is in floss.utils
        if script_verbose_level < Actual_DebugLevel_Floss.TRACE:
            set_vivisect_log_level(logging.CRITICAL)
            logging.getLogger("viv_utils.emulator_drivers").setLevel(logging.ERROR)
        else: # TRACE or SUPERTRACE for FLOSS
            set_vivisect_log_level(logging.DEBUG)
            logging.getLogger("viv_utils.emulator_drivers").setLevel(logging.DEBUG)
        logger.info(f"Vivisect loggers configured based on FLOSS debug level {script_verbose_level}.")
    else:
        logger.debug("FLOSS analysis components (like floss.utils) not available, cannot set Vivisect log level via FLOSS.")

def _load_floss_vivisect_workspace(sample_path_obj: Path, format_hint: str) -> Optional[VivWorkspace]:
    """Loads a Vivisect workspace for FLOSS analysis."""
    if not FLOSS_ANALYSIS_OK or not viv_utils: # Check if viv_utils was imported
        logger.error("Vivisect utilities (viv_utils) required by FLOSS are not available. Cannot load workspace.")
        return None

    logger.info(f"FLOSS: Loading Vivisect workspace for: {sample_path_obj} (format: {format_hint})")
    vw = None
    try:
        if format_hint == "auto":
            # Basic auto-detection based on suffix, FLOSS might do more internally
            if sample_path_obj.suffix.lower() in (".sc32", ".raw32"): format_hint = "sc32"
            elif sample_path_obj.suffix.lower() in (".sc64", ".raw64"): format_hint = "sc64"
            # else, it will be treated as 'pe' by default by viv_utils.getWorkspace

        if format_hint == "sc32":
            vw = viv_utils.getShellcodeWorkspaceFromFile(str(sample_path_obj), arch="i386", analyze=True)
        elif format_hint == "sc64":
            vw = viv_utils.getShellcodeWorkspaceFromFile(str(sample_path_obj), arch="amd64", analyze=True)
        else: # "pe" or other formats viv_utils can handle
            vw = viv_utils.getWorkspace(str(sample_path_obj), analyze=True, should_save=False)

        if vw: logger.info("FLOSS: Vivisect workspace analysis complete.")
        else: logger.warning("FLOSS: Vivisect workspace loading returned None.")
        return vw
    except Exception as e:
        logger.error(f"FLOSS: Error loading Vivisect workspace: {e}", exc_info=True)
        return None

def _parse_floss_analysis(
    pe_filepath_str: str,
    min_length: int,
    floss_verbose_level: int, # This is FLOSS's own -v, -vv for string output (0,1,2)
    floss_script_debug_level: int, # This is this script's verbosity mapped to FLOSS DebugLevel enum
    floss_format_hint: str,
    floss_disabled_types: List[str],
    floss_only_types: List[str],
    floss_functions_to_analyze: List[int], # List of function RVAs/VAs
    quiet_mode_for_floss_progress: bool, # For disabling FLOSS's own progress bars
    regex_search_pattern: Optional[str] = None
    ) -> Dict[str, Any]:
    """
    Performs string extraction using FLOSS, enriches with context, ranks with StringSifter,
    and returns a structured result.
    """
    floss_results_dict: Dict[str, Any] = {
        "status": "Not performed", "error": None,
        "metadata": {}, "analysis_config": {},
        "strings": {
            "static_strings": [], "stack_strings": [],
            "tight_strings": [], "decoded_strings": []
        },
        "regex_matches": []
    }

    if not FLOSS_AVAILABLE:
        floss_results_dict["status"] = "FLOSS library not available."
        floss_results_dict["error"] = f"Setup: {FLOSS_IMPORT_ERROR_SETUP}, Analysis: {FLOSS_IMPORT_ERROR_ANALYSIS}"
        logger.warning("FLOSS analysis requested but FLOSS is not fully available.")
        return floss_results_dict

    _setup_floss_logging(floss_script_debug_level, floss_verbose_level)

    log_progress = floss_script_debug_level >= Actual_DebugLevel_Floss.DEFAULT

    if log_progress:
        logger.info(f"--- Starting FLOSS Analysis for: {pe_filepath_str} ---")
    sample_path = Path(pe_filepath_str)

    analysis_conf = FlossAnalysis(
        enable_static_strings=Actual_StringType_Floss.STATIC not in floss_disabled_types,
        enable_stack_strings=Actual_StringType_Floss.STACK not in floss_disabled_types,
        enable_tight_strings=Actual_StringType_Floss.TIGHT not in floss_disabled_types,
        enable_decoded_strings=Actual_StringType_Floss.DECODED not in floss_disabled_types,
    )
    if floss_only_types:
        analysis_conf.enable_static_strings = Actual_StringType_Floss.STATIC in floss_only_types
        analysis_conf.enable_stack_strings = Actual_StringType_Floss.STACK in floss_only_types
        analysis_conf.enable_tight_strings = Actual_StringType_Floss.TIGHT in floss_only_types
        analysis_conf.enable_decoded_strings = Actual_StringType_Floss.DECODED in floss_only_types

    floss_results_dict["analysis_config"] = {
        "static_enabled": analysis_conf.enable_static_strings,
        "stack_enabled": analysis_conf.enable_stack_strings,
        "tight_enabled": analysis_conf.enable_tight_strings,
        "decoded_enabled": analysis_conf.enable_decoded_strings,
        "min_length": min_length,
        "format_hint": floss_format_hint,
        "functions_to_analyze_count": len(floss_functions_to_analyze),
        "floss_internal_verbosity": floss_verbose_level,
    }

    if analysis_conf.enable_static_strings:
        if log_progress: logger.info("FLOSS: Extracting static strings...")
        try:
            static_strings_gen = get_static_strings(sample_path, min_length)
            static_list = []
            for s_obj in static_strings_gen:
                static_list.append({"offset": hex(s_obj.offset), "string": s_obj.string})
            floss_results_dict["strings"]["static_strings"] = static_list
            logger.info(f"FLOSS: Found {len(static_list)} static strings.")
        except Exception as e:
            logger.error(f"FLOSS: Error extracting static strings: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
            floss_results_dict["strings"]["static_strings"] = [{"error": str(e)}]

    vw: Optional[VivWorkspace] = None
    selected_functions_fvas_set: Set[int] = set()
    needs_vivisect = (analysis_conf.enable_stack_strings or
                      analysis_conf.enable_tight_strings or
                      analysis_conf.enable_decoded_strings)

    if needs_vivisect:
        if log_progress: logger.info("FLOSS: Preparing Vivisect workspace for deeper analysis...")
        vw = _load_floss_vivisect_workspace(sample_path, floss_format_hint)
        if vw:
            try:
                imagebase = get_imagebase(vw)
                floss_results_dict["metadata"]["imagebase"] = imagebase # Store as int for calculations
                all_vw_functions_vas = set(vw.getFunctions())
                if floss_functions_to_analyze:
                    valid_user_functions = set()
                    for fva_or_rva in floss_functions_to_analyze:
                        fva = fva_or_rva
                        if imagebase is not None and fva < imagebase :
                            fva = imagebase + fva_or_rva
                        if fva in all_vw_functions_vas:
                            valid_user_functions.add(fva)
                        else:
                            logger.warning(f"FLOSS: Requested function 0x{fva_or_rva:x} (resolved to VA 0x{fva:x}) not found in Vivisect workspace.")
                    selected_functions_fvas_set = valid_user_functions
                    if log_progress: logger.info(f"FLOSS: User specified {len(valid_user_functions)} valid functions for analysis.")
                else:
                    selected_functions_fvas_set = all_vw_functions_vas
                    if log_progress: logger.info(f"FLOSS: Will analyze all {len(all_vw_functions_vas)} functions found in Vivisect workspace.")
            except Exception as e_vw_setup:
                logger.error(f"FLOSS: Error during Vivisect workspace post-processing: {e_vw_setup}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                vw = None
        else:
            logger.error("FLOSS: Failed to load Vivisect workspace. Deeper analysis will be skipped.")
            floss_results_dict["status"] = "Vivisect workspace load failed"
            floss_results_dict["error"] = "Failed to load Vivisect workspace for FLOSS advanced analysis."

    if vw and analysis_conf.enable_static_strings and floss_results_dict["strings"]["static_strings"]:
        logger.info("FLOSS: Starting static string context enrichment...")
        image_base_from_meta = floss_results_dict.get("metadata", {}).get("imagebase")
        if image_base_from_meta:
            # Build file-offset-to-VA conversion table from PE sections
            _offset_to_va_sections = []
            try:
                from pemcp.config import state as _fstate
                pe_obj = _fstate.pe_object
                if pe_obj and hasattr(pe_obj, 'sections'):
                    for sec in pe_obj.sections:
                        raw_ptr = sec.PointerToRawData
                        raw_size = sec.SizeOfRawData
                        virt_addr = sec.VirtualAddress
                        if raw_size > 0:
                            _offset_to_va_sections.append((raw_ptr, raw_size, virt_addr))
            except Exception as e_sec:
                logger.warning(f"Could not build offset-to-VA table: {e_sec}")

            def _file_offset_to_va(file_offset):
                """Convert a file offset to a virtual address using PE section mapping."""
                for raw_ptr, raw_size, virt_addr in _offset_to_va_sections:
                    if raw_ptr <= file_offset < raw_ptr + raw_size:
                        return image_base_from_meta + virt_addr + (file_offset - raw_ptr)
                # Fallback: treat offset as RVA (matches old behavior)
                return image_base_from_meta + file_offset

            static_strings_list = floss_results_dict["strings"]["static_strings"]
            total_enriched_strings = 0
            logger.debug(f"Attempting to enrich {len(static_strings_list)} static strings.")
            for i, string_item in enumerate(static_strings_list):
                try:
                    string_offset = int(string_item["offset"], 16)
                    string_va = _file_offset_to_va(string_offset)
                    xrefs = vw.getXrefsTo(string_va)

                    if i > 0 and i % 100 == 0:
                        logger.debug(f"Processing string {i}/{len(static_strings_list)} at VA {hex(string_va)}...")

                    if xrefs:
                        total_enriched_strings += 1
                        logger.debug(f"Found {len(xrefs)} cross-references for string at {hex(string_va)}")
                        string_item["references"] = []
                        for ref_tuple in xrefs:
                            from_va = ref_tuple[0]
                            ref_func_va = vw.getFunction(from_va)
                            context_snippet = []
                            for j in range(-2, 3):
                                try:
                                    op = vw.getOpcode(from_va + (j * 4))
                                    if op:
                                        context_snippet.append(f"{hex(op.va)}: {op.mnem} {op.getOperands() if op else ''}")
                                except Exception:
                                    pass

                            string_item["references"].append({
                                "ref_from_va": hex(from_va),
                                "function_va": hex(ref_func_va) if ref_func_va else None,
                                "disassembly_context": context_snippet
                            })
                except Exception as e_xref:
                    logger.warning(f"Could not get xrefs for string at {string_item['offset']}: {e_xref}")
            logger.info(f"FLOSS: Context enrichment complete. Enriched {total_enriched_strings} out of {len(static_strings_list)} static strings with references.")
        else:
            logger.warning("FLOSS: Skipping static string context enrichment because imagebase could not be determined.")

    if vw and FLOSS_ANALYSIS_OK:
        decoding_features_map: Dict[int, Any] = {}
        if analysis_conf.enable_decoded_strings or analysis_conf.enable_tight_strings:
            if log_progress: logger.info("FLOSS: Identifying decoding function features...")
            try:
                decoding_features_map, _ = find_decoding_function_features(vw, list(selected_functions_fvas_set), disable_progress=quiet_mode_for_floss_progress)
                if log_progress: logger.info(f"FLOSS: Found decoding features for {len(decoding_features_map)} functions.")
            except Exception as e:
                logger.error(f"FLOSS: Error finding decoding features: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                err_msg_feat = {"error": f"Feature identification error: {str(e)}"}
                if analysis_conf.enable_decoded_strings: floss_results_dict["strings"]["decoded_strings"] = [err_msg_feat]
                if analysis_conf.enable_tight_strings: floss_results_dict["strings"]["tight_strings"] = [err_msg_feat]

        if analysis_conf.enable_stack_strings:
            if log_progress: logger.info("FLOSS: Extracting stack strings...")
            try:
                stack_strings_gen = extract_stackstrings(
                    vw, list(selected_functions_fvas_set), min_length,
                    verbosity=floss_verbose_level,
                    disable_progress=quiet_mode_for_floss_progress
                )
                stack_list = []
                for s_obj in stack_strings_gen:
                    stack_list.append({
                        "function_va": hex(s_obj.function),
                        "string_va": hex(s_obj.offset),
                        "string": s_obj.string
                    })
                floss_results_dict["strings"]["stack_strings"] = stack_list
                logger.info(f"FLOSS: Found {len(stack_list)} stack strings.")
            except Exception as e:
                logger.error(f"FLOSS: Error extracting stack strings: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                floss_results_dict["strings"]["stack_strings"] = [{"error": str(e)}]

        if analysis_conf.enable_tight_strings:
            if log_progress: logger.info("FLOSS: Extracting tight strings...")
            try:
                if not decoding_features_map and (analysis_conf.enable_decoded_strings or analysis_conf.enable_tight_strings):
                    logger.warning("FLOSS: Decoding features map is empty, cannot identify functions with tight loops.")
                    floss_results_dict["strings"]["tight_strings"] = [{"error": "Decoding features map was empty, prerequisite for tight strings."}]
                else:
                    tightloop_fvas_dict = get_functions_with_tightloops(decoding_features_map)

                    if log_progress: logger.info(f"FLOSS: Identified {len(tightloop_fvas_dict)} functions with tight loops for tight string analysis.")

                    if tightloop_fvas_dict:
                        tight_strings_gen = extract_tightstrings(
                            vw, tightloop_fvas_dict, min_length,
                            verbosity=floss_verbose_level,
                            disable_progress=quiet_mode_for_floss_progress
                        )
                        tight_list = []
                        for s_obj in tight_strings_gen:
                            tight_list.append({
                                # FIX: Changed s_obj.function_address to s_obj.function
                                "function_va": hex(s_obj.function),
                                "address_or_offset": hex(s_obj.address if hasattr(s_obj, 'address') else s_obj.offset),
                                "string": s_obj.string
                            })
                        floss_results_dict["strings"]["tight_strings"] = tight_list
                        logger.info(f"FLOSS: Found {len(tight_list)} tight strings.")
                    else:
                        if log_progress: logger.info("FLOSS: No functions with tight loops identified from features. Skipping tight string extraction.")
                        floss_results_dict["strings"]["tight_strings"] = []
            except Exception as e:
                logger.error(f"FLOSS: Error extracting tight strings: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                floss_results_dict["strings"]["tight_strings"] = [{"error": str(e)}]

        if analysis_conf.enable_decoded_strings:
            if log_progress: logger.info("FLOSS: Extracting decoded strings...")
            try:
                if not decoding_features_map and (analysis_conf.enable_decoded_strings or analysis_conf.enable_tight_strings):
                    logger.warning("FLOSS: Decoding features map is empty, cannot identify top candidate functions for decoding.")
                    floss_results_dict["strings"]["decoded_strings"] = [{"error": "Decoding features map was empty, prerequisite for decoded strings."}]
                else:
                    top_candidate_funcs_features = get_top_functions(decoding_features_map, 20)
                    fvas_to_emulate_set = get_function_fvas(top_candidate_funcs_features)
                    if log_progress: logger.info(f"FLOSS: Identified {len(fvas_to_emulate_set)} top candidate functions for decoded string emulation.")
                    if fvas_to_emulate_set:
                        decoded_strings_gen = decode_strings(
                            vw, list(fvas_to_emulate_set), min_length,
                            verbosity=floss_verbose_level,
                            disable_progress=quiet_mode_for_floss_progress
                        )
                        decoded_list = []
                        for s_obj in decoded_strings_gen:
                            decoded_list.append({
                                "string_va": hex(s_obj.address),
                                "string": s_obj.string,
                                "decoding_routine_va": hex(s_obj.decoding_routine)
                            })
                        floss_results_dict["strings"]["decoded_strings"] = decoded_list
                        logger.info(f"FLOSS: Found {len(decoded_list)} decoded strings.")
                    else:
                        if log_progress: logger.info("FLOSS: No candidate functions found for decoded string emulation from features.")
                        floss_results_dict["strings"]["decoded_strings"] = []
            except Exception as e:
                logger.error(f"FLOSS: Error extracting decoded strings: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                floss_results_dict["strings"]["decoded_strings"] = [{"error": str(e)}]

        floss_results_dict["status"] = "FLOSS analysis complete."
    elif needs_vivisect and not vw:
        floss_results_dict["status"] = "FLOSS analysis incomplete due to Vivisect workspace load failure."
        floss_results_dict["error"] = floss_results_dict.get("error", "Vivisect workspace could not be loaded.")
        err_msg_vw = {"error": "Vivisect workspace load failed"}
        if analysis_conf.enable_stack_strings: floss_results_dict["strings"]["stack_strings"] = [err_msg_vw]
        if analysis_conf.enable_tight_strings: floss_results_dict["strings"]["tight_strings"] = [err_msg_vw]
        if analysis_conf.enable_decoded_strings: floss_results_dict["strings"]["decoded_strings"] = [err_msg_vw]
    elif not needs_vivisect:
         floss_results_dict["status"] = "FLOSS analysis complete (only static strings requested/enabled)."
    else:
        floss_results_dict["status"] = "FLOSS analysis status unclear."

    if regex_search_pattern:
        if log_progress:
            logger.info(f"Performing regex search with pattern: '{regex_search_pattern}'")

        try:
            from pemcp.utils import validate_regex_pattern
            validate_regex_pattern(regex_search_pattern)
            pattern = re.compile(regex_search_pattern, re.IGNORECASE)
        except (re.error, ValueError) as e:
            logger.error(f"Invalid regex pattern provided: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
            floss_results_dict["regex_matches"] = [{"error": f"Invalid regex pattern: {e}"}]
            return floss_results_dict

        all_found_strings = []
        for source_type, string_list in floss_results_dict["strings"].items():
            for string_item in string_list:
                if isinstance(string_item, dict) and "string" in string_item:
                    contextual_item = string_item.copy()
                    contextual_item["source_type"] = source_type.replace("_strings", "")
                    all_found_strings.append(contextual_item)

        matched_strings = []
        for string_item in all_found_strings:
            string_to_search = string_item["string"]
            if pattern.search(string_to_search):
                matched_strings.append(string_item)

        floss_results_dict["regex_matches"] = matched_strings
        if log_progress:
            logger.info(f"Found {len(matched_strings)} strings matching the regex pattern.")

    if log_progress or "complete" not in floss_results_dict["status"].lower():
        logger.info(f"--- FLOSS Analysis for: {pe_filepath_str} Finished (Status: {floss_results_dict['status']}) ---")

    return floss_results_dict
