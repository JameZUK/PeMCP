"""MCP tools for PE data retrieval - summary, full results, dynamic per-key tools, and reanalysis."""
import os
import json
import asyncio
from typing import Dict, Any, Optional, List
from pathlib import Path

from pemcp.config import (
    state, logger, Context, pefile,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    FLOSS_MIN_LENGTH_DEFAULT,
    Actual_DebugLevel_Floss, Actual_StringType_Floss,
    DEFAULT_PEID_DB_PATH,
)
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.parsers.pe import _parse_pe_to_dict

if ANGR_AVAILABLE:
    import angr


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
