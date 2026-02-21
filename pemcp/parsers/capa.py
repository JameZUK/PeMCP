"""Capa capability analysis integration."""
import os
import json
import logging

from pathlib import Path
from typing import Dict, Any, Optional

from pemcp.config import (
    logger, pefile, CAPA_AVAILABLE, CAPA_IMPORT_ERROR,
    DATA_DIR, CAPA_RULES_DEFAULT_DIR_NAME, CAPA_RULES_ZIP_URL, CAPA_RULES_SUBDIR_NAME,
)
from pemcp.resources import ensure_capa_rules_exist

if CAPA_AVAILABLE:
    import capa
    import capa.main
    import capa.rules
    import capa.loader
    import capa.capabilities.common
    import capa.render.result_document as rd
    import capa.engine
    import capa.render.json as capa_json_render
    import capa.features.extractors.pefile as capa_pefile_extractor
    import capa.features.common
    from capa.exceptions import (
        InvalidArgument, EmptyReportError, UnsupportedOSError,
        UnsupportedArchError, UnsupportedFormatError, UnsupportedRuntimeError,
    )


def _parse_capa_analysis(pe_obj: pefile.PE,
                         pe_filepath_original: str,
                         capa_rules_dir_path: Optional[str],
                         capa_sigs_dir_path: Optional[str],
                         verbose: bool) -> Dict[str, Any]:
    capa_results: Dict[str, Any] = {"status": "Not performed", "error": None, "results": None}

    if not CAPA_AVAILABLE:
        capa_results["status"] = "Capa library components not available."
        capa_results["error"] = f"Capa import error: {CAPA_IMPORT_ERROR}"
        logger.warning("Capa components not available. Error: %s", CAPA_IMPORT_ERROR)
        return capa_results

    effective_rules_path_str = capa_rules_dir_path
    if not effective_rules_path_str:
        default_rules_base = str(DATA_DIR / CAPA_RULES_DEFAULT_DIR_NAME)
        logger.info("Capa rules directory not specified, using default script-relative base: '%s'", default_rules_base)
        effective_rules_path_str = ensure_capa_rules_exist(default_rules_base, CAPA_RULES_ZIP_URL, verbose)
    elif not os.path.isdir(effective_rules_path_str) or not os.listdir(effective_rules_path_str):
        logger.warning("Provided capa_rules_dir_path '%s' is invalid. Attempting script-relative default.", capa_rules_dir_path)
        default_rules_base = str(DATA_DIR / CAPA_RULES_DEFAULT_DIR_NAME)
        effective_rules_path_str = ensure_capa_rules_exist(default_rules_base, CAPA_RULES_ZIP_URL, verbose)

    if not effective_rules_path_str:
        err_path_msg_part = capa_rules_dir_path if capa_rules_dir_path else str(DATA_DIR / CAPA_RULES_DEFAULT_DIR_NAME / CAPA_RULES_SUBDIR_NAME)
        capa_results["status"] = "Capa rules not found or download/extraction failed."
        capa_results["error"] = f"Failed to ensure capa rules at '{err_path_msg_part}'."
        logger.error(capa_results["error"])
        return capa_results
    else:
        logger.info("Using capa rules from: %s", effective_rules_path_str)


    class MockCapaCliArgs: pass
    mock_args = MockCapaCliArgs()
    mock_args.input_file = Path(pe_filepath_original)

    logger.info("Attempting capa analysis using capa.main workflow for: %s", mock_args.input_file)

    setattr(mock_args, 'rules', [Path(effective_rules_path_str)])
    if hasattr(mock_args, 'is_default_rules'): setattr(mock_args, 'is_default_rules', False)

    effective_capa_sigs_path_str_for_mock_args = ""
    if capa_sigs_dir_path and Path(capa_sigs_dir_path).is_dir():
        effective_capa_sigs_path_str_for_mock_args = str(capa_sigs_dir_path)
        logger.info("Using user-provided Capa signatures directory: %s", effective_capa_sigs_path_str_for_mock_args)
    else:
        if capa_sigs_dir_path:
            logger.warning("User-provided capa_sigs_dir '%s' is not a valid directory.", capa_sigs_dir_path)
        else:
            logger.info("Capa signatures directory not explicitly provided by user.")

        potential_script_relative_sigs = DATA_DIR / "capa_sigs"
        if potential_script_relative_sigs.is_dir():
             effective_capa_sigs_path_str_for_mock_args = str(potential_script_relative_sigs.resolve())
             logger.info("Found and using script-relative 'capa_sigs' directory: %s", effective_capa_sigs_path_str_for_mock_args)
        elif (DATA_DIR / CAPA_RULES_DEFAULT_DIR_NAME / "sigs").is_dir():
             effective_capa_sigs_path_str_for_mock_args = str((DATA_DIR / CAPA_RULES_DEFAULT_DIR_NAME / "sigs").resolve())
             logger.info("Found 'sigs' directory near default rules store: %s", effective_capa_sigs_path_str_for_mock_args)
        else:
            logger.warning("Capa signatures directory not found locally (e.g., ./capa_sigs or next to default rules). Explicitly telling Capa to load no library function signatures to prevent potential errors if Capa's internal default path is problematic.")
            effective_capa_sigs_path_str_for_mock_args = "" # Tell capa to load no library sigs

    setattr(mock_args, 'signatures', effective_capa_sigs_path_str_for_mock_args)
    if hasattr(mock_args, 'is_default_signatures'):
        is_capa_internal_default_path = False
        if hasattr(capa.main, 'SIGNATURES_PATH_DEFAULT_STRING'): # Check if this attribute exists in the capa version
             is_capa_internal_default_path = (effective_capa_sigs_path_str_for_mock_args == getattr(capa.main, 'SIGNATURES_PATH_DEFAULT_STRING'))
        setattr(mock_args, 'is_default_signatures', (not bool(capa_sigs_dir_path)) and is_capa_internal_default_path and effective_capa_sigs_path_str_for_mock_args != "")


    setattr(mock_args, 'format', getattr(capa.features.common, 'FORMAT_PE', 'pe')) # Default to PE
    setattr(mock_args, 'backend', getattr(capa.loader, 'BACKEND_AUTO', 'auto')) # Default to auto backend
    setattr(mock_args, 'os', getattr(capa.features.common, 'OS_WINDOWS', 'windows')) # Default to Windows
    setattr(mock_args, 'tag', None) # No specific tag filtering by default
    setattr(mock_args, 'verbose', verbose) # Propagate verbosity
    setattr(mock_args, 'vverbose', False) # Not super verbose by default
    setattr(mock_args, 'json', True) # We want JSON output internally
    setattr(mock_args, 'color', "never") # No color codes in internal JSON
    setattr(mock_args, 'debug', verbose) # Propagate debug
    setattr(mock_args, 'quiet', not verbose) # Quiet if not verbose

    # Ensure these exist for newer capa versions if they are checked by capa.main functions
    if not hasattr(mock_args, 'restrict_to_functions'): setattr(mock_args, 'restrict_to_functions', [])
    if not hasattr(mock_args, 'restrict_to_processes'): setattr(mock_args, 'restrict_to_processes', [])

    try:
        if verbose:
            sig_val = getattr(mock_args, 'signatures', 'N/A')
            if isinstance(sig_val, Path): sig_val = str(sig_val)
            rules_val_str_list = [str(r) for r in getattr(mock_args, 'rules', [])]
            logger.info("   [VERBOSE-CAPA] Mocked CLI args for capa.main: input_file='%s', rules=%s, format='%s', backend='%s', os='%s', signatures='%s'", mock_args.input_file, rules_val_str_list, mock_args.format, mock_args.backend, mock_args.os, sig_val)

        # Call capa's main argument handling and setup functions if they exist
        if hasattr(capa.main, 'handle_common_args'):
            capa.main.handle_common_args(mock_args)

        if hasattr(capa.main, 'ensure_input_exists_from_cli'):
            capa.main.ensure_input_exists_from_cli(mock_args)

        input_format = mock_args.format
        if hasattr(capa.main, 'get_input_format_from_cli'):
            input_format = capa.main.get_input_format_from_cli(mock_args)
        mock_args.format = input_format # Update mock_args with potentially deduced format

        rules = capa.main.get_rules_from_cli(mock_args)
        logger.info("Rules loaded via capa.main.get_rules_from_cli. Rule count: %s", len(rules.rules) if hasattr(rules, 'rules') and hasattr(rules.rules, '__len__') else 'N/A')

        backend = mock_args.backend
        if hasattr(capa.main, 'get_backend_from_cli'):
            backend = capa.main.get_backend_from_cli(mock_args, input_format)
        mock_args.backend = backend # Update mock_args

        if hasattr(capa.main, 'get_os_from_cli'): # os might be deduced
            mock_args.os = capa.main.get_os_from_cli(mock_args, backend)

        extractor = capa.main.get_extractor_from_cli(mock_args, input_format, backend)
        logger.info("Extractor obtained via capa.main.get_extractor_from_cli: %s", type(extractor).__name__)

        capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)
        logger.info("Capabilities search complete.")

        # Prepare metadata for the ResultDocument
        # Simulate argv for capa's metadata collection
        simulated_argv_for_meta = ["PeMCP.py", str(mock_args.input_file)] # Basic argv

        actual_rule_paths_for_meta = mock_args.rules
        # Ensure actual_rule_paths_for_meta is List[Path] for collect_metadata
        if not (isinstance(actual_rule_paths_for_meta, list) and \
                all(isinstance(p, Path) for p in actual_rule_paths_for_meta)):
            logger.warning("Rules paths for capa.loader.collect_metadata ('mock_args.rules': %s) are not List[Path] as expected. Metadata might be incomplete.", actual_rule_paths_for_meta)
            # Attempt to convert if they are strings, otherwise use empty list
            temp_paths = []
            all_valid = True
            if isinstance(actual_rule_paths_for_meta, list):
                for p_item in actual_rule_paths_for_meta:
                    if isinstance(p_item, Path): temp_paths.append(p_item)
                    elif isinstance(p_item, str) and os.path.exists(p_item): temp_paths.append(Path(p_item))
                    else: all_valid = False; break
            else: all_valid = False
            actual_rule_paths_for_meta = temp_paths if all_valid else []


        meta = capa.loader.collect_metadata(
            simulated_argv_for_meta,
            mock_args.input_file, # sample_path (Path object)
            input_format,         # format (str)
            mock_args.os,         # analysis_os (str)
            actual_rule_paths_for_meta, # rules_paths (List[Path])
            extractor,            # extractor (FeatureExtractor)
            capabilities          # capabilities (RuleSetCapabilities)
        )
        # Compute layout if necessary (newer capa versions handle this internally or via ResultDocument)
        if hasattr(meta, 'analysis') and hasattr(capabilities, 'matches') and hasattr(meta.analysis, 'layout') and hasattr(capa.loader, 'compute_layout'):
            meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

        # Create the ResultDocument and render to JSON
        doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
        # Render to JSON string, then parse back to dict to ensure consistent structure
        json_output_str = doc.model_dump_json(exclude_none=True) # exclude_none=True is good practice

        capa_results["results"] = json.loads(json_output_str)
        capa_results["status"] = "Analysis complete (adapted workflow)"

    except (InvalidArgument, EmptyReportError, UnsupportedOSError, UnsupportedArchError, UnsupportedFormatError, UnsupportedRuntimeError) as e_specific_api:
        error_msg = f"Capa analysis failed with specific API exception: {type(e_specific_api).__name__} - {str(e_specific_api)}"
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (API specific)"
        capa_results["error"] = error_msg
    except AttributeError as e_attr:
        error_msg = f"Capa API call failed (AttributeError): {e_attr}. This may indicate an API incompatibility or missing component in the capa version."
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (API incompatibility)"
        capa_results["error"] = error_msg
    except FileNotFoundError as e_fnf: # Catch if capa tries to access a file that's not there (e.g. during extraction)
        error_msg = f"Capa analysis failed (FileNotFoundError): {e_fnf}."
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (File Not Found for capa)"
        capa_results["error"] = error_msg
    except Exception as e:
        # Check if it's a capa-defined exit error
        should_exit_error_type = getattr(capa.main, 'ShouldExitError', None) # Gracefully check if this exists
        if should_exit_error_type and isinstance(e, should_exit_error_type):
            error_msg = f"Capa analysis aborted ({type(e).__name__}): {e} (status_code: {getattr(e, 'status_code', 'N/A')})"
            capa_results["status"] = f"Error during analysis ({type(e).__name__})"
            capa_results["hint"] = (
                "Capa's ShouldExitError typically means the sample is "
                "incompatible with the current capa version or its feature "
                "extractor could not process this binary.  Common causes: "
                "tiny/stripped PE, unusual architecture, or corrupted headers.  "
                "Try updating capa (pip install -U flare-capa) or use a "
                "different analysis tool for this sample."
            )
        else:
            error_msg = f"Unexpected error during adapted capa analysis: {type(e).__name__} - {e}"
            capa_results["status"] = "Unexpected error"
        logger.error(error_msg, exc_info=verbose)
        capa_results["error"] = error_msg

    return capa_results
