"""Main entry point: argument parsing, CLI mode, and MCP server startup."""
import os
import sys
import logging
import datetime
import threading
import argparse

from pathlib import Path

from pemcp.config import (
    state, logger, pefile,
    ANGR_AVAILABLE, MCP_SDK_AVAILABLE, FLOSS_AVAILABLE,
    FLOSS_MIN_LENGTH_DEFAULT,
    Actual_DebugLevel_Floss, Actual_StringType_Floss,
    DEFAULT_PEID_DB_PATH, DATA_DIR, CAPA_RULES_DEFAULT_DIR_NAME,
    CAPA_RULES_SUBDIR_NAME,
)
from pemcp.mock import MockPE
from pemcp.background import _console_heartbeat_loop, _update_progress, start_angr_background
from pemcp.parsers.pe import _parse_pe_to_dict, _parse_file_hashes
from pemcp.parsers.strings import _extract_strings_from_data, _format_hex_dump_lines, _perform_unified_string_sifting
from pemcp.parsers.floss import _parse_floss_analysis
from pemcp.cli.printers import _cli_analyze_and_print_pe
from pemcp.mcp.server import mcp_server

# Import all MCP tool modules to register them with the server
import pemcp.mcp.tools_pe
import pemcp.mcp.tools_strings
import pemcp.mcp.tools_angr
import pemcp.mcp.tools_angr_extended
import pemcp.mcp.tools_pe_extended
import pemcp.mcp.tools_new_libs
import pemcp.mcp.tools_binary_formats
import pemcp.mcp.tools_misc


def main():
    parser = argparse.ArgumentParser(description="Comprehensive PE File Analyzer.", formatter_class=argparse.RawTextHelpFormatter)

    # --- Input & Mode ---
    parser.add_argument("--input-file", type=str, default=None, help="Path to the file to be analyzed. Required for CLI mode. Optional for MCP server mode (use open_file tool instead).")
    parser.add_argument("--mode", choices=["auto", "pe", "elf", "macho", "shellcode"], default="auto", help="Analysis mode: 'auto' (default, detects from magic bytes), 'pe', 'elf', 'macho', or 'shellcode'.")

    # --- External Resources ---
    parser.add_argument("-d", "--db", dest="peid_db", default=None, help=f"Path to PEiD userdb.txt. If not specified, defaults to '{DEFAULT_PEID_DB_PATH}'. Downloads if not found.")
    parser.add_argument("-y", "--yara-rules", dest="yara_rules", default=None, help="Path to YARA rule file or directory.")
    parser.add_argument("--capa-rules-dir", default=None, help=f"Directory containing capa rule files. If not provided or empty/invalid, attempts download to '{DATA_DIR / CAPA_RULES_DEFAULT_DIR_NAME / CAPA_RULES_SUBDIR_NAME}'.")
    parser.add_argument("--capa-sigs-dir", default=None, help="Directory containing capa library identification signature files (e.g., sigs/*.sig). Optional. If not provided, attempts to find a script-relative 'capa_sigs' or uses Capa's internal default.")

    # --- Skips ---
    parser.add_argument("--skip-capa", action="store_true", help="Skip capa capability analysis entirely.")
    parser.add_argument("--skip-floss", action="store_true", help="Skip FLOSS advanced string analysis entirely.")
    parser.add_argument("--skip-peid", action="store_true", help="Skip PEiD signature scanning entirely.")
    parser.add_argument("--skip-yara", action="store_true", help="Skip YARA scanning entirely.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for CLI mode and more detailed MCP logging.")

    # --- PEiD Options ---
    peid_group = parser.add_argument_group('PEiD Specific Options (if PEiD scan is not skipped)')
    peid_group.add_argument("--skip-full-peid-scan", action="store_true", help="Skip full PEiD scan (only scan entry point).")
    peid_group.add_argument("--psah", "--peid-scan-all-sigs-heuristically", action="store_true", dest="peid_scan_all_sigs_heuristically", help="During full heuristic PEiD scan, use ALL signatures (not just non-EP_only).")

    # --- FLOSS Options ---
    floss_group = parser.add_argument_group('FLOSS Specific Options (if FLOSS scan is not skipped)')
    floss_group.add_argument("--floss-min-length", "-n", type=int, default=None, help=f"Minimum string length for FLOSS (default: {FLOSS_MIN_LENGTH_DEFAULT}).")
    floss_group.add_argument("--floss-format", "-f", default="auto", choices=["auto", "pe", "sc32", "sc64"], help="File format hint for FLOSS/Vivisect (auto, pe, sc32, sc64). Important for shellcode mode.")
    floss_group.add_argument("--floss-no-static", action="store_true", help="FLOSS: Do not extract static strings.")
    floss_group.add_argument("--floss-no-stack", action="store_true", help="FLOSS: Do not extract stack strings.")
    floss_group.add_argument("--floss-no-tight", action="store_true", help="FLOSS: Do not extract tight strings.")
    floss_group.add_argument("--floss-no-decoded", action="store_true", help="FLOSS: Do not extract decoded strings.")
    floss_group.add_argument("--floss-only-static", action="store_true", help="FLOSS: Only extract static strings.")
    floss_group.add_argument("--floss-only-stack", action="store_true", help="FLOSS: Only extract stack strings.")
    floss_group.add_argument("--floss-only-tight", action="store_true", help="FLOSS: Only extract tight strings.")
    floss_group.add_argument("--floss-only-decoded", action="store_true", help="FLOSS: Only extract decoded strings.")
    floss_group.add_argument("--floss-functions", type=str, nargs="+", default=[], help="FLOSS: Hex addresses (e.g., 0x401000) of functions to analyze for stack/decoded strings.")
    floss_group.add_argument("--floss-verbose-level", "--fv", type=int, default=0, choices=[0,1,2], help="FLOSS internal verbosity for string output (0=default, 1=verbose, 2=more verbose). Default: 0.")
    floss_group.add_argument("--floss-quiet", "--fq", action="store_true", help="FLOSS: Suppress FLOSS's own progress indicators. Overrides script verbosity for FLOSS progress bars.")
    floss_group.add_argument("--floss-script-debug-level", default="NONE", choices=["NONE", "DEFAULT", "DEBUG", "TRACE", "SUPERTRACE"], help="Set logging level for FLOSS internal loggers (NONE, DEFAULT, TRACE, SUPERTRACE). Default: NONE.")
    floss_group.add_argument("-r", "--regex", dest="regex_pattern", type=str, default=None, help="A regex pattern to search for within all extracted FLOSS strings (case-insensitive).")

    # --- CLI Options ---
    cli_group = parser.add_argument_group('CLI Mode Specific Options (ignored if --mcp-server is used)')
    cli_group.add_argument("--extract-strings", action="store_true", help="Extract and print strings from the PE file (basic method, use FLOSS for advanced).")
    cli_group.add_argument("--min-str-len", type=int, default=5, help="Minimum length for basic extracted strings (default: 5).")
    cli_group.add_argument("--search-string", action="append", help="String to search for within the PE file (multiple allowed, basic method).")
    cli_group.add_argument("--strings-limit", type=int, default=100, help="Limit for basic string extraction and search results display (default: 100).")
    cli_group.add_argument("--hexdump-offset", type=lambda x:int(x,0), help="Hex dump start offset (e.g., 0x1000 or 4096).")
    cli_group.add_argument("--hexdump-length", type=int, help="Hex dump length in bytes.")
    cli_group.add_argument("--hexdump-lines", type=int, default=16, help="Maximum number of lines to display for hex dump (default: 16).")

    # --- MCP Options ---
    mcp_group = parser.add_argument_group('MCP Server Mode Specific Options')
    mcp_group.add_argument("--mcp-server", action="store_true", help="Run in MCP server mode. The --input-file is pre-analyzed, and tools operate on this file.")
    mcp_group.add_argument("--mcp-host", type=str, default="127.0.0.1", help="MCP server host (default: 127.0.0.1).")
    mcp_group.add_argument("--mcp-port", type=int, default=8082, help="MCP server port (default: 8082).")
    mcp_group.add_argument("--mcp-transport", type=str, default="stdio", choices=["stdio", "sse", "streamable-http"], help="MCP transport protocol: 'stdio' (default), 'streamable-http' (recommended for network), or 'sse' (deprecated).")
    mcp_group.add_argument("--allowed-paths", nargs="+", default=None, help="Restrict open_file to these directories (security sandbox for HTTP mode). Accepts multiple paths.")

    args = None
    try:
        args = parser.parse_args()
    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e_parse:
        print(f"[!] Exception during argument parsing: {type(e_parse).__name__} - {e_parse}", file=sys.stderr)
        sys.exit(1)

    if args is None:
        print("[!] Args is None after parsing attempt, exiting.", file=sys.stderr)
        sys.exit(1)
    # Configure logging level based on verbosity AFTER args are parsed
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger.setLevel(log_level)
    logging.getLogger('mcp').setLevel(log_level)
    if args.mcp_transport in ('sse', 'streamable-http'):
        logging.getLogger('uvicorn').setLevel(log_level)
        logging.getLogger('uvicorn.error').setLevel(log_level)
        logging.getLogger('uvicorn.access').setLevel(logging.WARNING if not args.verbose else logging.DEBUG)

    if args.mcp_transport == 'sse':
        logger.warning("SSE transport is deprecated. Please use 'streamable-http' or 'stdio' instead.")

    # CLI mode requires --input-file
    if not args.mcp_server and not args.input_file:
        print("[!] Error: --input-file is required for CLI mode.", file=sys.stderr)
        sys.exit(1)

    abs_input_file = None
    if args.input_file:
        abs_input_file = str(Path(args.input_file).resolve())
        if not os.path.exists(abs_input_file):
            logger.critical(f"Input file not found: {abs_input_file}")
            print(f"[!] Error: Input file not found: {abs_input_file}", file=sys.stderr)
            sys.exit(1)

    abs_peid_db_path = str(Path(args.peid_db).resolve()) if args.peid_db else str(DEFAULT_PEID_DB_PATH)
    abs_yara_rules_path = str(Path(args.yara_rules).resolve()) if args.yara_rules else None
    abs_capa_rules_dir_arg = str(Path(args.capa_rules_dir).resolve()) if args.capa_rules_dir else None
    abs_capa_sigs_dir_arg = str(Path(args.capa_sigs_dir).resolve()) if args.capa_sigs_dir else None

    analyses_to_skip_arg_list = []
    if args.skip_capa: analyses_to_skip_arg_list.append("capa")
    if args.skip_floss: analyses_to_skip_arg_list.append("floss")
    if args.skip_peid: analyses_to_skip_arg_list.append("peid")
    if args.skip_yara: analyses_to_skip_arg_list.append("yara")
    if analyses_to_skip_arg_list:
        logger.info(f"Skipping analyses: {', '.join(analyses_to_skip_arg_list)}")

    # FLOSS Config
    floss_min_len_resolved = args.floss_min_length if args.floss_min_length is not None else FLOSS_MIN_LENGTH_DEFAULT
    floss_fmt = args.floss_format

    # Auto-detect architecture hint for shellcode mode if user left it as 'auto'
    if args.mode == 'shellcode' and floss_fmt == 'auto':
        floss_fmt = 'sc64' # Default to 64-bit if unspecified
        logger.info("Shellcode mode detected with 'auto' format. Defaulting to 'sc64' (64-bit). Use --floss-format sc32 for 32-bit.")

    floss_debug_level_map = {
        "NONE": Actual_DebugLevel_Floss.NONE, "DEFAULT": Actual_DebugLevel_Floss.DEFAULT,
        "DEBUG": Actual_DebugLevel_Floss.DEFAULT,
        "TRACE": Actual_DebugLevel_Floss.TRACE, "SUPERTRACE": Actual_DebugLevel_Floss.SUPERTRACE
    }
    floss_script_debug_level_enum_val_resolved = floss_debug_level_map.get(args.floss_script_debug_level.upper(), Actual_DebugLevel_Floss.NONE)

    if args.verbose and floss_script_debug_level_enum_val_resolved == Actual_DebugLevel_Floss.NONE:
        floss_script_debug_level_enum_val_resolved = Actual_DebugLevel_Floss.TRACE
        logger.info(f"Verbose mode active, elevating FLOSS debug level to TRACE.")

    # Resolve FLOSS lists
    floss_disabled_types_resolved = []
    if args.floss_no_static: floss_disabled_types_resolved.append(Actual_StringType_Floss.STATIC)
    if args.floss_no_stack: floss_disabled_types_resolved.append(Actual_StringType_Floss.STACK)
    if args.floss_no_tight: floss_disabled_types_resolved.append(Actual_StringType_Floss.TIGHT)
    if args.floss_no_decoded: floss_disabled_types_resolved.append(Actual_StringType_Floss.DECODED)

    floss_only_types_resolved = []
    if args.floss_only_static: floss_only_types_resolved.append(Actual_StringType_Floss.STATIC)
    if args.floss_only_stack: floss_only_types_resolved.append(Actual_StringType_Floss.STACK)
    if args.floss_only_tight: floss_only_types_resolved.append(Actual_StringType_Floss.TIGHT)
    if args.floss_only_decoded: floss_only_types_resolved.append(Actual_StringType_Floss.DECODED)

    floss_functions_to_analyze_resolved = []
    if args.floss_functions:
        for func_str in args.floss_functions:
            try: floss_functions_to_analyze_resolved.append(int(func_str, 0))
            except ValueError: logger.warning(f"Invalid FLOSS function address '{func_str}', skipping.")

    floss_quiet_resolved = args.floss_quiet or (not args.verbose and args.mcp_server and not (floss_script_debug_level_enum_val_resolved > Actual_DebugLevel_Floss.NONE))

    # --- MCP Server Mode ---
    if args.mcp_server:
        if not MCP_SDK_AVAILABLE:
            logger.critical("MCP SDK ('modelcontextprotocol') not available. Cannot start MCP server. Please install it (e.g., 'pip install \"mcp[cli]\"') and re-run.");
            sys.exit(1)

        # Configure path sandboxing
        if args.allowed_paths:
            state.allowed_paths = [str(Path(p).resolve()) for p in args.allowed_paths]
            logger.info(f"Path sandboxing enabled. Allowed paths: {state.allowed_paths}")
        elif args.mcp_transport in ("sse", "streamable-http"):
            logger.warning(
                "Running in network mode without --allowed-paths. "
                "MCP clients can open arbitrary files. Consider using --allowed-paths for security."
            )

        # --- Optional Pre-loading (only when --input-file is provided) ---
        if abs_input_file:
            logger.info(f"MCP Server: Loading input file: {abs_input_file} (Mode: {args.mode})")
            try:
                if not os.path.isfile(abs_input_file):
                    logger.critical(f"Input path for MCP server is not a file: {abs_input_file}")
                    sys.exit(1)

                # --- Auto-detect format if mode is 'auto' ---
                effective_mode = args.mode
                if effective_mode == 'auto':
                    with open(abs_input_file, 'rb') as f:
                        magic = f.read(4)
                    if magic[:2] == b'MZ':
                        effective_mode = 'pe'
                    elif magic == b'\x7fELF':
                        effective_mode = 'elf'
                    elif magic in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                                   b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                                   b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
                        effective_mode = 'macho'
                    else:
                        effective_mode = 'pe'  # fallback
                    logger.info(f"Auto-detected format: {effective_mode}")

                # --- Loading Logic with Mode Support ---
                if effective_mode == 'shellcode':
                    with open(abs_input_file, 'rb') as f:
                        raw_data = f.read()
                    state.pe_object = MockPE(raw_data)
                    state.filepath = abs_input_file

                    state.pe_data = {
                        "filepath": abs_input_file,
                        "mode": "shellcode",
                        "file_hashes": _parse_file_hashes(raw_data),
                        "basic_ascii_strings": [{"offset": hex(o), "string": s} for o, s in _extract_strings_from_data(raw_data, 5)],
                        "floss_analysis": {"status": "Pending..."}
                    }

                    if "floss" not in analyses_to_skip_arg_list:
                        state.pe_data['floss_analysis'] = _parse_floss_analysis(
                            abs_input_file, floss_min_len_resolved, args.floss_verbose_level,
                            floss_script_debug_level_enum_val_resolved, floss_fmt,
                            floss_disabled_types_resolved, floss_only_types_resolved,
                            floss_functions_to_analyze_resolved, floss_quiet_resolved,
                            args.regex_pattern
                        )
                        _perform_unified_string_sifting(state.pe_data)

                elif effective_mode in ('elf', 'macho'):
                    with open(abs_input_file, 'rb') as f:
                        raw_data = f.read()
                    state.pe_object = MockPE(raw_data)
                    state.filepath = abs_input_file
                    format_label = "ELF" if effective_mode == "elf" else "Mach-O"

                    state.pe_data = {
                        "filepath": abs_input_file,
                        "mode": effective_mode,
                        "format": format_label,
                        "file_hashes": _parse_file_hashes(raw_data),
                        "basic_ascii_strings": [{"offset": hex(o), "string": s} for o, s in _extract_strings_from_data(raw_data, 5)],
                        "note": f"{format_label} binary loaded. Use format-specific tools (elf_analyze/macho_analyze) and angr tools for analysis.",
                    }
                    logger.info(f"Loaded {format_label} binary: {abs_input_file}")

                else:
                    temp_pe_obj_for_preload = pefile.PE(abs_input_file, fast_load=False)
                    state.filepath = abs_input_file
                    state.pe_object = temp_pe_obj_for_preload

                    state.pe_data = _parse_pe_to_dict(
                        temp_pe_obj_for_preload, abs_input_file, abs_peid_db_path, abs_yara_rules_path,
                        abs_capa_rules_dir_arg, abs_capa_sigs_dir_arg,
                        args.verbose, args.skip_full_peid_scan, args.peid_scan_all_sigs_heuristically,
                        floss_min_len_arg=floss_min_len_resolved,
                        floss_verbose_level_arg=args.floss_verbose_level,
                        floss_script_debug_level_arg=floss_script_debug_level_enum_val_resolved,
                        floss_format_hint_arg=floss_fmt,
                        floss_disabled_types_arg=floss_disabled_types_resolved,
                        floss_only_types_arg=floss_only_types_resolved,
                        floss_functions_to_analyze_arg=floss_functions_to_analyze_resolved,
                        floss_quiet_mode_arg=floss_quiet_resolved,
                        analyses_to_skip=analyses_to_skip_arg_list
                    )

                logger.info(f"MCP: Successfully loaded analysis for: {abs_input_file}.")

                # --- Background Angr Analysis (Mode Aware) ---
                if ANGR_AVAILABLE:
                    arch_hint = "amd64" if "64" in floss_fmt else "x86"
                    start_angr_background(
                        abs_input_file,
                        mode=effective_mode,
                        arch_hint=arch_hint,
                        tool_label="startup_auto_analysis",
                    )

            except Exception as e:
                logger.critical(f"MCP: Failed to pre-load file: {str(e)}", exc_info=True)
                if 'temp_pe_obj_for_preload' in locals() and temp_pe_obj_for_preload:
                    temp_pe_obj_for_preload.close()
                state.filepath = None
                state.pe_data = None
                state.pe_object = None
                logger.error("MCP server startup aborted due to pre-load failure.")
                sys.exit(1)
        else:
            logger.info("MCP Server: No --input-file provided. Server starting without a pre-loaded file.")
            logger.info("Use the 'open_file' tool to load a PE file for analysis.")

        logger.info("The MCP server is ready.")

        if args.mcp_transport in ("sse", "streamable-http"):
            mcp_server.settings.host = args.mcp_host
            mcp_server.settings.port = args.mcp_port
            mcp_server.settings.log_level = logging.getLevelName(log_level).lower()
            transport_label = "streamable-http" if args.mcp_transport == "streamable-http" else "SSE (deprecated)"
            logger.info(f"Starting MCP server ({transport_label}) on http://{args.mcp_host}:{args.mcp_port}")
        else:
            logger.info("Starting MCP server (stdio).")

        server_exc=None
        try:
            mcp_server.run(transport=args.mcp_transport)
        except KeyboardInterrupt:
            logger.info("MCP Server stopped by user (KeyboardInterrupt).")
        except Exception as e:
            logger.critical(f"MCP Server encountered an unhandled error: {str(e)}", exc_info=True)
            server_exc=e
        finally:
            if state.pe_object:
                state.pe_object.close()
                logger.info("MCP: Closed pre-loaded object upon server exit.")
            sys.exit(1 if server_exc else 0)

    # --- CLI Mode ---
    else:
        try:
            if args.mode == 'shellcode':
                print(f"[*] CLI Mode: Shellcode Analysis ({abs_input_file})")  # abs_input_file guaranteed non-None in CLI mode
                with open(abs_input_file, 'rb') as f:
                    data = f.read()

                print(f"\n--- File Hashes ---")
                hashes = _parse_file_hashes(data)
                for k, v in hashes.items(): print(f"  {k.upper()}: {v}")

                if args.extract_strings:
                    print(f"\n--- Strings (Min Len: {args.min_str_len}) ---")
                    for off, s in _extract_strings_from_data(data, args.min_str_len):
                        print(f"  {hex(off)}: {s}")

                if args.hexdump_offset is not None and args.hexdump_length is not None:
                     print(f"\n--- Hex Dump ---")
                     start = args.hexdump_offset
                     end = start + args.hexdump_length
                     lines = _format_hex_dump_lines(data[start:end], start, 16)
                     for l in lines[:args.hexdump_lines]: print(l)

                print("\n[!] Note: For deep shellcode analysis (Angr/FLOSS), please use MCP Server mode or FLOSS directly.")

            else:
                # PE CLI Mode
                pe_obj = pefile.PE(abs_input_file, fast_load=False)
                _cli_analyze_and_print_pe(
                    abs_input_file, abs_peid_db_path, abs_yara_rules_path,
                    abs_capa_rules_dir_arg, abs_capa_sigs_dir_arg,
                    args.verbose, args.skip_full_peid_scan, args.peid_scan_all_sigs_heuristically,
                    floss_min_len_resolved, args.floss_verbose_level,
                    floss_script_debug_level_enum_val_resolved, floss_fmt,
                    floss_disabled_types_resolved, floss_only_types_resolved,
                    floss_functions_to_analyze_resolved, floss_quiet_resolved,
                    args.extract_strings, args.min_str_len, args.search_string,
                    args.strings_limit, args.hexdump_offset, args.hexdump_length,
                    args.hexdump_lines, analyses_to_skip_arg_list
                )
        except KeyboardInterrupt:
            print("\n[*] CLI Analysis interrupted by user. Exiting.")
            sys.exit(1)
        except Exception as e_cli_main:
            print(f"\n[!] A critical unexpected error occurred during CLI analysis: {type(e_cli_main).__name__} - {e_cli_main}", file=sys.stderr)
            sys.exit(1)
