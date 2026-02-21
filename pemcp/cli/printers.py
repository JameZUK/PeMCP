"""CLI printing and output formatting functions."""
import hashlib
import collections

from typing import Dict, Any, Optional, List

from pemcp.config import (
    logger, pefile, state,
    CRYPTOGRAPHY_AVAILABLE, SIGNIFY_AVAILABLE, YARA_AVAILABLE,
    CAPA_AVAILABLE, FLOSS_AVAILABLE, STRINGSIFTER_AVAILABLE,
)
from pemcp.utils import safe_print
from pemcp.parsers.pe import _parse_pe_to_dict
from pemcp.parsers.strings import (
    _extract_strings_from_data, _search_specific_strings_in_data,
    _format_hex_dump_lines, _perform_unified_string_sifting,
    _correlate_strings_and_capa,
)

# --- CLI Printing Helper Functions ---
VERBOSE_CLI_OUTPUT_FLAG = False # Global to control verbosity in print helpers

def _print_dict_structure_cli(data_dict: Dict[str, Any], indent: int = 1, title: Optional[str] = None):
    prefix = "  " * indent
    if title: safe_print(f"{prefix}{title}:")
    for key, value in data_dict.items():
        if key == "Structure": continue # Skip the "Structure" key if present from pefile dump_dict
        if isinstance(value, dict) and "Value" in value and isinstance(value["Value"], dict): # Nested pefile structure
            _print_dict_structure_cli(value["Value"], indent + 1, title=key)
        elif isinstance(value, list) and value and isinstance(value[0], dict) and "Value" in value[0] and "Structure" in value[0]: # List of pefile structures
            safe_print(f"{prefix}  {key}:")
            for i, item_struct_container in enumerate(value):
                if isinstance(item_struct_container, dict) and "Value" in item_struct_container:
                     _print_dict_structure_cli(item_struct_container["Value"], indent + 2, title=f"Item {i+1}")
                else: # Should not happen if format is consistent
                    safe_print(f"{prefix}    Item {i+1}: {item_struct_container}")
        elif isinstance(value, list) or isinstance(value, tuple):
            val_str = ', '.join(map(str, value)) if value else '[]'
            if len(val_str) > 120 and not VERBOSE_CLI_OUTPUT_FLAG : val_str = val_str[:117] + "..."
            safe_print(f"{prefix}  {key:<30} {val_str}")
        else:
            val_str = str(value)
            if len(val_str) > 120 and not VERBOSE_CLI_OUTPUT_FLAG: val_str = val_str[:117] + "..."
            safe_print(f"{prefix}  {key:<30} {val_str}")


def _print_file_hashes_cli(hashes: Dict[str, Any]):
    safe_print("\n--- File Hashes ---")
    for algo, h_val in hashes.items(): safe_print(f"  {algo.upper():<8}: {h_val if h_val else 'N/A'}")

def _print_dos_header_cli(dos_header: Dict[str, Any]):
    safe_print("\n--- DOS Header ---")
    if "error" in dos_header: safe_print(f"  {dos_header['error']}")
    elif "Value" in dos_header: _print_dict_structure_cli(dos_header["Value"], indent=1)
    else: safe_print("  DOS Header data not found.")

def _print_nt_headers_cli(nt_headers: Dict[str, Any]):
    safe_print("\n--- NT Headers ---")
    if "error" in nt_headers: safe_print(f"  {nt_headers['error']}"); return
    safe_print(f"  Signature: {nt_headers.get('signature')}")
    if 'file_header' in nt_headers:
        safe_print("\n   --- File Header (IMAGE_FILE_HEADER) ---")
        fh = nt_headers['file_header']
        if "error" in fh: safe_print(f"     {fh['error']}")
        elif "Value" in fh:
            _print_dict_structure_cli(fh["Value"], indent=2)
            safe_print(f"     TimeDateStamp (Formatted):        {fh.get('TimeDateStamp_ISO')}")
            safe_print(f"     Characteristics Flags:            {', '.join(fh.get('characteristics_list',[]))}")
    if 'optional_header' in nt_headers:
        safe_print("\n   --- Optional Header (IMAGE_OPTIONAL_HEADER) ---")
        oh = nt_headers['optional_header']
        if "error" in oh: safe_print(f"     {oh['error']}")
        elif "Value" in oh:
            _print_dict_structure_cli(oh["Value"], indent=2)
            safe_print(f"     PE Type:                          {oh.get('pe_type')}")
            safe_print(f"     DllCharacteristics Flags:         {', '.join(oh.get('dll_characteristics_list',[]))}")

def _print_data_directories_cli(data_dirs: List[Dict[str, Any]]):
    safe_print("\n--- Data Directories (IMAGE_DATA_DIRECTORY) ---")
    if not data_dirs: safe_print("  Data Directories not found or empty."); return
    for entry_dict in data_dirs:
        entry_value = entry_dict.get('Value', {}); entry_name = entry_dict.get('name', 'Unknown')
        # Only print if directory has size or address, or if verbose
        if entry_value.get('Size',0)>0 or entry_value.get('VirtualAddress',0)>0 or VERBOSE_CLI_OUTPUT_FLAG:
            safe_print(f"  {entry_name:<30} {'Offset' if entry_name=='IMAGE_DIRECTORY_ENTRY_SECURITY' else 'RVA'}: {hex(entry_value.get('VirtualAddress',0)):<12} Size: {hex(entry_value.get('Size',0))}")

def _print_sections_cli(sections_data: List[Dict[str, Any]], pe_obj: Optional[pefile.PE]):
    safe_print("\n--- Section Table (IMAGE_SECTION_HEADER) ---")
    if not sections_data: safe_print("  No sections found."); return
    for section_dict in sections_data:
        safe_print(f"\n  Section: {section_dict.get('name_str', 'Unknown Section')}")
        if "Value" in section_dict: _print_dict_structure_cli(section_dict["Value"], indent=2)
        safe_print(f"    Characteristics Flags:           {', '.join(section_dict.get('characteristics_list',[]))}")
        safe_print(f"    Entropy:                         {section_dict.get('entropy', 0.0):.4f}")
        if section_dict.get('md5'): safe_print(f"    MD5:                             {section_dict.get('md5')}")
        if section_dict.get('ssdeep'): safe_print(f"    SSDeep:                          {section_dict.get('ssdeep')}")
        if pe_obj and VERBOSE_CLI_OUTPUT_FLAG: # Only print data sample if verbose
            try:
                # Find the pefile.Section() object corresponding to this dict
                pe_sec = next((s for s in pe_obj.sections if s.Name.decode('utf-8','ignore').rstrip('\x00') == section_dict.get('name_str')), None)
                if pe_sec:
                    data_sample = pe_sec.get_data()[:32] # Get first 32 bytes
                    safe_print(f"    Data Sample (first 32 bytes):")
                    for line in _format_hex_dump_lines(data_sample,0,16): safe_print(f"        {line}")
            except Exception as e: logger.debug(f"Section sample error {section_dict.get('name_str')}: {e}")

def _print_imports_cli(imports_data: List[Dict[str, Any]]):
    safe_print("\n--- Import Table ---")
    if not imports_data: safe_print("  No import table found or empty."); return
    for entry in imports_data:
        safe_print(f"\n  DLL: {entry.get('dll_name', 'N/A')}")
        if "struct" in entry and "Value" in entry["struct"]: _print_dict_structure_cli(entry["struct"]["Value"], indent=2, title="Descriptor")
        for imp_sym in entry.get('symbols', []):
            name_str = imp_sym.get('name', "N/A (Imported by Ordinal)")
            bound_str = f" (Bound to: {imp_sym.get('bound')})" if imp_sym.get('bound') else ""
            safe_print(f"    Ordinal: {str(imp_sym.get('ordinal','N/A')):<6} Address: {imp_sym.get('address','N/A'):<12} Name: {name_str}{bound_str}")

def _print_exports_cli(exports_data: Dict[str, Any]):
    safe_print("\n--- Export Table ---")
    if not exports_data or "error" in exports_data or not exports_data.get('struct'): safe_print("  No export table found or empty."); return
    if "struct" in exports_data and "Value" in exports_data["struct"]: _print_dict_structure_cli(exports_data["struct"]["Value"], indent=1, title="Descriptor")
    safe_print(f"  Exported DLL Name:                 {exports_data.get('name', 'N/A')}")
    for exp_sym in exports_data.get('symbols', []):
        name_str = exp_sym.get('name', "N/A (Exported by Ordinal)")
        forwarder_str = f" -> {exp_sym.get('forwarder')}" if exp_sym.get('forwarder') else ""
        safe_print(f"    Ordinal: {str(exp_sym.get('ordinal','N/A')):<6} Address RVA: {exp_sym.get('address','N/A'):<12} Name: {name_str}{forwarder_str}")

def _print_resources_summary_cli(resources_summary: List[Dict[str, Any]]):
    safe_print("\n--- Resource Directory (Summary) ---")
    if not resources_summary: safe_print("  No resource directory or summary."); return
    for res in resources_summary: safe_print(f"  - Type: {res.get('type')}, ID/Name: {res.get('id_name')}, Lang: {res.get('lang_id')}, RVA: {res.get('offset_to_data_rva')}, Size: {res.get('size')}")

def _print_version_info_cli(ver_info: Dict[str, Any]):
    safe_print("\n--- Version Information (from RT_VERSION Resource) ---")
    if not ver_info or (not ver_info.get('vs_fixedfileinfo') and not ver_info.get('file_info_blocks')): safe_print("  No version information found."); return
    if ver_info.get('vs_fixedfileinfo'):
        for fixed_info in ver_info['vs_fixedfileinfo']:
            safe_print(f"  File Version: {fixed_info.get('FileVersion_str')}, Product Version: {fixed_info.get('ProductVersion_str')}")
            if "Value" in fixed_info: # Print other fixed file info if verbose or structure is simple
                for k,v in fixed_info["Value"].items():
                    if k not in ['Structure','FileVersionMS','FileVersionLS','ProductVersionMS','ProductVersionLS','Signature','StrucVersion']: safe_print(f"    {k}: {v}")
    if ver_info.get('file_info_blocks'):
        for block in ver_info['file_info_blocks']:
            safe_print(f"  {block.get('type')}:")
            if block.get('string_tables'):
                for st_table in block['string_tables']:
                    safe_print(f"    Lang/Codepage: {st_table.get('lang_codepage')}")
                    for k,v_str in st_table.get('entries',{}).items(): safe_print(f"        {k}: {v_str}")
            if block.get('vars'):
                for k,v_str in block.get('vars',{}).items(): safe_print(f"    {k}: {v_str}")

def _print_digital_signatures_cli(sig_info: Dict[str, Any]):
    safe_print("\n--- Digital Signatures (Authenticode) ---")
    if not sig_info: safe_print("  No signature information."); return
    if sig_info.get('security_directory'): safe_print(f"  Security Directory Offset: {sig_info['security_directory']['offset']}, Size: {sig_info['security_directory']['size']}")
    if sig_info.get('embedded_signature_present'):
        safe_print("  Embedded digital signature data found.")
        if sig_info.get('cryptography_parsed_certs_error'): safe_print(f"  Cryptography Parsing Error: {sig_info['cryptography_parsed_certs_error']}")
        elif sig_info.get('cryptography_parsed_certs'):
            safe_print("  Certificates (parsed by 'cryptography'):")
            for cert_idx,cert_data in enumerate(sig_info['cryptography_parsed_certs']):
                safe_print(f"    --- Certificate #{cert_idx+1} ---")
                for k,v_str in cert_data.items():safe_print(f"        {k.replace('_',' ').title()}: {v_str}")
        if sig_info.get('signify_validation'):
            safe_print("\n  --- Authenticode Validation (using 'signify') ---")
            val_res=sig_info['signify_validation']
            if isinstance(val_res,list):
                for i,item in enumerate(val_res):
                    if "error" in item:safe_print(f"    Signify Error: {item['error']}");continue
                    safe_print(f"    Signify Verification Context #{i+1}:")
                    safe_print(f"      Overall Verification Status: {item.get('status_description')}")
                    safe_print(f"      Is Valid (by signify): {item.get('is_valid')}")
                    if item.get('exception'):safe_print(f"      Verification Exception: {item.get('exception')}")
                    if item.get('signer_identification_string'):safe_print(f"      Signer Identification: {item.get('signer_identification_string')}")
                    if item.get('program_name'):safe_print(f"        Program Name: {item.get('program_name')}")
                    if item.get('timestamp_time'):safe_print(f"      Timestamp Signature: Valid, Time: {item.get('timestamp_time')}")
            else:safe_print(f"    Signify Info: {val_res}") # Should be a list or error string
    else:
        safe_print("  No embedded digital signature data found.")
        safe_print("  This file may be signed using a Windows Catalog (.cat) file (not checked by this script).")

def _print_peid_matches_cli(peid_res: Dict[str, Any]):
    safe_print("\n--- Packer/Compiler Detection (Custom PEiD) ---")
    if not peid_res: safe_print("  PEiD scan not performed or no results."); return
    status = peid_res.get("status", "Unknown status.")
    if status == "Scan performed":
        ep_matches = peid_res.get("ep_matches", []); heuristic_matches = peid_res.get("heuristic_matches", [])
        if ep_matches: safe_print("  Matches (Entry Point - Custom):"); [safe_print(f"    - {m}") for m in set(ep_matches)]
        else: safe_print("  No PEiD signatures matched at entry point (Custom).")

        add_heuristic = [m for m in set(heuristic_matches) if m not in set(ep_matches)]
        if add_heuristic: safe_print("\n  Additional Heuristic Matches (Full File - Custom):"); [safe_print(f"    - {m}") for m in sorted(list(set(add_heuristic)))]
        elif not ep_matches and heuristic_matches: safe_print("\n  Heuristic Matches (Full File - Custom):"); [safe_print(f"    - {m}") for m in sorted(list(set(heuristic_matches)))]
        if not ep_matches and not heuristic_matches: safe_print("  No PEiD signatures matched (Custom).")
    else: safe_print(f"  {status}")

def _print_yara_matches_cli(yara_res: List[Dict[str, Any]], yara_rules_path: Optional[str]):
    safe_print("\n--- YARA Scan Results ---")
    if not yara_rules_path: safe_print("  No YARA rules path. Scan skipped."); return
    if not yara_res: safe_print("  No YARA matches or scan not performed."); return

    if yara_res and isinstance(yara_res[0], dict) and yara_res[0].get("status") == "Skipped by user request":
        safe_print(f"  YARA Status: {yara_res[0]['status']}")
        return
    if yara_res and isinstance(yara_res[0], dict) and "error" in yara_res[0]:
        safe_print(f"  YARA Error: {yara_res[0]['error']}")
        return

    if yara_res:
        safe_print(f"  YARA Matches Found ({len(yara_res)}):")
        for match in yara_res:
            if isinstance(match, dict):
                safe_print(f"    Rule: {match.get('rule')}")
                if match.get('namespace'): safe_print(f"      Namespace: {match.get('namespace')}")
                if match.get('tags'): safe_print(f"      Tags: {', '.join(match.get('tags',[]))}")
                if match.get('meta'):
                    safe_print(f"      Meta:"); [safe_print(f"        {mk}: {mv}") for mk,mv in match.get('meta',{}).items()]
                if match.get('strings'):
                    safe_print(f"      Strings ({len(match.get('strings',[]))}):")
                    for idx,sm in enumerate(match.get('strings',[])):
                        if idx>=5 and not VERBOSE_CLI_OUTPUT_FLAG: safe_print(f"          ... ({len(match.get('strings',[]))-idx} more strings not shown)");break
                        safe_print(f"          Offset: {sm.get('offset')}, ID: {sm.get('identifier')}, Data: {sm.get('data')}")
            else:
                safe_print(f"    Unexpected YARA match format: {type(match)}")
    else: safe_print("  No YARA matches found.")


def _print_capa_analysis_cli(capa_analysis_data: Dict[str, Any], verbose_flag: bool):
    safe_print("\n--- Capa Capability Analysis ---")
    if not capa_analysis_data:
        safe_print("  Capa analysis data not available.")
        return

    status = capa_analysis_data.get("status", "Unknown status")
    if status != "Analysis complete (adapted workflow)" and status != "Analysis complete":
        safe_print(f"  Capa Status: {status}")
        if capa_analysis_data.get("error"):
            safe_print(f"  Capa Error: {capa_analysis_data['error']}")
        return

    results = capa_analysis_data.get("results")
    if not results:
        safe_print("  No capa results structure found, though analysis reported complete.")
        return

    meta = results.get("meta", {})
    rules_data = results.get("rules", {})

    safe_print("  Capa Metadata:")
    if meta.get("analysis"):
        analysis_meta = meta["analysis"]
        safe_print(f"    Format: {analysis_meta.get('format')}, Arch: {analysis_meta.get('arch')}, OS: {analysis_meta.get('os')}")
        safe_print(f"    Extractor: {analysis_meta.get('extractor')}")
        if verbose_flag and analysis_meta.get('rules'):
            safe_print(f"    Rules Paths Used: {', '.join(analysis_meta.get('rules', []))}")
    if verbose_flag and meta.get("version"):
        safe_print(f"    Capa Version: {meta.get('version')}")


    if not rules_data:
        safe_print("\n  No capabilities detected by capa.")
        return

    safe_print("\n  Detected Capabilities:")
    capability_count = 0
    for rule_name, rule_details in rules_data.items():
        capability_count +=1
        rule_meta = rule_details.get("meta", {})

        safe_print(f"\n  Capability: {rule_meta.get('name', rule_name)}")
        if rule_meta.get('namespace'):
            safe_print(f"    Namespace: {rule_meta.get('namespace')}")

        attck_entries = rule_meta.get('att&ck', [])
        if attck_entries:
            attck_display_list = []
            for entry in attck_entries:
                if isinstance(entry, dict):
                    display_str = entry.get('id', entry.get('name', str(entry)))
                    attck_display_list.append(str(display_str))
                else:
                    attck_display_list.append(str(entry))
            safe_print(f"    ATT&CK: {', '.join(attck_display_list)}")

        mbc_entries = rule_meta.get('mbc', [])
        if mbc_entries:
            mbc_display_list = []
            for entry in mbc_entries:
                if isinstance(entry, dict):
                    display_str = entry.get('id', entry.get('objective', entry.get('name', str(entry))))
                    mbc_display_list.append(str(display_str))
                else:
                    mbc_display_list.append(str(entry))
            safe_print(f"    MBC: {', '.join(mbc_display_list)}")


        if verbose_flag:
            if rule_meta.get('description'):
                safe_print(f"    Description: {rule_meta.get('description')}")
            if rule_meta.get('authors'):
                safe_print(f"    Authors: {', '.join(rule_meta.get('authors',[]))}")

        matches_data = rule_details.get("matches")

        # This block is updated to handle both dict and list formats
        match_locations = collections.defaultdict(list)
        if isinstance(matches_data, dict):
            for addr, details in matches_data.items():
                match_locations[addr].extend(details)
        elif isinstance(matches_data, list) and matches_data:
            for item in matches_data:
                if isinstance(item, list) and len(item) == 2:
                    addr_obj, detail_obj = item[0], item[1]
                    if isinstance(addr_obj, dict) and "value" in addr_obj:
                        addr_val = addr_obj["value"]
                        match_locations[addr_val].append(detail_obj)

        if match_locations:
            safe_print(f"    Matches ({len(match_locations)}):")
            match_count_on_cli = 0
            for addr_val, match_list_at_addr in sorted(match_locations.items()):
                addr_hex = hex(addr_val) if isinstance(addr_val, int) else str(addr_val)
                if not verbose_flag and match_count_on_cli >= 3:
                    safe_print(f"      ... (additional matches for this rule omitted, use --verbose)")
                    break
                safe_print(f"      At Address: {addr_hex}")
                if verbose_flag and isinstance(match_list_at_addr, list):
                    for match_idx, match_item_detail in enumerate(match_list_at_addr):
                        feature_desc = "N/A"
                        if isinstance(match_item_detail, dict):
                            feature_dict = match_item_detail.get('feature', {})
                            if isinstance(feature_dict, dict):
                                feature_type = feature_dict.get('type', 'N/A')
                                feature_value = feature_dict.get('value', '')
                                feature_description = feature_dict.get('description', '')
                                parts = [f"Type: {feature_type}"]
                                if feature_value: parts.append(f"Value: {str(feature_value)[:50]}")
                                if feature_description: parts.append(f"Desc: {str(feature_description)[:50]}")
                                feature_desc = ", ".join(parts)
                            else:
                                feature_desc = f"Feature: {str(feature_dict)[:100]}"
                        else:
                            feature_desc = f"Match item: {str(match_item_detail)[:100]}"
                        safe_print(f"        Match Detail #{match_idx+1}: {feature_desc}")
                match_count_on_cli += 1
        else:
            safe_print("    No specific address match locations found.")


        if not verbose_flag and capability_count >= 10:
            safe_print("\n  ... (additional capabilities omitted, use --verbose to see all)")
            break

    if capability_count == 0:
        safe_print("\n  No capabilities detected by capa.")


def _print_rich_header_cli(rich_header_data: Optional[Dict[str, Any]]):
    safe_print("\n--- Rich Header ---")
    if not rich_header_data: safe_print("  No Rich Header found or empty."); return
    safe_print(f"  XOR Key: {rich_header_data.get('key_hex')}")
    safe_print(f"  Checksum (from Rich Header struct): {rich_header_data.get('checksum')}")
    if rich_header_data.get('decoded_values'):
        safe_print("  Decoded Values (CompID / Count):")
        for val_entry in rich_header_data['decoded_values']: safe_print(f"    - ProdID: {val_entry['product_id_hex']} (Dec: {val_entry['product_id_dec']}), Build: {val_entry['build_number']}, Count: {val_entry['count']} (Raw CompID: {val_entry['raw_comp_id']})")
    else: safe_print("  No decoded Rich Header values.")

def _print_coff_symbols_cli(coff_symbols: List[Dict[str, Any]], verbose_flag: bool):
    safe_print("\n--- COFF Symbol Table ---")
    if not coff_symbols: safe_print("  No COFF Symbol Table found or empty."); return
    limit = None if verbose_flag else 50; displayed_count = 0 # Limit if not verbose
    safe_print(f"  Total Symbol Records: {len(coff_symbols)}")
    for i,sym_data in enumerate(coff_symbols):
        if limit is not None and displayed_count>=limit: safe_print(f"  ... (omitting remaining {len(coff_symbols)-displayed_count} symbols, use --verbose)");break
        safe_print(f"\n  Symbol {i+1}: {sym_data.get('name_str')}")
        safe_print(f"    Value: {hex(sym_data.get('value',0))}");safe_print(f"    SectionNumber: {sym_data.get('section_number')}")
        safe_print(f"    Type: {hex(sym_data.get('type',0))} ({sym_data.get('type_str')})")
        safe_print(f"    StorageClass: {sym_data.get('storage_class')} ({sym_data.get('storage_class_str')})")
        safe_print(f"    NumberOfAuxSymbols: {sym_data.get('number_of_aux_symbols')}")
        if sym_data.get('auxiliary_symbols'):
            for aux_sym in sym_data['auxiliary_symbols']:
                safe_print(f"    Auxiliary Record ({aux_sym.get('aux_record_index')}): Type: {aux_sym.get('type')}")
                for k,v in aux_sym.items():
                    if k not in['aux_record_index','type']:safe_print(f"        {k}: {v}")
        displayed_count+=1

def _print_pefile_warnings_cli(warnings_list: List[str]):
    safe_print("\n--- PEFile Warnings ---")
    if warnings_list: [safe_print(f"  - {w}") for w in warnings_list]
    else: safe_print("  No warnings from pefile.")

def _print_floss_analysis_cli(floss_data: Dict[str, Any], verbose_flag: bool):
    """Prints FLOSS analysis results to the console."""
    safe_print("\n--- FLOSS Advanced String Analysis ---")
    if not floss_data or "status" not in floss_data:
        safe_print("  FLOSS analysis data not available or malformed.")
        return

    status = floss_data.get("status", "Unknown status")
    safe_print(f"  Status: {status}")
    if floss_data.get("error"):
        safe_print(f"  Error: {floss_data['error']}")

    if verbose_flag and floss_data.get("metadata"):
        safe_print("  FLOSS Metadata:")
        for k, v in floss_data["metadata"].items():
            safe_print(f"    {k.replace('_', ' ').title()}: {v}")

    if verbose_flag and floss_data.get("analysis_config"):
        safe_print("  FLOSS Analysis Configuration:")
        for k, v in floss_data["analysis_config"].items():
            safe_print(f"    {k.replace('_', ' ').title()}: {v}")

    strings_results = floss_data.get("strings", {})
    if not strings_results and status == "FLOSS library not available.":
        return

    for str_type, str_list in strings_results.items():
        type_name_pretty = str_type.replace("_", " ").title()
        safe_print(f"\n  --- {type_name_pretty} ---")
        if isinstance(str_list, list) and str_list:
            if isinstance(str_list[0], dict) and "error" in str_list[0]:
                safe_print(f"    Error during extraction: {str_list[0]['error']}")
                continue

            # If verbose, sort by sifter score to show most relevant first
            if verbose_flag and 'sifter_score' in str_list[0]:
                str_list_sorted = sorted(str_list, key=lambda x: x.get('sifter_score', 0.0), reverse=True)
            else:
                str_list_sorted = str_list

            limited_str_list = str_list_sorted[:20] if not verbose_flag and len(str_list_sorted) > 20 else str_list_sorted
            for item_idx, item_dict in enumerate(limited_str_list):
                sifter_score_str = ""
                if verbose_flag and 'sifter_score' in item_dict:
                    sifter_score_str = f" (Sifter Score: {item_dict['sifter_score']:.2f})"

                if str_type == "static_strings":
                    safe_print(f"    Offset: {item_dict.get('offset', 'N/A')}, String: \"{item_dict.get('string', '')}\"{sifter_score_str}")
                elif str_type == "stack_strings":
                    safe_print(f"    Function VA: {item_dict.get('function_va', 'N/A')}, String VA: {item_dict.get('string_va', 'N/A')}, String: \"{item_dict.get('string', '')}\"{sifter_score_str}")
                elif str_type == "tight_strings":
                    safe_print(f"    Function VA: {item_dict.get('function_va', 'N/A')}, Addr/Offset: {item_dict.get('address_or_offset', 'N/A')}, String: \"{item_dict.get('string', '')}\"{sifter_score_str}")
                elif str_type == "decoded_strings":
                    char_str = f" (Characteristics: {', '.join(item_dict.get('characteristics',[]))})" if item_dict.get('characteristics') else ""
                    safe_print(f"    String VA: {item_dict.get('string_va', 'N/A')}, Routine VA: {item_dict.get('decoding_routine_va', 'N/A')}, String: \"{item_dict.get('string', '')}\"{sifter_score_str}{char_str}")
                else:
                    safe_print(f"    {item_dict}")

            if not verbose_flag and len(str_list_sorted) > 20:
                safe_print(f"    ... ({len(str_list_sorted) - 20} more strings omitted, use --verbose for all {type_name_pretty})")
        elif not str_list:
             safe_print(f"    No {type_name_pretty.lower()} found.")
        else:
            safe_print(f"    Unexpected data format for {type_name_pretty}: {type(str_list)}")


# --- Main CLI Printing Function ---
def _cli_analyze_and_print_pe(filepath: str, peid_db_path: Optional[str],
                              yara_rules_path: Optional[str],
                              capa_rules_dir: Optional[str],
                              capa_sigs_dir: Optional[str],
                              verbose: bool,
                              skip_full_peid_scan: bool,
                              peid_scan_all_sigs_heuristically: bool,
                              # FLOSS args
                              floss_min_len_cli: int,
                              floss_verbose_level_cli: int,
                              floss_script_debug_level_cli: int,
                              floss_format_hint_cli: str,
                              floss_disabled_types_cli: List[str],
                              floss_only_types_cli: List[str],
                              floss_functions_to_analyze_cli: List[int],
                              floss_quiet_mode_cli: bool,
                              # General CLI args
                              extract_strings_cli: bool,
                              min_str_len_cli: int,
                              search_strings_cli: Optional[List[str]],
                              strings_limit_cli: int,
                              hexdump_offset_cli: Optional[int],
                              hexdump_length_cli: Optional[int],
                              hexdump_lines_cli: int,
                              analyses_to_skip_cli_arg: Optional[List[str]] = None
                              ):

    VERBOSE_CLI_OUTPUT_FLAG = verbose

    pefile_version_str = "unknown"
    try: pefile_version_str = pefile.__version__
    except AttributeError: pass

    if verbose:
        logger.info(f"Starting CLI analysis for: {filepath}. pefile version: {pefile_version_str}")

    safe_print(f"[*] Analyzing PE file: {filepath}\n")

    pe_obj_for_cli = None
    try:
        pe_obj_for_cli = pefile.PE(filepath, fast_load=False)
    except pefile.PEFormatError as e_pe_format:
        safe_print(f"[!] Error: Not a valid PE file or PE format error: {e_pe_format}")
        logger.error(f"PEFormatError for CLI file '{filepath}': {e_pe_format}", exc_info=verbose)
        raise
    except FileNotFoundError:
        safe_print(f"[!] Error: Input file not found: {filepath}")
        logger.error(f"FileNotFoundError for CLI file '{filepath}'")
        raise
    except Exception as e_load:
        safe_print(f"[!] Error loading PE file for CLI analysis: {type(e_load).__name__} - {e_load}")
        logger.error(f"Generic error loading PE file '{filepath}' for CLI: {e_load}", exc_info=verbose)
        raise

    effective_analyses_to_skip = analyses_to_skip_cli_arg if analyses_to_skip_cli_arg is not None else []

    cli_pe_info_dict = _parse_pe_to_dict(
        pe_obj_for_cli, filepath, peid_db_path, yara_rules_path,
        capa_rules_dir,
        capa_sigs_dir,
        verbose, skip_full_peid_scan, peid_scan_all_sigs_heuristically,
        # FLOSS args
        floss_min_len_cli,
        floss_verbose_level_cli,
        floss_script_debug_level_cli,
        floss_format_hint_cli,
        floss_disabled_types_cli,
        floss_only_types_cli,
        floss_functions_to_analyze_cli,
        floss_quiet_mode_cli,
        analyses_to_skip=effective_analyses_to_skip
    )
    _perform_unified_string_sifting(cli_pe_info_dict)

    _print_file_hashes_cli(cli_pe_info_dict.get('file_hashes',{}))
    _print_dos_header_cli(cli_pe_info_dict.get('dos_header',{}))
    _print_nt_headers_cli(cli_pe_info_dict.get('nt_headers',{}))
    _print_data_directories_cli(cli_pe_info_dict.get('data_directories',[]))
    _print_sections_cli(cli_pe_info_dict.get('sections',[]),pe_obj_for_cli)
    _print_imports_cli(cli_pe_info_dict.get('imports',[]))
    _print_exports_cli(cli_pe_info_dict.get('exports',{}))
    _print_resources_summary_cli(cli_pe_info_dict.get('resources_summary',[]))
    _print_version_info_cli(cli_pe_info_dict.get('version_info',{}))
    _print_digital_signatures_cli(cli_pe_info_dict.get('digital_signature',{}))

    if "peid" not in effective_analyses_to_skip:
        _print_peid_matches_cli(cli_pe_info_dict.get('peid_matches',{}))
    else:
        safe_print("\n--- Packer/Compiler Detection (Custom PEiD) ---")
        safe_print("  Skipped by user request.")

    if "yara" not in effective_analyses_to_skip:
        _print_yara_matches_cli(cli_pe_info_dict.get('yara_matches',[]), yara_rules_path)
    else:
        safe_print("\n--- YARA Scan Results ---")
        safe_print("  Skipped by user request.")

    if "capa" not in effective_analyses_to_skip:
        _print_capa_analysis_cli(cli_pe_info_dict.get('capa_analysis',{}), verbose)
    else:
        safe_print("\n--- Capa Capability Analysis ---")
        safe_print("  Skipped by user request.")

    if "floss" not in effective_analyses_to_skip:
        _print_floss_analysis_cli(cli_pe_info_dict.get('floss_analysis',{}), verbose)
    else:
        safe_print("\n--- FLOSS Advanced String Analysis ---")
        safe_print("  Skipped by user request.")

    _print_rich_header_cli(cli_pe_info_dict.get('rich_header'))

    remaining_keys_to_print_generic = [
        ("delay_load_imports","Delay-Load Imports"), ("tls_info", "TLS Information"),
        ("load_config", "Load Configuration"), ("com_descriptor", ".NET COM Descriptor"),
        ("overlay_data", "Overlay Data"), ("base_relocations", "Base Relocations"),
        ("bound_imports", "Bound Imports"), ("exception_data", "Exception Data"),
        ("checksum_verification", "Checksum Verification")
    ]

    _print_coff_symbols_cli(cli_pe_info_dict.get('coff_symbols',[]),verbose)
    _print_pefile_warnings_cli(cli_pe_info_dict.get('pefile_warnings',[]))

    if extract_strings_cli:
        safe_print(f"\n--- Extracted Strings (min_length={min_str_len_cli}, limit={strings_limit_cli}) ---")
        try:
            extracted_strings_list = _extract_strings_from_data(pe_obj_for_cli.__data__, min_str_len_cli)
            if not extracted_strings_list:
                safe_print("  No strings found matching criteria.")
            else:
                for i, (offset, s_val) in enumerate(extracted_strings_list):
                    if i >= strings_limit_cli:
                        safe_print(f"  ... (output limited to {strings_limit_cli} strings)")
                        break
                    safe_print(f"  Offset: {hex(offset)}: {s_val}")
        except Exception as e_str:
            safe_print(f"  Error during string extraction: {e_str}")
            logger.warning("CLI: Error during string extraction", exc_info=verbose)

    if search_strings_cli:
        safe_print(f"\n--- Searched Strings (limit {strings_limit_cli} per term) ---")
        try:
            search_results_dict = _search_specific_strings_in_data(pe_obj_for_cli.__data__, search_strings_cli)
            found_any_terms = False
            for term, offsets_list in search_results_dict.items():
                if offsets_list:
                    found_any_terms = True
                    safe_print(f"  Found '{term}' at offsets (limit {strings_limit_cli} per term shown):")
                    for i, offset_val in enumerate(offsets_list):
                        if i >= strings_limit_cli:
                            safe_print(f"    ... (further occurrences of '{term}' omitted)")
                            break
                        safe_print(f"      - {hex(offset_val)}")
                else:
                    safe_print(f"  String '{term}' not found.")
            if not found_any_terms and not search_results_dict:
                 safe_print("  No specified strings found or search terms were empty.")

        except Exception as e_search:
            safe_print(f"  Error during specific string search: {e_search}")
            logger.warning("CLI: Error during specific string search", exc_info=verbose)

    if hexdump_offset_cli is not None and hexdump_length_cli is not None:
        safe_print(f"\n--- Hex Dump (Offset: {hex(hexdump_offset_cli)}, Length: {hexdump_length_cli}, Max Lines: {hexdump_lines_cli}) ---")
        try:
            file_size = len(pe_obj_for_cli.__data__)
            if hexdump_offset_cli >= file_size:
                safe_print("  Error: Start offset is beyond the file size.")
            else:
                actual_dump_length = min(hexdump_length_cli, file_size - hexdump_offset_cli)
                if actual_dump_length <= 0:
                    safe_print("  Error: Calculated length for hex dump is zero or negative (start_offset might be at or past EOF).")
                else:
                    data_chunk_to_dump = pe_obj_for_cli.__data__[hexdump_offset_cli : hexdump_offset_cli + actual_dump_length]
                    dump_lines_list = _format_hex_dump_lines(data_chunk_to_dump, start_address=hexdump_offset_cli)

                    if not dump_lines_list:
                        safe_print("  No data to dump for the specified range (or range was empty).")
                    else:
                        for i, line_str in enumerate(dump_lines_list):
                            if i >= hexdump_lines_cli:
                                safe_print(f"  ... (output limited to {hexdump_lines_cli} lines)")
                                break
                            safe_print(f"  {line_str}")
        except IndexError:
             safe_print("  Error: Hex dump range is invalid or out of bounds for the file data.")
        except Exception as e_dump:
            safe_print(f"  Error during hex dump: {e_dump}")
            logger.warning("CLI: Error during hex dump", exc_info=verbose)

    safe_print("\n[*] CLI Analysis complete.")

    if pe_obj_for_cli:
        pe_obj_for_cli.close()
