"""PEiD signature parsing, pattern matching, and YARA scanning."""
import os
import re
import concurrent.futures
import logging

from typing import Dict, Any, Optional, List

from pemcp.config import logger, YARA_AVAILABLE, YARA_IMPORT_ERROR
from pemcp.utils import safe_print

if YARA_AVAILABLE:
    import yara


def parse_signature_file(db_path: str, verbose: bool = False) -> List[Dict[str, Any]]:
    if verbose: safe_print(f"   [VERBOSE-PEID] Starting to parse signature file: {db_path}", verbose_prefix=" ")
    signatures = []
    current_signature: Optional[Dict[str, Any]] = None
    try:
        with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
            for _line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith(';'): continue
                name_match = re.match(r'^\[(.*)\]$', line)
                if name_match:
                    if current_signature and 'name' in current_signature and ('pattern_bytes' in current_signature or 'regex_pattern' in current_signature):
                        signatures.append(current_signature)
                    current_signature = {'name': name_match.group(1).strip(), 'ep_only': False, 'regex_pattern': None, 'pattern_bytes': []}
                    continue
                if current_signature:
                    sig_match = re.match(r'^signature\s*=\s*(.*)', line, re.IGNORECASE)
                    if sig_match:
                        pat_str = sig_match.group(1).strip().upper()
                        byte_pat_list: List[Optional[int]] = []
                        regex_b_list: List[bytes] = []
                        hex_b = pat_str.split()
                        valid = True
                        for b_str in hex_b:
                            if b_str == '??':
                                byte_pat_list.append(None)
                                regex_b_list.append(b'.')
                            elif len(b_str) == 2 and all(c in '0123456789ABCDEF' for c in b_str):
                                try:
                                    b_val = int(b_str, 16)
                                    byte_pat_list.append(b_val)
                                    regex_b_list.append(re.escape(bytes([b_val])))
                                except ValueError:
                                    valid = False
                                    break
                            elif len(b_str) == 2 and (b_str[0] == '?' or b_str[1] == '?'):
                                byte_pat_list.append(None)
                                regex_c = b_str.replace('?', '.')
                                regex_b_list.append(regex_c.encode('ascii'))
                            else:
                                valid = False
                                break
                        if valid and regex_b_list:
                            current_signature['pattern_bytes'] = byte_pat_list
                            try:
                                current_signature['regex_pattern'] = re.compile(b''.join(regex_b_list))
                            except re.error:
                                current_signature = None  # Invalid regex pattern
                        else:
                            current_signature = None  # Invalid hex byte pattern
                        continue  # Processed signature line
                    ep_match = re.match(r'^ep_only\s*=\s*(true|false)', line, re.IGNORECASE)
                    if ep_match:
                        current_signature['ep_only'] = ep_match.group(1).lower() == 'true'
        if current_signature and 'name' in current_signature and ('pattern_bytes' in current_signature or 'regex_pattern' in current_signature):
            signatures.append(current_signature)
    except FileNotFoundError: safe_print(f"[!] PEiD DB not found: {db_path}"); return []
    except Exception as e: safe_print(f"[!] Error parsing PEiD DB {db_path}: {e}"); return []
    if verbose: safe_print(f"   [VERBOSE-PEID] Loaded {len(signatures)} PEiD signatures.", verbose_prefix=" ")
    return signatures

def find_pattern_in_data_regex(data_block: bytes, signature_dict: Dict[str, Any], verbose: bool = False, section_name_for_log: str = "UnknownSection") -> Optional[str]:
    regex_pattern = signature_dict.get('regex_pattern')
    pattern_name = signature_dict.get('name', "Unknown")
    if not regex_pattern or not data_block: return None
    try:
        match = regex_pattern.search(data_block)
        if match:
            if verbose: safe_print(f"       [VERBOSE-PEID-MATCH-REGEX] Pattern '{pattern_name}' matched at offset {hex(match.start())} in {section_name_for_log}.", verbose_prefix=" ")
            return pattern_name
    except Exception as e_re_search:
        if verbose: safe_print(f"       [VERBOSE-PEID-REGEX-ERROR] Error searching for pattern '{pattern_name}': {e_re_search}", verbose_prefix=" ")
    return None

def perform_yara_scan(filepath: str, file_data: bytes, yara_rules_path: Optional[str], yara_available_flag: bool, verbose: bool = False) -> List[Dict[str, Any]]:
    scan_results: List[Dict[str, Any]] = []
    if not yara_available_flag:
        logger.warning("   'yara-python' library not found. Skipping YARA scan.")
        if verbose and YARA_IMPORT_ERROR: logger.debug("         [VERBOSE-DEBUG] YARA import error: %s", YARA_IMPORT_ERROR)
        return scan_results
    if not yara_rules_path: # yara_rules_path is expected to be absolute if provided
        logger.info("   No YARA rules path provided. Skipping YARA scan.")
        return scan_results
    try:
        if verbose: logger.info("   [VERBOSE-YARA] Loading rules from: %s", yara_rules_path)
        rules = None
        if os.path.isdir(yara_rules_path):
            # Collect rule files grouped by immediate subdirectory so that
            # rules within the same source (e.g. reversinglabs/, community/)
            # are compiled together — this preserves YARA `import` support.
            # Use relative path as key to avoid collisions when multiple
            # subdirectories contain files with the same basename.
            filepaths: Dict[str, str] = {}
            for dirname, _, files in os.walk(yara_rules_path):
                for f_name in files:
                    if f_name.lower().endswith(('.yar', '.yara')):
                        full = os.path.join(dirname, f_name)
                        rel = os.path.relpath(full, yara_rules_path).replace(os.sep, '/')
                        # Skip deprecated rules (e.g. community/deprecated/Android/)
                        # which use YARA module features not available at compile time
                        if '/deprecated/' in rel or rel.startswith('deprecated/'):
                            continue
                        filepaths[rel] = full
            if not filepaths: logger.warning("   No .yar or .yara files in dir: %s", yara_rules_path); return scan_results

            # Group files by top-level subdirectory for batch compilation.
            groups: Dict[str, Dict[str, str]] = {}
            for rel, full in filepaths.items():
                group_key = rel.split('/')[0] if '/' in rel else '__root__'
                groups.setdefault(group_key, {})[rel] = full

            compiled_list = []
            for group_key, group_files in groups.items():
                # Try batch compilation first (preserves `import "pe"` etc.)
                try:
                    compiled_list.append(yara.compile(filepaths=group_files))
                    if verbose:
                        logger.info("   [VERBOSE-YARA] Batch-compiled %d rules from %s/", len(group_files), group_key)
                except yara.Error as e_batch:
                    # Batch failed — fall back to per-file compilation for this group
                    logger.info("   YARA batch compile failed for %s/ (%s) — trying per-file.", group_key, e_batch)
                    for key, path in group_files.items():
                        try:
                            compiled_list.append(yara.compile(filepath=path))
                        except yara.Error as e_comp:
                            logger.warning("   YARA compile error in %s: %s — skipping.", key, e_comp)

            if not compiled_list:
                logger.warning("   All YARA rule files failed to compile in: %s", yara_rules_path)
                return scan_results
            rules = compiled_list  # list of compiled rule sets
        elif os.path.isfile(yara_rules_path): rules = [yara.compile(filepath=yara_rules_path)]
        else: logger.warning("   YARA rules path not valid: %s", yara_rules_path); return scan_results

        # rules is now a list of compiled rule sets
        all_matches = []
        for ruleset in rules:
            try:
                all_matches.extend(ruleset.match(data=file_data))
            except yara.Error as e_scan:
                logger.warning("   YARA scan error in one ruleset: %s", e_scan)

        # Deduplicate matches by rule name (same rule can exist in multiple
        # sources, e.g. both ReversingLabs and Community).
        seen_rules: set = set()
        matches = []
        for m in all_matches:
            if m.rule not in seen_rules:
                seen_rules.add(m.rule)
                matches.append(m)

        # Cap string instances per match to prevent huge responses
        # (e.g. contains_base64 can produce thousands of false-positive hits).
        _MAX_STRINGS_PER_MATCH = 25

        if matches:
            logger.info("   YARA Matches Found (%d unique, %d total):", len(matches), len(all_matches))
            for match in matches:
                match_detail:Dict[str,Any]={"rule":match.rule,"namespace":match.namespace if match.namespace!='default'else None,"tags":list(match.tags)if match.tags else None,"meta":dict(match.meta)if match.meta else None,"strings":[]}
                if match.strings:
                    for string_match in match.strings:
                        # Support both yara-python 3.x (tuples) and 4.x (objects)
                        if isinstance(string_match, tuple):
                            s_match_offset, s_match_id, s_match_data_bytes = string_match
                            try:
                                try:
                                    str_data_repr = s_match_data_bytes.decode('utf-8')
                                except UnicodeDecodeError:
                                    try:
                                        str_data_repr = s_match_data_bytes.decode('latin-1')
                                    except UnicodeDecodeError:
                                        str_data_repr = s_match_data_bytes.hex()
                            except Exception:
                                str_data_repr = s_match_data_bytes.hex()

                            if len(str_data_repr) > 80:
                                str_data_repr = str_data_repr[:77] + "..."
                            match_detail["strings"].append({"offset": hex(s_match_offset), "identifier": s_match_id, "data": str_data_repr})
                        else:
                            # yara-python 4.x: StringMatch object
                            s_match_id = string_match.identifier
                            for instance in string_match.instances:
                                s_match_offset = instance.offset
                                s_match_data_bytes = instance.matched_data
                                try:
                                    try:
                                        str_data_repr = s_match_data_bytes.decode('utf-8')
                                    except UnicodeDecodeError:
                                        try:
                                            str_data_repr = s_match_data_bytes.decode('latin-1')
                                        except UnicodeDecodeError:
                                            str_data_repr = s_match_data_bytes.hex()
                                except Exception:
                                    str_data_repr = s_match_data_bytes.hex()

                                if len(str_data_repr) > 80:
                                    str_data_repr = str_data_repr[:77] + "..."
                                match_detail["strings"].append({"offset": hex(s_match_offset), "identifier": s_match_id, "data": str_data_repr})
                # Cap string instances to keep response sizes manageable
                total_strings = len(match_detail["strings"])
                if total_strings > _MAX_STRINGS_PER_MATCH:
                    match_detail["strings"] = match_detail["strings"][:_MAX_STRINGS_PER_MATCH]
                    match_detail["strings_truncated_from"] = total_strings
                scan_results.append(match_detail)
        else: logger.info("   No YARA matches found.")
    except yara.Error as e: logger.error("   YARA Error: %s", e); scan_results.append({"error":f"YARA Error: {e!s}"})
    except Exception as e: logger.error("   Unexpected YARA scan error: %s", e, exc_info=verbose); scan_results.append({"error":f"Unexpected YARA scan error: {e!s}"})
    return scan_results
