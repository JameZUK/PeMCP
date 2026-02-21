"""String extraction, search, sifting, correlation, and deobfuscation utilities."""
import os
import re
import collections

from typing import Dict, Any, Optional, List, Tuple

from pemcp.config import (
    logger, STRINGSIFTER_AVAILABLE,
)

if STRINGSIFTER_AVAILABLE:
    import stringsifter.lib.util as sifter_util
    import joblib


def _extract_strings_from_data(data_bytes: bytes, min_length: int = 5) -> List[Tuple[int, str]]:
    # Ensure we have a concrete bytes/bytearray (not memoryview, mmap, etc.)
    # so that iteration yields ints, not single-byte bytes objects.
    if not isinstance(data_bytes, (bytes, bytearray)):
        data_bytes = bytes(data_bytes)
    strings_found = []
    current_string = ""
    current_offset = -1
    for i, byte_val in enumerate(data_bytes):
        char = chr(byte_val)
        if ' ' <= char <= '~': # Printable ASCII range
            if not current_string: current_offset = i
            current_string += char
        else:
            if len(current_string) >= min_length: strings_found.append((current_offset, current_string))
            current_string = ""; current_offset = -1
    if len(current_string) >= min_length: strings_found.append((current_offset, current_string)) # Catch trailing string
    return strings_found

def _search_specific_strings_in_data(data_bytes: bytes, search_terms: List[str]) -> Dict[str, List[int]]:
    results: Dict[str, List[int]] = {term: [] for term in search_terms}
    for term in search_terms:
        term_bytes = term.encode('ascii', 'ignore') # Assume ASCII search terms for simplicity
        offset = 0
        while True:
            found_at = data_bytes.find(term_bytes, offset)
            if found_at == -1: break
            results[term].append(found_at)
            offset = found_at + 1
    return results

def _format_hex_dump_lines(data_chunk: bytes, start_address: int = 0, bytes_per_line: int = 16) -> List[str]:
    # Ensure concrete bytes so iteration yields ints
    if not isinstance(data_chunk, (bytes, bytearray)):
        data_chunk = bytes(data_chunk)
    lines = []
    for i in range(0, len(data_chunk), bytes_per_line):
        chunk = data_chunk[i:i+bytes_per_line]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        # Ensure hex_part is padded to align the ASCII part correctly
        hex_part_padded = hex_part.ljust(bytes_per_line * 3 -1) # (byte_hex + space) * count - last_space
        lines.append(f"{start_address + i:08x}  {hex_part_padded}  |{ascii_part}|")
    return lines

def _perform_unified_string_sifting(pe_info_dict: Dict[str, Any]):
    """
    Finds all strings from all sources, categorizes them, ranks them with
    StringSifter, and adds the enriched data back into the dictionary.
    This function modifies pe_info_dict in place.
    """
    if not STRINGSIFTER_AVAILABLE:
        logger.info("StringSifter not available, skipping string ranking.")
        return

    logger.info("Performing unified string categorization and sifting...")
    try:
        all_strings_for_sifter = []
        string_object_map = collections.defaultdict(list)

        all_string_sources = [
            pe_info_dict.get('floss_analysis', {}).get('strings', {}).values(),
            [pe_info_dict.get('basic_ascii_strings', [])]
        ]

        for source in all_string_sources:
            for string_list in source:
                if not isinstance(string_list, list):
                    continue
                for string_dict in string_list:
                    if not isinstance(string_dict, dict):
                        continue
                    str_val = string_dict.get('string')
                    if str_val:
                        all_strings_for_sifter.append(str_val)
                        string_object_map[str_val].append(string_dict)

        if not all_strings_for_sifter:
            logger.info("No strings found from any source to rank.")
            return

        logger.info("Ranking %d total strings with StringSifter...", len(all_strings_for_sifter))
        modeldir = os.path.join(sifter_util.package_base(), "model")
        featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
        ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))

        X_test = featurizer.transform(all_strings_for_sifter)
        y_scores = ranker.predict(X_test)

        string_score_map = {s: score for s, score in zip(all_strings_for_sifter, y_scores)}
        for str_val, score in string_score_map.items():
            for original_item_dict in string_object_map.get(str_val, []):
                original_item_dict['sifter_score'] = round(float(score), 4)

        logger.info("Unified string sifting and categorization complete.")

    except Exception as e_sifter:
        logger.error("Error during unified string analysis: %s", e_sifter, exc_info=True)
        pe_info_dict["sifter_error"] = str(e_sifter)

def _correlate_strings_and_capa(pe_info_dict: Dict[str, Any]):
    """
    Correlates string usage with Capa's behavioral findings by checking if
    a string's referencing function is also flagged by a Capa rule.
    Modifies pe_info_dict in place.
    """
    logger.info("Correlating strings with Capa behavioral indicators...")
    try:
        capa_analysis = pe_info_dict.get('capa_analysis')
        floss_analysis = pe_info_dict.get('floss_analysis')

        if not capa_analysis or not floss_analysis or 'results' not in capa_analysis or not capa_analysis.get('results'):
            logger.info("Skipping correlation: Capa or FLOSS results are missing or incomplete.")
            return

        capa_rules = capa_analysis.get('results', {}).get('rules', {})
        if not capa_rules:
            logger.info("No Capa rules found in results to correlate.")
            return

        # 1. Build a map of Function VA -> List of Capa Rule Names
        capa_func_map = collections.defaultdict(list)
        for rule_name, rule_details in capa_rules.items():
            rule_meta = rule_details.get('meta', {})
            capa_id = rule_meta.get('name', rule_name)
            if rule_meta.get('namespace'):
                capa_id = f"{rule_meta['namespace']}/{capa_id}"

            matches_data = rule_details.get("matches", {})
            match_addresses = set()
            if isinstance(matches_data, dict):
                match_addresses.update(matches_data.keys())
            elif isinstance(matches_data, list):
                for item in matches_data:
                    if isinstance(item, list) and len(item) > 0 and isinstance(item[0], dict) and 'value' in item[0]:
                        match_addresses.add(item[0]['value'])

            for addr in match_addresses:
                capa_func_map[addr].append(capa_id)

        # 2. Iterate through all FLOSS strings and check for correlation
        all_strings_with_refs = []
        floss_string_types = floss_analysis.get('strings', {})
        for str_type, str_list in floss_string_types.items():
            if not isinstance(str_list, list): continue
            for string_item in str_list:
                if not isinstance(string_item, dict): continue

                # Handle static strings with their list of references
                if 'references' in string_item:
                    for ref in string_item.get('references', []):
                        if ref.get('function_va'):
                            try:
                                all_strings_with_refs.append((string_item, int(ref['function_va'], 16)))
                            except (ValueError, TypeError): continue
                # Handle stack, tight, and decoded strings
                elif 'function_va' in string_item:
                    try:
                        all_strings_with_refs.append((string_item, int(string_item['function_va'], 16)))
                    except (ValueError, TypeError): continue
                elif 'decoding_routine_va' in string_item:
                    try:
                        all_strings_with_refs.append((string_item, int(string_item['decoding_routine_va'], 16)))
                    except (ValueError, TypeError): continue

        # 3. Add correlation data back to the string items
        for string_item, func_va in all_strings_with_refs:
            if func_va in capa_func_map:
                if 'related_capabilities' not in string_item:
                    string_item['related_capabilities'] = []

                for capa_rule in capa_func_map[func_va]:
                    if capa_rule not in string_item['related_capabilities']:
                        string_item['related_capabilities'].append(capa_rule)

        logger.info("String and Capa correlation complete.")

    except Exception as e:
        logger.error("Failed to correlate strings and Capa results: %s", e, exc_info=True)
        pe_info_dict['correlation_error'] = str(e)

def _get_string_category(string_value: str) -> Optional[str]:
    """
    Categorizes a string based on a set of regular expressions for common
    indicator of compromise (IOC) patterns.

    Args:
        string_value: The string to categorize.

    Returns:
        A string representing the category (e.g., 'ipv4', 'url') or None if no category matches.
    """
    # Note: These regexes are examples and can be refined for better accuracy.
    # The order matters, as it will return the first category that matches.
    REGEX_CATEGORIES = {
        "ipv4": re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"),
        "url": re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"),
        "domain": re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}$"),
        "filepath_windows": re.compile(r"^[a-zA-Z]:\\[\\\S|*\S].*"),
        "registry_key": re.compile(r"^(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS)\\[\w\\\s\-. ]+"),
        "email": re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    }

    for category, pattern in REGEX_CATEGORIES.items():
        if pattern.match(string_value):
            return category
    return None

def _decode_single_byte_xor(data: bytes) -> Optional[Tuple[bytes, int]]:
    """
    Attempts to decode data by bruteforcing a single-byte XOR key.

    It tries every possible key from 1 to 255. For each result, it checks
    how much of the output is printable ASCII. It returns the decoded bytes
    and the key that produced the most printable result, but only if that
    result meets a minimum printability threshold.

    Args:
        data: The byte string to decode.

    Returns:
        A tuple containing the decoded bytes and the key used, or None if no
        key produces a sufficiently printable result.
    """
    best_result = None
    max_printable_score = 0
    best_key = 0

    # A successful XOR decode should be mostly ASCII text
    required_printable_ratio = 0.85

    for key in range(1, 256):
        decoded_bytes = bytes([b ^ key for b in data])

        # Score the result based on how many characters are printable
        printable_chars = sum(1 for b in decoded_bytes if 32 <= b <= 126 or b in [9, 10, 13])

        try:
            printable_score = printable_chars / len(decoded_bytes)
        except ZeroDivisionError:
            printable_score = 0

        if printable_score > max_printable_score:
            max_printable_score = printable_score
            best_result = decoded_bytes
            best_key = key

    # Only return a result if it's highly likely to be text
    if max_printable_score > required_printable_ratio:
        return (best_result, best_key)

    return None
