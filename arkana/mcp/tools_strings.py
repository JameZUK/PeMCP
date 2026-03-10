"""MCP tools for string analysis, FLOSS, capa, and fuzzy search."""
import re
import json
import copy
import os
import asyncio
import threading

from typing import Dict, Any, Optional, List, Union

from arkana.config import (
    state, logger, Context,
    STRINGSIFTER_AVAILABLE, RAPIDFUZZ_AVAILABLE, CAPA_AVAILABLE,
    MAX_MCP_RESPONSE_SIZE_BYTES,
)
from arkana.mcp.server import (
    tool_decorator, _check_pe_loaded, _check_data_key_available,
    _check_mcp_response_size,
)
from arkana.mcp._progress_bridge import ProgressBridge
from arkana.parsers.strings import _extract_strings_from_data, _search_specific_strings_in_data
from arkana.mcp._input_helpers import _parse_int_param
from arkana.utils import validate_regex_pattern as _validate_regex_pattern, safe_regex_search as _safe_regex_search

from arkana.constants import MAX_TOOL_LIMIT as _MAX_LIMIT
from arkana.mcp._input_helpers import _make_cache_key

if RAPIDFUZZ_AVAILABLE:
    from rapidfuzz import fuzz

if STRINGSIFTER_AVAILABLE:
    import stringsifter.lib.util as sifter_util
    import joblib

# Lazy-loaded StringSifter model cache (avoids re-reading from disk on every call)
_sifter_featurizer = None
_sifter_ranker = None
_sifter_lock = threading.Lock()


def _get_cached_flat_strings(include_basic_ascii: bool = True, deduplicate: bool = True):
    """Build and cache a flat list of strings from FLOSS + basic_ascii data.

    Two cache variants via ``state.result_cache``:
    - ``("_flat_strings", "floss_all")`` — all FLOSS strings with source_type, no dedup
    - ``("_flat_strings", "deduped_all")`` — FLOSS + basic_ascii, deduped by value

    Returns a list of string dicts (copies with source_type added for FLOSS items).
    """
    cache = state.result_cache
    if deduplicate and include_basic_ascii:
        cache_key = "deduped_all"
    elif not deduplicate and not include_basic_ascii:
        cache_key = "floss_all"
    else:
        cache_key = f"{'deduped' if deduplicate else 'all'}_{'with_basic' if include_basic_ascii else 'floss'}"

    cached = cache.get("_flat_strings", cache_key)
    if cached is not None:
        return cached

    all_strings = []
    seen = set() if deduplicate else None
    pe_data = state.pe_data or {}

    # FLOSS strings
    if 'floss_analysis' in pe_data and isinstance(pe_data['floss_analysis'], dict):
        floss_strings = pe_data['floss_analysis'].get('strings', {})
        if isinstance(floss_strings, dict):
            for str_type, str_list in floss_strings.items():
                if not isinstance(str_list, list):
                    continue
                for item in str_list:
                    if isinstance(item, dict):
                        val = item.get('string', '')
                        if not val:
                            continue
                        if seen is not None:
                            if val in seen:
                                continue
                            seen.add(val)
                        entry = item.copy()
                        entry['source_type'] = str_type.replace('_strings', '')
                        all_strings.append(entry)
                    elif isinstance(item, str) and item:
                        if seen is not None:
                            if item in seen:
                                continue
                            seen.add(item)
                        all_strings.append({"string": item, "source_type": str_type.replace('_strings', '')})

    # Basic ASCII strings
    if include_basic_ascii and 'basic_ascii_strings' in pe_data:
        basic = pe_data['basic_ascii_strings']
        if isinstance(basic, list):
            for item in basic:
                if isinstance(item, dict):
                    val = item.get('string', '')
                    if not val:
                        continue
                    if seen is not None:
                        if val in seen:
                            continue
                        seen.add(val)
                    all_strings.append(item)
                elif isinstance(item, str) and item:
                    if seen is not None:
                        if item in seen:
                            continue
                        seen.add(item)
                    all_strings.append({"string": item})

    cache.set("_flat_strings", cache_key, all_strings)
    return all_strings


def _get_sifter_models():
    """Return cached (featurizer, ranker) tuple, loading from disk on first call."""
    global _sifter_featurizer, _sifter_ranker
    if _sifter_featurizer is not None and _sifter_ranker is not None:
        return _sifter_featurizer, _sifter_ranker
    with _sifter_lock:
        # Double-check after acquiring lock
        if _sifter_featurizer is not None and _sifter_ranker is not None:
            return _sifter_featurizer, _sifter_ranker
        modeldir = os.path.join(sifter_util.package_base(), "model")
        _sifter_featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
        _sifter_ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))
    return _sifter_featurizer, _sifter_ranker


@tool_decorator
async def search_floss_strings(
    ctx: Context,
    regex_patterns: List[str],
    min_sifter_score: Optional[float] = None,
    max_sifter_score: Optional[float] = None,
    sort_order: Optional[str] = None,
    min_length: int = 0,
    limit: int = 20,
    case_sensitive: bool = False
) -> Dict[str, Any]:
    """
    [Phase: explore] Performs a regex search against FLOSS strings with advanced
    score filtering and sorting.

    When to use: When looking for specific patterns in strings — network indicators
    (IPs, URLs, domains), file paths, registry keys, or suspicious API references.
    More targeted than get_strings_summary() or get_top_sifted_strings().

    Next steps: If IOCs found → add_note(content, category='tool_result') to record them.
    Use get_string_usage_context(string_offset) to find code that references a string.

    Args:
        ctx: The MCP Context object.
        regex_patterns: (List[str]) A list of regex patterns to search for.
        min_sifter_score: (Optional[float]) If provided, only include strings with a sifter_score >= this value.
        max_sifter_score: (Optional[float]) If provided, only include strings with a sifter_score <= this value.
        sort_order: (Optional[str]) If provided, sorts results by score. Valid: 'ascending', 'descending'. Defaults to None (no sorting).
        min_length: (int) The minimum length for a matched string to be included. Defaults to 0.
        limit: (int) The maximum number of matches to return. Defaults to 100.
        case_sensitive: (bool) If True, the regex search will be case-sensitive. Defaults to False.

    Returns:
        A dictionary containing a list of matched strings and pagination information.

    Raises:
        RuntimeError: If no FLOSS analysis data is available or sifter is required but unavailable.
        ValueError: For invalid parameters or if the response size is too large.
    """
    await ctx.info(f"Request to search FLOSS strings. Patterns: {len(regex_patterns)}, Score Range: {min_sifter_score}-{max_sifter_score}, Sort: {sort_order}, Limit: {limit}")

    # --- Parameter Validation ---
    if (min_sifter_score is not None or max_sifter_score is not None or sort_order is not None) and not STRINGSIFTER_AVAILABLE:
        raise RuntimeError("Score filtering/sorting is requested, but StringSifter is not available on the server.")
    if min_sifter_score is not None and not isinstance(min_sifter_score, (int, float)):
        raise ValueError("Parameter 'min_sifter_score' must be a number if provided.")
    if max_sifter_score is not None and not isinstance(max_sifter_score, (int, float)):
        raise ValueError("Parameter 'max_sifter_score' must be a number if provided.")
    if sort_order is not None and sort_order.lower() not in ['ascending', 'descending']:
        raise ValueError("Parameter 'sort_order' must be either 'ascending', 'descending', or None.")
    if not regex_patterns or not isinstance(regex_patterns, list):
        raise ValueError("The 'regex_patterns' parameter must be a non-empty list of strings.")
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("The 'limit' parameter must be a positive integer.")

    # --- Data Retrieval ---
    _check_data_key_available("floss_analysis", "search_floss_strings")
    floss_data = state.pe_data.get('floss_analysis', {})
    if not floss_data.get("strings"):
        return {"matches": [], "message": "No FLOSS strings available to search."}

    # --- Filtering Logic ---
    compiled_patterns = []
    try:
        flags = 0 if case_sensitive else re.IGNORECASE
        for pattern_str in regex_patterns:
            _validate_regex_pattern(pattern_str)
            compiled_patterns.append(re.compile(pattern_str, flags))
    except re.error as e:
        raise ValueError(f"Invalid regex pattern provided in the list: {e}")

    all_strings_with_context = _get_cached_flat_strings(include_basic_ascii=False, deduplicate=False)

    matches = []
    for item in all_strings_with_context:
        # Cheap checks first: length, then score, then expensive regex
        string_to_search = item.get("string", "")
        if len(string_to_search) < min_length:
            continue

        score = item.get('sifter_score', -999.0)
        min_ok = (min_sifter_score is None) or (score >= min_sifter_score)
        if not min_ok:
            continue
        max_ok = (max_sifter_score is None) or (score <= max_sifter_score)
        if not max_ok:
            continue

        if any(_safe_regex_search(p, string_to_search) for p in compiled_patterns):
            matches.append(item)

    # --- Sorting Logic ---
    if sort_order:
        is_reversed = (sort_order.lower() == 'descending')
        matches.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=is_reversed)

    # --- Finalize and Return ---
    paginated_matches = matches[:limit]
    response = {
        "matches": paginated_matches,
        "pagination_info": {
            "limit": limit,
            "returned_matches": len(paginated_matches),
            "total_matches_found": len(matches)
        }
    }

    limit_info_str = "the 'limit' parameter or by using more specific filters ('regex_patterns', 'min_sifter_score', etc.)"
    return await _check_mcp_response_size(ctx, response, "search_floss_strings", limit_info_str)


@tool_decorator
async def get_floss_analysis_info(ctx: Context,
                                  string_type: Optional[str] = None,
                                  only_with_references: bool = False,
                                  limit: int = 20,
                                  offset: Optional[int] = 0,
                                  compact: bool = False,
                                 ) -> Dict[str, Any]:
    """
    [Phase: explore] Retrieves FLOSS analysis results with option to filter for
    strings that have code cross-references.

    When to use: When you need raw FLOSS string data (static, stack, tight, decoded)
    or metadata about the FLOSS analysis. Use only_with_references=True to find
    strings actually used in code (reduces noise significantly).

    Next steps: Use get_string_usage_context(string_offset) for disassembly context
    around a specific string, or search_floss_strings() for regex-based filtering.

    Args:
        ctx: The MCP Context object.
        string_type: (Optional[str]) The type of FLOSS strings to retrieve. Valid values: "static_strings", "stack_strings", "tight_strings", "decoded_strings". If None, returns metadata.
        only_with_references: (bool) If True and string_type is 'static_strings', only return strings that have code cross-references. Defaults to False.
        limit: (int) Max number of strings to return if string_type is specified. Defaults to 100.
        offset: (Optional[int]) Starting index for string pagination if string_type is specified. Defaults to 0.

    Returns:
        A dictionary containing the requested FLOSS information.
    """
    await ctx.info(f"Request for FLOSS info. Type: {string_type}, Refs Only: {only_with_references}, Limit: {limit}")

    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    limit = min(limit, _MAX_LIMIT)
    if offset is not None and not (isinstance(offset, int) and offset >= 0):
        raise ValueError("Parameter 'offset' must be a non-negative integer if provided.")

    valid_string_types = ["static_strings", "stack_strings", "tight_strings", "decoded_strings"]
    if string_type is not None and string_type not in valid_string_types:
        raise ValueError(f"Invalid 'string_type'. Must be one of: {', '.join(valid_string_types)} or None.")

    _check_data_key_available("floss_analysis", "get_floss_analysis_info")

    floss_data_block = state.pe_data.get('floss_analysis', {})
    status = floss_data_block.get("status", "Unknown")

    if status != "FLOSS analysis complete." and "incomplete" not in status:
         data_to_send = {"status": status, "error": floss_data_block.get("error", "FLOSS analysis did not complete successfully."), "data": {}}
         return await _check_mcp_response_size(ctx, data_to_send, "get_floss_analysis_info")

    response_data: Dict[str, Any] = {"status": status}
    if floss_data_block.get("error"): response_data["error_details"] = floss_data_block.get("error")

    if compact:
        # Compact: counts per string type + top 5 strings per type
        strings_data = floss_data_block.get("strings", {})
        counts = {}
        top_strings = {}
        for stype in ["static_strings", "stack_strings", "tight_strings", "decoded_strings"]:
            items = strings_data.get(stype, [])
            counts[stype] = len(items) if isinstance(items, list) else 0
            if isinstance(items, list) and items:
                top_strings[stype] = [
                    (s.get("string", s) if isinstance(s, dict) else str(s))
                    for s in items[:5]
                ]
        response_data["string_counts"] = counts
        response_data["top_strings"] = top_strings
        return response_data

    if string_type is None: # Return metadata and config
        response_data["metadata"] = floss_data_block.get("metadata", {})
        response_data["analysis_config"] = floss_data_block.get("analysis_config", {})
        await ctx.info("Returning FLOSS metadata and analysis configuration.")
    else: # Return specific string type with pagination
        all_strings_of_type = floss_data_block.get("strings", {}).get(string_type, [])

        # --- NEW FILTERING LOGIC ---
        if string_type == 'static_strings' and only_with_references:
            await ctx.info("Filtering static strings for only those with code references.")
            all_strings_of_type = [item for item in all_strings_of_type if item.get('references')]

        if isinstance(all_strings_of_type, list):
            current_offset_val = offset if offset is not None else 0
            paginated_strings = all_strings_of_type[current_offset_val : current_offset_val + limit]
            response_data["strings"] = paginated_strings
            response_data["pagination_info"] = {
                'offset': current_offset_val,
                'limit': limit,
                'current_items_count': len(paginated_strings),
                'total_items_for_type': len(all_strings_of_type)
            }
            await ctx.info(f"Returning {len(paginated_strings)} {string_type} (total available after filter: {len(all_strings_of_type)}).")
        else:
            response_data["strings"] = []
            response_data["error_in_type"] = f"Data for {string_type} is not in the expected list format."
            response_data["pagination_info"] = {'offset': 0, 'limit': limit, 'current_items_count': 0, 'total_items_for_type': 0}

    limit_info_str = f"parameters like 'limit' or 'offset' for string_type '{string_type}'" if string_type else "parameters (none for metadata)"
    return await _check_mcp_response_size(ctx, response_data, "get_floss_analysis_info", limit_info_str)


@tool_decorator
async def get_capa_analysis_info(ctx: Context,
                                 limit: int = 20,
                                 offset: Optional[int] = 0,
                                 filter_rule_name: Optional[str] = None,
                                 filter_namespace: Optional[str] = None,
                                 filter_attck_id: Optional[str] = None,
                                 filter_mbc_id: Optional[str] = None,
                                 fields_per_rule: Optional[List[str]] = None,
                                 get_report_metadata_only: bool = False,
                                 source_string_limit: Optional[int] = None,
                                 compact: bool = False,
                                 ) -> Dict[str, Any]:
    """
    [Phase: explore] Retrieves an overview of Capa capability rules with filtering
    and pagination. Each rule's matches are summarized by unique address count.

    When to use: After triage to explore detected capabilities (MITRE ATT&CK,
    MBC). Filter by namespace (e.g. 'anti-analysis'), ATT&CK ID, or rule name.

    Next steps: Use get_capa_rule_match_details(rule_id) to inspect specific match
    locations, then decompile_function_with_angr() at those addresses.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max capability rules to return. Defaults to 20. Must be positive.
        offset: (Optional[int]) Starting index for rule pagination. Defaults to 0.
        filter_rule_name: (Optional[str]) Filter rules by name/ID (substring, case-insensitive).
        filter_namespace: (Optional[str]) Filter rules by namespace prefix (case-insensitive, e.g. 'anti-analysis' matches 'anti-analysis/obfuscation/...').
        filter_attck_id: (Optional[str]) Filter rules by ATT&CK ID/tactic (substring, case-insensitive).
        filter_mbc_id: (Optional[str]) Filter rules by MBC ID/objective (substring, case-insensitive).
        fields_per_rule: (Optional[List[str]]) Specific top-level fields for each rule (e.g., ["meta", "source", "matches"]).
                         If "matches" is included, it will be a summary count.
        get_report_metadata_only: (bool) If True, returns only trimmed top-level 'meta' of the Capa report.
        source_string_limit: (Optional[int]) Limits length of a rule's 'source' string if requested. None for no limit.

    Returns:
        Dict with "rules" (summarized), "pagination", "report_metadata", and optionally "error".
    Raises:
        RuntimeError: If no Capa analysis data is found.
        ValueError: If parameters are invalid, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request for 'capa_analysis_overview'. Limit(rules): {limit}, Offset(rules): {offset}, "
                   f"Filters: rule='{filter_rule_name}', ns='{filter_namespace}', att&ck='{filter_attck_id}', mbc='{filter_mbc_id}'. "
                   f"FieldsPerRule: {fields_per_rule}, MetaOnly: {get_report_metadata_only}, "
                   f"SourceStrLimit: {source_string_limit}")

    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' for Capa analysis must be a positive integer.")
    limit = min(limit, _MAX_LIMIT)
    if source_string_limit is not None and not (isinstance(source_string_limit, int) and source_string_limit >= 0):
        raise ValueError("Parameter 'source_string_limit' must be a non-negative integer if provided.")

    _check_data_key_available("capa_analysis", "get_capa_analysis_info")

    capa_data_block = state.pe_data.get('capa_analysis', {})
    capa_full_results = capa_data_block.get('results')
    capa_status = capa_data_block.get("status", "Unknown")

    if compact and capa_full_results:
        # Compact: rule names and namespaces only, no match details
        rules = capa_full_results.get("rules", {})
        compact_rules = []
        for rule_id, rule_data in list(rules.items())[:limit]:
            meta = rule_data.get("meta", {}) if isinstance(rule_data, dict) else {}
            compact_rules.append({
                "name": meta.get("name", rule_id),
                "namespace": meta.get("namespace", ""),
            })
        return {
            "status": capa_status,
            "total_capabilities": len(rules),
            "rules": compact_rules,
        }

    current_offset = 0
    if offset is not None and isinstance(offset, int) and offset >= 0:
        current_offset = offset
    elif offset is not None:
        await ctx.warning(f"Invalid 'offset' parameter for rules, defaulting to 0. Received: {offset}")

    base_pagination_info = {
        'offset': current_offset, 'limit': limit, 'current_items_count': 0,
        'total_items_after_filtering': 0, 'total_capabilities_in_report': 0
    }

    report_meta_from_capa_original = capa_full_results.get('meta', {}) if capa_full_results else {}
    processed_report_meta = copy.deepcopy(report_meta_from_capa_original)

    if 'analysis' in processed_report_meta and isinstance(processed_report_meta['analysis'], dict):
        analysis_section = processed_report_meta['analysis']
        if 'layout' in analysis_section:
            del analysis_section['layout']
        if 'feature_counts' in analysis_section:
            del analysis_section['feature_counts']

    if capa_status == "Skipped by user request":
        data_to_send = {"error": "Capa analysis was skipped.", "rules": {}, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")

    if (capa_status != "Analysis complete (adapted workflow)" and capa_status != "Analysis complete") or not capa_full_results:
        error_data: Dict[str, Any] = {"error": f"Capa analysis not complete/results missing. Status: {capa_status}",
                        "rules": {}, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
        # Forward hint and raw error detail from the capa parser
        capa_hint = capa_data_block.get("hint")
        if capa_hint:
            error_data["hint"] = capa_hint
        capa_error_detail = capa_data_block.get("error")
        if capa_error_detail:
            error_data["error_detail"] = capa_error_detail
        return await _check_mcp_response_size(ctx, error_data, "get_capa_analysis_info", "parameters like 'limit' or filters")


    if get_report_metadata_only:
        data_to_send = {"report_metadata": processed_report_meta, "rules": {}, "pagination": base_pagination_info}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")


    all_rules_dict_from_capa = capa_full_results.get('rules', {})
    if not isinstance(all_rules_dict_from_capa, dict):
        base_pagination_info['total_capabilities_in_report'] = 0
        data_to_send = {"error": "Capa 'rules' data malformed.", "rules": {}, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")

    base_pagination_info['total_capabilities_in_report'] = len(all_rules_dict_from_capa)

    # Cache the filtered rule list keyed on filter params (pagination excluded)
    _capa_cache_key = _make_cache_key(
        filter_rule_name=filter_rule_name, filter_namespace=filter_namespace,
        filter_attck_id=filter_attck_id, filter_mbc_id=filter_mbc_id,
    )
    filtered_rule_items = state.result_cache.get("_capa_filtered_rules", _capa_cache_key)
    if filtered_rule_items is None:
        filtered_rule_items = []
        for rule_id, rule_details_original in all_rules_dict_from_capa.items():
            if not isinstance(rule_details_original, dict):
                continue

            meta = rule_details_original.get("meta", {})
            if not isinstance(meta, dict): meta = {}

            passes_filter = True
            if filter_rule_name and filter_rule_name.lower() not in str(meta.get("name", rule_id)).lower(): passes_filter = False
            if passes_filter and filter_namespace and not meta.get("namespace", "").lower().startswith(filter_namespace.lower()): passes_filter = False

            if passes_filter and filter_attck_id:
                attck_values = meta.get("att&ck", [])
                if not isinstance(attck_values, list): attck_values = [str(attck_values)]
                if not any(filter_attck_id.lower() in (" ".join(str(v) for v in entry.values()) if isinstance(entry, dict) else str(entry)).lower() for entry in attck_values):
                    passes_filter = False

            if passes_filter and filter_mbc_id:
                mbc_values = meta.get("mbc", [])
                if not isinstance(mbc_values, list): mbc_values = [str(mbc_values)]
                if not any(filter_mbc_id.lower() in (" ".join(str(v) for v in entry.values()) if isinstance(entry, dict) else str(entry)).lower() for entry in mbc_values):
                    passes_filter = False
            if passes_filter:
                filtered_rule_items.append((rule_id, rule_details_original))
        state.result_cache.set("_capa_filtered_rules", _capa_cache_key, filtered_rule_items)

    base_pagination_info['total_items_after_filtering'] = len(filtered_rule_items)
    paginated_rule_items_tuples = filtered_rule_items[current_offset : current_offset + limit]
    base_pagination_info['current_items_count'] = len(paginated_rule_items_tuples)

    final_rules_output_dict = {}
    for rule_id, rule_details_original_for_page in paginated_rule_items_tuples:
        rule_data_to_process = copy.deepcopy(rule_details_original_for_page)

        if fields_per_rule:
            rule_data_to_process = {k: v for k, v in rule_data_to_process.items() if k in fields_per_rule}

        if 'source' in rule_data_to_process and isinstance(rule_data_to_process['source'], str) and source_string_limit is not None:
            if len(rule_data_to_process['source']) > source_string_limit:
                rule_data_to_process['source'] = rule_data_to_process['source'][:source_string_limit] + "... (truncated)"

        if 'matches' in rule_data_to_process:
            original_matches_field = rule_details_original_for_page.get('matches')
            match_address_count = 0
            note = None
            error_msg = None

            if original_matches_field is None:
                note = "Matches field was null/None in original data."
            elif isinstance(original_matches_field, dict):
                match_address_count = len(original_matches_field)
            elif isinstance(original_matches_field, list):
                unique_addresses = set()
                for item in original_matches_field:
                    if isinstance(item, list) and len(item) > 0 and isinstance(item[0], dict) and "value" in item[0]:
                        unique_addresses.add(item[0]["value"])
                match_address_count = len(unique_addresses)
                if not unique_addresses and original_matches_field:
                    note = "Matches field was a list, but no standard address objects found within it."
                elif not original_matches_field:
                    note = "Matches field was an empty list."
            else:
                error_msg = f"Original matches data not a dictionary or list (was {type(original_matches_field).__name__})."

            summary_matches = {"match_address_count": match_address_count}
            if note: summary_matches["note"] = note
            if error_msg: summary_matches["error"] = error_msg
            rule_data_to_process['matches'] = summary_matches

        final_rules_output_dict[rule_id] = rule_data_to_process

    await ctx.info(f"Returning capa_analysis_overview. Rules on page: {base_pagination_info['current_items_count']} of {base_pagination_info['total_items_after_filtering']}.")
    data_to_send = {"rules": final_rules_output_dict, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
    limit_info_str = "parameters like 'limit' (for rules), 'offset', or by using filters (e.g., 'filter_rule_name')"
    return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", limit_info_str)


_MAX_BATCH_CAPA_RULES = 20


def _process_single_capa_rule(all_rules_dict, rule_id, address_limit, address_offset=0,
                              detail_limit_per_address=None, selected_feature_fields=None,
                              feature_value_string_limit=None):
    """Process match details for a single capa rule. Returns result dict (sync)."""
    current_addr_offset = address_offset or 0
    empty_pagination = {
        'offset': current_addr_offset, 'limit': address_limit,
        'current_items_count': 0, 'total_addresses_for_rule': 0,
    }

    if rule_id not in all_rules_dict:
        return {"error": f"Rule ID '{rule_id}' not found.", "rule_id": rule_id,
                "matches_data": {}, "address_pagination": empty_pagination}

    original_rule_details = all_rules_dict[rule_id]
    original_matches_field = original_rule_details.get('matches')

    standardized_matches_dict = {}

    if isinstance(original_matches_field, dict):
        for addr_val, details_list in original_matches_field.items():
            addr_str_key = hex(addr_val) if isinstance(addr_val, int) else str(addr_val)
            standardized_matches_dict[addr_str_key] = details_list
    elif isinstance(original_matches_field, list):
        for item in original_matches_field:
            if isinstance(item, list) and len(item) == 2:
                addr_obj, detail_obj = item[0], item[1]
                if isinstance(addr_obj, dict) and "value" in addr_obj:
                    addr_val = addr_obj["value"]
                    addr_str_key = hex(addr_val) if isinstance(addr_val, int) else str(addr_val)
                    if addr_str_key not in standardized_matches_dict:
                        standardized_matches_dict[addr_str_key] = []
                    standardized_matches_dict[addr_str_key].append(detail_obj)

    all_match_addresses_items = list(standardized_matches_dict.items())
    total_addresses_for_rule = len(all_match_addresses_items)
    paginated_address_items = all_match_addresses_items[current_addr_offset:current_addr_offset + address_limit]

    processed_matches_data = {}
    for addr_key_str, original_addr_details_list_for_addr in paginated_address_items:
        details_list_copy = copy.deepcopy(original_addr_details_list_for_addr)

        if not isinstance(details_list_copy, list):
            processed_matches_data[addr_key_str] = [{"error": "Match details structure error."}]
            continue

        processed_addr_details = []
        num_details_to_process = len(details_list_copy)

        if detail_limit_per_address is not None:
            if detail_limit_per_address == 0:
                processed_matches_data[addr_key_str] = []
                continue
            num_details_to_process = min(len(details_list_copy), detail_limit_per_address)

        for i in range(num_details_to_process):
            detail_item = details_list_copy[i]

            if isinstance(detail_item, dict) and 'feature' in detail_item and \
               isinstance(detail_item['feature'], dict):
                feature_obj = detail_item['feature']

                if selected_feature_fields is not None:
                    feature_obj = {
                        f_key: feature_obj[f_key]
                        for f_key in selected_feature_fields
                        if f_key in feature_obj
                    }

                if 'value' in feature_obj and isinstance(feature_obj['value'], str) and \
                   feature_value_string_limit is not None:
                    feat_val_str = feature_obj['value']
                    if len(feat_val_str) > feature_value_string_limit:
                        feature_obj['value'] = feat_val_str[:feature_value_string_limit] + "... (truncated)"

                detail_item['feature'] = feature_obj

            processed_addr_details.append(detail_item)

        processed_matches_data[addr_key_str] = processed_addr_details

    pagination_info = {
        'offset': current_addr_offset, 'limit': address_limit,
        'current_items_count': len(processed_matches_data),
        'total_addresses_for_rule': total_addresses_for_rule,
    }

    return {"rule_id": rule_id, "matches_data": processed_matches_data,
            "address_pagination": pagination_info}


@tool_decorator
async def get_capa_rule_match_details(ctx: Context,
                                      rule_id: str = "",
                                      rule_ids: Optional[List[str]] = None,
                                      address_limit: int = 5,
                                      address_offset: Optional[int] = 0,
                                      detail_limit_per_address: Optional[int] = None,
                                      selected_feature_fields: Optional[List[str]] = None,
                                      feature_value_string_limit: Optional[int] = None
                                      ) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Retrieves detailed match locations for a specific Capa rule.

    When to use: After get_capa_analysis_info() identified interesting rules — use
    this to find the exact code addresses where the capability was detected.

    Next steps: decompile_function_with_angr() at match addresses to understand the
    implementation, then auto_note_function() to record findings.

    Args:
        ctx: The MCP Context object.
        rule_id: (str) The ID/name of the rule to fetch matches for. Required unless rule_ids is provided.
        rule_ids: (Optional[List[str]]) Batch mode: list of rule IDs to fetch matches
            for in one call. Up to 20 items. Returns results keyed by rule_id.
        address_limit: (int) Max number of match addresses to return per rule. Must be positive. Default 5.
        address_offset: (Optional[int]) Starting index for paginating match addresses. Defaults to 0.
        detail_limit_per_address: (Optional[int]) Limits feature match details per address. None for no limit.
        selected_feature_fields: (Optional[List[str]]) Specific fields from 'feature' object (e.g., ["type", "value"]).
        feature_value_string_limit: (Optional[int]) Limits length of string 'value' in feature fields.

    Returns:
        Dict with "rule_id", "matches_data" (address-keyed dict), "address_pagination", and optionally "error".
        In batch mode: {"batch_results": {rule_id: {...}, ...}, "total": N, "succeeded": M}
    Raises:
        RuntimeError: If no Capa analysis data is found.
        ValueError: If parameters are invalid, or if the response size exceeds the server limit.
    """
    if not rule_id and not rule_ids:
        raise ValueError("Either 'rule_id' or 'rule_ids' must be provided.")
    if not (isinstance(address_limit, int) and address_limit > 0):
        raise ValueError("'address_limit' must be positive.")
    for param_name, param_val in [
        ('address_offset', address_offset),
        ('detail_limit_per_address', detail_limit_per_address),
        ('feature_value_string_limit', feature_value_string_limit)
    ]:
        if param_val is not None and not (isinstance(param_val, int) and param_val >= 0):
            raise ValueError(f"Parameter '{param_name}' must be a non-negative integer if provided.")
    if selected_feature_fields is not None and not isinstance(selected_feature_fields, list):
        raise ValueError("'selected_feature_fields' must be a list of strings if provided.")

    _check_data_key_available("capa_analysis", "get_capa_rule_match_details")

    capa_data_block = state.pe_data.get('capa_analysis', {})
    capa_full_results = capa_data_block.get('results')
    capa_status = capa_data_block.get("status", "Unknown")

    if (capa_status != "Analysis complete (adapted workflow)" and capa_status != "Analysis complete") or not capa_full_results:
        error_data: Dict[str, Any] = {"error": f"Capa analysis not complete/results missing. Status: {capa_status}"}
        capa_hint = capa_data_block.get("hint")
        if capa_hint:
            error_data["hint"] = capa_hint
        capa_error_detail = capa_data_block.get("error")
        if capa_error_detail:
            error_data["error_detail"] = capa_error_detail
        return await _check_mcp_response_size(ctx, error_data, "get_capa_rule_match_details", "parameters like 'address_limit'")

    all_rules_dict = capa_full_results.get('rules', {})

    # ── Batch mode ──
    if rule_ids is not None:
        items = list(rule_ids[:_MAX_BATCH_CAPA_RULES])
        await ctx.info(f"Batch capa rule details: {len(items)} rules, address_limit={address_limit}")

        batch_results: Dict[str, Any] = {}
        succeeded = 0
        for rid in items:
            try:
                entry = _process_single_capa_rule(
                    all_rules_dict, rid, address_limit, address_offset,
                    detail_limit_per_address, selected_feature_fields,
                    feature_value_string_limit,
                )
                batch_results[rid] = entry
                if "error" not in entry:
                    succeeded += 1
            except Exception as e:
                batch_results[rid] = {"error": str(e)}

        response: Dict[str, Any] = {
            "batch_results": batch_results,
            "total": len(batch_results),
            "succeeded": succeeded,
            "failed": len(batch_results) - succeeded,
        }
        return await _check_mcp_response_size(ctx, response, "get_capa_rule_match_details",
                                               "parameters like 'address_limit' or 'detail_limit_per_address'")

    # ── Single-rule mode (original behaviour) ──
    if not rule_id:
        raise ValueError("Parameter 'rule_id' is mandatory when 'rule_ids' is not provided.")

    await ctx.info(f"Request for 'capa_rule_match_details'. RuleID: {rule_id}, AddressLimit: {address_limit}, AddressOffset: {address_offset}, "
                   f"DetailLimitPerAddr: {detail_limit_per_address}, SelectedFeatFields: {selected_feature_fields}, "
                   f"FeatureValStrLimit: {feature_value_string_limit}")

    data_to_send = _process_single_capa_rule(
        all_rules_dict, rule_id, address_limit, address_offset,
        detail_limit_per_address, selected_feature_fields, feature_value_string_limit,
    )

    await ctx.info(f"Returning match details for rule '{rule_id}'. Addresses: {data_to_send.get('address_pagination', {}).get('current_items_count', 0)}.")
    limit_info_str = "parameters like 'address_limit', 'address_offset', or 'detail_limit_per_address'"
    return await _check_mcp_response_size(ctx, data_to_send, "get_capa_rule_match_details", limit_info_str)


@tool_decorator
async def extract_strings_from_binary(
    ctx: Context,
    limit: int,
    min_length: int = 5,
    rank_with_sifter: bool = False,
    min_sifter_score: Optional[float] = None,
    sort_by_score: bool = False
) -> List[Dict[str, Any]]:
    """
    [Phase: explore] Extracts printable ASCII strings directly from the binary,
    optionally ranking them with StringSifter for relevance.

    When to use: When FLOSS data is unavailable or you need raw ASCII extraction
    with ML scoring. Prefer get_floss_analysis_info() when FLOSS ran successfully.

    Next steps: Use get_strings_summary() for categorized overview, or
    search_for_specific_strings() to look for known IOC patterns.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. The maximum number of strings to return. Must be positive.
        min_length: (int) The minimum length for a sequence of characters to be considered a string. Defaults to 5.
        rank_with_sifter: (bool) If True, rank extracted strings using StringSifter. Defaults to False.
        min_sifter_score: (Optional[float]) If ranking, only include strings with a score >= this value.
        sort_by_score: (bool) If ranking, sort the results by relevance score (descending).

    Returns:
        A list of dictionaries, where each dictionary contains "offset", "string", and optionally "sifter_score".
        Returns an empty list if no PE file is loaded or no strings are found.

    Raises:
        RuntimeError: If no PE file is currently loaded, a ranking error occurs, or if StringSifter is required but unavailable.
        ValueError: If parameters are invalid, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request to extract strings. MinLen: {min_length}, Limit: {limit}, Sifter: {rank_with_sifter}")

    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    if rank_with_sifter and not STRINGSIFTER_AVAILABLE:
        raise RuntimeError("Ranking is requested, but StringSifter is not available on the server.")
    if min_sifter_score is not None and not rank_with_sifter:
        await ctx.warning("'min_sifter_score' is set, but 'rank_with_sifter' is False. The score filter will be ignored.")
    if min_sifter_score is not None and not (0.0 <= min_sifter_score <= 1.0):
        raise ValueError("Parameter 'min_sifter_score' must be between 0.0 and 1.0.")

    if state.pe_object is None or not hasattr(state.pe_object, '__data__'):
        raise RuntimeError(
            "No PE file loaded or PE data unavailable. "
            "The server must be started with --input-file to pre-load a file. "
            "If a file was provided, check the server logs for load errors."
        )

    try:
        await ctx.report_progress(5, 100)
        await ctx.info("[strings] Extracting from binary...")
        file_data = state.pe_object.__data__
        found = _extract_strings_from_data(file_data, min_length)
        results = [{"offset": hex(offset), "string": s} for offset, s in found]
        await ctx.report_progress(60, 100)
    except Exception as e:
        await ctx.error(f"String extraction error: {e}")
        raise RuntimeError(f"Failed during string extraction: {e}") from e

    # --- StringSifter Integration Logic ---
    if rank_with_sifter:
        try:
            await ctx.report_progress(65, 100)
            await ctx.info("[strings] Ranking with StringSifter...")

            # Get just the string values for ranking
            string_values = [res["string"] for res in results]
            if not string_values:
                return [] # No strings to rank

            # Use cached model (loaded once, reused across calls)
            featurizer, ranker = _get_sifter_models()
            X_test = await asyncio.to_thread(featurizer.transform, string_values)
            y_scores = await asyncio.to_thread(ranker.predict, X_test)

            # Add scores back to the results
            for i, res_dict in enumerate(results):
                res_dict['sifter_score'] = round(float(y_scores[i]), 4)

            # Filter by score if requested
            if min_sifter_score is not None:
                results = [res for res in results if res.get('sifter_score', -1.0) >= min_sifter_score]

            # Sort by score if requested
            if sort_by_score:
                results.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=True)
        except Exception as e:
            await ctx.error(f"StringSifter ranking error: {e}")
            raise RuntimeError(f"Failed during StringSifter ranking: {e}") from e

    try:
        data_to_send = results[:limit]
        limit_info_str = "the 'limit' parameter or by adjusting 'min_sifter_score'"
        return await _check_mcp_response_size(ctx, data_to_send, "extract_strings_from_binary", limit_info_str)
    except Exception as e:
        await ctx.error(f"Response formatting error: {e}")
        raise RuntimeError(f"Failed formatting string extraction results: {e}") from e


@tool_decorator
async def search_for_specific_strings(ctx: Context, search_terms: List[str], limit_per_term: Optional[int] = 100) -> Dict[str, List[str]]:
    """
    [Phase: explore] Searches for exact ASCII string occurrences in the binary data,
    returning file offsets for each match.

    When to use: When you have specific strings to locate (e.g. known C2 domains,
    config markers, known malware strings). Case-sensitive exact matching.

    Next steps: Use get_hex_dump(start_offset=<offset>) to inspect surrounding
    data, or get_string_usage_context(string_offset) for code references.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        search_terms: (List[str]) A list of ASCII strings to search for. Case-sensitive.
        limit_per_term: (Optional[int]) The maximum number of occurrences to report for each search term.
                          Defaults to 100. If None or 0 or negative, a default internal limit may apply.

    Returns:
        A dictionary where keys are the search terms and values are lists of hexadecimal offsets.
    Raises:
        RuntimeError: If no PE file is currently loaded or a search error occurs.
        ValueError: If `search_terms` is empty or not a list, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request to search strings: {search_terms}. Limit per term: {limit_per_term}")
    if state.pe_object is None or not hasattr(state.pe_object, '__data__'):
        raise RuntimeError(
            "No PE file loaded or PE data unavailable. "
            "The server must be started with --input-file to pre-load a file. "
            "If a file was provided, check the server logs for load errors."
        )
    if not search_terms or not isinstance(search_terms, list):
        raise ValueError("search_terms must be a non-empty list of strings.")

    effective_limit_pt = 100
    if limit_per_term is not None and isinstance(limit_per_term, int) and limit_per_term > 0:
        effective_limit_pt = limit_per_term
    elif limit_per_term is not None:
        await ctx.warning(f"Invalid limit_per_term value '{limit_per_term}'. Using default of {effective_limit_pt}.")

    try:
        file_data = state.pe_object.__data__
        found_offsets_dict = _search_specific_strings_in_data(file_data, search_terms)

        limited_results: Dict[str, List[str]] = {}
        for term, offsets_list_int in found_offsets_dict.items():
            limited_results[term] = [hex(off) for off in offsets_list_int[:effective_limit_pt]]

        limit_info_str = "the 'limit_per_term' parameter or by providing fewer/more specific 'search_terms'"
        return await _check_mcp_response_size(ctx, limited_results, "search_for_specific_strings", limit_info_str)
    except Exception as e:
        await ctx.error(f"String search error: {e}")
        raise RuntimeError(f"Failed during specific string search: {e}") from e


@tool_decorator
async def get_top_sifted_strings(
    ctx: Context,
    limit: int,
    string_sources: Optional[List[str]] = None,
    min_sifter_score: Optional[float] = 5.0,
    max_sifter_score: Optional[float] = None,
    sort_order: str = 'descending',
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    filter_regex: Optional[str] = None,
    filter_by_category: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    [Phase: explore] Returns ML-ranked strings from all sources (FLOSS + basic ASCII)
    with advanced filtering by score, length, regex, and category.

    When to use: When you want the most relevant strings ranked by StringSifter ML
    scoring. More powerful than get_strings_summary() for targeted filtering.

    Next steps: Record IOCs with add_note(content, category='tool_result'). Use
    get_string_usage_context() to trace how interesting strings are used in code.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. The maximum number of ranked strings to return.
        string_sources: (Optional[List[str]]) Sources to include: 'floss', 'basic_ascii'. Defaults to all.
        min_sifter_score: (Optional[float]) The minimum relevance score for a string to be included.
        max_sifter_score: (Optional[float]) The maximum relevance score for a string to be included.
        sort_order: (str) Sort order: 'ascending', 'descending'. Defaults to 'descending'.
        min_length: (Optional[int]) Filter for strings with a minimum length.
        max_length: (Optional[int]) Filter for strings with a maximum length.
        filter_regex: (Optional[str]) A regex pattern that strings must match.
        filter_by_category: (Optional[str]) Filter for a specific category (e.g., 'url', 'ipv4').

    Returns:
        A list of unique string dictionaries, filtered and sorted as requested.
    """
    await ctx.info(f"Request for top sifted strings with granular filters.")
    await ctx.report_progress(5, 100)

    # --- Parameter Validation ---
    # (Includes validation for all new and existing parameters)
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    if not STRINGSIFTER_AVAILABLE:
        raise RuntimeError("StringSifter is not available, so no scores were computed.")
    if min_sifter_score is not None and not isinstance(min_sifter_score, (int, float)):
        raise ValueError("Parameter 'min_sifter_score' must be a number if provided.")
    if max_sifter_score is not None and not isinstance(max_sifter_score, (int, float)):
        raise ValueError("Parameter 'max_sifter_score' must be a number if provided.")
    if sort_order.lower() not in ['ascending', 'descending']:
        raise ValueError("Parameter 'sort_order' must be either 'ascending' or 'descending'.")
    _compiled_filter_regex = None
    if filter_regex:
        _validate_regex_pattern(filter_regex)
        _compiled_filter_regex = re.compile(filter_regex)

    # --- Data Retrieval and Aggregation (cached) ---
    _check_pe_loaded("get_top_sifted_strings")
    sources_to_check = string_sources or ['floss', 'basic_ascii']
    include_basic = 'basic_ascii' in sources_to_check
    include_floss = 'floss' in sources_to_check

    all_cached = _get_cached_flat_strings(include_basic_ascii=include_basic, deduplicate=True)
    # Filter by source if only one source requested
    if include_floss and not include_basic:
        all_strings = all_cached
    elif include_basic and not include_floss:
        all_strings = [s for s in all_cached if 'source_type' not in s or not s.get('source_type', '').startswith('floss')]
    else:
        all_strings = all_cached
    # Only include items with sifter_score
    all_strings = [s for s in all_strings if isinstance(s, dict) and 'sifter_score' in s]

    await ctx.report_progress(30, 100)
    await ctx.info("[sifted] Filtering strings...")

    # --- Granular Filtering Logic ---
    filtered_strings = []
    for item in all_strings:
        score = item.get('sifter_score', 0.0)
        str_val = item.get('string', '')
        if not str_val:
            continue
        category = item.get('category')

        if min_sifter_score is not None and score < min_sifter_score: continue
        if max_sifter_score is not None and score > max_sifter_score: continue
        if min_length is not None and len(str_val) < min_length: continue
        if max_length is not None and len(str_val) > max_length: continue
        if filter_by_category is not None and category != filter_by_category: continue
        if _compiled_filter_regex and not _safe_regex_search(_compiled_filter_regex, str_val): continue

        filtered_strings.append(item)

    await ctx.report_progress(70, 100)
    await ctx.info("[sifted] Sorting results...")

    # --- Sorting Logic ---
    is_reversed = (sort_order.lower() == 'descending')
    filtered_strings.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=is_reversed)

    # --- Finalize and Return ---
    data_to_send = filtered_strings[:limit]
    return await _check_mcp_response_size(ctx, data_to_send, "get_top_sifted_strings", "the 'limit' parameter or by adding more filters")


@tool_decorator
async def get_strings_for_function(
    ctx: Context,
    function_va: Union[int, str] = 0,
    limit: int = 20
) -> List[Dict[str, Any]]:
    """
    [Phase: deep-dive] Finds all strings referenced by a specific function via
    FLOSS cross-reference data.

    When to use: After decompiling a function, to understand what strings it uses
    (config values, error messages, API names, URLs).

    Next steps: auto_note_function(address) to record behavioral summary,
    add_note() to record specific string-based IOCs found.

    Args:
        ctx: The MCP Context object.
        function_va: Virtual address of the function — hex string (e.g. '0x401000') or int.
        limit: (int) The maximum number of strings to return. Defaults to 100.

    Returns:
        A list of string dictionaries that are associated with the given function.
    """
    function_va = _parse_int_param(function_va, "function_va")
    await ctx.info(f"Request for strings referenced by function: {hex(function_va)}")
    _check_data_key_available("floss_analysis", "get_strings_for_function")

    found_strings = []
    all_floss_strings = state.pe_data['floss_analysis'].get('strings', {})
    for str_type, str_list in all_floss_strings.items():
        if not isinstance(str_list, list): continue
        for item in str_list:
            if not isinstance(item, dict): continue
            is_match = False
            try:
                if 'references' in item:
                    for ref in item.get('references', []):
                        if ref.get('function_va') and int(ref.get('function_va', '0x0'), 16) == function_va:
                            is_match = True; break
                elif 'function_va' in item and int(item.get('function_va', '0x0'), 16) == function_va:
                    is_match = True
                elif 'decoding_routine_va' in item and int(item.get('decoding_routine_va', '0x0'), 16) == function_va:
                    is_match = True
            except (ValueError, TypeError):
                continue  # Skip items with non-hex VA strings

            if is_match:
                item_with_context = item.copy()
                item_with_context['source_type'] = f"floss_{str_type.replace('_strings', '')}"
                found_strings.append(item_with_context)

    if found_strings and 'sifter_score' in found_strings[0]:
        found_strings.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=True)

    return await _check_mcp_response_size(ctx, found_strings[:limit], "get_strings_for_function", "the 'limit' parameter")


@tool_decorator
async def get_string_usage_context(
    ctx: Context,
    string_offset: Union[int, str] = 0,
    limit: int = 20
) -> List[Dict[str, Any]]:
    """
    [Phase: deep-dive] Finds a static string by file offset and returns disassembly
    context for each code location that references it.

    When to use: After finding an interesting string (via search_floss_strings,
    get_top_sifted_strings, etc.) to understand HOW it's used in code.

    Next steps: decompile_function_with_angr() at the referencing function VA,
    then auto_note_function() to record findings.

    **IMPORTANT PREREQUISITES FOR THIS FUNCTION TO RETURN RESULTS:**
    1.  The `string_offset` MUST correspond to a **static string**. This tool does not work for stack, tight, or decoded strings.
    2.  The static string must have code cross-references (xrefs). An unused string will have no references.
    3.  FLOSS analysis, including the vivisect workspace analysis, must have run successfully during the initial PE file loading, as this is what generates the context.

    Args:
        ctx: The MCP Context object.
        string_offset: File offset — hex string (e.g. '0x3039') or int (e.g. 12345).
        limit: (int) Max number of reference contexts to return. Defaults to 20.

    Returns:
        A list of reference objects, where each object contains the function VA and
        a snippet of disassembly code showing how the string is used. Returns an
        empty list if the offset is not found or has no references.
    """
    string_offset = _parse_int_param(string_offset, "string_offset")
    await ctx.info(f"Request for usage context for string at offset: {hex(string_offset)}")
    _check_data_key_available("floss_analysis", "get_string_usage_context")

    static_strings = state.pe_data['floss_analysis'].get('strings', {}).get('static_strings', [])
    for item in static_strings:
        # Ensure we handle both '0x...' hex strings and integer offsets
        try:
            item_offset = int(item.get('offset', '-1'), 16)
        except (ValueError, TypeError):
            continue

        if item_offset == string_offset:
            references = item.get('references', [])
            return await _check_mcp_response_size(ctx, references[:limit], "get_string_usage_context", "the 'limit' parameter")

    return []


@tool_decorator
async def fuzzy_search_strings(
    ctx: Context,
    query_string: str,
    limit: int,
    string_sources: Optional[List[str]] = None,
    min_similarity_ratio: int = 85
) -> List[Dict[str, Any]]:
    """
    [Phase: explore] Fuzzy search for strings similar to a query across all sources.
    Results sorted by similarity ratio.

    When to use: When you have an approximate string (e.g. partial IOC, typo'd
    domain, obfuscated variant) and want to find near-matches in the binary.

    Next steps: Use get_string_usage_context() for code references to matched
    strings, add_note() to record interesting fuzzy matches found.
    """
    await ctx.info(f"Fuzzy search request for '{query_string}'. Min Ratio: {min_similarity_ratio}, Limit: {limit}")

    # --- Parameter Validation ---
    # CHANGED: Check RAPIDFUZZ_AVAILABLE instead of THEFUZZ_AVAILABLE
    if not RAPIDFUZZ_AVAILABLE:
        raise RuntimeError("Fuzzy search is not available because the 'rapidfuzz' library is not installed.")

    if not query_string:
        raise ValueError("Parameter 'query_string' cannot be empty.")
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    if not (isinstance(min_similarity_ratio, int) and 0 <= min_similarity_ratio <= 100):
        raise ValueError("Parameter 'min_similarity_ratio' must be an integer between 0 and 100.")

    # --- Data Retrieval and Aggregation (cached, with deduplication) ---
    _check_pe_loaded("fuzzy_search_strings")
    sources_to_check = string_sources or ['floss', 'basic_ascii']
    include_basic = 'basic_ascii' in sources_to_check
    include_floss = 'floss' in sources_to_check

    all_cached = _get_cached_flat_strings(include_basic_ascii=include_basic, deduplicate=True)
    if include_floss and not include_basic:
        all_strings = all_cached
    elif include_basic and not include_floss:
        all_strings = [s for s in all_cached if 'source_type' not in s or not s.get('source_type', '').startswith('floss')]
    else:
        all_strings = all_cached

    if not all_strings:
        return []

    await ctx.report_progress(20, 100)
    await ctx.info(f"[fuzzy] Comparing against {len(all_strings)} strings...")

    # --- Fuzzy Matching Logic ---
    # Batch all comparisons in a single thread to avoid per-string dispatch overhead.
    # fuzz.ratio is microsecond-level CPU work; thread scheduling dominates otherwise.
    def _batch_fuzzy_match():
        results = []
        for item in all_strings:
            target_string = item.get("string")
            if not target_string:
                continue
            ratio = fuzz.ratio(query_string, target_string)
            if ratio >= min_similarity_ratio:
                match_item = item.copy()
                match_item['similarity_ratio'] = ratio
                results.append(match_item)
        return results

    matches = await asyncio.to_thread(_batch_fuzzy_match)

    await ctx.report_progress(85, 100)
    await ctx.info(f"[fuzzy] Found {len(matches)} matches, sorting...")

    # --- Sorting and Finalizing ---
    matches.sort(key=lambda x: x.get('similarity_ratio', 0), reverse=True)

    data_to_send = matches[:limit]
    limit_info = "the 'limit' parameter or by adjusting 'min_similarity_ratio'"
    return await _check_mcp_response_size(ctx, data_to_send, "fuzzy_search_strings", limit_info)


# ---- Categorized String Summary (AI-friendly) ----

@tool_decorator
async def get_strings_summary(
    ctx: Context,
    top_per_category: int = 5,
    min_sifter_score: float = 0.0,
    categories: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    [Phase: triage] Categorizes all extracted strings by type and returns counts
    with top examples. Far more context-efficient than dumping raw strings.

    When to use: As a first look at strings after triage — gives a structured
    overview of IOC categories without overwhelming context. Call this before
    diving into search_floss_strings() or get_top_sifted_strings().

    Categories: urls, ip_addresses, domains, file_paths, registry_keys,
    mutex_names, email_addresses, base64_blobs, high_value (ML-scored).

    Next steps: If IOCs found → add_note(content, category='tool_result').
    Use search_floss_strings() to regex-search for related patterns.

    Args:
        ctx: The MCP Context object.
        top_per_category: (int) Max example strings per category. Default 5.
        min_sifter_score: (float) Minimum StringSifter score to include in 'high_value'. Default 0.0.
        categories: (Optional[List[str]]) Filter to specific categories. None = all.

    Returns:
        A dictionary with categorized string counts and examples.
    """
    from arkana.mcp._category_maps import STRING_CATEGORY_PATTERNS, BENIGN_IP_PREFIXES

    _check_pe_loaded("get_strings_summary")

    # Collect all string values (cached, deduped)
    all_strings = _get_cached_flat_strings(include_basic_ascii=True, deduplicate=True)

    total_strings = len(all_strings)

    # Categorize using patterns
    categorized: Dict[str, list] = {cat: [] for cat in STRING_CATEGORY_PATTERNS}
    categorized["high_value"] = []

    for s_obj in all_strings:
        s = s_obj.get("string", "") if isinstance(s_obj, dict) else str(s_obj)
        if not s:
            continue

        for cat_name, pattern in STRING_CATEGORY_PATTERNS.items():
            m = pattern.search(s)
            if m:
                # IP validation: skip private/benign IPs
                if cat_name == "ip_addresses":
                    ip = m.group()
                    octets = ip.split('.')
                    try:
                        first = int(octets[0])
                        if first in BENIGN_IP_PREFIXES:
                            continue
                        if first == 192 and int(octets[1]) == 168:
                            continue
                        if first == 172 and 16 <= int(octets[1]) <= 31:
                            continue
                        if not all(0 <= int(o) <= 255 for o in octets):
                            continue
                    except (ValueError, IndexError):
                        continue
                categorized[cat_name].append(s)

        # High-value strings (ML-scored)
        score = s_obj.get("sifter_score", 0.0) if isinstance(s_obj, dict) else 0.0
        if isinstance(score, (int, float)) and score >= max(min_sifter_score, 7.0):
            categorized["high_value"].append(s)

    # Build result
    result_categories: Dict[str, Any] = {}
    active_cats = categories or list(categorized.keys())

    for cat_name in active_cats:
        if cat_name not in categorized:
            continue
        items = categorized[cat_name]
        # Deduplicate
        unique = list(dict.fromkeys(items))
        if unique:
            result_categories[cat_name] = {
                "count": len(unique),
                "examples": unique[:top_per_category],
            }

    # Sifter score distribution
    score_dist: Dict[str, int] = {"9-10": 0, "7-9": 0, "5-7": 0, "0-5": 0}
    for s_obj in all_strings:
        score = s_obj.get("sifter_score", 0.0) if isinstance(s_obj, dict) else 0.0
        if isinstance(score, (int, float)):
            if score >= 9.0:
                score_dist["9-10"] += 1
            elif score >= 7.0:
                score_dist["7-9"] += 1
            elif score >= 5.0:
                score_dist["5-7"] += 1
            else:
                score_dist["0-5"] += 1

    result: Dict[str, Any] = {
        "total_strings": total_strings,
        "categorized": result_categories,
        "sifter_score_distribution": score_dist,
    }

    return await _check_mcp_response_size(ctx, result, "get_strings_summary")


# ===================================================================
#  search_yara_custom
# ===================================================================

@tool_decorator
async def search_yara_custom(
    ctx: Context,
    rules_string: str = "",
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: explore] Compiles and runs custom YARA rules (provided as a string)
    against the currently loaded binary. Returns matching rules with offsets.

    When to use: When you have a hypothesis about specific byte patterns, strings,
    or structures in the binary and want to validate it with a YARA rule.

    Args:
        ctx: The MCP Context object.
        rules_string: (str) YARA rules as a string, e.g.
            'rule test { strings: $a = "MZ" condition: $a }'
        limit: (int) Max matches to return per rule.
    """
    from arkana.config import YARA_AVAILABLE
    await ctx.info("Running custom YARA rules")
    await ctx.report_progress(5, 100)
    _check_pe_loaded("search_yara_custom")

    if not YARA_AVAILABLE:
        raise RuntimeError(
            "[search_yara_custom] YARA is not installed. Install with: pip install yara-python"
        )
    if not rules_string.strip():
        raise ValueError("rules_string is required. Provide YARA rules as a string.")

    import yara

    try:
        compiled = yara.compile(source=rules_string)
    except yara.SyntaxError as e:
        return {"error": f"YARA compilation error: {e}"}

    await ctx.report_progress(30, 100)
    await ctx.info("[yara] Scanning binary...")

    filepath = state.filepath
    try:
        matches = compiled.match(filepath)
    except Exception as e:
        return {"error": f"YARA scan error: {e}"}

    results = []
    for match in matches:
        match_info: Dict[str, Any] = {
            "rule": match.rule,
            "tags": list(match.tags) if match.tags else [],
            "meta": dict(match.meta) if match.meta else {},
        }
        string_matches = []
        for s in match.strings:
            for instance in s.instances[:limit]:
                string_matches.append({
                    "identifier": s.identifier,
                    "offset": instance.offset,
                    "matched_data": instance.matched_data.hex()[:64],
                })
        match_info["strings"] = string_matches[:limit]
        results.append(match_info)

    return await _check_mcp_response_size(ctx, {
        "matches": results,
        "match_count": len(results),
        "rules_compiled": True,
    }, "search_yara_custom")


# ===================================================================
#  get_string_at_va
# ===================================================================

_MAX_BATCH_STRING_VA = 50


def _extract_ascii(data: bytes) -> str:
    end = data.find(b'\x00')
    if end == -1:
        end = len(data)
    return data[:end].decode('ascii', errors='replace')


def _extract_utf16(data: bytes) -> str:
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i + 1] == 0:
            return data[:i].decode('utf-16-le', errors='replace')
    return data.decode('utf-16-le', errors='replace')


def _extract_string_at_va(pe, filepath: str, va: int, max_length: int, encoding: str) -> Dict[str, Any]:
    """Core logic to extract a string at a single VA. Returns result dict."""
    try:
        offset = pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase)
    except Exception:
        return {"error": f"Could not resolve VA {hex(va)} to a file offset."}

    try:
        with open(filepath, "rb") as f:
            f.seek(offset)
            raw = f.read(max_length)
    except Exception as e:
        return {"error": f"Failed to read at offset {offset}: {e}"}

    result: Dict[str, Any] = {
        "virtual_address": hex(va),
        "file_offset": hex(offset),
    }

    if encoding == "auto":
        ascii_str = _extract_ascii(raw)
        utf16_str = _extract_utf16(raw)
        ascii_printable = sum(1 for c in ascii_str if c.isprintable())
        utf16_printable = sum(1 for c in utf16_str if c.isprintable())
        if utf16_printable > ascii_printable and len(utf16_str) > 1:
            result["string"] = utf16_str
            result["encoding"] = "utf-16-le"
        else:
            result["string"] = ascii_str
            result["encoding"] = "ascii"
    elif encoding == "utf16le":
        result["string"] = _extract_utf16(raw)
        result["encoding"] = "utf-16-le"
    else:
        result["string"] = _extract_ascii(raw)
        result["encoding"] = "ascii"

    result["length"] = len(result["string"])
    result["hex_preview"] = raw[:32].hex()
    return result


@tool_decorator
async def get_string_at_va(
    ctx: Context,
    virtual_address: str = "",
    virtual_addresses: Optional[List[str]] = None,
    max_length: int = 256,
    encoding: str = "auto",
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Extracts a string at a given virtual address by resolving
    the VA to a file offset and reading bytes until a null terminator or max_length.

    When to use: When decompilation or disassembly references a string at a VA
    and you want to see the actual string content without manually calculating offsets.

    Args:
        ctx: The MCP Context object.
        virtual_address: (str) Virtual address as hex string (e.g. '0x401000').
        virtual_addresses: (Optional[List[str]]) Batch mode: list of hex VA strings
            to extract in one call. Up to 50 items. Returns results keyed by address.
        max_length: (int) Maximum bytes to read (default 256).
        encoding: (str) 'ascii', 'utf16le', or 'auto' (tries both).
    """
    _check_pe_loaded("get_string_at_va")

    pe = state.pe_object
    if pe is None:
        return {"error": "PE object not available. This tool requires a PE file."}

    from arkana.mcp._input_helpers import _parse_int_param

    # ── Batch mode ──
    if virtual_addresses is not None:
        items = list(virtual_addresses[:_MAX_BATCH_STRING_VA])
        await ctx.info(f"Batch extracting strings at {len(items)} VAs")

        batch_results: Dict[str, Any] = {}
        succeeded = 0
        for va_str in items:
            try:
                va = _parse_int_param(va_str, "virtual_address")
                entry = _extract_string_at_va(pe, state.filepath, va, max_length, encoding)
                batch_results[hex(va)] = entry
                if "error" not in entry:
                    succeeded += 1
            except Exception as e:
                batch_results[va_str] = {"error": str(e)}

        response: Dict[str, Any] = {
            "batch_results": batch_results,
            "total": len(batch_results),
            "succeeded": succeeded,
        }
        return await _check_mcp_response_size(ctx, response, "get_string_at_va")

    # ── Single-address mode (original behaviour) ──
    await ctx.info(f"Extracting string at VA {virtual_address}")

    if not virtual_address:
        raise ValueError("virtual_address is required (e.g. '0x401000').")

    va = _parse_int_param(virtual_address, "virtual_address")
    return _extract_string_at_va(pe, state.filepath, va, max_length, encoding)


# ---- Hex Pattern Search -----------------------------------------

def _hex_pattern_to_regex(pattern: str) -> bytes:
    """Convert a space-separated hex pattern with ?? wildcards to a bytes regex.

    Example: "4D 5A ?? ?? 50 45" → re pattern matching MZ..PE
    """
    from arkana.constants import MAX_HEX_PATTERN_TOKENS
    tokens = pattern.strip().split()
    if len(tokens) > MAX_HEX_PATTERN_TOKENS:
        raise ValueError(f"Pattern too long ({len(tokens)} tokens). Maximum is {MAX_HEX_PATTERN_TOKENS}.")
    if not tokens:
        raise ValueError("Empty hex pattern.")

    regex_parts = []
    for token in tokens:
        token = token.strip()
        if token == "??" or token == "?":
            regex_parts.append(b".")
        else:
            if len(token) != 2:
                raise ValueError(f"Invalid hex token '{token}'. Each token must be 2 hex chars or '??'.")
            try:
                byte_val = int(token, 16)
            except ValueError:
                raise ValueError(f"Invalid hex token '{token}'.") from None
            regex_parts.append(re.escape(bytes([byte_val])))

    return b"".join(regex_parts)


def _find_section_for_offset(pe, offset: int) -> Optional[str]:
    """Resolve which PE section contains a file offset."""
    try:
        if hasattr(pe, 'sections'):
            for section in pe.sections:
                start = section.PointerToRawData
                end = start + section.SizeOfRawData
                if start <= offset < end:
                    return section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    except Exception:
        pass
    return None


@tool_decorator
async def search_hex_pattern(
    ctx: Context,
    pattern: str,
    section: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    [Phase: explore] Search for hex byte patterns in the loaded binary. Supports
    wildcard bytes (??) for flexible matching.

    When to use: To find specific byte sequences — magic bytes, shellcode signatures,
    XOR keys, crypto constants, or known opcode patterns.

    Args:
        ctx: The MCP Context object.
        pattern: (str) Space-separated hex bytes with ?? wildcards.
            Example: "4D 5A ?? ?? 50 45" to find MZ..PE patterns.
        section: (Optional[str]) Restrict search to a named PE section (e.g. '.text').
            Only applies to PE files; ignored for ELF/Mach-O.
        limit: (int) Maximum number of matches to return (default 50, max 5000).

    Returns:
        List of match offsets with surrounding context.
    """
    _check_pe_loaded("search_hex_pattern")
    if state.pe_object is None or not hasattr(state.pe_object, '__data__'):
        raise RuntimeError("No binary data available for hex pattern search.")

    if not pattern or not pattern.strip():
        raise ValueError("pattern must be a non-empty hex string.")

    from arkana.constants import MAX_HEX_PATTERN_MATCHES
    effective_limit = min(max(1, limit), MAX_HEX_PATTERN_MATCHES)

    # Compile pattern
    regex_pattern = _hex_pattern_to_regex(pattern)

    file_data = state.pe_object.__data__

    # Determine search range
    search_data = file_data
    search_offset_base = 0
    section_info = None

    if section and hasattr(state.pe_object, 'sections'):
        found_section = None
        try:
            for sec in state.pe_object.sections:
                sec_name = sec.Name.rstrip(b'\x00').decode('ascii', errors='replace')
                if sec_name == section:
                    found_section = sec
                    break
        except Exception:
            pass
        if found_section is None:
            raise ValueError(f"Section '{section}' not found in this binary.")
        search_offset_base = found_section.PointerToRawData
        search_data = file_data[found_section.PointerToRawData:
                                found_section.PointerToRawData + found_section.SizeOfRawData]
        section_info = section

    await ctx.info(f"Searching {len(search_data)} bytes for pattern: {pattern}")

    def _do_search():
        compiled = re.compile(regex_pattern, re.DOTALL)
        matches = []
        for m in compiled.finditer(search_data):
            file_offset = search_offset_base + m.start()
            # Get a small context window around the match
            ctx_start = max(0, m.start() - 8)
            ctx_end = min(len(search_data), m.end() + 8)
            context_hex = search_data[ctx_start:ctx_end].hex()

            match_entry = {
                "offset": hex(file_offset),
                "offset_decimal": file_offset,
                "matched_bytes": search_data[m.start():m.end()].hex(),
                "context": context_hex,
            }
            # Try to identify containing section
            sec_name = _find_section_for_offset(state.pe_object, file_offset)
            if sec_name:
                match_entry["section"] = sec_name

            matches.append(match_entry)
            if len(matches) >= effective_limit:
                break
        return matches

    matches = await asyncio.to_thread(_do_search)

    result = {
        "pattern": pattern,
        "matches": matches,
        "match_count": len(matches),
        "limit_applied": len(matches) >= effective_limit,
        "searched_bytes": len(search_data),
    }
    if section_info:
        result["section_filter"] = section_info
    return await _check_mcp_response_size(ctx, result, "search_hex_pattern")
