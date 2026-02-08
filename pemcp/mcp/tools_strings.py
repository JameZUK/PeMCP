"""MCP tools for string analysis, FLOSS, capa, and fuzzy search."""
import re
import json
import copy
import os
import asyncio

from typing import Dict, Any, Optional, List

from pemcp.config import (
    state, logger, Context,
    STRINGSIFTER_AVAILABLE, RAPIDFUZZ_AVAILABLE, CAPA_AVAILABLE,
    MAX_MCP_RESPONSE_SIZE_BYTES,
)
from pemcp.mcp.server import (
    tool_decorator, _check_pe_loaded, _check_data_key_available,
    _check_mcp_response_size,
)
from pemcp.parsers.strings import _extract_strings_from_data, _search_specific_strings_in_data

if RAPIDFUZZ_AVAILABLE:
    from rapidfuzz import fuzz

if STRINGSIFTER_AVAILABLE:
    import stringsifter.lib.util as sifter_util
    import joblib


@tool_decorator
async def search_floss_strings(
    ctx: Context,
    regex_patterns: List[str],
    min_sifter_score: Optional[float] = None,
    max_sifter_score: Optional[float] = None,
    sort_order: Optional[str] = None,
    min_length: int = 0,
    limit: int = 100,
    case_sensitive: bool = False
) -> Dict[str, Any]:
    """
    Performs a regex search against FLOSS strings, with advanced score filtering and sorting.

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
            compiled_patterns.append(re.compile(pattern_str, flags))
    except re.error as e:
        raise ValueError(f"Invalid regex pattern provided in the list: {e}")

    all_strings_with_context = []
    for source_type, string_list in floss_data.get("strings", {}).items():
        for string_item in string_list:
            if isinstance(string_item, dict) and "string" in string_item:
                contextual_item = string_item.copy()
                contextual_item["source_type"] = source_type.replace("_strings", "")
                all_strings_with_context.append(contextual_item)

    matches = []
    for item in all_strings_with_context:
        # Score filtering
        score = item.get('sifter_score', -999.0)
        min_ok = (min_sifter_score is None) or (score >= min_sifter_score)
        max_ok = (max_sifter_score is None) or (score <= max_sifter_score)

        if min_ok and max_ok:
            # Length and Regex filtering
            string_to_search = item["string"]
            if any(p.search(string_to_search) for p in compiled_patterns):
                if len(string_to_search) >= min_length:
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
                                  limit: int = 100,
                                  offset: Optional[int] = 0
                                 ) -> Dict[str, Any]:
    """
    Retrieves FLOSS analysis results, with new option to filter for strings with code context.

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
                                 limit: int,
                                 offset: Optional[int] = 0,
                                 filter_rule_name: Optional[str] = None,
                                 filter_namespace: Optional[str] = None,
                                 filter_attck_id: Optional[str] = None,
                                 filter_mbc_id: Optional[str] = None,
                                 fields_per_rule: Optional[List[str]] = None,
                                 get_report_metadata_only: bool = False,
                                 source_string_limit: Optional[int] = None
                                 ) -> Dict[str, Any]:
    """
    Retrieves an overview of Capa capability rules, with filtering and pagination.
    For each rule, 'matches' are summarized by a count of unique addresses found.
    Use 'get_capa_rule_match_details' to fetch detailed match information for a specific rule.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max capability rules to return. Must be positive.
        offset: (Optional[int]) Starting index for rule pagination. Defaults to 0.
        filter_rule_name: (Optional[str]) Filter rules by name/ID (substring, case-insensitive).
        filter_namespace: (Optional[str]) Filter rules by namespace (exact, case-insensitive).
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
    if source_string_limit is not None and not (isinstance(source_string_limit, int) and source_string_limit >= 0):
        raise ValueError("Parameter 'source_string_limit' must be a non-negative integer if provided.")

    _check_data_key_available("capa_analysis", "get_capa_analysis_info")

    capa_data_block = state.pe_data.get('capa_analysis', {})
    capa_full_results = capa_data_block.get('results')
    capa_status = capa_data_block.get("status", "Unknown")

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
        if 'layout' in analysis_section: del analysis_section['layout']
        if 'feature_counts' in analysis_section: del analysis_section['feature_counts']

    if capa_status == "Skipped by user request":
        data_to_send = {"error": "Capa analysis was skipped.", "rules": {}, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")

    if capa_status != "Analysis complete (adapted workflow)" and capa_status != "Analysis complete" or not capa_full_results:
        data_to_send = {"error": f"Capa analysis not complete/results missing. Status: {capa_status}",
                        "rules": {}, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")


    if get_report_metadata_only:
        data_to_send = {"report_metadata": processed_report_meta, "rules": {}, "pagination": base_pagination_info}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")


    all_rules_dict_from_capa = capa_full_results.get('rules', {})
    if not isinstance(all_rules_dict_from_capa, dict):
        base_pagination_info['total_capabilities_in_report'] = 0
        data_to_send = {"error": "Capa 'rules' data malformed.", "rules": {}, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")

    base_pagination_info['total_capabilities_in_report'] = len(all_rules_dict_from_capa)

    filtered_rule_items = []
    for rule_id, rule_details_original in all_rules_dict_from_capa.items():
        if not isinstance(rule_details_original, dict):
            await ctx.warning(f"Skipping malformed rule entry for ID '{rule_id}'.")
            continue

        meta = rule_details_original.get("meta", {})
        if not isinstance(meta, dict): meta = {}

        passes_filter = True
        if filter_rule_name and filter_rule_name.lower() not in str(meta.get("name", rule_id)).lower(): passes_filter = False
        if passes_filter and filter_namespace and meta.get("namespace", "").lower() != filter_namespace.lower(): passes_filter = False

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


@tool_decorator
async def get_capa_rule_match_details(ctx: Context,
                                      rule_id: str,
                                      address_limit: int,
                                      address_offset: Optional[int] = 0,
                                      detail_limit_per_address: Optional[int] = None,
                                      selected_feature_fields: Optional[List[str]] = None,
                                      feature_value_string_limit: Optional[int] = None
                                      ) -> Dict[str, Any]:
    """
    Retrieves detailed match information for a single, specified Capa rule, with pagination and content control.
    Handles cases where 'matches' in Capa output is a dictionary OR a list of match instances.

    Args:
        ctx: The MCP Context object.
        rule_id: (str) Mandatory. The ID/name of the rule to fetch matches for.
        address_limit: (int) Mandatory. Max number of match addresses to return. Must be positive.
        address_offset: (Optional[int]) Starting index for paginating match addresses. Defaults to 0.
        detail_limit_per_address: (Optional[int]) Limits feature match details per address. None for no limit.
        selected_feature_fields: (Optional[List[str]]) Specific fields from 'feature' object (e.g., ["type", "value"]).
        feature_value_string_limit: (Optional[int]) Limits length of string 'value' in feature fields.

    Returns:
        Dict with "rule_id", "matches_data" (address-keyed dict), "address_pagination", and optionally "error".
    Raises:
        RuntimeError: If no Capa analysis data is found.
        ValueError: If parameters are invalid, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request for 'capa_rule_match_details'. RuleID: {rule_id}, AddressLimit: {address_limit}, AddressOffset: {address_offset}, "
                   f"DetailLimitPerAddr: {detail_limit_per_address}, SelectedFeatFields: {selected_feature_fields}, "
                   f"FeatureValStrLimit: {feature_value_string_limit}")

    if not rule_id: raise ValueError("Parameter 'rule_id' is mandatory.")
    if not (isinstance(address_limit, int) and address_limit > 0): raise ValueError("'address_limit' must be positive.")
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

    current_addr_offset = 0
    if address_offset is not None: current_addr_offset = address_offset

    empty_address_pagination = {
        'offset': current_addr_offset, 'limit': address_limit,
        'current_items_count': 0, 'total_addresses_for_rule': 0
    }

    if capa_status != "Analysis complete (adapted workflow)" and capa_status != "Analysis complete" or not capa_full_results:
        data_to_send = {"error": f"Capa analysis not complete/results missing. Status: {capa_status}",
                        "rule_id": rule_id, "matches_data": {}, "address_pagination": empty_address_pagination}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_rule_match_details", "parameters like 'address_limit'")


    all_rules_dict = capa_full_results.get('rules', {})
    if rule_id not in all_rules_dict:
        data_to_send = {"error": f"Rule ID '{rule_id}' not found.",
                        "rule_id": rule_id, "matches_data": {}, "address_pagination": empty_address_pagination}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_rule_match_details", "parameters like 'address_limit'")


    original_rule_details = all_rules_dict[rule_id]
    original_matches_field = original_rule_details.get('matches')

    standardized_matches_dict = {}

    if isinstance(original_matches_field, dict):
        for addr_val, details_list in original_matches_field.items():
            addr_str_key = hex(addr_val) if isinstance(addr_val, int) else str(addr_val)
            standardized_matches_dict[addr_str_key] = details_list

    elif isinstance(original_matches_field, list):
        await ctx.info(f"Matches for rule '{rule_id}' is a list. Attempting to standardize.")
        for item in original_matches_field:
            if isinstance(item, list) and len(item) == 2:
                addr_obj, detail_obj = item[0], item[1]
                if isinstance(addr_obj, dict) and "value" in addr_obj:
                    addr_val = addr_obj["value"]
                    addr_str_key = hex(addr_val) if isinstance(addr_val, int) else str(addr_val)

                    if addr_str_key not in standardized_matches_dict:
                        standardized_matches_dict[addr_str_key] = []
                    standardized_matches_dict[addr_str_key].append(detail_obj)
                else:
                    await ctx.warning(f"Skipping item in matches list for rule '{rule_id}': address object malformed. Item: {str(item)[:100]}")
            else:
                await ctx.warning(f"Skipping item in matches list for rule '{rule_id}': item not a pair. Item: {str(item)[:100]}")
    elif original_matches_field is None:
        await ctx.info(f"Matches data for rule '{rule_id}' was None. No address-specific matches.")
    else:
        await ctx.warning(f"Matches data for rule '{rule_id}' is unexpected type '{type(original_matches_field).__name__}'. Treating as no matches.")

    all_match_addresses_items = list(standardized_matches_dict.items())
    total_addresses_for_rule = len(all_match_addresses_items)

    paginated_address_items = all_match_addresses_items[current_addr_offset : current_addr_offset + address_limit]

    processed_matches_data = {}
    for addr_key_str, original_addr_details_list_for_addr in paginated_address_items:
        details_list_copy = copy.deepcopy(original_addr_details_list_for_addr)

        if not isinstance(details_list_copy, list):
            processed_matches_data[addr_key_str] = [{"error": "Match details structure error after standardization."}]
            continue

        processed_addr_details_for_this_addr = []
        num_details_to_process = len(details_list_copy)

        if detail_limit_per_address is not None:
            if detail_limit_per_address == 0:
                processed_matches_data[addr_key_str] = []
                continue
            num_details_to_process = min(len(details_list_copy), detail_limit_per_address)

        for i in range(num_details_to_process):
            detail_item_processed = details_list_copy[i]

            if isinstance(detail_item_processed, dict) and 'feature' in detail_item_processed and \
               isinstance(detail_item_processed['feature'], dict):

                feature_obj_for_processing = detail_item_processed['feature']

                if selected_feature_fields is not None:
                    feature_obj_for_processing = {
                        f_key: feature_obj_for_processing[f_key]
                        for f_key in selected_feature_fields
                        if f_key in feature_obj_for_processing
                    }

                if 'value' in feature_obj_for_processing and \
                   isinstance(feature_obj_for_processing['value'], str) and \
                   feature_value_string_limit is not None:
                    feat_val_str = feature_obj_for_processing['value']
                    if len(feat_val_str) > feature_value_string_limit:
                        feature_obj_for_processing['value'] = feat_val_str[:feature_value_string_limit] + "... (truncated)"

                detail_item_processed['feature'] = feature_obj_for_processing

            processed_addr_details_for_this_addr.append(detail_item_processed)

        processed_matches_data[addr_key_str] = processed_addr_details_for_this_addr

    address_pagination_info = {
        'offset': current_addr_offset,
        'limit': address_limit,
        'current_items_count': len(processed_matches_data),
        'total_addresses_for_rule': total_addresses_for_rule
    }

    await ctx.info(f"Returning match details for rule '{rule_id}'. Addresses on page: {len(processed_matches_data)} of {total_addresses_for_rule}.")
    data_to_send = {"rule_id": rule_id, "matches_data": processed_matches_data, "address_pagination": address_pagination_info}
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
    Extracts printable ASCII strings and can optionally rank them with StringSifter.

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
        file_data = state.pe_object.__data__
        found = _extract_strings_from_data(file_data, min_length)
        results = [{"offset": hex(offset), "string": s} for offset, s in found]

        # --- StringSifter Integration Logic ---
        if rank_with_sifter:
            await ctx.info("Ranking extracted strings with StringSifter...")

            # Get just the string values for ranking
            string_values = [res["string"] for res in results]
            if not string_values:
                return [] # No strings to rank

            # Load model and rank
            modeldir = os.path.join(sifter_util.package_base(), "model")
            featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
            ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))
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

        data_to_send = results[:limit]
        limit_info_str = "the 'limit' parameter or by adjusting 'min_sifter_score'"
        return await _check_mcp_response_size(ctx, data_to_send, "extract_strings_from_binary", limit_info_str)

    except Exception as e:
        await ctx.error(f"String extraction/ranking error: {e}")
        raise RuntimeError(f"Failed during string extraction: {e}") from e


@tool_decorator
async def search_for_specific_strings(ctx: Context, search_terms: List[str], limit_per_term: Optional[int] = 100) -> Dict[str, List[str]]:
    """
    Searches for occurrences of specific ASCII strings within the pre-loaded PE file's binary data.
    'limit_per_term' controls occurrences per search term.

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
    if not search_terms or not isinstance(search_terms,list): raise ValueError("search_terms must be a non-empty list of strings.")

    effective_limit_pt = 100
    if limit_per_term is not None and isinstance(limit_per_term, int) and limit_per_term > 0:
        effective_limit_pt = limit_per_term
    elif limit_per_term is not None:
        await ctx.warning(f"Invalid limit_per_term value '{limit_per_term}'. Using default of {effective_limit_pt}.")

    try:
        file_data=state.pe_object.__data__; found_offsets_dict=_search_specific_strings_in_data(file_data,search_terms)

        limited_results:Dict[str,List[str]]={}
        for term, offsets_list_int in found_offsets_dict.items():
            limited_results[term] = [hex(off) for off in offsets_list_int[:effective_limit_pt]]

        limit_info_str = "the 'limit_per_term' parameter or by providing fewer/more specific 'search_terms'"
        return await _check_mcp_response_size(ctx, limited_results, "search_for_specific_strings", limit_info_str)
    except Exception as e: await ctx.error(f"String search error: {e}"); raise RuntimeError(f"Failed during specific string search: {e}")from e


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
    Returns top-ranked strings from all sources with advanced, granular filtering.

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
    if filter_regex:
        try:
            re.compile(filter_regex)
        except re.error as e:
            raise ValueError(f"Invalid 'filter_regex': {e}")

    # --- Data Retrieval and Aggregation ---
    _check_pe_loaded("get_top_sifted_strings")

    all_strings = []
    seen_string_values = set()
    sources_to_check = string_sources or ['floss', 'basic_ascii']

    if 'floss' in sources_to_check and 'floss_analysis' in state.pe_data:
        floss_strings = state.pe_data['floss_analysis'].get('strings', {})
        for str_type, str_list in floss_strings.items():
            for item in str_list:
                if isinstance(item, dict) and 'sifter_score' in item:
                    str_val = item.get("string")
                    if str_val and str_val not in seen_string_values:
                        item_with_context = item.copy()
                        item_with_context['source_type'] = f"floss_{str_type.replace('_strings', '')}"
                        all_strings.append(item_with_context)
                        seen_string_values.add(str_val)

    if 'basic_ascii' in sources_to_check and 'basic_ascii_strings' in state.pe_data:
        for item in state.pe_data['basic_ascii_strings']:
            if isinstance(item, dict) and 'sifter_score' in item:
                str_val = item.get("string")
                if str_val and str_val not in seen_string_values:
                    all_strings.append(item)
                    seen_string_values.add(str_val)

    # --- Granular Filtering Logic ---
    filtered_strings = []
    for item in all_strings:
        score = item['sifter_score']
        str_val = item['string']
        category = item.get('category')

        if min_sifter_score is not None and score < min_sifter_score: continue
        if max_sifter_score is not None and score > max_sifter_score: continue
        if min_length is not None and len(str_val) < min_length: continue
        if max_length is not None and len(str_val) > max_length: continue
        if filter_by_category is not None and category != filter_by_category: continue
        if filter_regex and not re.search(filter_regex, str_val): continue

        filtered_strings.append(item)

    # --- Sorting Logic ---
    is_reversed = (sort_order.lower() == 'descending')
    filtered_strings.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=is_reversed)

    # --- Finalize and Return ---
    data_to_send = filtered_strings[:limit]
    return await _check_mcp_response_size(ctx, data_to_send, "get_top_sifted_strings", "the 'limit' parameter or by adding more filters")


@tool_decorator
async def get_strings_for_function(
    ctx: Context,
    function_va: int,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Finds and returns all strings that are referenced by a specific function.

    Args:
        ctx: The MCP Context object.
        function_va: (int) The virtual address of the function to query.
        limit: (int) The maximum number of strings to return. Defaults to 100.

    Returns:
        A list of string dictionaries that are associated with the given function.
    """
    await ctx.info(f"Request for strings referenced by function: {hex(function_va)}")
    _check_data_key_available("floss_analysis", "get_strings_for_function")

    found_strings = []
    all_floss_strings = state.pe_data['floss_analysis'].get('strings', {})
    for str_type, str_list in all_floss_strings.items():
        if not isinstance(str_list, list): continue
        for item in str_list:
            if not isinstance(item, dict): continue
            is_match = False
            if 'references' in item:
                for ref in item.get('references', []):
                    if ref.get('function_va') and int(ref.get('function_va', '0x0'), 16) == function_va:
                        is_match = True; break
            elif 'function_va' in item and int(item.get('function_va', '0x0'), 16) == function_va:
                is_match = True
            elif 'decoding_routine_va' in item and int(item.get('decoding_routine_va', '0x0'), 16) == function_va:
                is_match = True

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
    string_offset: int,
    limit: int = 20
) -> List[Dict[str, Any]]:
    """
    Finds a static string by its file offset and returns the disassembly
    context for each location where it is referenced in code.

    **IMPORTANT PREREQUISITES FOR THIS FUNCTION TO RETURN RESULTS:**
    1.  The `string_offset` MUST correspond to a **static string**. This tool does not work for stack, tight, or decoded strings.
    2.  The static string must have code cross-references (xrefs). An unused string will have no references.
    3.  FLOSS analysis, including the vivisect workspace analysis, must have run successfully during the initial PE file loading, as this is what generates the context.

    Args:
        ctx: The MCP Context object.
        string_offset: (int) The file offset (e.g., 12345) of the static string to look up.
        limit: (int) Max number of reference contexts to return. Defaults to 20.

    Returns:
        A list of reference objects, where each object contains the function VA and
        a snippet of disassembly code showing how the string is used. Returns an
        empty list if the offset is not found or has no references.
    """
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
    Performs a fuzzy search to find strings similar to the query string across
    all specified sources. Results are sorted by similarity.
    ... (rest of docstring is fine) ...
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

    # --- Data Retrieval and Aggregation (with deduplication) ---
    _check_pe_loaded("fuzzy_search_strings")

    all_strings = []
    seen_string_values = set()
    sources_to_check = string_sources or ['floss', 'basic_ascii']

    # Process FLOSS first to prioritize its richer context
    if 'floss' in sources_to_check and 'floss_analysis' in state.pe_data:
        floss_strings = state.pe_data['floss_analysis'].get('strings', {})
        for str_type, str_list in floss_strings.items():
            for item in str_list:
                if isinstance(item, dict):
                    str_val = item.get("string")
                    if str_val and str_val not in seen_string_values:
                        item_with_context = item.copy()
                        item_with_context['source_type'] = f"floss_{str_type.replace('_strings', '')}"
                        all_strings.append(item_with_context)
                        seen_string_values.add(str_val)

    # Process Basic ASCII strings
    if 'basic_ascii' in sources_to_check and 'basic_ascii_strings' in state.pe_data:
        for item in state.pe_data['basic_ascii_strings']:
            if isinstance(item, dict):
                str_val = item.get("string")
                if str_val and str_val not in seen_string_values:
                    all_strings.append(item)
                    seen_string_values.add(str_val)

    if not all_strings:
        return []

    # --- Fuzzy Matching Logic ---
    matches = []
    for item in all_strings:
        target_string = item.get("string")
        if not target_string:
            continue

        # Calculate the similarity ratio
        ratio = await asyncio.to_thread(fuzz.ratio, query_string, target_string)

        if ratio >= min_similarity_ratio:
            match_item = item.copy()
            match_item['similarity_ratio'] = ratio
            matches.append(match_item)

    # --- Sorting and Finalizing ---
    matches.sort(key=lambda x: x.get('similarity_ratio', 0), reverse=True)

    data_to_send = matches[:limit]
    limit_info = "the 'limit' parameter or by adjusting 'min_similarity_ratio'"
    return await _check_mcp_response_size(ctx, data_to_send, "fuzzy_search_strings", limit_info)
