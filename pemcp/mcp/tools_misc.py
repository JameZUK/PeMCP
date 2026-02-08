"""MCP tools for deobfuscation, hex dump, triage reports, task status, and utilities."""
import re
import base64
import codecs
import datetime
import json
import uuid
import asyncio
import os

from typing import Dict, Any, Optional, List, Tuple

from pemcp.config import (
    state, logger, Context,
    REQUESTS_AVAILABLE, VT_API_KEY, VT_API_URL_FILE_REPORT,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    STRINGSIFTER_AVAILABLE, YARA_AVAILABLE,
)
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_data_key_available, _check_mcp_response_size
from pemcp.parsers.strings import _decode_single_byte_xor, _format_hex_dump_lines

if REQUESTS_AVAILABLE:
    import requests

if STRINGSIFTER_AVAILABLE:
    import stringsifter.lib.util as sifter_util
    import joblib


@tool_decorator
async def get_virustotal_report_for_loaded_file(ctx: Context) -> Dict[str, Any]:
    """
    Retrieves a summary report from VirusTotal for the pre-loaded PE file using its hash.
    Requires the 'requests' library and a VirusTotal API key set in the VT_API_KEY environment variable.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing VirusTotal report summary or an error status.
        Includes hashes (MD5, SHA1, SHA256, ssdeep) reported by VirusTotal,
        detection statistics, and other relevant metadata.

    Raises:
        RuntimeError: If no PE file is loaded or hashes are unavailable.
        ValueError: If the response size exceeds the server limit.
    """

    tool_name = "get_virustotal_report_for_loaded_file"
    await ctx.info(f"Request for VirusTotal report for the loaded file.")

    if not state.pe_data or 'file_hashes' not in state.pe_data:
        raise RuntimeError("No PE file loaded or file hashes are unavailable. Cannot query VirusTotal.")

    file_hashes = state.pe_data['file_hashes']
    main_hash_value: Optional[str] = None
    hash_type_used: Optional[str] = None

    if file_hashes.get('sha256'):
        main_hash_value = file_hashes['sha256']
        hash_type_used = "sha256"
    elif file_hashes.get('sha1'):
        main_hash_value = file_hashes['sha1']
        hash_type_used = "sha1"
    elif file_hashes.get('md5'):
        main_hash_value = file_hashes['md5']
        hash_type_used = "md5"

    if not main_hash_value or not hash_type_used:
        await ctx.error("No suitable hash (SHA256, SHA1, MD5) available for VirusTotal query.")
        return await _check_mcp_response_size(ctx, {
            "status": "error",
            "message": "No suitable file hash (SHA256, SHA1, MD5) available for VirusTotal query.",
            "query_hash_type": None,
            "query_hash": None
        }, tool_name)


    if not VT_API_KEY:
        await ctx.warning("VirusTotal API key (VT_API_KEY) is not configured. Skipping VirusTotal lookup.")
        return await _check_mcp_response_size(ctx, {
            "status": "api_key_missing",
            "message": "VirusTotal API key (VT_API_KEY) is not configured in the environment.",
            "query_hash_type": hash_type_used,
            "query_hash": main_hash_value
        }, tool_name)

    if not REQUESTS_AVAILABLE:
        await ctx.warning("'requests' library is not available. Skipping VirusTotal lookup.")
        return await _check_mcp_response_size(ctx, {
            "status": "requests_unavailable",
            "message": "'requests' library is not installed/available, which is required for VirusTotal queries.",
            "query_hash_type": hash_type_used,
            "query_hash": main_hash_value
        }, tool_name)

    headers = {"x-apikey": VT_API_KEY}
    api_url = f"{VT_API_URL_FILE_REPORT}{main_hash_value}"
    response_payload: Dict[str, Any] = {
        "status": "pending",
        "query_hash_type": hash_type_used,
        "query_hash": main_hash_value,
        "locally_calculated_ssdeep": file_hashes.get('ssdeep'),
    }

    try:
        await ctx.info(f"Querying VirusTotal API for hash: {main_hash_value}")
        http_response = await asyncio.to_thread(requests.get, api_url, headers=headers, timeout=20)

        if http_response.status_code == 200:
            vt_json_response = http_response.json()
            vt_attributes = vt_json_response.get("data", {}).get("attributes", {})

            vt_data_summary = {
                "report_link": f"https://www.virustotal.com/gui/file/{main_hash_value}",
                "retrieved_hashes": {
                    "md5": vt_attributes.get("md5"),
                    "sha1": vt_attributes.get("sha1"),
                    "sha256": vt_attributes.get("sha256"),
                    "ssdeep_from_vt": vt_attributes.get("ssdeep"),
                },
                "detection_stats": vt_attributes.get("last_analysis_stats"),
                "last_analysis_date_utc": datetime.datetime.fromtimestamp(vt_attributes.get("last_analysis_date"), datetime.timezone.utc).isoformat() if vt_attributes.get("last_analysis_date") else None,
                "first_submission_date_utc": datetime.datetime.fromtimestamp(vt_attributes.get("first_submission_date"), datetime.timezone.utc).isoformat() if vt_attributes.get("first_submission_date") else None,
                "last_submission_date_utc": datetime.datetime.fromtimestamp(vt_attributes.get("last_submission_date"), datetime.timezone.utc).isoformat() if vt_attributes.get("last_submission_date") else None,
                "reputation": vt_attributes.get("reputation"),
                "tags": vt_attributes.get("tags", []),
                "suggested_threat_label": vt_attributes.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "trid": vt_attributes.get("trid", []),
                "meaningful_name": vt_attributes.get("meaningful_name"),
                "names": list(set(vt_attributes.get("names", [])))[:10],
                "size": vt_attributes.get("size"),
            }
            response_payload["status"] = "success"
            response_payload["message"] = "VirusTotal report summary retrieved successfully."
            response_payload["virustotal_report_summary"] = vt_data_summary
            await ctx.info(f"Successfully retrieved VirusTotal report for {main_hash_value}")

        elif http_response.status_code == 404:
            response_payload["status"] = "not_found"
            response_payload["message"] = f"Hash {main_hash_value} not found on VirusTotal."
            await ctx.info(f"Hash {main_hash_value} not found on VirusTotal.")
        elif http_response.status_code == 401:
            response_payload["status"] = "error_auth"
            response_payload["message"] = "VirusTotal API authentication failed. Check your VT_API_KEY."
            await ctx.error("VirusTotal API authentication failed (401).")
        elif http_response.status_code == 429:
            response_payload["status"] = "error_rate_limit"
            response_payload["message"] = "VirusTotal API rate limit exceeded. Please try again later."
            await ctx.warning("VirusTotal API rate limit exceeded (429).")
        else:
            response_payload["status"] = "error_api"
            response_payload["message"] = f"VirusTotal API returned an error. Status Code: {http_response.status_code}. Response: {http_response.text[:200]}"
            await ctx.error(f"VirusTotal API error for {main_hash_value}: {http_response.status_code} - {http_response.text[:200]}")

    except requests.exceptions.Timeout:
        response_payload["status"] = "error_timeout"
        response_payload["message"] = "Request to VirusTotal API timed out."
        await ctx.error(f"VirusTotal API request timed out for hash {main_hash_value}.")
    except requests.exceptions.RequestException as e_req:
        response_payload["status"] = "error_request"
        response_payload["message"] = f"Error during VirusTotal API request: {str(e_req)}"
        await ctx.error(f"VirusTotal API request error for {main_hash_value}: {e_req}")
    except Exception as e:
        response_payload["status"] = "error_unexpected"
        response_payload["message"] = f"An unexpected error occurred while fetching VirusTotal data: {str(e)}"
        logger.error(f"MCP: Unexpected error in {tool_name} for {main_hash_value}: {e}", exc_info=True)
        await ctx.error(f"Unexpected error in {tool_name}: {e}")

    limit_info_str = "parameters for this tool (none currently, rely on server-side summarization)"
    return await _check_mcp_response_size(ctx, response_payload, tool_name, limit_info_str)


@tool_decorator
async def get_hex_dump(ctx: Context, start_offset: int, length: int, bytes_per_line: Optional[int]=16, limit_lines: Optional[int]=256) -> List[str]:
    """
    Retrieves a hex dump of a specified region from the pre-loaded PE file.
    'limit_lines' controls the number of lines in the output.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        start_offset: (int) The starting offset (0-based) in the file from which to begin the hex dump.
        length: (int) The number of bytes to include in the hex dump. Must be positive.
        bytes_per_line: (Optional[int]) The number of bytes to display per line. Defaults to 16. Must be positive.
        limit_lines: (Optional[int]) The maximum number of lines to return. Defaults to 256. Must be positive.

    Returns:
        A list of strings, where each string is a formatted line of the hex dump.
    Raises:
        RuntimeError: If no PE file is currently loaded or a hex dump error occurs.
        ValueError: If inputs are invalid, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Hex dump requested: Offset {hex(start_offset)}, Length {length}, Bytes/Line {bytes_per_line}, Limit Lines {limit_lines}")
    if state.pe_object is None or not hasattr(state.pe_object, '__data__'):
        raise RuntimeError(
            "No PE file loaded or PE data unavailable. "
            "The server must be started with --input-file to pre-load a file. "
            "If a file was provided, check the server logs for load errors."
        )
    if not isinstance(start_offset,int)or start_offset<0:raise ValueError("start_offset must be a non-negative integer.")
    if not isinstance(length,int)or length<=0:raise ValueError("length must be a positive integer.")

    bpl = 16
    if bytes_per_line is not None:
        if isinstance(bytes_per_line, int) and bytes_per_line > 0: bpl = bytes_per_line
        else: raise ValueError("bytes_per_line must be a positive integer.")

    ll = 256
    if limit_lines is not None:
        if isinstance(limit_lines, int) and limit_lines > 0: ll = limit_lines
        else: raise ValueError("limit_lines must be a positive integer.")

    try:
        file_data=state.pe_object.__data__
        if start_offset>=len(file_data):
            # This case results in an empty list or error message, which is small.
            return ["Error: Start offset is beyond the file size."]
        actual_len=min(length,len(file_data)-start_offset)
        if actual_len<=0:
            # This case results in an empty list or error message, which is small.
            return["Error: Calculated length for hex dump is zero or negative (start_offset might be at or past EOF)."]

        data_chunk=file_data[start_offset:start_offset+actual_len]
        hex_lines=await asyncio.to_thread(_format_hex_dump_lines,data_chunk,start_offset,bpl)

        data_to_send = hex_lines[:ll]
        limit_info_str = "parameters like 'length' or 'limit_lines'"
        return await _check_mcp_response_size(ctx, data_to_send, "get_hex_dump", limit_info_str)
    except Exception as e:await ctx.error(f"Hex dump error: {e}");raise RuntimeError(f"Failed during hex dump generation: {e}")from e

@tool_decorator
async def deobfuscate_base64(ctx: Context, hex_string: str) -> Optional[str]:
    """
    Deobfuscates a hex-encoded string that is presumed to represent Base64 encoded data.
    The input 'hex_string' should be the hexadecimal representation of a Base64 string.
    Example: If original data is "test", its Base64 is "dGVzdA==", and the hex of "dGVzdA==" is "6447567a64413d3d".
             This function expects "6447567a64413d3d" as input.

    Args:
        ctx: The MCP Context object.
        hex_string: (str) The hex-encoded string of the Base64 data.

    Returns:
        (Optional[str]) The deobfuscated string (UTF-8 decoded, errors ignored).
        Returns None if deobfuscation fails (e.g., invalid hex, not valid Base64).
    Raises:
        ValueError: If the response size exceeds the server limit.
    """
    await ctx.info(f"Attempting to deobfuscate Base64 from hex string: {hex_string[:60]}...")
    try:
        base64_encoded_bytes = bytes.fromhex(hex_string)
        decoded_payload_bytes = codecs.decode(base64_encoded_bytes, 'base64') # pyright: ignore [reportUnknownMemberType]
        result = decoded_payload_bytes.decode('utf-8', 'ignore')
        await ctx.info("Base64 deobfuscation successful.")

        limit_info_str = "a shorter 'hex_string' if the decoded content is too large (this tool has no direct data limiting parameters)"
        # Note: `result` can be None if decoding fails in a way that doesn't raise an exception but returns None (though unlikely for base64)
        # The _check_mcp_response_size helper handles `None` by attempting to JSON serialize it, which is fine.
        return await _check_mcp_response_size(ctx, result, "deobfuscate_base64", limit_info_str)

    except ValueError as e: # Handles bytes.fromhex error or other ValueErrors
        await ctx.error(f"Invalid hex string or Base64 content for deobfuscation: {str(e)}")
        logger.warning(f"MCP: Invalid hex/Base64 for deobfuscation: {hex_string[:60]}... - {str(e)}")
        return None # Return None on decoding failure before size check
    except Exception as e: # Catch other errors like binascii.Error from codecs.decode
        await ctx.error(f"Base64 deobfuscation error: {str(e)}")
        logger.error(f"MCP: Base64 deobfuscation error for {hex_string[:60]}... - {str(e)}", exc_info=True)
        return None # Return None on decoding failure

@tool_decorator
async def deobfuscate_xor_single_byte(ctx: Context, data_hex: str, key: int) -> Dict[str, Optional[str]]:
    """
    Deobfuscates a hex-encoded data string using a single-byte XOR key.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) The hex-encoded data string to be XORed.
        key: (int) The single byte (0-255) to use as the XOR key.

    Returns:
        A dictionary containing:
        - "deobfuscated_hex": (str) The hex representation of the XORed data.
        - "deobfuscated_printable_string": (Optional[str]) A printable representation of the XORed data
          (UTF-8 or Latin-1 decoded if possible, otherwise dot-replaced non-printables).
          Can be None if an error occurs during string representation.

    Raises:
        ValueError: If `key` is not between 0-255 or `data_hex` is not valid hex, or if the response size exceeds the server limit.
        RuntimeError: For other deobfuscation errors.
    """
    await ctx.info(f"Attempting to deobfuscate hex data '{data_hex[:60]}...' with XOR key: {key:#04x} ({key})")
    if not (0 <= key <= 255):
        await ctx.error(f"XOR key must be an integer between 0 and 255. Received: {key}")
        logger.warning(f"MCP: Invalid XOR key {key} requested.")
        raise ValueError("XOR key must be an integer between 0 and 255.")

    try:
        data_bytes = bytes.fromhex(data_hex)
        deobfuscated_bytes = bytes([b ^ key for b in data_bytes])
        deobfuscated_hex_output = deobfuscated_bytes.hex()

        printable_representation = None
        try:
            try: printable_representation = deobfuscated_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try: printable_representation = deobfuscated_bytes.decode('latin-1')
                except UnicodeDecodeError: printable_representation = "".join(chr(b) if 32 <= b <= 126 or b in [9,10,13] else '.' for b in deobfuscated_bytes)
        except Exception as e_decode:
            logger.warning(f"MCP: Error creating printable string for XOR result (key {key}): {e_decode}")
            printable_representation = "[Error creating printable string]"

        await ctx.info("XOR deobfuscation successful.")
        data_to_send = {
            "deobfuscated_hex": deobfuscated_hex_output,
            "deobfuscated_printable_string": printable_representation
        }
        limit_info_str = "a shorter 'data_hex' if the decoded content is too large (this tool has no direct data limiting parameters)"
        return await _check_mcp_response_size(ctx, data_to_send, "deobfuscate_xor_single_byte", limit_info_str)

    except ValueError as e_val: # Handles bytes.fromhex error
        await ctx.error(f"Invalid hex string provided for data_hex in XOR deobfuscation: {str(e_val)}")
        logger.warning(f"MCP: Invalid hex string for XOR data_hex: {data_hex[:60]}... - {str(e_val)}")
        raise # Re-raise to be handled by MCP framework
    except Exception as e_gen:
        await ctx.error(f"XOR deobfuscation error: {str(e_gen)}")
        logger.error(f"MCP: XOR deobfuscation error for data_hex {data_hex[:60]}..., key {key} - {str(e_gen)}", exc_info=True)
        raise RuntimeError(f"XOR deobfuscation failed: {str(e_gen)}") from e_gen

@tool_decorator
async def is_mostly_printable_ascii(ctx: Context, text_input: str, threshold: float = 0.8) -> bool:
    """
    Checks if the given string 'text_input' consists mostly of printable ASCII characters.
    Printable includes standard ASCII (space to '~') and common whitespace (newline, tab, carriage return).

    Args:
        ctx: The MCP Context object.
        text_input: (str) The string to check.
        threshold: (float) The minimum ratio (0.0 to 1.0) of printable characters to total characters
                   for the string to be considered "mostly printable". Defaults to 0.8 (80%).

    Returns:
        (bool) True if the ratio of printable ASCII characters meets or exceeds the threshold, False otherwise.
               Returns False for an empty input string.

    Raises:
        ValueError: If `threshold` is not between 0.0 and 1.0.
    """
    await ctx.info(f"Checking if string is mostly printable ASCII. Threshold: {threshold}, String length: {len(text_input)}")
    if not text_input:
        await ctx.info("Input string for printable check is empty, returning False.")
        return False

    if not (0.0 <= threshold <= 1.0):
        await ctx.error(f"Threshold for printable check must be between 0.0 and 1.0. Received: {threshold}")
        logger.warning(f"MCP: Invalid threshold {threshold} for printable check.")
        raise ValueError("Threshold must be between 0.0 and 1.0.")

    printable_char_in_string_count = sum(1 for char_in_s in text_input
                                         if (' ' <= char_in_s <= '~') or char_in_s in '\n\r\t')

    ratio = printable_char_in_string_count / len(text_input)
    result = ratio >= threshold
    await ctx.info(f"Printable character ratio: {ratio:.2f}. Result: {result}")
    return result

# --- Helper for find_and_decode_encoded_strings ---
def _is_mostly_printable_ascii_sync(text_input: str, threshold: float = 0.8) -> bool:
    """
    Synchronous helper to check if a string consists mostly of printable ASCII characters.
    Printable includes standard ASCII (space to '~') and common whitespace (newline, tab, carriage return).
    """
    if not text_input:
        return False # Empty string is not considered printable for this purpose

    printable_char_in_string_count = sum(1 for char_in_s in text_input
                                         if (' ' <= char_in_s <= '~') or char_in_s in '\n\r\t')

    if not text_input: return False # Should be caught by the first check, but defensive.

    ratio = printable_char_in_string_count / len(text_input)
    return ratio >= threshold

@tool_decorator
async def find_and_decode_encoded_strings(
    ctx: Context,
    limit: int,
    rank_with_sifter: bool = False,
    min_sifter_score: Optional[float] = None,
    min_confidence: float = 0.6,
    min_candidate_len_b64: int = 20,
    min_candidate_len_b32: int = 24,
    min_candidate_len_hex: int = 8,
    min_candidate_len_url: int = 3,
    min_decoded_printable_length: int = 4,
    printable_threshold: float = 0.8,
    max_decode_layers: int = 3,
    decoded_regex_patterns: Optional[List[str]] = None,
    verbose_mcp_output: bool = False
) -> List[Dict[str, Any]]:
    """
    Finds, decodes (recursively), and optionally ranks encoded strings with heuristics.

    This enhanced tool implements multi-layer decoding, adds a confidence score based
    on the location of the string, and includes a single-byte XOR bruteforce decoder.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. Maximum number of decoded results to return.
        rank_with_sifter: (bool) If True, rank the successfully decoded strings.
        min_sifter_score: (Optional[float]) If ranking, only include strings with a score >= this value.
        min_confidence: (float) Minimum confidence score (0.0-1.0) for a result to be included. Based on heuristics like PE section. Defaults to 0.6.
        min_candidate_len_b64: (int) Minimum length of a potential Base64 sequence.
        min_candidate_len_b32: (int) Minimum length of a potential Base32 sequence.
        min_candidate_len_hex: (int) Minimum length of a potential Hex sequence.
        min_candidate_len_url: (int) Minimum length of a potential URL-encoded sequence.
        min_decoded_printable_length: (int) Minimum length of a successfully decoded string.
        printable_threshold: (float) Ratio (0.0-1.0) of printable chars for decoded data.
        max_decode_layers: (int) The maximum number of encoding layers to decode. Defaults to 3.
        decoded_regex_patterns: (Optional[List[str]]) Regex patterns to search within decoded strings.
        verbose_mcp_output: (bool) Enables more detailed server-side logging.

    Returns:
        A list of dictionaries, each representing a successfully decoded and filtered string.
    """
    await ctx.info(f"Request to find/decode strings. Limit: {limit}, Max Layers: {max_decode_layers}, Min Confidence: {min_confidence}")

    # --- Parameter Validation ---
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    if rank_with_sifter and not STRINGSIFTER_AVAILABLE:
        raise RuntimeError("Ranking is requested, but StringSifter is not available on the server.")
    if not (0.0 <= min_confidence <= 1.0):
        raise ValueError("Parameter 'min_confidence' must be between 0.0 and 1.0.")
    if not (isinstance(max_decode_layers, int) and 1 <= max_decode_layers <= 10):
        raise ValueError("Parameter 'max_decode_layers' must be an integer between 1 and 10.")

    # --- Setup ---
    if state.pe_object is None or not hasattr(state.pe_object, '__data__'):
        raise RuntimeError("No PE file loaded or PE data unavailable.")

    pe = state.pe_object
    file_data = pe.__data__
    found_decoded_strings = []

    base64_pattern = re.compile(rb"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)")
    hex_pattern = re.compile(rb"(?:[0-9a-fA-F]{2}){4,}") # Require at least 4 hex pairs

    initial_candidates = []
    for pat, min_len in [(base64_pattern, min_candidate_len_b64), (hex_pattern, min_candidate_len_hex)]:
        for match in pat.finditer(file_data):
            if len(match.group(0)) >= min_len:
                initial_candidates.append(match)

    decoding_attempts = [
        ("base64", lambda b: codecs.decode(b, 'base64')),
        ("hex", lambda b: bytes.fromhex(b.decode('ascii'))),
    ]
    for match in initial_candidates:
        if len(found_decoded_strings) >= limit: break

        original_encoded_bytes = match.group(0)
        start_offset = match.start()

        # --- HEURISTIC: Calculate confidence based on section ---
        confidence = 0.5 # Default low confidence
        try:
            section = pe.get_section_by_offset(start_offset)
            if section:
                sec_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                if '.data' in sec_name or '.rdata' in sec_name:
                    confidence = 1.0 # High confidence for data sections
                elif '.text' not in sec_name:
                    confidence = 0.8 # Medium confidence for other non-code sections
        except Exception:
            pass # Keep default confidence if section lookup fails

        if confidence < min_confidence:
            continue

        # --- MULTI-LAYER DECODING ---
        current_bytes = original_encoded_bytes
        encoding_layers = []
        final_decoded_text = None

        for _ in range(max_decode_layers):
            decoded_this_layer = False
            # Try standard decoders first
            for enc_name, dec_func in decoding_attempts:
                try:
                    decoded_bytes = await asyncio.to_thread(dec_func, current_bytes)
                    if decoded_bytes and decoded_bytes != current_bytes:
                        encoding_layers.append(enc_name)
                        current_bytes = decoded_bytes
                        decoded_this_layer = True
                        break
                except Exception:
                    continue

            # If standard decoders found something, check if the result is printable
            if decoded_this_layer:
                try:
                    text_candidate = current_bytes.decode('utf-8', 'ignore')
                    if _is_mostly_printable_ascii_sync(text_candidate, printable_threshold):
                        final_decoded_text = text_candidate
                        break # Found final printable payload
                except Exception:
                    pass # Not printable, continue to next layer or XOR

            # If standard decoders failed OR result wasn't printable, try XOR
            if not final_decoded_text:
                xor_result = await asyncio.to_thread(_decode_single_byte_xor, current_bytes)
                if xor_result:
                    decoded_bytes, key = xor_result
                    encoding_layers.append(f"xor(0x{key:02x})")
                    current_bytes = decoded_bytes
                    final_decoded_text = current_bytes.decode('utf-8', 'ignore')
                    break # Assume XOR result is final payload

            if not decoded_this_layer:
                break # No decoders worked on this layer, stop

        # --- Final filtering and result creation ---
        if final_decoded_text and len(final_decoded_text) >= min_decoded_printable_length:
            if decoded_regex_patterns:
                try:
                    if not any(re.search(p, final_decoded_text) for p in decoded_regex_patterns):
                        continue
                except re.error:
                    await ctx.warning("An invalid regex was skipped during search.")
                    continue

            snippet_start = max(0, start_offset - 16)
            snippet_end = min(len(file_data), match.end() + 16)

            found_decoded_strings.append({
                "original_match_offset": hex(start_offset),
                "encoded_substring_repr": original_encoded_bytes.decode('ascii', 'replace')[:200],
                "encoding_layers": encoding_layers,
                "decoded_string": final_decoded_text,
                "confidence": round(confidence, 2),
                "context_snippet_hex": file_data[snippet_start:snippet_end].hex()
            })

    # --- Final Ranking, Filtering and Return ---
    final_results = found_decoded_strings
    if rank_with_sifter and final_results:
        string_values = [res["decoded_string"] for res in final_results]
        if string_values:
            modeldir = os.path.join(sifter_util.package_base(), "model")
            featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
            ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))
            X_test = await asyncio.to_thread(featurizer.transform, string_values)
            y_scores = await asyncio.to_thread(ranker.predict, X_test)

            for i, res_dict in enumerate(final_results):
                res_dict['sifter_score'] = round(float(y_scores[i]), 4)

        if min_sifter_score is not None:
            final_results = [res for res in final_results if res.get('sifter_score', -999.0) >= min_sifter_score]

        final_results.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=True)

    return await _check_mcp_response_size(ctx, final_results[:limit], "find_and_decode_encoded_strings", "the 'limit' parameter or by adjusting filters")

@tool_decorator
async def get_triage_report(
    ctx: Context,
    sifter_score_threshold: float = 8.0,
    indicator_limit: int = 15
) -> Dict[str, Any]:
    """
    Runs an automated triage workflow to find the most suspicious indicators
    and behaviors in the analyzed file, returning a condensed summary.

    Args:
        ctx: The MCP Context object.
        sifter_score_threshold: (float) The minimum sifter score for a string to be considered a high-value indicator.
        indicator_limit: (int) The max number of items to return for each category in the report.

    Returns:
        A dictionary summarizing the most critical findings.
    """
    await ctx.info(f"Generating automated triage report...")

    _check_pe_loaded("get_triage_report")

    triage_report = {
        "HighValueIndicators": [],
        "SuspiciousCapabilities": [],
        "SuspiciousImports": [],
        # "SignatureAndPacker": state.pe_data.get('peid_matches', {}), # Optional inclusion
    }

    # --- 1. Find High-Value String Indicators ---
    all_strings = []
    # Collect strings from FLOSS results safely
    if 'floss_analysis' in state.pe_data and isinstance(state.pe_data['floss_analysis'], dict):
        floss_strings = state.pe_data['floss_analysis'].get('strings')
        if isinstance(floss_strings, dict):
            for str_list in floss_strings.values():
                if isinstance(str_list, list):
                    all_strings.extend(str_list)

    # Collect strings from Basic ASCII
    basic_strings = state.pe_data.get('basic_ascii_strings')
    if isinstance(basic_strings, list):
        all_strings.extend(basic_strings)

    # Filter high-value strings
    high_value_strings = []
    for s in all_strings:
        if isinstance(s, dict) and s.get('sifter_score', 0.0) >= sifter_score_threshold:
            # Only include if it has a category (e.g. IP, URL) or is very highly ranked
            if s.get('category') or s.get('sifter_score', 0.0) >= 9.0:
                high_value_strings.append(s)

    # Deduplicate and sort
    # Use string value as unique key
    unique_indicators = {s['string']: s for s in high_value_strings}
    sorted_indicators = sorted(unique_indicators.values(), key=lambda x: x.get('sifter_score', 0.0), reverse=True)
    triage_report["HighValueIndicators"] = sorted_indicators[:indicator_limit]

    # --- 2. Find High-Severity Capa Capabilities ---
    CAPA_SEVERITY_MAP = {
        # High severity namespaces
        "anti-analysis": "High",
        "collection": "High",
        "credential-access": "High",
        "defense-evasion": "High",
        "execution": "High",
        "impact": "High",
        "persistence": "High",
        "privilege-escalation": "High",
        "caching": "High",
        # Medium severity
        "bootloader": "Medium",
        "communication": "Medium",
        "data-manipulation": "Medium",
        "discovery": "Medium",
    }

    # BUG FIX: Added safe checks for 'results' being None
    if 'capa_analysis' in state.pe_data:
        capa_analysis = state.pe_data['capa_analysis']
        # Ensure results exist and are a dictionary
        if isinstance(capa_analysis.get('results'), dict):
            capa_rules = capa_analysis['results'].get('rules', {})

            for rule_name, rule_details in capa_rules.items():
                meta = rule_details.get('meta', {})
                namespace = meta.get('namespace', '').split('/')[0]
                severity = CAPA_SEVERITY_MAP.get(namespace, "Low")

                if severity in ["High", "Medium"]:
                    triage_report["SuspiciousCapabilities"].append({
                        "capability": meta.get('name', rule_name),
                        "namespace": meta.get('namespace'),
                        "severity": severity
                    })

            triage_report["SuspiciousCapabilities"].sort(key=lambda x: x['severity'], reverse=True)
            triage_report["SuspiciousCapabilities"] = triage_report["SuspiciousCapabilities"][:indicator_limit]

    # --- 3. Find Suspicious Imports ---
    SUSPICIOUS_IMPORTS = {
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 'ShellExecute',
        'LdrLoadDll', 'IsDebuggerPresent', 'URLDownloadToFile', 'InternetOpen',
        'HttpSendRequest', 'RegSetValueEx', 'AdjustTokenPrivileges'
    }

    if 'imports' in state.pe_data and isinstance(state.pe_data['imports'], list):
        for dll_entry in state.pe_data['imports']:
            dll_name = dll_entry.get('dll_name', 'Unknown')
            for sym in dll_entry.get('symbols', []):
                func_name = sym.get('name')
                if func_name and any(susp in func_name for susp in SUSPICIOUS_IMPORTS):
                    triage_report["SuspiciousImports"].append({
                        "function": func_name,
                        "dll": dll_name,
                        "address": sym.get('address')
                    })

    triage_report["SuspiciousImports"] = triage_report["SuspiciousImports"][:indicator_limit]

    return await _check_mcp_response_size(ctx, triage_report, "get_triage_report", "This tool has no size-limiting parameters.")

@tool_decorator
async def get_current_datetime(ctx: Context) -> Dict[str,str]:
    """
    Retrieves the current date and time in UTC and the server's local timezone.
    This tool does not depend on a PE file being loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing:
        - "utc_datetime": (str) Current UTC date and time in ISO 8601 format.
        - "local_datetime": (str) Current local date and time in ISO 8601 format (includes timezone offset).
        - "local_timezone_name": (str) Name of the server's local timezone.
    """
    await ctx.info("Request for current datetime.")
    now_utc=datetime.datetime.now(datetime.timezone.utc);now_local=datetime.datetime.now().astimezone()
    return{"utc_datetime":now_utc.isoformat(),"local_datetime":now_local.isoformat(),"local_timezone_name":str(now_local.tzinfo)}

@tool_decorator
async def check_task_status(ctx: Context, task_id: str) -> Dict[str, Any]:
    """
    Checks the status and progress of a background analysis task.

    Args:
        task_id: The ID returned by a tool running in background mode.
    """
    # await ctx.info(f"Checking status for task: {task_id}") # Optional: Comment out to reduce noise

    task = state.get_task(task_id)
    if not task:
        return {"error": f"Task ID '{task_id}' not found.", "available_task_ids": state.get_all_task_ids()}

    response = {
        "task_id": task_id,
        "status": task["status"],
        "progress_percent": task.get("progress_percent", 0),
        "progress_message": task.get("progress_message", "Initializing..."),
        "created_at": task.get("created_at", "unknown"),
        "tool": task.get("tool", "unknown")
    }

    if task["status"] == "completed":
        result_data = task.get("result")
        full_response = {**response, "result": result_data}
        return await _check_mcp_response_size(ctx, full_response, f"check_task_status_{task_id}")

    elif task["status"] == "failed":
        response["error"] = task.get("error", "Unknown error")

    elif task["status"] == "running":
        response["hint"] = "Task is still processing. Poll again shortly with check_task_status."

    return response
