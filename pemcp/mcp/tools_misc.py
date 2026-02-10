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
    state, logger, Context, analysis_cache,
    REQUESTS_AVAILABLE, VT_API_URL_FILE_REPORT,
    ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE,
    STRINGSIFTER_AVAILABLE, YARA_AVAILABLE,
)
from pemcp.user_config import get_config_value, set_config_value, get_masked_config
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


    # Read API key at runtime (supports set_api_key and env var changes)
    vt_api_key = get_config_value("vt_api_key")

    if not vt_api_key:
        await ctx.warning("VirusTotal API key is not configured. Set it with set_api_key('vt_api_key', '<your-key>') or the VT_API_KEY environment variable.")
        return await _check_mcp_response_size(ctx, {
            "status": "api_key_missing",
            "message": "VirusTotal API key is not configured. Use the set_api_key tool or set the VT_API_KEY environment variable.",
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

    headers = {"x-apikey": vt_api_key}
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

# ===================================================================
#  Suspicious Import Database (risk-categorized)
# ===================================================================

SUSPICIOUS_IMPORTS_DB = {
    # CRITICAL — Process injection / code execution
    "CreateRemoteThread": "CRITICAL", "NtCreateThreadEx": "CRITICAL",
    "RtlCreateUserThread": "CRITICAL", "WriteProcessMemory": "CRITICAL",
    "NtWriteVirtualMemory": "CRITICAL", "VirtualAllocEx": "CRITICAL",
    "NtAllocateVirtualMemory": "CRITICAL", "QueueUserAPC": "CRITICAL",
    "NtQueueApcThread": "CRITICAL", "SetWindowsHookEx": "CRITICAL",
    "NtMapViewOfSection": "CRITICAL", "NtUnmapViewOfSection": "CRITICAL",
    "ZwMapViewOfSection": "CRITICAL",
    # CRITICAL — Credential theft / privilege escalation
    "MiniDumpWriteDump": "CRITICAL", "LsaEnumerateLogonSessions": "CRITICAL",
    "AdjustTokenPrivileges": "CRITICAL", "ImpersonateLoggedOnUser": "CRITICAL",
    "OpenProcessToken": "CRITICAL", "DuplicateToken": "CRITICAL",
    "LdrLoadDll": "CRITICAL",
    # HIGH — Anti-analysis / evasion
    "IsDebuggerPresent": "HIGH", "CheckRemoteDebuggerPresent": "HIGH",
    "NtQueryInformationProcess": "HIGH", "OutputDebugString": "HIGH",
    "GetTickCount": "HIGH", "QueryPerformanceCounter": "HIGH",
    "NtSetInformationThread": "HIGH",
    # HIGH — Networking (C2 potential)
    "InternetOpen": "HIGH", "InternetConnect": "HIGH",
    "HttpOpenRequest": "HIGH", "HttpSendRequest": "HIGH",
    "URLDownloadToFile": "HIGH", "URLDownloadToCacheFile": "HIGH",
    "WinHttpOpen": "HIGH", "WinHttpConnect": "HIGH",
    # HIGH — Process/service manipulation
    "OpenProcess": "HIGH", "TerminateProcess": "HIGH",
    "CreateService": "HIGH", "StartService": "HIGH",
    "ShellExecute": "HIGH", "WinExec": "HIGH",
    "CreateProcess": "HIGH",
    # MEDIUM — Registry / persistence
    "RegSetValueEx": "MEDIUM", "RegCreateKeyEx": "MEDIUM",
    "RegDeleteKey": "MEDIUM", "RegDeleteValue": "MEDIUM",
    # MEDIUM — Crypto (ransomware indicators)
    "CryptEncrypt": "MEDIUM", "CryptDecrypt": "MEDIUM",
    "CryptAcquireContext": "MEDIUM", "BCryptEncrypt": "MEDIUM",
    "CryptDeriveKey": "MEDIUM", "CryptGenKey": "MEDIUM",
    # MEDIUM — File operations (dropper indicators)
    "CreateFileMapping": "MEDIUM", "MapViewOfFile": "MEDIUM",
    "VirtualProtect": "MEDIUM", "SetFileAttributes": "MEDIUM",
    # MEDIUM — Socket-level networking
    "WSAStartup": "MEDIUM", "connect": "MEDIUM",
    "send": "MEDIUM", "recv": "MEDIUM", "socket": "MEDIUM",
    "bind": "MEDIUM", "listen": "MEDIUM", "accept": "MEDIUM",
}


@tool_decorator
async def get_triage_report(
    ctx: Context,
    sifter_score_threshold: float = 8.0,
    indicator_limit: int = 20
) -> Dict[str, Any]:
    """
    Comprehensive automated triage of the loaded binary. Works across PE, ELF,
    Mach-O, and shellcode formats with format-specific analysis sections.

    Analyses entropy, packing indicators, digital signatures, suspicious imports
    (risk-categorized), capa capabilities, network IOCs, section anomalies,
    timestamp anomalies, Rich header, overlay/appended data, resource anomalies,
    import anomalies, YARA matches, header corruption, and platform-specific
    security features (ELF: PIE/NX/RELRO/canaries, Mach-O: code signing/PIE).

    Designed to give an AI analyst a complete first-look assessment without needing
    to call multiple individual tools.

    Args:
        ctx: The MCP Context object.
        sifter_score_threshold: (float) Min sifter score for high-value string indicators.
        indicator_limit: (int) Max items per category in the report.

    Returns:
        A comprehensive triage dictionary with sections:
        - file_info: path, hashes, mode, file size
        - timestamp_analysis: compilation timestamp anomalies (PE)
        - packing_assessment: entropy, PEiD, import count analysis
        - digital_signature: signing status and signer info
        - rich_header_summary: build environment fingerprint (PE)
        - suspicious_imports: risk-categorized API imports
        - import_anomalies: ordinal-only imports, non-standard DLLs
        - suspicious_capabilities: capa MITRE ATT&CK matches
        - network_iocs: IPs, URLs, domains, registry paths
        - section_anomalies: W+X, size mismatches
        - overlay_analysis: appended data with embedded signature detection
        - resource_anomalies: nested PEs, large RCDATA payloads
        - yara_matches: matched YARA rules
        - header_anomalies: pefile warnings, checksum, entry point issues
        - high_value_strings: ML-ranked high-value strings
        - elf_security: PIE, NX, RELRO, stack canaries, stripped status (ELF)
        - macho_security: PIE, code signing, entitlements (Mach-O)
        - risk_score / risk_level: cumulative risk assessment
        - suggested_next_tools: format-aware recommended next analysis steps
    """
    import math

    await ctx.info("Generating comprehensive triage report...")

    _check_pe_loaded("get_triage_report")

    risk_score = 0  # Cumulative risk score (higher = more suspicious)

    triage_report: Dict[str, Any] = {
        "file_info": {},
        "timestamp_analysis": {},
        "packing_assessment": {},
        "digital_signature": {},
        "rich_header_summary": {},
        "suspicious_imports": [],
        "import_anomalies": {},
        "suspicious_capabilities": [],
        "network_iocs": {},
        "section_anomalies": [],
        "overlay_analysis": {},
        "resource_anomalies": [],
        "yara_matches": [],
        "header_anomalies": [],
        "high_value_strings": [],
        "elf_security": {},
        "macho_security": {},
        "risk_score": 0,
        "risk_level": "UNKNOWN",
        "suggested_next_tools": [],
    }

    # ===================================================================
    # 0. Basic file info
    # ===================================================================
    file_hashes = state.pe_data.get('file_hashes', {})
    analysis_mode = state.pe_data.get('mode', 'pe')
    file_size = 0
    try:
        if state.filepath and os.path.isfile(state.filepath):
            file_size = os.path.getsize(state.filepath)
    except Exception:
        pass

    triage_report["file_info"] = {
        "filepath": state.filepath,
        "md5": file_hashes.get('md5'),
        "sha256": file_hashes.get('sha256'),
        "mode": analysis_mode,
        "file_size": file_size,
        "loaded_from_cache": state.loaded_from_cache,
    }

    # ===================================================================
    # 0a. Timestamp Anomaly Detection (PE only)
    # ===================================================================
    if analysis_mode == 'pe':
        ts_anomalies = []
        nt_headers = state.pe_data.get('nt_headers', {})
        file_header = nt_headers.get('file_header', {})
        # Extract raw TimeDateStamp value
        raw_ts = None
        for key in ('TimeDateStamp', 'timedatestamp'):
            candidate = file_header.get(key)
            if isinstance(candidate, dict):
                raw_ts = candidate.get('Value', candidate.get('value'))
            elif isinstance(candidate, (int, float)):
                raw_ts = candidate
            if raw_ts is not None:
                break

        ts_info: Dict[str, Any] = {"raw_timestamp": raw_ts}
        if raw_ts is not None and isinstance(raw_ts, (int, float)):
            try:
                compile_dt = datetime.datetime.utcfromtimestamp(int(raw_ts))
                ts_info["compile_date"] = compile_dt.isoformat() + "Z"
                now = datetime.datetime.utcnow()
                # Future timestamp
                if compile_dt > now:
                    ts_anomalies.append("Compilation timestamp is in the future")
                    risk_score += 2
                # Epoch zero (1970-01-01)
                if int(raw_ts) == 0:
                    ts_anomalies.append("Timestamp is epoch zero (zeroed/wiped)")
                    risk_score += 1
                # Very old (before Windows NT era, ~1993)
                elif compile_dt.year < 1993:
                    ts_anomalies.append(f"Timestamp predates Windows NT era ({compile_dt.year})")
                    risk_score += 1
                # Known fake timestamps used by Delphi
                elif int(raw_ts) == 0x2A425E19:
                    ts_anomalies.append("Delphi signature timestamp (0x2A425E19) — may be Delphi-compiled or spoofed")
                # Known Borland timestamp
                elif int(raw_ts) == 0x19610714:
                    ts_anomalies.append("Borland linker signature timestamp")
            except (OSError, ValueError, OverflowError):
                ts_anomalies.append("Timestamp value overflows or is unparseable")
                risk_score += 1

        # Check debug directory timestamps for mismatches
        debug_info = state.pe_data.get('debug_info', [])
        if isinstance(debug_info, list) and raw_ts is not None:
            for dbg_entry in debug_info:
                if isinstance(dbg_entry, dict):
                    dbg_ts = dbg_entry.get('TimeDateStamp', dbg_entry.get('timedatestamp'))
                    if isinstance(dbg_ts, dict):
                        dbg_ts = dbg_ts.get('Value', dbg_ts.get('value'))
                    if isinstance(dbg_ts, (int, float)) and dbg_ts != 0 and abs(int(dbg_ts) - int(raw_ts)) > 86400:
                        ts_anomalies.append("Debug directory timestamp differs from PE header by >24h (possible timestomping)")
                        risk_score += 2
                        break

        ts_info["anomalies"] = ts_anomalies
        triage_report["timestamp_analysis"] = ts_info
    else:
        triage_report["timestamp_analysis"] = {"note": f"Not applicable for {analysis_mode} mode"}

    # ===================================================================
    # 1. Packing Assessment (entropy + PEiD + import count + section names)
    # ===================================================================
    sections_data = state.pe_data.get('sections', [])
    peid_data = state.pe_data.get('peid_matches', {})
    imports_data = state.pe_data.get('imports', [])

    max_entropy = 0.0
    high_entropy_sections = []
    for sec in sections_data:
        if isinstance(sec, dict):
            ent = sec.get('entropy', 0.0)
            if isinstance(ent, (int, float)) and ent > max_entropy:
                max_entropy = ent
            name = sec.get('name', '')
            chars = sec.get('characteristics_str', sec.get('characteristics', ''))
            is_exec = 'EXECUTE' in str(chars).upper() or 'CODE' in str(chars).upper()
            if ent > 7.0 and is_exec:
                high_entropy_sections.append({"name": name, "entropy": round(ent, 3)})
                risk_score += 3
            elif ent > 7.0:
                high_entropy_sections.append({"name": name, "entropy": round(ent, 3)})
                risk_score += 1

    # Count total imported functions
    total_import_funcs = 0
    for dll_entry in imports_data:
        if isinstance(dll_entry, dict):
            total_import_funcs += len(dll_entry.get('symbols', []))

    # PEiD matches
    ep_matches = peid_data.get('ep_matches', [])
    heuristic_matches = peid_data.get('heuristic_matches', [])
    packer_names = [m.get('name', m.get('match', 'unknown')) for m in (ep_matches + heuristic_matches) if isinstance(m, dict)]
    if packer_names:
        risk_score += 4

    # Known packer section names
    PACKER_SECTION_NAMES = {'UPX0', 'UPX1', 'UPX2', '.aspack', '.adata', '.nsp0', '.nsp1',
                            '.perplex', '.themida', '.vmp0', '.vmp1', '.enigma1', '.petite'}
    suspicious_section_names = []
    for sec in sections_data:
        if isinstance(sec, dict):
            name = sec.get('name', '').strip()
            if name in PACKER_SECTION_NAMES:
                suspicious_section_names.append(name)
                risk_score += 3

    is_likely_packed = (
        bool(packer_names)
        or len(high_entropy_sections) > 0
        or total_import_funcs < 10
        or bool(suspicious_section_names)
    )

    triage_report["packing_assessment"] = {
        "likely_packed": is_likely_packed,
        "max_section_entropy": round(max_entropy, 3),
        "high_entropy_executable_sections": high_entropy_sections,
        "peid_matches": packer_names[:5],
        "total_import_functions": total_import_funcs,
        "minimal_imports": total_import_funcs < 10,
        "packer_section_names": suspicious_section_names,
    }

    # ===================================================================
    # 2. Digital Signature Assessment
    # ===================================================================
    sig_data = state.pe_data.get('digital_signature', {})
    sig_present = sig_data.get('embedded_signature_present', False) if isinstance(sig_data, dict) else False
    sig_valid = None
    sig_signer = None
    if isinstance(sig_data, dict):
        sig_valid = sig_data.get('validation_result')
        # Try to extract signer from various possible locations
        certs = sig_data.get('certificates', sig_data.get('signer_info', []))
        if isinstance(certs, list) and certs:
            first_cert = certs[0] if isinstance(certs[0], dict) else {}
            sig_signer = first_cert.get('subject', first_cert.get('signer'))

    if not sig_present:
        risk_score += 1  # Unsigned binaries are slightly more suspicious

    triage_report["digital_signature"] = {
        "present": sig_present,
        "valid": sig_valid,
        "signer": sig_signer,
    }

    # ===================================================================
    # 2a. Rich Header Summary (PE only — build environment fingerprint)
    # ===================================================================
    if analysis_mode == 'pe':
        rich_data = state.pe_data.get('rich_header')
        if rich_data and isinstance(rich_data, dict):
            entries = rich_data.get('decoded_entries', rich_data.get('entries', []))
            compiler_ids = set()
            product_names = set()
            for entry in (entries if isinstance(entries, list) else []):
                if isinstance(entry, dict):
                    comp_id = entry.get('comp_id', entry.get('CompID'))
                    prod = entry.get('product_name', entry.get('product', ''))
                    if comp_id is not None:
                        compiler_ids.add(comp_id)
                    if prod:
                        product_names.add(str(prod))
            triage_report["rich_header_summary"] = {
                "present": True,
                "entry_count": len(entries) if isinstance(entries, list) else 0,
                "unique_compiler_ids": len(compiler_ids),
                "products_used": sorted(product_names)[:10],
                "checksum_valid": rich_data.get('checksum_valid', rich_data.get('valid')),
                "raw_hash": rich_data.get('hash', rich_data.get('checksum')),
            }
            # Rich header checksum mismatch can indicate tampering
            if rich_data.get('checksum_valid') is False:
                risk_score += 1
                triage_report["rich_header_summary"]["anomaly"] = "Rich header checksum mismatch — possible tampering"
        else:
            triage_report["rich_header_summary"] = {"present": False, "note": "No Rich header (MinGW, Go, Rust, or stripped)"}
    else:
        triage_report["rich_header_summary"] = {"note": f"Not applicable for {analysis_mode} mode"}

    # ===================================================================
    # 3. Suspicious Imports (risk-categorized)
    # ===================================================================
    found_imports = []
    if isinstance(imports_data, list):
        for dll_entry in imports_data:
            if not isinstance(dll_entry, dict):
                continue
            dll_name = dll_entry.get('dll_name', 'Unknown')
            for sym in dll_entry.get('symbols', []):
                func_name = sym.get('name', '')
                if not func_name:
                    continue
                # Check against database (partial match for A/W suffix variants)
                for susp_name, severity in SUSPICIOUS_IMPORTS_DB.items():
                    if susp_name in func_name:
                        found_imports.append({
                            "function": func_name,
                            "dll": dll_name,
                            "risk": severity,
                        })
                        if severity == "CRITICAL":
                            risk_score += 3
                        elif severity == "HIGH":
                            risk_score += 2
                        elif severity == "MEDIUM":
                            risk_score += 1
                        break  # Only match highest severity per function

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    found_imports.sort(key=lambda x: severity_order.get(x['risk'], 3))
    triage_report["suspicious_imports"] = found_imports[:indicator_limit]
    triage_report["suspicious_import_summary"] = {
        "critical": sum(1 for i in found_imports if i['risk'] == 'CRITICAL'),
        "high": sum(1 for i in found_imports if i['risk'] == 'HIGH'),
        "medium": sum(1 for i in found_imports if i['risk'] == 'MEDIUM'),
    }

    # ===================================================================
    # 4. Capa Capabilities (severity-mapped)
    # ===================================================================
    CAPA_SEVERITY_MAP = {
        "anti-analysis": "High", "collection": "High",
        "credential-access": "High", "defense-evasion": "High",
        "execution": "High", "impact": "High",
        "persistence": "High", "privilege-escalation": "High",
        "lateral-movement": "High",
        "communication": "Medium", "data-manipulation": "Medium",
        "discovery": "Medium", "c2": "High",
    }

    if 'capa_analysis' in state.pe_data:
        capa_analysis = state.pe_data['capa_analysis']
        if isinstance(capa_analysis.get('results'), dict):
            capa_rules = capa_analysis['results'].get('rules', {})
            for rule_name, rule_details in capa_rules.items():
                meta = rule_details.get('meta', {})
                namespace = meta.get('namespace', '').split('/')[0]
                severity = CAPA_SEVERITY_MAP.get(namespace, "Low")
                if severity in ["High", "Medium"]:
                    triage_report["suspicious_capabilities"].append({
                        "capability": meta.get('name', rule_name),
                        "namespace": meta.get('namespace'),
                        "severity": severity,
                    })
                    if severity == "High":
                        risk_score += 2
                    else:
                        risk_score += 1

            triage_report["suspicious_capabilities"].sort(key=lambda x: x['severity'])
            triage_report["suspicious_capabilities"] = triage_report["suspicious_capabilities"][:indicator_limit]

    # ===================================================================
    # 5. Network IOC Extraction (IPs, URLs, domains from strings)
    # ===================================================================
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    url_pattern = re.compile(r'(?:https?|ftp)://[^\s\'"<>]+', re.IGNORECASE)
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|su|onion)\b', re.IGNORECASE)
    registry_pattern = re.compile(r'(?:HKLM|HKCU|HKCR|HKU|HKCC|Software)\\[^\s\'"]+', re.IGNORECASE)

    all_string_values = set()

    # Gather strings from all sources
    if 'floss_analysis' in state.pe_data and isinstance(state.pe_data['floss_analysis'], dict):
        floss_strings = state.pe_data['floss_analysis'].get('strings')
        if isinstance(floss_strings, dict):
            for str_list in floss_strings.values():
                if isinstance(str_list, list):
                    for s in str_list:
                        if isinstance(s, dict):
                            all_string_values.add(s.get('string', ''))
                        elif isinstance(s, str):
                            all_string_values.add(s)

    basic_strings = state.pe_data.get('basic_ascii_strings')
    if isinstance(basic_strings, list):
        for s in basic_strings:
            if isinstance(s, dict):
                all_string_values.add(s.get('string', ''))
            elif isinstance(s, str):
                all_string_values.add(s)

    all_text = '\n'.join(all_string_values)

    found_ips = set()
    for m in ip_pattern.finditer(all_text):
        ip = m.group()
        # Filter private/loopback/broadcast
        octets = ip.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            first = int(octets[0])
            if first not in (0, 10, 127, 255) and not (first == 192 and int(octets[1]) == 168) and not (first == 172 and 16 <= int(octets[1]) <= 31):
                found_ips.add(ip)

    found_urls = set()
    for m in url_pattern.finditer(all_text):
        found_urls.add(m.group())

    found_domains = set()
    for m in domain_pattern.finditer(all_text):
        found_domains.add(m.group().lower())

    found_registry = set()
    for m in registry_pattern.finditer(all_text):
        found_registry.add(m.group())

    if found_ips or found_urls or found_domains:
        risk_score += 3

    triage_report["network_iocs"] = {
        "ip_addresses": sorted(found_ips)[:indicator_limit],
        "urls": sorted(found_urls)[:indicator_limit],
        "domains": sorted(found_domains)[:indicator_limit],
        "registry_paths": sorted(found_registry)[:indicator_limit],
    }

    # ===================================================================
    # 6. Section Anomalies
    # ===================================================================
    anomalies = []
    for sec in sections_data:
        if not isinstance(sec, dict):
            continue
        name = sec.get('name', '').strip()
        chars = str(sec.get('characteristics_str', sec.get('characteristics', '')))
        vsize = sec.get('virtual_size', sec.get('Misc_VirtualSize', 0))
        rsize = sec.get('raw_size', sec.get('SizeOfRawData', 0))
        ent = sec.get('entropy', 0.0)

        if 'WRITE' in chars.upper() and 'EXECUTE' in chars.upper():
            anomalies.append({"section": name, "issue": "Write+Execute (W+X)", "severity": "HIGH"})
            risk_score += 2
        if isinstance(vsize, int) and isinstance(rsize, int) and vsize > 0 and rsize == 0:
            anomalies.append({"section": name, "issue": "Virtual size > 0 but raw size = 0 (runtime unpacking)", "severity": "MEDIUM"})
            risk_score += 1
        if isinstance(vsize, int) and isinstance(rsize, int) and rsize > 0 and vsize > rsize * 10:
            anomalies.append({"section": name, "issue": f"Virtual size ({vsize}) >> raw size ({rsize})", "severity": "MEDIUM"})
            risk_score += 1

    triage_report["section_anomalies"] = anomalies[:indicator_limit]

    # ===================================================================
    # 6a. Overlay / Appended Data Analysis (PE only)
    # ===================================================================
    if analysis_mode == 'pe':
        overlay_data = state.pe_data.get('overlay_data')
        if overlay_data and isinstance(overlay_data, dict):
            overlay_size = overlay_data.get('size', 0)
            overlay_offset = overlay_data.get('offset')
            overlay_info: Dict[str, Any] = {
                "present": True,
                "offset": overlay_offset,
                "size": overlay_size,
                "md5": overlay_data.get('md5'),
                "sha256": overlay_data.get('sha256'),
            }
            # Check if overlay is a large proportion of the file
            if file_size > 0 and overlay_size > 0:
                overlay_pct = round((overlay_size / file_size) * 100, 1)
                overlay_info["percent_of_file"] = overlay_pct
                if overlay_pct > 50:
                    overlay_info["note"] = "Overlay is >50% of file — likely contains appended data, resources, or embedded payload"
                    risk_score += 2

            # Check for embedded PE signatures in the overlay sample hex
            sample_hex = overlay_data.get('sample_hex', '')
            embedded_sigs = []
            if sample_hex:
                # MZ header
                if '4d5a' in sample_hex.lower()[:20]:
                    embedded_sigs.append("PE/MZ header detected at overlay start")
                    risk_score += 3
                # PK (ZIP) header
                if '504b0304' in sample_hex.lower()[:20]:
                    embedded_sigs.append("ZIP/PK archive detected at overlay start")
                # 7z header
                if '377abcaf271c' in sample_hex.lower()[:20]:
                    embedded_sigs.append("7-Zip archive detected at overlay start")
                # RAR header
                if '526172211a07' in sample_hex.lower()[:20]:
                    embedded_sigs.append("RAR archive detected at overlay start")
                # PDF header
                if '25504446' in sample_hex.lower()[:20]:
                    embedded_sigs.append("PDF document detected at overlay start")
            overlay_info["embedded_signatures"] = embedded_sigs
            triage_report["overlay_analysis"] = overlay_info
        else:
            triage_report["overlay_analysis"] = {"present": False}
    else:
        triage_report["overlay_analysis"] = {"note": f"Not applicable for {analysis_mode} mode"}

    # ===================================================================
    # 6b. Import Anomalies (ordinal-only imports, unusual DLLs)
    # ===================================================================
    if analysis_mode == 'pe' and isinstance(imports_data, list):
        ordinal_only_imports = []
        unusual_dll_imports = []
        COMMON_DLLS = {
            'kernel32.dll', 'ntdll.dll', 'user32.dll', 'advapi32.dll', 'gdi32.dll',
            'ole32.dll', 'oleaut32.dll', 'shell32.dll', 'shlwapi.dll', 'msvcrt.dll',
            'ws2_32.dll', 'wininet.dll', 'crypt32.dll', 'comctl32.dll', 'comdlg32.dll',
            'rpcrt4.dll', 'secur32.dll', 'winhttp.dll', 'urlmon.dll', 'version.dll',
            'imagehlp.dll', 'psapi.dll', 'iphlpapi.dll', 'setupapi.dll', 'winspool.drv',
            'mscoree.dll', 'msvcp140.dll', 'vcruntime140.dll', 'ucrtbase.dll',
            'api-ms-win-crt-runtime-l1-1-0.dll', 'api-ms-win-crt-heap-l1-1-0.dll',
            'api-ms-win-crt-stdio-l1-1-0.dll', 'api-ms-win-crt-string-l1-1-0.dll',
            'api-ms-win-crt-math-l1-1-0.dll', 'api-ms-win-crt-locale-l1-1-0.dll',
        }

        for dll_entry in imports_data:
            if not isinstance(dll_entry, dict):
                continue
            dll_name = dll_entry.get('dll_name', '')
            dll_lower = dll_name.lower()
            # Check for unusual DLLs (not in the common set and not api-ms-win-*)
            if dll_lower and dll_lower not in COMMON_DLLS and not dll_lower.startswith('api-ms-win-'):
                unusual_dll_imports.append(dll_name)
            for sym in dll_entry.get('symbols', []):
                if isinstance(sym, dict):
                    name = sym.get('name', '')
                    ordinal = sym.get('ordinal')
                    if (not name or name.startswith('ord(')) and ordinal is not None:
                        ordinal_only_imports.append({"dll": dll_name, "ordinal": ordinal})

        import_anom: Dict[str, Any] = {}
        if ordinal_only_imports:
            import_anom["ordinal_only_imports"] = ordinal_only_imports[:indicator_limit]
            import_anom["ordinal_only_count"] = len(ordinal_only_imports)
            if len(ordinal_only_imports) > 5:
                risk_score += 1  # Many ordinal-only imports can indicate evasion
        if unusual_dll_imports:
            import_anom["non_standard_dlls"] = sorted(set(unusual_dll_imports))[:indicator_limit]
        triage_report["import_anomalies"] = import_anom
    else:
        triage_report["import_anomalies"] = {"note": f"Not applicable for {analysis_mode} mode" if analysis_mode != 'pe' else "No imports data"}

    # ===================================================================
    # 6c. Resource Anomalies (PE only — nested PEs, high-entropy resources)
    # ===================================================================
    if analysis_mode == 'pe':
        res_anomalies = []
        resources = state.pe_data.get('resources_summary', [])
        if isinstance(resources, list):
            for res in resources:
                if not isinstance(res, dict):
                    continue
                res_size = res.get('size', 0)
                res_type = res.get('type', '')
                # Suspiciously large resources
                if isinstance(res_size, int) and res_size > 500000:
                    res_anomalies.append({
                        "type": res_type,
                        "size": res_size,
                        "issue": f"Large resource ({res_size} bytes) — may contain embedded payload",
                        "severity": "MEDIUM",
                    })
                # RCDATA or custom type with large sizes are suspicious
                if res_type in ('RT_RCDATA', 'RCDATA', '10') and isinstance(res_size, int) and res_size > 50000:
                    res_anomalies.append({
                        "type": res_type,
                        "size": res_size,
                        "issue": "Large RCDATA resource — common vector for embedded payloads",
                        "severity": "HIGH",
                    })
                    risk_score += 1

        # Check if PE object has resource data we can scan for embedded PEs
        if state.pe_object and hasattr(state.pe_object, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for res_type_entry in state.pe_object.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(res_type_entry, 'directory') and res_type_entry.directory:
                        for res_id_entry in res_type_entry.directory.entries:
                            if hasattr(res_id_entry, 'directory') and res_id_entry.directory:
                                for res_lang_entry in res_id_entry.directory.entries:
                                    if hasattr(res_lang_entry, 'data') and hasattr(res_lang_entry.data, 'struct'):
                                        try:
                                            data_rva = res_lang_entry.data.struct.OffsetToData
                                            data_size = res_lang_entry.data.struct.Size
                                            res_bytes = state.pe_object.get_data(data_rva, min(data_size, 4))
                                            if len(res_bytes) >= 2 and res_bytes[:2] == b'MZ':
                                                type_id = getattr(res_type_entry, 'id', None)
                                                type_str = str(type_id) if type_id else 'unknown'
                                                res_anomalies.append({
                                                    "type": type_str,
                                                    "size": data_size,
                                                    "issue": "Embedded PE (MZ header) found inside resource",
                                                    "severity": "CRITICAL",
                                                })
                                                risk_score += 4
                                        except Exception:
                                            pass
            except Exception:
                pass

        triage_report["resource_anomalies"] = res_anomalies[:indicator_limit]
    else:
        triage_report["resource_anomalies"] = []

    # ===================================================================
    # 6d. YARA Match Integration
    # ===================================================================
    yara_data = state.pe_data.get('yara_matches', [])
    if isinstance(yara_data, list) and yara_data:
        yara_summary = []
        for match in yara_data:
            if isinstance(match, dict):
                yara_summary.append({
                    "rule": match.get('rule', match.get('name', 'unknown')),
                    "tags": match.get('tags', []),
                    "meta": match.get('meta', {}),
                })
                risk_score += 2  # Each YARA rule match adds risk
            elif isinstance(match, str):
                yara_summary.append({"rule": match})
                risk_score += 2
        triage_report["yara_matches"] = yara_summary[:indicator_limit]
    else:
        triage_report["yara_matches"] = []

    # ===================================================================
    # 6e. Header Anomalies & Corruption Detection
    # ===================================================================
    header_anomalies = []
    if analysis_mode == 'pe':
        # Check pefile warnings for corruption indicators
        pefile_warnings = state.pe_data.get('pefile_warnings', [])
        if isinstance(pefile_warnings, list) and pefile_warnings:
            for warn in pefile_warnings[:10]:
                header_anomalies.append({
                    "issue": str(warn),
                    "severity": "MEDIUM",
                    "source": "pefile_parser",
                })
            if len(pefile_warnings) > 3:
                risk_score += 1  # Many warnings indicate a malformed binary

        # Checksum verification
        checksum_info = state.pe_data.get('checksum_verification', {})
        if isinstance(checksum_info, dict):
            if checksum_info.get('valid') is False:
                header_anomalies.append({
                    "issue": f"PE checksum mismatch: header={checksum_info.get('header_checksum')}, computed={checksum_info.get('computed_checksum')}",
                    "severity": "LOW",
                    "source": "checksum",
                })
                # Mismatched checksums are common for unsigned binaries, low risk

        # Check for suspicious entry point
        nt_headers = state.pe_data.get('nt_headers', {})
        opt_header = nt_headers.get('optional_header', {})
        ep_rva = opt_header.get('AddressOfEntryPoint', opt_header.get('addressofentrypoint'))
        if isinstance(ep_rva, dict):
            ep_rva = ep_rva.get('Value', ep_rva.get('value'))
        if isinstance(ep_rva, int):
            # EP outside any section
            ep_in_section = False
            for sec in sections_data:
                if isinstance(sec, dict):
                    sec_va = sec.get('virtual_address', sec.get('VirtualAddress', 0))
                    sec_vs = sec.get('virtual_size', sec.get('Misc_VirtualSize', 0))
                    if isinstance(sec_va, int) and isinstance(sec_vs, int):
                        if sec_va <= ep_rva < sec_va + sec_vs:
                            ep_in_section = True
                            sec_name = sec.get('name', '').strip()
                            # EP not in .text or CODE section is unusual
                            if sec_name.lower() not in ('.text', 'code', '.code', ''):
                                header_anomalies.append({
                                    "issue": f"Entry point is in '{sec_name}' section (not .text/CODE)",
                                    "severity": "MEDIUM",
                                    "source": "entry_point",
                                })
                                risk_score += 1
                            break
            if not ep_in_section and ep_rva != 0:
                header_anomalies.append({
                    "issue": "Entry point address does not fall within any section",
                    "severity": "HIGH",
                    "source": "entry_point",
                })
                risk_score += 3

        # Section name anomalies (non-printable characters)
        for sec in sections_data:
            if isinstance(sec, dict):
                name = sec.get('name', '')
                if name and any(ord(c) < 32 or ord(c) > 126 for c in name.replace('\x00', '')):
                    header_anomalies.append({
                        "issue": f"Section '{repr(name)}' contains non-printable characters",
                        "severity": "MEDIUM",
                        "source": "section_names",
                    })
                    risk_score += 1
                    break  # Only report once

    triage_report["header_anomalies"] = header_anomalies[:indicator_limit]

    # ===================================================================
    # 6f. ELF Security Features (ELF only)
    # ===================================================================
    if analysis_mode == 'elf':
        elf_sec: Dict[str, Any] = {}
        try:
            if state.filepath and os.path.isfile(state.filepath):
                with open(state.filepath, 'rb') as f:
                    elf_header = f.read(64)

                if len(elf_header) >= 20:
                    elf_sec["class"] = "64-bit" if elf_header[4] == 2 else "32-bit"
                    elf_sec["endianness"] = "little-endian" if elf_header[5] == 1 else "big-endian"
                    # e_type at offset 16 (2 bytes)
                    import struct as _struct
                    byte_order = '<' if elf_header[5] == 1 else '>'
                    e_type = _struct.unpack_from(byte_order + 'H', elf_header, 16)[0]
                    TYPE_MAP = {0: 'ET_NONE', 1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE'}
                    elf_sec["type"] = TYPE_MAP.get(e_type, f'unknown({e_type})')
                    # ET_DYN with entry point suggests PIE
                    elf_sec["is_pie"] = (e_type == 3)
                    if not elf_sec["is_pie"]:
                        risk_score += 1  # Non-PIE binaries lack ASLR

                # Read full binary to check for security features in section names / segments
                with open(state.filepath, 'rb') as f:
                    full_data = f.read()

                # Check for common security indicators in the binary
                elf_sec["has_stack_canary"] = b'__stack_chk_fail' in full_data
                elf_sec["has_fortify"] = b'__fortify_fail' in full_data or b'__chk_fail' in full_data
                elf_sec["stripped"] = b'.symtab' not in full_data
                if elf_sec["stripped"]:
                    elf_sec["note_stripped"] = "Symbol table stripped — harder to analyze"

                # Check for RELRO by looking for GNU_RELRO segment marker
                elf_sec["has_gnu_relro"] = b'GNU_RELRO' in full_data or b'.got.plt' in full_data

                # Check for NX / executable stack
                # The PT_GNU_STACK segment flags determine if stack is executable
                elf_sec["has_nx_indicator"] = b'GNU_STACK' in full_data

        except Exception as e:
            elf_sec["error"] = f"ELF security check failed: {e}"
        triage_report["elf_security"] = elf_sec
    else:
        triage_report["elf_security"] = {}

    # ===================================================================
    # 6g. Mach-O Security Features (Mach-O only)
    # ===================================================================
    if analysis_mode == 'macho':
        macho_sec: Dict[str, Any] = {}
        try:
            if state.filepath and os.path.isfile(state.filepath):
                with open(state.filepath, 'rb') as f:
                    macho_header = f.read(32)
                    full_data = f.seek(0) or f.read()

                if len(macho_header) >= 16:
                    import struct as _struct
                    magic = _struct.unpack_from('<I', macho_header, 0)[0]
                    is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
                    is_le = magic in (0xFEEDFACE, 0xFEEDFACF)
                    macho_sec["bits"] = "64-bit" if is_64 else "32-bit"
                    byte_order = '<' if is_le else '>'

                    # Read filetype at offset 12
                    filetype = _struct.unpack_from(byte_order + 'I', macho_header, 12)[0]
                    FILETYPE_MAP = {1: 'MH_OBJECT', 2: 'MH_EXECUTE', 6: 'MH_DYLIB',
                                    8: 'MH_BUNDLE', 9: 'MH_DYLIB_STUB', 11: 'MH_DSYM'}
                    macho_sec["filetype"] = FILETYPE_MAP.get(filetype, f'unknown({filetype})')

                    # Check flags at offset 24 (32-bit) or same for 64-bit
                    flags_offset = 24
                    flags = _struct.unpack_from(byte_order + 'I', macho_header, flags_offset)[0]
                    macho_sec["is_pie"] = bool(flags & 0x200000)  # MH_PIE
                    macho_sec["no_heap_execution"] = bool(flags & 0x1000000)  # MH_NO_HEAP_EXECUTION
                    macho_sec["has_restrict"] = bool(flags & 0x00000080)  # MH_RESTRICT segment

                # Check for code signature
                macho_sec["has_code_signature"] = b'__LINKEDIT' in full_data and b'\xfa\xde\x0c\xc0' in full_data
                # Check for entitlements
                macho_sec["has_entitlements"] = b'</plist>' in full_data and b'<key>' in full_data

                if not macho_sec.get("is_pie", True):
                    risk_score += 1

        except Exception as e:
            macho_sec["error"] = f"Mach-O security check failed: {e}"
        triage_report["macho_security"] = macho_sec
    else:
        triage_report["macho_security"] = {}

    # ===================================================================
    # 7. High-Value String Indicators
    # ===================================================================
    high_value_strings = []
    for s_text in all_string_values:
        if not s_text:
            continue
        # Check for high-value patterns in strings
        for s in (state.pe_data.get('basic_ascii_strings', []) +
                  list(all_string_values)):
            pass  # Already collected above
        break

    # Use sifter scores if available
    for source in [state.pe_data.get('basic_ascii_strings', [])]:
        if isinstance(source, list):
            for s in source:
                if isinstance(s, dict) and s.get('sifter_score', 0.0) >= sifter_score_threshold:
                    if s.get('category') or s.get('sifter_score', 0.0) >= 9.0:
                        high_value_strings.append(s)

    if 'floss_analysis' in state.pe_data and isinstance(state.pe_data['floss_analysis'], dict):
        floss_strings = state.pe_data['floss_analysis'].get('strings')
        if isinstance(floss_strings, dict):
            for str_list in floss_strings.values():
                if isinstance(str_list, list):
                    for s in str_list:
                        if isinstance(s, dict) and s.get('sifter_score', 0.0) >= sifter_score_threshold:
                            if s.get('category') or s.get('sifter_score', 0.0) >= 9.0:
                                high_value_strings.append(s)

    unique_indicators = {s.get('string', str(s)): s for s in high_value_strings if isinstance(s, dict)}
    sorted_indicators = sorted(unique_indicators.values(), key=lambda x: x.get('sifter_score', 0.0), reverse=True)
    triage_report["high_value_strings"] = sorted_indicators[:indicator_limit]

    # ===================================================================
    # 8. Risk Score & Suggested Next Tools
    # ===================================================================
    triage_report["risk_score"] = risk_score

    if risk_score >= 15:
        triage_report["risk_level"] = "CRITICAL"
    elif risk_score >= 8:
        triage_report["risk_level"] = "HIGH"
    elif risk_score >= 4:
        triage_report["risk_level"] = "MEDIUM"
    elif risk_score >= 1:
        triage_report["risk_level"] = "LOW"
    else:
        triage_report["risk_level"] = "BENIGN"

    # Context-aware, format-aware tool suggestions
    suggested = []
    if analysis_mode == 'pe':
        if is_likely_packed:
            suggested.append("auto_unpack_pe — attempt automatic unpacking")
            suggested.append("get_pe_data(key='peid_matches') — review packer signatures")
        else:
            if not triage_report["suspicious_capabilities"]:
                suggested.append("get_capa_analysis_info — run capa for capability detection")
            suggested.append("find_and_decode_encoded_strings — hunt for obfuscated IOCs")
        if not found_ips and not found_urls:
            suggested.append("search_floss_strings — search for network indicators with regex")
        if triage_report.get("overlay_analysis", {}).get("present"):
            suggested.append("scan_for_embedded_files — scan overlay for embedded binaries")
        if triage_report.get("resource_anomalies"):
            suggested.append("get_pe_data(key='resources_summary') — inspect suspicious resources")
        suggested.append("classify_binary_purpose — determine if GUI app, service, DLL, etc.")
    elif analysis_mode == 'elf':
        suggested.append("elf_analyze — full ELF header, section, and symbol analysis")
        suggested.append("elf_dwarf_info — extract debug symbols and source file names")
        if triage_report.get("elf_security", {}).get("stripped"):
            suggested.append("decompile_function — use angr to decompile stripped functions")
        suggested.append("parse_binary_with_lief — cross-format binary analysis")
    elif analysis_mode == 'macho':
        suggested.append("macho_analyze — full Mach-O load commands, segments, and symbols")
        suggested.append("parse_binary_with_lief — cross-format binary analysis")
    elif analysis_mode == 'shellcode':
        suggested.append("emulate_shellcode_with_speakeasy — emulate with Windows API hooks")
        suggested.append("disassemble_raw_bytes — disassemble the shellcode")
    # Universal suggestions
    if risk_score >= 8:
        suggested.append("get_virustotal_report_for_loaded_file — check community reputation")
    suggested.append("compute_similarity_hashes — compute ssdeep/TLSH for sample clustering")
    triage_report["suggested_next_tools"] = suggested[:7]

    return await _check_mcp_response_size(ctx, triage_report, "get_triage_report", "the 'indicator_limit' parameter")

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


@tool_decorator
async def set_api_key(ctx: Context, key_name: str, key_value: str) -> Dict[str, str]:
    """
    Stores an API key in the user's persistent configuration (~/.pemcp/config.json).
    The key is saved securely (file permissions restricted to owner only) and will
    be recalled automatically in future sessions.

    Supported key names:
    - 'vt_api_key': VirusTotal API key (used by get_virustotal_report_for_loaded_file)

    Note: Environment variables (e.g. VT_API_KEY) always take priority over stored keys.

    Args:
        ctx: The MCP Context object.
        key_name: (str) The configuration key name (e.g. 'vt_api_key').
        key_value: (str) The API key value to store.

    Returns:
        A dictionary confirming the key was saved.
    """
    allowed_keys = {"vt_api_key"}
    if key_name not in allowed_keys:
        raise ValueError(
            f"[set_api_key] Unknown key '{key_name}'. "
            f"Supported keys: {', '.join(sorted(allowed_keys))}"
        )

    if not key_value or not key_value.strip():
        raise ValueError("[set_api_key] key_value must not be empty.")

    set_config_value(key_name, key_value.strip())
    await ctx.info(f"API key '{key_name}' saved to persistent configuration.")

    return {
        "status": "success",
        "message": f"Key '{key_name}' saved successfully. It will be used automatically in future sessions.",
        "note": "Environment variables always take priority over stored keys.",
    }


@tool_decorator
async def get_config(ctx: Context) -> Dict[str, Any]:
    """
    Retrieves the current PeMCP configuration, including stored API keys (masked)
    and which keys are overridden by environment variables.

    This tool does not depend on a PE file being loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing the current configuration with sensitive values masked.
    """
    await ctx.info("Retrieving current configuration.")
    config = get_masked_config()

    # Add server capability info
    config["_server_info"] = {
        "angr_available": ANGR_AVAILABLE,
        "capa_available": CAPA_AVAILABLE,
        "floss_available": FLOSS_AVAILABLE,
        "yara_available": YARA_AVAILABLE,
        "stringsifter_available": STRINGSIFTER_AVAILABLE,
        "requests_available": REQUESTS_AVAILABLE,
        "file_loaded": state.filepath is not None,
        "loaded_filepath": state.filepath,
    }

    return config


# ===================================================================
#  Analysis Cache Management Tools
# ===================================================================

@tool_decorator
async def get_cache_stats(ctx: Context) -> Dict[str, Any]:
    """
    Returns statistics about the disk-based analysis cache (~/.pemcp/cache/).
    Shows entry count, total size, utilization, and a list of cached files.

    This tool does not require a file to be loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary with cache statistics including entry count, size,
        and per-entry details.
    """
    await ctx.info("Retrieving cache statistics...")
    return analysis_cache.get_stats()


@tool_decorator
async def clear_analysis_cache(ctx: Context) -> Dict[str, Any]:
    """
    Clears the entire disk-based analysis cache (~/.pemcp/cache/).
    Removes all cached file analysis results. This frees disk space but
    means the next file open will require a full re-analysis.

    This tool does not require a file to be loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary with the number of entries removed and space freed.
    """
    await ctx.info("Clearing analysis cache...")
    result = analysis_cache.clear()
    await ctx.info(
        f"Cache cleared: {result['entries_removed']} entries, "
        f"{result['space_freed_mb']} MB freed."
    )
    return {"status": "success", **result}


@tool_decorator
async def remove_cached_analysis(ctx: Context, sha256_hash: str) -> Dict[str, Any]:
    """
    Removes a specific cached analysis result by its SHA256 file hash.
    Use get_cache_stats to see which hashes are cached.

    This tool does not require a file to be loaded.

    Args:
        ctx: The MCP Context object.
        sha256_hash: (str) The full SHA256 hash (64 hex characters) of the
            file whose cached analysis should be removed.

    Returns:
        A dictionary confirming removal or indicating the entry was not found.
    """
    sha = sha256_hash.lower().strip()
    if len(sha) != 64 or not all(c in "0123456789abcdef" for c in sha):
        raise ValueError("Invalid SHA256 hash. Must be 64 hex characters.")

    await ctx.info(f"Removing cache entry for {sha[:16]}...")
    existed = analysis_cache.remove_entry_by_hash(sha)

    if existed:
        return {"status": "success", "message": f"Cache entry for {sha[:16]}... removed."}
    return {"status": "not_found", "message": f"No cache entry found for {sha[:16]}..."}


# ===================================================================
#  Binary Purpose Classification
# ===================================================================

@tool_decorator
async def classify_binary_purpose(ctx: Context) -> Dict[str, Any]:
    """
    Classifies the loaded binary by purpose and type using PE header analysis,
    import patterns, section characteristics, and resource presence.

    Categories: GUI Application, Console Application, DLL/Library, System Service,
    Device Driver, Installer/SFX, .NET Assembly, and more.

    Returns:
        A dictionary with the primary classification, confidence indicators,
        and supporting evidence.
    """
    await ctx.info("Classifying binary purpose...")
    _check_pe_loaded("classify_binary_purpose")

    classifications = []
    evidence = []

    mode = state.pe_data.get('mode', 'pe')

    # Non-PE formats
    if mode in ('elf', 'macho', 'shellcode'):
        return {
            "primary_type": mode.upper(),
            "classifications": [mode.upper()],
            "evidence": [f"File loaded in {mode} mode"],
            "note": "Detailed classification is PE-specific. Use format-specific tools for analysis.",
        }

    pe_data = state.pe_data
    sections_data = pe_data.get('sections', [])
    imports_data = pe_data.get('imports', [])
    version_info = pe_data.get('version_info', {})
    resources = pe_data.get('resources_summary', [])
    nt_headers = pe_data.get('nt_headers', {})
    com_descriptor = pe_data.get('com_descriptor', {})

    # Extract key header fields
    file_header = nt_headers.get('file_header', {})
    optional_header = nt_headers.get('optional_header', {})
    characteristics = file_header.get('characteristics', file_header.get('Characteristics', 0))
    subsystem = optional_header.get('subsystem', optional_header.get('Subsystem', 0))
    dll_characteristics = optional_header.get('dll_characteristics', optional_header.get('DllCharacteristics', 0))

    # Gather all import function names
    all_import_names = set()
    all_dll_names = set()
    for dll_entry in imports_data:
        if isinstance(dll_entry, dict):
            dll_name = dll_entry.get('dll_name', '').lower()
            all_dll_names.add(dll_name)
            for sym in dll_entry.get('symbols', []):
                name = sym.get('name', '')
                if name:
                    all_import_names.add(name)

    # ---- DLL Check ----
    is_dll = False
    if isinstance(characteristics, int):
        is_dll = bool(characteristics & 0x2000)  # IMAGE_FILE_DLL
    elif isinstance(characteristics, str) and 'DLL' in characteristics.upper():
        is_dll = True

    if is_dll:
        classifications.append("DLL/Library")
        evidence.append("FILE_HEADER.Characteristics has IMAGE_FILE_DLL flag")

    # ---- Subsystem Check ----
    subsystem_val = subsystem
    if isinstance(subsystem, str):
        if 'GUI' in subsystem.upper():
            subsystem_val = 2
        elif 'CONSOLE' in subsystem.upper():
            subsystem_val = 3
        elif 'NATIVE' in subsystem.upper():
            subsystem_val = 1
        elif 'EFI' in subsystem.upper():
            subsystem_val = 10

    if subsystem_val == 2:
        classifications.append("GUI Application")
        evidence.append("Subsystem: Windows GUI")
    elif subsystem_val == 3:
        classifications.append("Console Application")
        evidence.append("Subsystem: Windows Console")
    elif subsystem_val == 1:
        classifications.append("Native/Kernel-mode")
        evidence.append("Subsystem: Native (kernel-mode driver or boot program)")
    elif isinstance(subsystem_val, int) and 10 <= subsystem_val <= 13:
        classifications.append("EFI Application")
        evidence.append(f"Subsystem: EFI ({subsystem_val})")

    # ---- .NET Assembly ----
    if com_descriptor and isinstance(com_descriptor, dict) and com_descriptor.get('cb', com_descriptor.get('size', 0)):
        classifications.append(".NET Assembly")
        evidence.append("COM/.NET descriptor (IMAGE_COR20_HEADER) present")

    # ---- Driver Detection ----
    driver_dlls = {'ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'wdm.sys', 'ntdll.dll'}
    driver_imports = {'IoCreateDevice', 'IoDeleteDevice', 'IoCreateSymbolicLink',
                      'KeInitializeDpc', 'MmMapIoSpace', 'ExAllocatePool',
                      'ObReferenceObjectByHandle', 'PsCreateSystemThread'}
    if all_dll_names & driver_dlls or all_import_names & driver_imports:
        classifications.append("Device Driver")
        evidence.append(f"Driver DLLs/imports detected: {(all_dll_names & driver_dlls) | (all_import_names & driver_imports)}")

    # ---- System Service Detection ----
    service_imports = {'StartServiceCtrlDispatcherA', 'StartServiceCtrlDispatcherW',
                       'RegisterServiceCtrlHandlerA', 'RegisterServiceCtrlHandlerW',
                       'RegisterServiceCtrlHandlerExA', 'RegisterServiceCtrlHandlerExW'}
    if all_import_names & service_imports:
        classifications.append("Windows Service")
        evidence.append(f"Service dispatcher imports: {all_import_names & service_imports}")

    # ---- Installer/SFX Detection ----
    installer_indicators = []
    # Check for NSIS/InnoSetup/InstallShield sections or resources
    for sec in sections_data:
        if isinstance(sec, dict):
            name = sec.get('name', '').strip()
            if name in ('.ndata', '.nsis'):
                installer_indicators.append(f"NSIS section: {name}")
    # Check version info
    if isinstance(version_info, dict):
        for key in ('FileDescription', 'ProductName', 'InternalName', 'OriginalFilename'):
            val = str(version_info.get(key, '')).lower()
            if any(kw in val for kw in ('setup', 'install', 'uninstall', 'updater')):
                installer_indicators.append(f"Version info '{key}' contains installer keyword: {val}")
    # Check for large overlay (common in SFX)
    overlay = pe_data.get('overlay_data', {})
    if isinstance(overlay, dict) and overlay.get('size', 0) > 100000:
        installer_indicators.append(f"Large overlay ({overlay.get('size')} bytes) — common in SFX archives")

    if installer_indicators:
        classifications.append("Installer/SFX")
        evidence.extend(installer_indicators)

    # ---- Networking Tool Detection ----
    net_dlls = {'ws2_32.dll', 'winhttp.dll', 'wininet.dll', 'urlmon.dll', 'mswsock.dll'}
    if len(all_dll_names & net_dlls) >= 2:
        classifications.append("Networking-Heavy")
        evidence.append(f"Multiple networking DLLs: {all_dll_names & net_dlls}")

    # ---- Crypto-Heavy Detection ----
    crypto_dlls = {'advapi32.dll', 'bcrypt.dll', 'ncrypt.dll', 'crypt32.dll'}
    crypto_funcs = {'CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt',
                    'CryptDeriveKey', 'CryptGenKey', 'CryptAcquireContext'}
    if all_import_names & crypto_funcs:
        classifications.append("Crypto-Heavy")
        evidence.append(f"Cryptographic API imports: {all_import_names & crypto_funcs}")

    # ---- GUI Evidence ----
    gui_dlls = {'user32.dll', 'gdi32.dll', 'comctl32.dll', 'comdlg32.dll', 'uxtheme.dll'}
    gui_funcs = {'CreateWindowExA', 'CreateWindowExW', 'ShowWindow', 'MessageBoxA',
                 'MessageBoxW', 'DialogBoxParamA', 'DialogBoxParamW', 'GetDC'}
    if len(all_dll_names & gui_dlls) >= 2 or all_import_names & gui_funcs:
        if "GUI Application" not in classifications:
            classifications.append("GUI Application")
        evidence.append(f"GUI DLLs: {all_dll_names & gui_dlls}")

    # ---- Primary Classification ----
    # Prioritize: Driver > Service > .NET > DLL > Installer > GUI > Console > Unknown
    priority_order = ["Device Driver", "Native/Kernel-mode", "Windows Service",
                      ".NET Assembly", "Installer/SFX", "DLL/Library",
                      "GUI Application", "Console Application", "EFI Application"]
    primary = "Unknown PE"
    for p in priority_order:
        if p in classifications:
            primary = p
            break

    return {
        "primary_type": primary,
        "classifications": classifications,
        "evidence": evidence,
        "is_dll": is_dll,
        "subsystem": subsystem,
        "has_overlay": bool(overlay.get('size', 0) > 0) if isinstance(overlay, dict) else False,
        "has_dotnet": ".NET Assembly" in classifications,
        "import_dll_count": len(all_dll_names),
        "import_function_count": len(all_import_names),
    }
