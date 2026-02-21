"""MCP tools for hex dump, deobfuscation, and encoded string detection."""
import re
import base64
import codecs
import os
import asyncio
from typing import Dict, Any, Optional, List
from pemcp.config import state, logger, Context, STRINGSIFTER_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.utils import safe_regex_search as _safe_regex_search
from pemcp.parsers.strings import _decode_single_byte_xor, _format_hex_dump_lines, _get_string_category
if STRINGSIFTER_AVAILABLE:
    from pemcp.mcp.tools_strings import _get_sifter_models


@tool_decorator
async def get_hex_dump(ctx: Context, start_offset: int, length: int, bytes_per_line: Optional[int]=16, limit_lines: Optional[int]=256, offset: Optional[int] = None) -> List[str]:
    """
    Retrieves a hex dump of a specified region from the pre-loaded PE file.
    'limit_lines' controls the number of lines in the output.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        start_offset: (int) The starting offset (0-based) in the file from which to begin the hex dump.
        offset: (Optional[int]) Alias for start_offset. If provided, overrides start_offset.
        length: (int) The number of bytes to include in the hex dump. Must be positive.
        bytes_per_line: (Optional[int]) The number of bytes to display per line. Defaults to 16. Must be positive.
        limit_lines: (Optional[int]) The maximum number of lines to return. Defaults to 256. Must be positive.

    Returns:
        A list of strings, where each string is a formatted line of the hex dump.
    Raises:
        RuntimeError: If no PE file is currently loaded or a hex dump error occurs.
        ValueError: If inputs are invalid, or if the response size exceeds the server limit.
    """
    if offset is not None:
        start_offset = offset  # Allow 'offset' as an alias for 'start_offset'
    await ctx.info(f"Hex dump requested: Offset {hex(start_offset)}, Length {length}, Bytes/Line {bytes_per_line}, Limit Lines {limit_lines}")
    if state.pe_object is None or not hasattr(state.pe_object, '__data__'):
        raise RuntimeError(
            "No PE file loaded or PE data unavailable. "
            "The server must be started with --input-file to pre-load a file. "
            "If a file was provided, check the server logs for load errors."
        )
    if not isinstance(start_offset, int) or start_offset < 0:
        raise ValueError("start_offset must be a non-negative integer.")
    if not isinstance(length, int) or length <= 0:
        raise ValueError("length must be a positive integer.")

    bpl = 16
    if bytes_per_line is not None:
        if isinstance(bytes_per_line, int) and bytes_per_line > 0:
            bpl = bytes_per_line
        else:
            raise ValueError("bytes_per_line must be a positive integer.")

    ll = 256
    if limit_lines is not None:
        if isinstance(limit_lines, int) and limit_lines > 0:
            ll = limit_lines
        else:
            raise ValueError("limit_lines must be a positive integer.")

    try:
        file_data = state.pe_object.__data__
        if start_offset >= len(file_data):
            return ["Error: Start offset is beyond the file size."]
        actual_len = min(length, len(file_data) - start_offset)
        if actual_len <= 0:
            return ["Error: Calculated length for hex dump is zero or negative (start_offset might be at or past EOF)."]

        data_chunk = file_data[start_offset:start_offset + actual_len]
        hex_lines = await asyncio.to_thread(_format_hex_dump_lines, data_chunk, start_offset, bpl)

        data_to_send = hex_lines[:ll]
        limit_info_str = "parameters like 'length' or 'limit_lines'"
        return await _check_mcp_response_size(ctx, data_to_send, "get_hex_dump", limit_info_str)
    except Exception as e:
        await ctx.error(f"Hex dump error: {e}")
        raise RuntimeError(f"Failed during hex dump generation: {e}") from e

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
        logger.warning("MCP: Invalid hex/Base64 for deobfuscation: %s... - %s", hex_string[:60], e)
        return None # Return None on decoding failure before size check
    except Exception as e: # Catch other errors like binascii.Error from codecs.decode
        await ctx.error(f"Base64 deobfuscation error: {str(e)}")
        logger.error("MCP: Base64 deobfuscation error for %s... - %s", hex_string[:60], e, exc_info=True)
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
        logger.warning("MCP: Invalid XOR key %d requested.", key)
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
            logger.warning("MCP: Error creating printable string for XOR result (key %d): %s", key, e_decode)
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
        logger.warning("MCP: Invalid hex string for XOR data_hex: %s... - %s", data_hex[:60], e_val)
        raise # Re-raise to be handled by MCP framework
    except Exception as e_gen:
        await ctx.error(f"XOR deobfuscation error: {str(e_gen)}")
        logger.error("MCP: XOR deobfuscation error for data_hex %s..., key %d - %s", data_hex[:60], key, e_gen, exc_info=True)
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
        logger.warning("MCP: Invalid threshold %s for printable check.", threshold)
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
        return False

    printable_char_in_string_count = sum(1 for char_in_s in text_input
                                         if (' ' <= char_in_s <= '~') or char_in_s in '\n\r\t')

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

    # Validate regex patterns upfront to avoid wasting CPU on decode cycles
    _compiled_decoded_regex = []
    if decoded_regex_patterns:
        for i, pat in enumerate(decoded_regex_patterns):
            try:
                _compiled_decoded_regex.append(re.compile(pat))
            except re.error as e:
                raise ValueError(f"Invalid regex pattern at index {i} ('{pat}'): {e}")

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

        # --- HEURISTIC: Calculate initial confidence based on section ---
        section_confidence = 0.5  # Default low confidence
        try:
            section = pe.get_section_by_offset(start_offset)
            if section:
                sec_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                if '.data' in sec_name or '.rdata' in sec_name:
                    section_confidence = 1.0  # High confidence for data sections
                elif '.text' not in sec_name:
                    section_confidence = 0.8  # Medium confidence for other non-code sections
        except Exception:
            pass  # Keep default confidence if section lookup fails

        # Early filter: skip candidates that can't possibly reach min_confidence
        if section_confidence < min_confidence:
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
            # Adjust confidence based on decoded content quality
            confidence = section_confidence
            decoded_stripped = final_decoded_text.strip()

            # Reduce confidence for purely numeric strings (dates, versions)
            if decoded_stripped.isdigit():
                confidence *= 0.3

            # Reduce confidence for common benign patterns
            _benign_patterns = (
                re.compile(r'^\d{4}[-/]\d{2}[-/]\d{2}'),    # date YYYY-MM-DD
                re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}'),   # version x.y.z
                re.compile(r'^[A-Z][a-z]+ \d{1,2},? \d{4}'), # "January 1, 2024"
            )
            if any(p.match(decoded_stripped) for p in _benign_patterns):
                confidence *= 0.4

            # Very short decoded strings are less interesting
            if len(decoded_stripped) < 8:
                confidence *= 0.7

            if confidence < min_confidence:
                continue

            if _compiled_decoded_regex:
                try:
                    if not any(_safe_regex_search(p, final_decoded_text) for p in _compiled_decoded_regex):
                        continue
                except ValueError:
                    await ctx.warning("A regex timed out during search (possible ReDoS). Skipping.")
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
            featurizer, ranker = _get_sifter_models()
            X_test = await asyncio.to_thread(featurizer.transform, string_values)
            y_scores = await asyncio.to_thread(ranker.predict, X_test)

            for i, res_dict in enumerate(final_results):
                res_dict['sifter_score'] = round(float(y_scores[i]), 4)

        if min_sifter_score is not None:
            final_results = [res for res in final_results if res.get('sifter_score', -999.0) >= min_sifter_score]

        final_results.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=True)

    truncated = final_results[:limit]

    # Auto-note high-confidence decoded strings that look like IOCs
    auto_noted_count = 0
    for entry in truncated:
        decoded = entry.get("decoded_string", "")
        conf = entry.get("confidence", 0)
        if conf < 0.8 or not decoded:
            continue
        cat = _get_string_category(decoded.strip())
        if cat:
            try:
                state.add_note(
                    content=f"[auto] Decoded {cat}: {decoded.strip()[:200]} "
                            f"(encoding: {', '.join(entry.get('encoding_layers', []))})",
                    category="tool_result",
                    tool_name="find_and_decode_encoded_strings",
                )
                auto_noted_count += 1
            except Exception:
                pass  # Don't fail the tool if note creation fails

    # Wrap results with a note-taking hint when encoded strings are found
    result_wrapper: Dict[str, Any] = {
        "decoded_strings": truncated,
        "count": len(truncated),
        "total_candidates": len(found_decoded_strings),
    }
    if auto_noted_count:
        result_wrapper["auto_noted"] = (
            f"{auto_noted_count} high-confidence IOC(s) auto-saved as tool_result notes."
        )
    if truncated:
        result_wrapper["next_step"] = (
            "Review decoded strings for IOCs (IPs, URLs, domains, registry keys). "
            "Call add_note(content, category='tool_result') to record significant findings."
        )

    return await _check_mcp_response_size(ctx, result_wrapper, "find_and_decode_encoded_strings", "the 'limit' parameter or by adjusting filters")
