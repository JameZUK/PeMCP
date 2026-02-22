"""MCP tools powered by Binary Refinery for advanced transformations.

Covers regex extraction, regex replacement, key derivation (PBKDF2, HKDF, HMAC),
automatic XOR decryption, string operations (slice, trim, replace, case),
pretty-printing (JSON, XML, JavaScript), and Python bytecode decompilation.
"""
import asyncio

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._refinery_helpers import (
    _require_refinery, _safe_decode, _bytes_to_hex, _hex_to_bytes,
    _get_file_data, _get_data_from_hex_or_file,
    _MAX_INPUT_SIZE_SMALL as _MAX_INPUT_SIZE,
    _MAX_OUTPUT_ITEMS,
)


# ===================================================================
#  1. REGEX EXTRACTION
# ===================================================================

@tool_decorator
async def refinery_regex_extract(
    ctx: Context,
    pattern: str,
    data_hex: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Extract data matching a regular expression from binary data using Binary Refinery.

    The rex unit supports Python regex syntax with named groups. If the pattern
    contains capture groups, only the captured portions are returned. Useful
    for extracting custom patterns (crypto keys, encoded strings, protocol fields).

    Args:
        ctx: The MCP Context object.
        pattern: (str) Python regex pattern. Use (?P<name>...) for named groups.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        limit: (int) Max matches to return. Default 200.

    Returns:
        Dictionary with all regex matches.
    """
    _require_refinery("refinery_regex_extract")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]

    await ctx.info(f"Extracting regex pattern from {len(data)} bytes...")

    def _run():
        from refinery.units.pattern.rex import rex
        results = []
        for chunk in data | rex(pattern):
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "match_hex": _bytes_to_hex(raw, 512),
                "match_text": _safe_decode(raw)[:500],
                "size": len(raw),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('offset', 'group', 'match'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "pattern": pattern,
        "matches_found": len(results),
        "data_size": len(data),
        "results": results,
    }, "refinery_regex_extract")


# ===================================================================
#  2. REGEX REPLACEMENT
# ===================================================================

@tool_decorator
async def refinery_regex_replace(
    ctx: Context,
    pattern: str,
    replacement: str,
    data_hex: str,
) -> Dict[str, Any]:
    """
    Find and replace using regex in binary data using Binary Refinery.

    Performs regex substitution on binary data. The replacement string
    supports backreferences (\\1, \\g<name>). Useful for patching or
    transforming structured binary formats.

    Args:
        ctx: The MCP Context object.
        pattern: (str) Python regex pattern to find.
        replacement: (str) Replacement string (supports backreferences).
        data_hex: (str) Input data as hex string.

    Returns:
        Dictionary with transformed output.
    """
    _require_refinery("refinery_regex_replace")

    try:
        data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        data = data_hex.encode("utf-8")

    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Regex replace: {pattern} -> {replacement}")

    def _run():
        from refinery.units.pattern.resub import resub
        # resub expects replacement as bytes, not str
        repl_bytes = replacement.encode("utf-8") if isinstance(replacement, str) else replacement
        return data | resub(pattern, repl_bytes) | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "pattern": pattern,
        "replacement": replacement,
        "input_size": len(data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_regex_replace")


# ===================================================================
#  3. AUTOMATIC XOR/SUB DECRYPTION
# ===================================================================

@tool_decorator
async def refinery_auto_decrypt(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Automatically detect and decrypt XOR/SUB encrypted data using Binary Refinery.

    Uses frequency analysis, known plaintext attacks, and file signature
    detection (cribs) to automatically recover the encryption key and
    decrypt the data. More powerful than xkey for complex cases.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Encrypted data as hex. If None, uses loaded file.

    Returns:
        Dictionary with decrypted output and detected key.
    """
    _require_refinery("refinery_auto_decrypt")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]

    await ctx.info(f"Auto-decrypting {len(data)} bytes...")

    def _run():
        from refinery.units.misc.autoxor import autoxor
        result = data | autoxor() | bytes
        return result

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_auto_decrypt")


# ===================================================================
#  4. KEY DERIVATION
# ===================================================================

@tool_decorator
async def refinery_key_derive(
    ctx: Context,
    method: str,
    password_hex: str,
    salt_hex: Optional[str] = None,
    key_length: int = 32,
    iterations: int = 10000,
    hash_algorithm: str = "SHA256",
) -> Dict[str, Any]:
    """
    Derive cryptographic keys from passwords using Binary Refinery.

    Supports: pbkdf2, hkdf, hmac.

    Useful for reproducing key derivation used by malware to generate
    encryption keys from hardcoded passwords.

    Args:
        ctx: The MCP Context object.
        method: (str) Derivation method: 'pbkdf2', 'hkdf', 'hmac'.
        password_hex: (str) Password/input key material as hex.
        salt_hex: (Optional[str]) Salt as hex. Required for PBKDF2/HKDF.
        key_length: (int) Desired key length in bytes. Default 32.
        iterations: (int) Iteration count for PBKDF2. Default 10000.
        hash_algorithm: (str) Hash algorithm: SHA256, SHA1, SHA512, MD5. Default SHA256.

    Returns:
        Dictionary with the derived key.
    """
    _require_refinery("refinery_key_derive")

    password = _hex_to_bytes(password_hex)
    salt = _hex_to_bytes(salt_hex) if salt_hex else b''

    await ctx.info(f"Deriving key via {method} (len={key_length}, hash={hash_algorithm})...")

    method_lower = method.lower()

    _KDF_MAP = {
        "pbkdf2": "refinery.units.crypto.keyderive.pbkdf2:pbkdf2",
        "hkdf": "refinery.units.crypto.keyderive.hkdf:hkdf",
        "hmac": "refinery.units.crypto.keyderive.hmac:hmac",
    }

    if method_lower not in _KDF_MAP:
        return {"error": f"Unknown method '{method}'.", "supported": sorted(_KDF_MAP.keys())}

    mod_path, cls_name = _KDF_MAP[method_lower].rsplit(":", 1)

    def _run():
        import importlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)

        if method_lower == "pbkdf2":
            return password | unit_cls(key_length, salt, iter=iterations, hash=hash_algorithm) | bytes
        elif method_lower == "hkdf":
            return password | unit_cls(key_length, salt, hash=hash_algorithm) | bytes
        elif method_lower == "hmac":
            return password | unit_cls(salt, hash=hash_algorithm) | bytes
        return b''

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "method": method,
        "hash_algorithm": hash_algorithm,
        "key_length": key_length,
        "iterations": iterations if method_lower == "pbkdf2" else None,
        "derived_key_hex": result.hex(),
        "derived_key_length": len(result),
    }, "refinery_key_derive")


# ===================================================================
#  5. STRING OPERATIONS
# ===================================================================

@tool_decorator
async def refinery_string_operations(
    ctx: Context,
    data_hex: str,
    operation: str,
    argument: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Perform string/binary operations on data using Binary Refinery.

    Operations:
    - 'snip:start:stop' — Python-style byte slice (e.g. 'snip:10:50').
    - 'trim' — Remove leading/trailing whitespace and null bytes.
    - 'replace:old_hex:new_hex' — Replace byte sequences.
    - 'lower' — Convert text to lowercase.
    - 'upper' — Convert text to uppercase.
    - 'swapcase' — Swap character case.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Input data as hex string.
        operation: (str) Operation name: 'snip', 'trim', 'replace', 'lower', 'upper', 'swapcase'.
        argument: (Optional[str]) Operation-specific argument (see operation descriptions).

    Returns:
        Dictionary with transformed output.
    """
    _require_refinery("refinery_string_operations")

    try:
        data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        data = data_hex.encode("utf-8")

    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    op = operation.lower()
    await ctx.info(f"String operation: {op}")

    def _run():
        if op.startswith("snip"):
            # Parse start:stop:step from operation or argument
            parts = (argument or op).replace("snip:", "").replace("snip", "").split(":")
            parts = [p.strip() for p in parts if p.strip()]
            # Build a slice and apply directly — simpler and more reliable
            # than going through refinery's Arg parser for slice types.
            if len(parts) == 0:
                s = slice(None)
            elif len(parts) == 1:
                s = slice(int(parts[0]))
            elif len(parts) == 2:
                start = int(parts[0]) if parts[0] else None
                stop = int(parts[1]) if parts[1] else None
                s = slice(start, stop)
            else:
                start = int(parts[0]) if parts[0] else None
                stop = int(parts[1]) if parts[1] else None
                step = int(parts[2]) if parts[2] else None
                s = slice(start, stop, step)
            return bytes(data[s])
        elif op == "trim":
            from refinery.units.strings.trim import trim
            return data | trim() | bytes
        elif op == "replace":
            from refinery.units.strings.repl import repl
            if not argument:
                raise ValueError("Replace requires argument as 'old_hex:new_hex'.")
            parts = argument.split(":")
            old = bytes.fromhex(parts[0])
            new = bytes.fromhex(parts[1]) if len(parts) > 1 else b''
            return data | repl(old, new) | bytes
        elif op == "lower":
            from refinery.units.strings.clower import clower
            return data | clower() | bytes
        elif op == "upper":
            from refinery.units.strings.cupper import cupper
            return data | cupper() | bytes
        elif op == "swapcase":
            from refinery.units.strings.cswap import cswap
            return data | cswap() | bytes
        else:
            raise ValueError(f"Unknown operation '{op}'. Supported: snip, trim, replace, lower, upper, swapcase.")

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "operation": op,
        "input_size": len(data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_string_operations")


# ===================================================================
#  6. PRETTY-PRINT (JSON, XML, JavaScript)
# ===================================================================

@tool_decorator
async def refinery_pretty_print(
    ctx: Context,
    data_hex: str,
    format: str = "json",
) -> Dict[str, Any]:
    """
    Pretty-print structured data using Binary Refinery.

    Supports: json, xml, javascript/js.

    Formats minified or obfuscated structured data into readable,
    indented output. Useful for analyzing configuration files, API
    responses, and obfuscated JavaScript found in malware.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Data as hex string.
        format: (str) Format to pretty-print: 'json', 'xml', 'js'/'javascript'. Default 'json'.

    Returns:
        Dictionary with formatted output text.
    """
    _require_refinery("refinery_pretty_print")

    try:
        data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        data = data_hex.encode("utf-8")

    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    _PP_MAP = {
        "json": "refinery.units.sinks.ppjson:ppjson",
        "xml": "refinery.units.sinks.ppxml:ppxml",
        "js": "refinery.units.sinks.ppjscript:ppjscript",
        "javascript": "refinery.units.sinks.ppjscript:ppjscript",
    }

    fmt = format.lower()
    if fmt not in _PP_MAP:
        return {"error": f"Unknown format '{format}'.", "supported": ["json", "xml", "js"]}

    await ctx.info(f"Pretty-printing {fmt}...")
    mod_path, cls_name = _PP_MAP[fmt].rsplit(":", 1)

    def _run():
        import importlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)
        return data | unit_cls() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "format": fmt,
        "input_size": len(data),
        "output_size": len(result),
        "formatted_text": _safe_decode(result)[:8000],
    }, "refinery_pretty_print")


# ===================================================================
#  7. PYTHON BYTECODE DECOMPILATION
# ===================================================================

@tool_decorator
async def refinery_decompile_python(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Decompile Python bytecode (.pyc) files using Binary Refinery.

    Converts compiled Python bytecode back to readable source code.
    Useful for analyzing Python-based malware, PyInstaller bundles,
    and obfuscated Python scripts.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) .pyc file data as hex. If None, uses loaded file.

    Returns:
        Dictionary with decompiled Python source code.
    """
    _require_refinery("refinery_decompile_python")

    data = _get_data_from_hex_or_file(data_hex)
    await ctx.info(f"Decompiling Python bytecode ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.pyc import pyc
        return data | pyc() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "source_code": _safe_decode(result)[:8000],
    }, "refinery_decompile_python")


# ===================================================================
#  8. AUTOIT DECOMPILATION
# ===================================================================

@tool_decorator
async def refinery_decompile_autoit(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Decompile AutoIt scripts (.a3x) using Binary Refinery.

    Extracts and decompiles AutoIt v3 compiled scripts. AutoIt is
    frequently used by malware authors for initial access and
    dropper functionality.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) AutoIt script data as hex. If None, uses loaded file.

    Returns:
        Dictionary with decompiled AutoIt source code.
    """
    _require_refinery("refinery_decompile_autoit")

    data = _get_data_from_hex_or_file(data_hex)
    await ctx.info(f"Decompiling AutoIt script ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.a3x import a3x
        results = []
        for chunk in data | a3x():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "text": _safe_decode(raw)[:4000],
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('name', 'path', 'type'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            results.append(entry)
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "items_found": len(results),
        "results": results,
    }, "refinery_decompile_autoit")


# ===================================================================
#  9. DNS DOMAIN EXTRACTION
# ===================================================================

@tool_decorator
async def refinery_extract_domains(
    ctx: Context,
    data_hex: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Extract DNS domain names from binary data using Binary Refinery.

    Uses DNS wire format parsing to find domain names embedded in binary
    data. More accurate than regex-based extraction for DNS protocol data,
    DNS caches, and raw packet payloads.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        limit: (int) Max domains to extract. Default 200.

    Returns:
        Dictionary with extracted domain names.
    """
    _require_refinery("refinery_extract_domains")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]

    await ctx.info(f"Extracting DNS domains from {len(data)} bytes...")

    def _run():
        from refinery.units.pattern.dnsdomain import dnsdomain
        results = []
        seen = set()
        for chunk in data | dnsdomain():
            domain = bytes(chunk).decode("utf-8", errors="replace").strip()
            if domain and domain not in seen:
                seen.add(domain)
                results.append(domain)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "domains_found": len(results),
        "data_size": len(data),
        "domains": results,
    }, "refinery_extract_domains")
