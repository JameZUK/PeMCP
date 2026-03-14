"""MCP tools powered by Binary Refinery for advanced transformations.

Covers regex operations, automatic XOR decryption, key derivation,
string operations, pretty-printing, decompilation, and domain extraction.
"""
import asyncio

from typing import Dict, Any, Optional, List

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._refinery_helpers import (
    _require_refinery, _safe_decode, _bytes_to_hex, _hex_to_bytes,
    _get_file_data, _get_data_from_hex_or_file,
    _write_output_and_register_artifact,
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
    limit: int = 20,
) -> Dict[str, Any]:
    """Extract regex matches from binary data via Binary Refinery.

    Args:
        ctx: MCP Context.
        pattern: (str) Python regex pattern. Use (?P<name>...) for named groups.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        limit: (int) Max matches. Default 200.

    Returns:
        Dictionary with all regex matches.
    """
    _require_refinery("refinery_regex_extract")

    # H1-v9: Validate regex against ReDoS before passing to refinery
    from arkana.utils import validate_regex_pattern
    validate_regex_pattern(pattern)

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
            if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                for key in ("offset", "group", "match"):
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
    """Find and replace using regex in binary data via Binary Refinery.

    Args:
        ctx: MCP Context.
        pattern: (str) Python regex pattern.
        replacement: (str) Replacement string (supports backreferences \\1, \\g<name>).
        data_hex: (str) Input data as hex.

    Returns:
        Dictionary with transformed output.
    """
    _require_refinery("refinery_regex_replace")

    # H1-v9: Validate regex against ReDoS before passing to refinery
    from arkana.utils import validate_regex_pattern
    validate_regex_pattern(pattern)

    try:
        data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        data = data_hex.encode("utf-8")

    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Regex replace: {pattern} -> {replacement}")

    def _run():
        from refinery.units.pattern.resub import resub
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
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Auto-detect and decrypt XOR/SUB encrypted data via Binary Refinery.

    Uses frequency analysis, known plaintext attacks, and file signature
    detection to automatically recover the encryption key.

    Args:
        ctx: MCP Context.
        data_hex: (Optional[str]) Encrypted data as hex. If None, uses loaded file.
        output_path: (Optional[str]) Save decrypted output to this path and register as artifact.

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
        return data | autoxor() | bytes

    result = await asyncio.to_thread(_run)
    response: Dict[str, Any] = {
        "input_size": len(data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }
    if output_path:
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, result, "refinery_auto_decrypt",
            "Auto-decrypted data",
        )
        response["artifact"] = artifact_meta
    return await _check_mcp_response_size(ctx, response, "refinery_auto_decrypt")


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
    """Derive cryptographic keys from passwords via Binary Refinery.

    Methods: pbkdf2, hkdf, hmac.

    Args:
        ctx: MCP Context.
        method: (str) Derivation method.
        password_hex: (str) Password/input key material as hex.
        salt_hex: (Optional[str]) Salt as hex.
        key_length: (int) Desired key length in bytes. Default 32.
        iterations: (int) Iteration count for PBKDF2. Default 10000.
        hash_algorithm: (str) Hash: SHA256, SHA1, SHA512, MD5. Default SHA256.

    Returns:
        Dictionary with the derived key.
    """
    _require_refinery("refinery_key_derive")

    # H2-v9: Bound iterations and key_length to prevent CPU/memory exhaustion
    _MAX_ITERATIONS = 10_000_000
    _MAX_KEY_LENGTH = 1024
    if iterations < 1 or iterations > _MAX_ITERATIONS:
        raise ValueError(f"iterations must be 1-{_MAX_ITERATIONS}, got {iterations}")
    if key_length < 1 or key_length > _MAX_KEY_LENGTH:
        raise ValueError(f"key_length must be 1-{_MAX_KEY_LENGTH}, got {key_length}")

    password = _hex_to_bytes(password_hex)
    salt = _hex_to_bytes(salt_hex) if salt_hex else b""

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
        return b""

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
    """String/binary operations via Binary Refinery.

    Operations: snip (byte slice), trim, replace (old_hex:new_hex), lower, upper, swapcase.

    Args:
        ctx: MCP Context.
        data_hex: (str) Input data as hex.
        operation: (str) Operation name.
        argument: (Optional[str]) Operation-specific argument.

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
            # M3-v9: Add bounds validation and error handling for snip indices
            try:
                parts = (argument or op).replace("snip:", "").replace("snip", "").split(":")
                parts = [p.strip() for p in parts if p.strip()]
                max_idx = max(len(data) * 2, 1)
                parsed = []
                for p in parts:
                    v = int(p)
                    if abs(v) > max_idx:
                        raise ValueError(f"Slice index {v} out of reasonable range (max {max_idx})")
                    parsed.append(v)
                if len(parsed) == 0:
                    s = slice(None)
                elif len(parsed) == 1:
                    s = slice(parsed[0])
                elif len(parsed) == 2:
                    s = slice(parsed[0], parsed[1])
                else:
                    s = slice(parsed[0], parsed[1], parsed[2])
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid snip argument: {e}")
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
            new = bytes.fromhex(parts[1]) if len(parts) > 1 else b""
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
#  6. PRETTY-PRINT
# ===================================================================

@tool_decorator
async def refinery_pretty_print(
    ctx: Context,
    data_hex: str,
    format: str = "json",
) -> Dict[str, Any]:
    """Pretty-print structured data via Binary Refinery.

    Formats: json, xml, js/javascript.

    Args:
        ctx: MCP Context.
        data_hex: (str) Data as hex.
        format: (str) Format: 'json', 'xml', 'js'. Default 'json'.

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
#  7. DECOMPILATION (merged Python + AutoIt)
# ===================================================================

@tool_decorator
async def refinery_decompile(
    ctx: Context,
    language: str,
    data_hex: Optional[str] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Decompile bytecode/compiled scripts via Binary Refinery.

    Languages:
    - 'python': Decompile Python bytecode (.pyc) to source.
    - 'autoit': Decompile AutoIt scripts (.a3x).

    Args:
        ctx: MCP Context.
        language: (str) 'python' or 'autoit'.
        data_hex: (Optional[str]) Compiled data as hex. If None, uses loaded file.
        output_path: (Optional[str]) Save decompiled source to this path and register as artifact.

    Returns:
        Dictionary with decompiled source code.
    """
    _require_refinery("refinery_decompile")

    data = _get_data_from_hex_or_file(data_hex)
    lang = language.lower()

    if lang not in ("python", "autoit"):
        return {"error": f"Unknown language '{language}'.", "supported": ["python", "autoit"]}

    await ctx.info(f"Decompiling {lang} ({len(data)} bytes)...")

    if lang == "python":
        def _run_python():
            from refinery.units.formats.pyc import pyc
            return data | pyc() | bytes

        result = await asyncio.to_thread(_run_python)
        response: Dict[str, Any] = {
            "language": lang,
            "input_size": len(data),
            "output_size": len(result),
            "source_code": _safe_decode(result)[:8000],
        }
        if output_path:
            artifact_meta = await asyncio.to_thread(
                _write_output_and_register_artifact,
                output_path, result, "refinery_decompile",
                f"Decompiled {lang} source",
            )
            response["artifact"] = artifact_meta
        return await _check_mcp_response_size(ctx, response, "refinery_decompile")

    # lang == "autoit"
    def _run_autoit():
        from refinery.units.formats.a3x import a3x
        results = []
        for chunk in data | a3x():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "text": _safe_decode(raw)[:4000],
            }
            if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                for key in ("name", "path", "type"):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            results.append(entry)
        return results

    results = await asyncio.to_thread(_run_autoit)
    response = {
        "language": lang,
        "input_size": len(data),
        "items_found": len(results),
        "results": results,
    }
    if output_path:
        import json as _json
        text_bytes = _json.dumps(results, indent=2, default=str).encode("utf-8")
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, text_bytes, "refinery_decompile",
            f"Decompiled AutoIt ({len(results)} items)",
        )
        response["artifact"] = artifact_meta
    return await _check_mcp_response_size(ctx, response, "refinery_decompile")


# ===================================================================
#  8. DNS DOMAIN EXTRACTION
# ===================================================================

@tool_decorator
async def refinery_extract_domains(
    ctx: Context,
    data_hex: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """Extract DNS domain names from binary data via Binary Refinery.

    Uses DNS wire format parsing (more accurate than regex for DNS data).

    Args:
        ctx: MCP Context.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        limit: (int) Max domains. Default 200.

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
