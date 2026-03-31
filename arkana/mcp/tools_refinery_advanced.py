"""MCP tools powered by Binary Refinery for advanced transformations.

Covers regex operations, automatic XOR decryption, key derivation,
string operations, pretty-printing, decompilation, and domain extraction.
"""
import asyncio

from typing import Dict, Any, Optional, List

from arkana.config import state, logger, Context
from arkana.constants import MAX_TOOL_LIMIT
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

    ---compact: extract regex matches from binary data | named groups supported | needs: refinery

    Args:
        ctx: MCP Context.
        pattern: (str) Python regex pattern. Use (?P<name>...) for named groups.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        limit: (int) Max matches. Default 20.

    Returns:
        Dictionary with all regex matches.
    """
    _require_refinery("refinery_regex_extract")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))

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
                "match_text": _safe_decode(raw, max_len=500),
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

    ---compact: regex find-and-replace in binary data | backreferences supported | needs: refinery

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

    _used_text_fallback = False
    try:
        data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        logger.warning("refinery_regex_replace: input is not valid hex, treating as raw text")
        data = data_hex.encode("utf-8")
        _used_text_fallback = True

    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Regex replace: {pattern} -> {replacement}")

    def _run():
        from refinery.units.pattern.resub import resub
        repl_bytes = replacement.encode("utf-8") if isinstance(replacement, str) else replacement
        return data | resub(pattern, repl_bytes) | bytes

    result = await asyncio.to_thread(_run)
    response: Dict[str, Any] = {
        "pattern": pattern,
        "replacement": replacement,
        "input_size": len(data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result, max_len=2000),
    }
    if _used_text_fallback:
        response["_warning"] = "Input was not valid hex — treated as raw UTF-8 text. Verify your input."
    return await _check_mcp_response_size(ctx, response, "refinery_regex_replace")


# ===================================================================
#  3. AUTOMATIC XOR/SUB DECRYPTION
# ===================================================================

@tool_decorator
async def refinery_auto_decrypt(
    ctx: Context,
    data_hex: Optional[str] = None,
    output_path: Optional[str] = None,
    plaintext_hex: Optional[str] = None,
    key_range_max: int = 32,
) -> Dict[str, Any]:
    """Auto-detect and decrypt XOR/SUB encrypted data via Binary Refinery.

    Uses frequency analysis, known plaintext attacks, and file signature
    detection to automatically recover the encryption key.

    ---compact: auto-detect + decrypt XOR/SUB encryption | frequency analysis | needs: refinery

    Args:
        ctx: MCP Context.
        data_hex: (Optional[str]) Encrypted data as hex. If None, uses loaded file.
        output_path: (Optional[str]) Save decrypted output to this path and register as artifact.
        plaintext_hex: (Optional[str]) Known plaintext crib as hex for known-plaintext attack.
        key_range_max: (int) Maximum key length to try (default 32 bytes, max 256).

    Returns:
        Dictionary with decrypted output and detected key.
    """
    _require_refinery("refinery_auto_decrypt")

    # Validate key_range_max bounds
    key_range_max = max(1, min(key_range_max, 256))

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]

    # Validate plaintext_hex if provided
    plaintext_bytes = None
    if plaintext_hex:
        plaintext_bytes = _hex_to_bytes(plaintext_hex)

    await ctx.info(f"Auto-decrypting {len(data)} bytes (key range 1-{key_range_max})...")

    def _run():
        from refinery.units.misc.autoxor import autoxor
        kwargs: Dict[str, Any] = {}
        if plaintext_bytes:
            kwargs["plaintext"] = plaintext_bytes
        kwargs["range"] = slice(1, key_range_max + 1)
        return data | autoxor(**kwargs) | bytes

    result = await asyncio.to_thread(_run)
    response: Dict[str, Any] = {
        "input_size": len(data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result, max_len=2000),
        "key_range_max": key_range_max,
    }
    if plaintext_hex:
        response["plaintext_crib"] = plaintext_hex
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

    Methods: pbkdf2, hkdf, hmac, scrypt, argon2, pbkdf1, deskd, kblob, mscdk, mspdb, unixcrypt.

    ---compact: derive keys from passwords | pbkdf2, hkdf, scrypt, argon2 + 7 more | needs: refinery

    Args:
        ctx: MCP Context.
        method: (str) Derivation method.
        password_hex: (str) Password/input key material as hex.
        salt_hex: (Optional[str]) Salt as hex.
        key_length: (int) Desired key length in bytes. Default 32.
        iterations: (int) Iteration count for iterative KDFs (pbkdf2, argon2, pbkdf1, mspdb). Default 10000.
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
        "scrypt": "refinery.units.crypto.keyderive.scrypt:scrypt",
        "argon2": "refinery.units.crypto.keyderive.argon2:argon2",
        "pbkdf1": "refinery.units.crypto.keyderive.pbkdf1:pbkdf1",
        "deskd": "refinery.units.crypto.keyderive.deskd:deskd",
        "kblob": "refinery.units.crypto.keyderive.kblob:kblob",
        "mscdk": "refinery.units.crypto.keyderive.mscdk:mscdk",
        "mspdb": "refinery.units.crypto.keyderive.mspdb:mspdb",
        "unixcrypt": "refinery.units.crypto.keyderive.unixcrypt:ucrypt",
    }

    # KDFs that use iterations
    _ITERATIVE_KDFS = {"pbkdf2", "argon2", "pbkdf1", "mspdb"}

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
        elif method_lower == "scrypt":
            return password | unit_cls(key_length, salt) | bytes
        elif method_lower == "argon2":
            return password | unit_cls(key_length, salt, iter=iterations) | bytes
        elif method_lower == "pbkdf1":
            return password | unit_cls(key_length, salt, iter=iterations, hash=hash_algorithm) | bytes
        elif method_lower == "deskd":
            return password | unit_cls(key_length) | bytes
        elif method_lower == "kblob":
            return password | unit_cls() | bytes
        elif method_lower == "mscdk":
            return password | unit_cls(key_length, hash=hash_algorithm) | bytes
        elif method_lower == "mspdb":
            return password | unit_cls(key_length, salt, iter=iterations, hash=hash_algorithm) | bytes
        elif method_lower == "unixcrypt":
            return password | unit_cls() | bytes
        else:
            # Generic fallback — introspect constructor params
            import inspect
            kdf_kwargs: Dict[str, Any] = {}
            try:
                sig = inspect.signature(unit_cls.__init__)
                params = set(sig.parameters.keys()) - {"self"}
                if "size" in params and key_length:
                    kdf_kwargs["size"] = key_length
                if "salt" in params and salt:
                    kdf_kwargs["salt"] = salt
                if "iter" in params and iterations > 1:
                    kdf_kwargs["iter"] = iterations
                if "hash" in params and hash_algorithm:
                    kdf_kwargs["hash"] = hash_algorithm
            except Exception:
                pass
            return password | unit_cls(**kdf_kwargs) | bytes

    result = await asyncio.to_thread(_run)
    response: Dict[str, Any] = {
        "method": method,
        "hash_algorithm": hash_algorithm,
        "key_length": key_length,
        "iterations": iterations if method_lower in _ITERATIVE_KDFS else None,
        "derived_key_hex": result.hex(),
        "derived_key_length": len(result),
    }
    if method_lower == "hmac":
        response["note"] = f"HMAC output size is determined by {hash_algorithm} digest length, not key_length parameter."
    elif method_lower == "kblob":
        response["note"] = "kblob extracts key material from Windows DPAPI/CNG key blobs. key_length parameter is ignored."
    elif method_lower == "unixcrypt":
        response["note"] = "unixcrypt derives a DES-based Unix crypt hash. key_length parameter is ignored."
    elif method_lower == "deskd":
        response["note"] = "deskd derives DES key material. salt and iterations parameters are ignored."
    return await _check_mcp_response_size(ctx, response, "refinery_key_derive")


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

    ---compact: string/binary transforms | snip, trim, replace, case ops | needs: refinery

    Args:
        ctx: MCP Context.
        data_hex: (str) Input data as hex.
        operation: (str) Operation name.
        argument: (Optional[str]) Operation-specific argument.

    Returns:
        Dictionary with transformed output.
    """
    _require_refinery("refinery_string_operations")

    _used_text_fallback = False
    try:
        data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        logger.warning("refinery_string_operations: input is not valid hex, treating as raw text")
        data = data_hex.encode("utf-8")
        _used_text_fallback = True

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
            _MAX_HEX_INPUT_LEN = 2_000_000  # 2M hex chars = 1MB decoded
            for _p in parts:
                if len(_p) > _MAX_HEX_INPUT_LEN:
                    raise ValueError(
                        f"Hex argument too large ({len(_p):,} chars, "
                        f"limit {_MAX_HEX_INPUT_LEN:,})."
                    )
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
    response: Dict[str, Any] = {
        "operation": op,
        "input_size": len(data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result, max_len=2000),
    }
    if _used_text_fallback:
        response["_warning"] = "Input was not valid hex — treated as raw UTF-8 text. Verify your input."
    return await _check_mcp_response_size(ctx, response, "refinery_string_operations")


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

    ---compact: pretty-print structured data | json, xml, javascript | needs: refinery

    Args:
        ctx: MCP Context.
        data_hex: (str) Data as hex.
        format: (str) Format: 'json', 'xml', 'js'. Default 'json'.

    Returns:
        Dictionary with formatted output text.
    """
    _require_refinery("refinery_pretty_print")

    _used_text_fallback = False
    try:
        data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        logger.warning("refinery_pretty_print: input is not valid hex, treating as raw text")
        data = data_hex.encode("utf-8")
        _used_text_fallback = True

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
    response: Dict[str, Any] = {
        "format": fmt,
        "input_size": len(data),
        "output_size": len(result),
        "formatted_text": _safe_decode(result, max_len=8000),
    }
    if _used_text_fallback:
        response["_warning"] = "Input was not valid hex — treated as raw UTF-8 text. Verify your input."
    return await _check_mcp_response_size(ctx, response, "refinery_pretty_print")


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

    ---compact: decompile Python .pyc or AutoIt .a3x to source | needs: refinery

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
            "source_code": _safe_decode(result, max_len=8000),
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
                "text": _safe_decode(raw, max_len=4000),
            }
            if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                for key in ("name", "path", "type"):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            results.append(entry)
            if len(results) >= _MAX_OUTPUT_ITEMS:
                break
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

    ---compact: extract DNS domains via wire format parsing | needs: refinery

    Args:
        ctx: MCP Context.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        limit: (int) Max domains. Default 20.

    Returns:
        Dictionary with extracted domain names.
    """
    _require_refinery("refinery_extract_domains")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))

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
