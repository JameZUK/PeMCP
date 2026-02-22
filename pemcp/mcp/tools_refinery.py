"""MCP tools powered by Binary Refinery for data transformation and analysis.

Binary Refinery (https://github.com/binref/refinery) provides 200+ composable
units for binary data transformation — encryption, encoding, compression,
pattern extraction, PE operations, and script deobfuscation.  These MCP tools
expose the most useful refinery capabilities for malware triage and binary
analysis workflows.
"""
import asyncio

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.mcp._refinery_helpers import (
    _require_refinery, _hex_to_bytes, _bytes_to_hex, _safe_decode,
    _get_file_data, _MAX_INPUT_SIZE_SMALL as _MAX_INPUT_SIZE,
    _MAX_OUTPUT_ITEMS,
)


# ===================================================================
#  1. ENCODING / DECODING
# ===================================================================

@tool_decorator
async def refinery_decode(
    ctx: Context,
    data_hex: str,
    encoding: str = "b64",
) -> Dict[str, Any]:
    """
    Decode data using Binary Refinery encoding units.

    Supports: b64, hex, b32, b58, b62, b85, a85, b92, url, esc, u16,
    uuenc, netbios, cp1252, wshenc, morse, htmlesc, z85.

    See also: deobfuscate_base64() for pefile-based base64 decoding,
    find_and_decode_encoded_strings() for automatic multi-layer decoding.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Input data as hex string, or raw text for text-based encodings.
        encoding: (str) Encoding to decode. Default 'b64'.

    Returns:
        Dictionary with decoded output (hex + text preview).
    """
    _require_refinery("refinery_decode")
    await ctx.info(f"Decoding with refinery: {encoding}")

    # Map encoding names to refinery unit imports
    _ENCODING_MAP = {
        "b64": "refinery.units.encoding.b64:b64",
        "hex": "refinery.units.encoding.hex:hex",
        "b32": "refinery.units.encoding.b32:b32",
        "b58": "refinery.units.encoding.b58:b58",
        "b62": "refinery.units.encoding.b62:b62",
        "b85": "refinery.units.encoding.b85:b85",
        "a85": "refinery.units.encoding.a85:a85",
        "b92": "refinery.units.encoding.b92:b92",
        "url": "refinery.units.encoding.url:url",
        "esc": "refinery.units.encoding.esc:esc",
        "u16": "refinery.units.encoding.u16:u16",
        "uuenc": "refinery.units.encoding.uuenc:uuenc",
        "netbios": "refinery.units.encoding.netbios:netbios",
        "cp1252": "refinery.units.encoding.cp1252:cp1252",
        "wshenc": "refinery.units.encoding.wshenc:wshenc",
        "morse": "refinery.units.encoding.morse:morse",
        "htmlesc": "refinery.units.encoding.htmlesc:htmlesc",
        "z85": "refinery.units.encoding.z85:z85",
    }

    encoding_lower = encoding.lower()
    if encoding_lower not in _ENCODING_MAP:
        return {
            "error": f"Unknown encoding '{encoding}'.",
            "supported": sorted(_ENCODING_MAP.keys()),
        }

    mod_path, cls_name = _ENCODING_MAP[encoding_lower].rsplit(":", 1)

    try:
        input_data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        input_data = data_hex.encode("utf-8")

    if len(input_data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(input_data)} bytes). Max: {_MAX_INPUT_SIZE}.")

    def _run():
        import importlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)
        return input_data | unit_cls() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "encoding": encoding,
        "input_size": len(input_data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_decode")


@tool_decorator
async def refinery_encode(
    ctx: Context,
    data_hex: str,
    encoding: str = "b64",
) -> Dict[str, Any]:
    """
    Encode data using Binary Refinery encoding units (reverse mode).

    Same encodings as refinery_decode but applies the reverse transform.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Input data as hex string.
        encoding: (str) Encoding to apply. Default 'b64'.

    Returns:
        Dictionary with encoded output.
    """
    _require_refinery("refinery_encode")
    await ctx.info(f"Encoding with refinery: {encoding}")

    _ENCODING_MAP = {
        "b64": "refinery.units.encoding.b64:b64",
        "hex": "refinery.units.encoding.hex:hex",
        "b32": "refinery.units.encoding.b32:b32",
        "b58": "refinery.units.encoding.b58:b58",
        "b62": "refinery.units.encoding.b62:b62",
        "b85": "refinery.units.encoding.b85:b85",
        "a85": "refinery.units.encoding.a85:a85",
        "url": "refinery.units.encoding.url:url",
        "u16": "refinery.units.encoding.u16:u16",
        "uuenc": "refinery.units.encoding.uuenc:uuenc",
    }

    encoding_lower = encoding.lower()
    if encoding_lower not in _ENCODING_MAP:
        return {"error": f"Unknown encoding '{encoding}'.", "supported": sorted(_ENCODING_MAP.keys())}

    mod_path, cls_name = _ENCODING_MAP[encoding_lower].rsplit(":", 1)

    try:
        input_data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        input_data = data_hex.encode("utf-8")

    if len(input_data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(input_data)} bytes).")

    def _run():
        import importlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)
        # Negate the unit for reverse (encoding) mode
        return input_data | -unit_cls() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "encoding": encoding,
        "input_size": len(input_data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_encode")


# ===================================================================
#  2. DECRYPTION / ENCRYPTION
# ===================================================================

@tool_decorator
async def refinery_decrypt(
    ctx: Context,
    data_hex: str,
    algorithm: str,
    key_hex: str,
    iv_hex: Optional[str] = None,
    mode: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Decrypt data using Binary Refinery cipher units.

    Supports 37 ciphers: aes, des, des3, rc4, blowfish, camellia, cast,
    chacha, salsa, serpent, tea, xtea, xxtea, rc2, rc5, rc6, sm4, rabbit,
    seal, gost, fernet, speck, hc128, hc256, isaac, sosemanuk, vigenere,
    rot, rijndael, chaskey, blabla, rncrypt, codebook, rc4mod, secstr.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Ciphertext as hex string.
        algorithm: (str) Cipher name (e.g. 'aes', 'rc4', 'des').
        key_hex: (str) Key as hex string.
        iv_hex: (Optional[str]) IV/nonce as hex string. Required for CBC/CTR modes.
        mode: (Optional[str]) Block cipher mode: ECB, CBC, CTR, CFB, OFB, GCM. Default varies by cipher.

    Returns:
        Dictionary with decrypted plaintext (hex + text preview).
    """
    _require_refinery("refinery_decrypt")
    await ctx.info(f"Decrypting with {algorithm}" + (f" mode={mode}" if mode else ""))

    _CIPHER_MAP = {
        "aes": "refinery.units.crypto.cipher.aes:aes",
        "des": "refinery.units.crypto.cipher.des:des",
        "des3": "refinery.units.crypto.cipher.des3:des3",
        "rc4": "refinery.units.crypto.cipher.rc4:rc4",
        "blowfish": "refinery.units.crypto.cipher.blowfish:blowfish",
        "camellia": "refinery.units.crypto.cipher.camellia:camellia",
        "cast": "refinery.units.crypto.cipher.cast:cast",
        "chacha": "refinery.units.crypto.cipher.chacha:chacha",
        "salsa": "refinery.units.crypto.cipher.salsa:salsa",
        "serpent": "refinery.units.crypto.cipher.serpent:serpent",
        "tea": "refinery.units.crypto.cipher.tea:tea",
        "xtea": "refinery.units.crypto.cipher.xtea:xtea",
        "xxtea": "refinery.units.crypto.cipher.xxtea:xxtea",
        "rc2": "refinery.units.crypto.cipher.rc2:rc2",
        "rc5": "refinery.units.crypto.cipher.rc5:rc5",
        "rc6": "refinery.units.crypto.cipher.rc6:rc6",
        "sm4": "refinery.units.crypto.cipher.sm4:sm4",
        "rabbit": "refinery.units.crypto.cipher.rabbit:rabbit",
        "seal": "refinery.units.crypto.cipher.seal:seal",
        "gost": "refinery.units.crypto.cipher.gost:gost",
        "fernet": "refinery.units.crypto.cipher.fernet:fernet",
        "speck": "refinery.units.crypto.cipher.speck:speck",
        "hc128": "refinery.units.crypto.cipher.hc128:hc128",
        "hc256": "refinery.units.crypto.cipher.hc256:hc256",
        "isaac": "refinery.units.crypto.cipher.isaac:isaac",
        "sosemanuk": "refinery.units.crypto.cipher.sosemanuk:sosemanuk",
        "vigenere": "refinery.units.crypto.cipher.vigenere:vigenere",
        "rot": "refinery.units.crypto.cipher.rot:rot",
        "rijndael": "refinery.units.crypto.cipher.rijndael:rijndael",
        "chaskey": "refinery.units.crypto.cipher.chaskey:chaskey",
        "blabla": "refinery.units.crypto.cipher.blabla:blabla",
        "rncrypt": "refinery.units.crypto.cipher.rncrypt:rncrypt",
        "codebook": "refinery.units.crypto.cipher.codebook:codebook",
        "rc4mod": "refinery.units.crypto.cipher.rc4mod:rc4mod",
        "secstr": "refinery.units.crypto.cipher.secstr:secstr",
    }

    algo = algorithm.lower()
    if algo not in _CIPHER_MAP:
        return {"error": f"Unknown cipher '{algorithm}'.", "supported": sorted(_CIPHER_MAP.keys())}

    mod_path, cls_name = _CIPHER_MAP[algo].rsplit(":", 1)

    ciphertext = _hex_to_bytes(data_hex)
    key = _hex_to_bytes(key_hex)

    if len(ciphertext) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(ciphertext)} bytes).")

    kwargs: Dict[str, Any] = {"key": key}
    if iv_hex:
        kwargs["iv"] = _hex_to_bytes(iv_hex)
    if mode:
        kwargs["mode"] = mode.upper()

    def _run():
        import importlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)
        return ciphertext | unit_cls(**kwargs) | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "algorithm": algorithm,
        "mode": mode or "default",
        "input_size": len(ciphertext),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_decrypt")


# ===================================================================
#  3. XOR OPERATIONS
# ===================================================================

@tool_decorator
async def refinery_xor(
    ctx: Context,
    data_hex: str,
    key_hex: str,
) -> Dict[str, Any]:
    """
    Apply XOR with a single-byte or multi-byte key using Binary Refinery.

    Handles repeating-key XOR automatically. For single-byte, pass a 1-byte key.

    See also: deobfuscate_xor_single_byte() for pefile-based single-byte XOR,
    deobfuscate_xor_multi_byte() for multi-byte XOR with key rotation.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Data as hex string.
        key_hex: (str) XOR key as hex string (e.g. '41' for single-byte, '4d414c57' for multi-byte).

    Returns:
        Dictionary with XOR result (hex + text preview).
    """
    _require_refinery("refinery_xor")

    data = _hex_to_bytes(data_hex)
    key = _hex_to_bytes(key_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"XOR with {len(key)}-byte key: {key.hex()}")

    def _run():
        from refinery.units.blockwise.xor import xor
        return data | xor(key) | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "key_hex": key.hex(),
        "key_length": len(key),
        "input_size": len(data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_xor")


@tool_decorator
async def refinery_xor_guess_key(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Automatically guess the XOR key used to encrypt data using Binary Refinery's xkey unit.

    Can operate on provided hex data or on the currently loaded file's raw bytes.
    Uses statistical analysis to find the most likely XOR key.

    See also: bruteforce_xor_key() for pefile-based brute-force key guessing.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Data as hex string. If None, uses the loaded file.

    Returns:
        Dictionary with the guessed key and a preview of decrypted data.
    """
    _require_refinery("refinery_xor_guess_key")

    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
        data = _get_file_data()

    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]
        await ctx.warning(f"Data truncated to {_MAX_INPUT_SIZE} bytes for key guessing.")

    await ctx.info(f"Guessing XOR key for {len(data)} bytes of data...")

    def _run():
        from refinery.units.misc.xkey import xkey
        keys = []
        for chunk in data | xkey():
            keys.append(bytes(chunk))
        return keys

    keys = await asyncio.to_thread(_run)

    if not keys:
        return {"status": "no_key_found", "message": "Could not determine XOR key."}

    # Decrypt with the first (best) key
    best_key = keys[0]

    def _decrypt():
        from refinery.units.blockwise.xor import xor
        return data[:512] | xor(best_key) | bytes

    preview = await asyncio.to_thread(_decrypt)

    return await _check_mcp_response_size(ctx, {
        "guessed_key_hex": best_key.hex(),
        "guessed_key_length": len(best_key),
        "guessed_key_ascii": _safe_decode(best_key),
        "decrypted_preview_hex": preview.hex(),
        "decrypted_preview_text": _safe_decode(preview)[:500],
        "total_candidates": len(keys),
    }, "refinery_xor_guess_key")


# ===================================================================
#  4. COMPRESSION / DECOMPRESSION
# ===================================================================

@tool_decorator
async def refinery_decompress(
    ctx: Context,
    data_hex: Optional[str] = None,
    algorithm: str = "auto",
) -> Dict[str, Any]:
    """
    Decompress data using Binary Refinery.

    The 'auto' mode tries all known compression algorithms automatically.
    Specific algorithms: zl (zlib/deflate), bz2, lzma, lz4, brotli, zstd,
    lznt1, lzo, ap (aPlib), blz, lzf, lzg, lzip, lzjb, lzw, lzx,
    mscf (CAB), nrv (NRV/UCL), pkw, qlz, szdd, flz, jcalg.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Compressed data as hex. If None, uses loaded file data.
        algorithm: (str) Compression algorithm or 'auto'. Default 'auto'.

    Returns:
        Dictionary with decompressed output (hex + text preview + size).
    """
    _require_refinery("refinery_decompress")

    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
        data = _get_file_data()

    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    algo = algorithm.lower()
    await ctx.info(f"Decompressing with: {algo}")

    _COMPRESS_MAP = {
        "auto": "refinery.units.compression.decompress:decompress",
        "zl": "refinery.units.compression.zl:zl",
        "bz2": "refinery.units.compression.bz2:bz2",
        "lz4": "refinery.units.compression.lz4:lz4",
        "brotli": "refinery.units.compression.brotli:brotli",
        "zstd": "refinery.units.compression.zstd:zstd",
        "lznt1": "refinery.units.compression.lznt1:lznt1",
        "lzo": "refinery.units.compression.lzo:lzo",
        "ap": "refinery.units.compression.ap:ap",
        "lzma": "refinery.units.compression.lz:lzma",
        "blz": "refinery.units.compression.blz:blz",
        "lzf": "refinery.units.compression.lzf:lzf",
        "lzg": "refinery.units.compression.lzg:lzg",
        "lzip": "refinery.units.compression.lzip:lzip",
        "lzjb": "refinery.units.compression.lzjb:lzjb",
        "lzw": "refinery.units.compression.lzw:lzw",
        "lzx": "refinery.units.compression.lzx:lzx",
        "mscf": "refinery.units.compression.mscf:mscf",
        "nrv": "refinery.units.compression.nrv:nrv",
        "pkw": "refinery.units.compression.pkw:pkw",
        "qlz": "refinery.units.compression.qlz:qlz",
        "szdd": "refinery.units.compression.szdd:szdd",
        "flz": "refinery.units.compression.flz:flz",
        "jcalg": "refinery.units.compression.jcalg:jcalg",
    }

    if algo not in _COMPRESS_MAP:
        return {"error": f"Unknown algorithm '{algorithm}'.", "supported": sorted(_COMPRESS_MAP.keys())}

    mod_path, cls_name = _COMPRESS_MAP[algo].rsplit(":", 1)

    def _run():
        import importlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)
        return data | unit_cls() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "algorithm": algo,
        "input_size": len(data),
        "output_size": len(result),
        "compression_ratio": round(len(result) / max(len(data), 1), 2),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_decompress")


# ===================================================================
#  5. PATTERN EXTRACTION (IOCs, URLs, IPs, emails, etc.)
# ===================================================================

@tool_decorator
async def refinery_extract_iocs(
    ctx: Context,
    data_hex: Optional[str] = None,
    indicator_type: str = "all",
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Extract indicators of compromise (IOCs) from data using Binary Refinery's xtp unit.

    The xtp unit is a powerful regex-based indicator extractor that supports:
    url, ipv4, ipv6, email, domain, path, hostname, md5, sha1, sha256, guid,
    and more. Use 'all' to extract all indicator types at once.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Data as hex string. If None, uses loaded file's strings.
        indicator_type: (str) Type of indicator: 'all', 'url', 'ipv4', 'ipv6',
            'email', 'domain', 'path', 'hostname', 'md5', 'sha1', 'sha256', 'guid'.
        limit: (int) Maximum number of results. Default 200.

    Returns:
        Dictionary with extracted indicators grouped by type.
    """
    _require_refinery("refinery_extract_iocs")

    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
        # Use loaded file data
        data = _get_file_data()

    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]
        await ctx.warning(f"Data truncated to {_MAX_INPUT_SIZE} bytes for IOC extraction.")

    itype = indicator_type.lower()
    await ctx.info(f"Extracting IOCs (type={itype}) from {len(data)} bytes...")

    _XTP_TYPES = ["url", "ipv4", "ipv6", "email", "domain", "path", "hostname",
                  "md5", "sha1", "sha256", "guid"]

    types_to_scan = _XTP_TYPES if itype == "all" else [itype]

    def _run():
        from refinery.units.pattern.xtp import xtp
        results = {}
        for t in types_to_scan:
            try:
                found = []
                for chunk in data | xtp(t):
                    val = bytes(chunk).decode("utf-8", errors="replace")
                    if val not in found:
                        found.append(val)
                    if len(found) >= limit:
                        break
                if found:
                    results[t] = found
            except Exception as e:
                logger.debug("xtp(%s) failed: %s", t, e)
        return results

    results = await asyncio.to_thread(_run)
    total = sum(len(v) for v in results.values())
    return await _check_mcp_response_size(ctx, {
        "indicator_type": itype,
        "total_found": total,
        "by_type": results,
        "data_size": len(data),
    }, "refinery_extract_iocs")


# ===================================================================
#  6. PATTERN CARVING (embedded files, encoded blobs)
# ===================================================================

@tool_decorator
async def refinery_carve(
    ctx: Context,
    pattern: str = "b64",
    data_hex: Optional[str] = None,
    decode: bool = True,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Carve and optionally decode embedded patterns from data using Binary Refinery.

    The carve unit extracts data matching common encoding patterns.
    Supported patterns: b64, hex, b32, b85, url, intarray, string.

    For file carving (extracting embedded PE, ZIP, etc.), use refinery_carve_files.

    Args:
        ctx: The MCP Context object.
        pattern: (str) Pattern to carve: 'b64', 'hex', 'b32', 'b85', 'url', 'intarray', 'string'.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        decode: (bool) Automatically decode carved data. Default True.
        limit: (int) Max items to return. Default 50.

    Returns:
        Dictionary with carved (and optionally decoded) data blobs.
    """
    _require_refinery("refinery_carve")

    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
        data = _get_file_data()

    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]

    await ctx.info(f"Carving pattern '{pattern}' from {len(data)} bytes...")

    def _run():
        from refinery.units.pattern.carve import carve
        results = []
        for chunk in data | carve(pattern):
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "raw_hex": _bytes_to_hex(raw, 512),
                "raw_text": _safe_decode(raw)[:200],
                "size": len(raw),
            }
            if decode:
                try:
                    # Decode the carved pattern
                    _ENC_MAP = {
                        "b64": "refinery.units.encoding.b64:b64",
                        "hex": "refinery.units.encoding.hex:hex",
                        "b32": "refinery.units.encoding.b32:b32",
                        "b85": "refinery.units.encoding.b85:b85",
                        "url": "refinery.units.encoding.url:url",
                    }
                    if pattern in _ENC_MAP:
                        import importlib
                        mod_path, cls_name = _ENC_MAP[pattern].rsplit(":", 1)
                        mod = importlib.import_module(mod_path)
                        unit_cls = getattr(mod, cls_name)
                        decoded = raw | unit_cls() | bytes
                        entry["decoded_hex"] = _bytes_to_hex(decoded, 512)
                        entry["decoded_text"] = _safe_decode(decoded)[:200]
                        entry["decoded_size"] = len(decoded)
                except Exception as e:
                    entry["decode_error"] = str(e)
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "pattern": pattern,
        "items_found": len(results),
        "decode_applied": decode,
        "results": results,
    }, "refinery_carve")


@tool_decorator
async def refinery_carve_files(
    ctx: Context,
    file_type: str = "pe",
    data_hex: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    Carve embedded files from data using Binary Refinery.

    Extracts complete embedded files (PE executables, ZIP archives, etc.)
    from binary data — useful for finding packed/embedded payloads.

    Supported types: pe, zip, 7z, rtf, json, xml, lnk, der (certificates).

    Args:
        ctx: The MCP Context object.
        file_type: (str) File type to carve: 'pe', 'zip', '7z', 'rtf', 'json', 'xml', 'lnk', 'der'.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        limit: (int) Max files to extract. Default 20.

    Returns:
        Dictionary with carved file metadata (offsets, sizes, hashes).
    """
    _require_refinery("refinery_carve_files")

    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
        data = _get_file_data()

    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]

    _CARVE_MAP = {
        "pe": "refinery.units.pattern.carve_pe:carve_pe",
        "zip": "refinery.units.pattern.carve_zip:carve_zip",
        "7z": "refinery.units.pattern.carve_7z:carve_7z",
        "rtf": "refinery.units.pattern.carve_rtf:carve_rtf",
        "json": "refinery.units.pattern.carve_json:carve_json",
        "xml": "refinery.units.pattern.carve_xml:carve_xml",
        "lnk": "refinery.units.pattern.carve_lnk:carve_lnk",
        "der": "refinery.units.pattern.carve_der:carve_der",
    }

    ftype = file_type.lower()
    if ftype not in _CARVE_MAP:
        return {"error": f"Unknown type '{file_type}'.", "supported": sorted(_CARVE_MAP.keys())}

    await ctx.info(f"Carving embedded {ftype.upper()} files from {len(data)} bytes...")
    mod_path, cls_name = _CARVE_MAP[ftype].rsplit(":", 1)

    def _run():
        import importlib
        import hashlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)
        results = []
        for chunk in data | unit_cls():
            raw = bytes(chunk)
            results.append({
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "md5": hashlib.md5(raw).hexdigest(),
                "preview_hex": raw[:64].hex(),
            })
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "file_type": ftype,
        "files_found": len(results),
        "data_size": len(data),
        "results": results,
    }, "refinery_carve_files")


# ===================================================================
#  7. PE FILE OPERATIONS
# ===================================================================

@tool_decorator
async def refinery_pe_operations(
    ctx: Context,
    operation: str,
) -> Dict[str, Any]:
    """
    Perform PE-specific operations using Binary Refinery's PE units.

    Operations:
    - 'overlay': Extract PE overlay data (appended after the last section).
    - 'meta': Extract PE metadata (version info, timestamps, etc.).
    - 'resources': Extract PE resources as separate items.
    - 'strip': Remove overlay and debug data to get a minimal PE.
    - 'debloat': Remove bloated sections (large zero-filled regions packers add).
    - 'signature': Extract Authenticode signature data.

    Args:
        ctx: The MCP Context object.
        operation: (str) Operation to perform: 'overlay', 'meta', 'resources',
            'strip', 'debloat', 'signature'.

    Returns:
        Dictionary with operation results.
    """
    _require_refinery("refinery_pe_operations")
    _check_pe_loaded("refinery_pe_operations")

    data = _get_file_data()
    op = operation.lower()

    _OP_MAP = {
        "overlay": "refinery.units.formats.pe.peoverlay:peoverlay",
        "meta": "refinery.units.formats.pe.pemeta:pemeta",
        "resources": "refinery.units.formats.pe.perc:perc",
        "strip": "refinery.units.formats.pe.pestrip:pestrip",
        "debloat": "refinery.units.formats.pe.pedebloat:pedebloat",
        "signature": "refinery.units.formats.pe.pesig:pesig",
    }

    if op not in _OP_MAP:
        return {"error": f"Unknown operation '{operation}'.", "supported": sorted(_OP_MAP.keys())}

    await ctx.info(f"PE operation: {op}")
    mod_path, cls_name = _OP_MAP[op].rsplit(":", 1)

    def _run():
        import importlib
        import hashlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)

        results = []
        for chunk in data | unit_cls():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            if op == "meta":
                entry["text"] = _safe_decode(raw)[:2000]
            elif op in ("overlay", "signature"):
                entry["preview_hex"] = raw[:128].hex()
                entry["preview_text"] = _safe_decode(raw[:128])
            elif op == "resources":
                entry["preview_hex"] = raw[:64].hex()
            elif op in ("strip", "debloat"):
                entry["preview_hex"] = raw[:32].hex()
            results.append(entry)
        return results

    results = await asyncio.to_thread(_run)

    response: Dict[str, Any] = {
        "operation": op,
        "filepath": state.filepath,
        "input_size": len(data),
    }

    if len(results) == 1 and op in ("strip", "debloat", "overlay", "signature"):
        response.update(results[0])
        if op in ("strip", "debloat"):
            response["size_reduction"] = f"{len(data) - results[0]['size']} bytes removed"
    else:
        response["items_found"] = len(results)
        response["results"] = results[:_MAX_OUTPUT_ITEMS]

    return await _check_mcp_response_size(ctx, response, "refinery_pe_operations")


# ===================================================================
#  8. SCRIPT DEOBFUSCATION
# ===================================================================

@tool_decorator
async def refinery_deobfuscate_script(
    ctx: Context,
    data_hex: str,
    script_type: str,
) -> Dict[str, Any]:
    """
    Deobfuscate scripts using Binary Refinery's specialized deobfuscation units.

    These units apply multiple heuristic passes to simplify obfuscated code:
    - 'ps1': PowerShell deobfuscation (string concat, encoding, invoke expansion, etc.)
    - 'vba': VBA macro deobfuscation (string manipulation, char codes, etc.)
    - 'js': JavaScript deobfuscation (array unpacking, string concat, etc.)

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Obfuscated script as hex string.
        script_type: (str) Script type: 'ps1', 'vba', 'js'.

    Returns:
        Dictionary with deobfuscated script text.
    """
    _require_refinery("refinery_deobfuscate_script")

    data = _hex_to_bytes(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    stype = script_type.lower()
    _DEOB_MAP = {
        "ps1": "refinery.units.obfuscation.ps1.all:deob_ps1",
        "vba": "refinery.units.obfuscation.vba.all:deob_vba",
    }

    # JS doesn't have an 'all' module — we chain individual units
    if stype == "js":
        await ctx.info("Deobfuscating JavaScript...")

        def _run_js():
            from refinery.units.obfuscation.js.concat import deob_js_concat
            from refinery.units.obfuscation.js.arrays import deob_js_arrays
            from refinery.units.obfuscation.js.arithmetic import deob_js_arithmetic
            result = data
            for unit_cls in [deob_js_arrays, deob_js_concat, deob_js_arithmetic]:
                try:
                    result = result | unit_cls() | bytes
                except Exception:
                    pass
            return result

        result = await asyncio.to_thread(_run_js)
    elif stype in _DEOB_MAP:
        await ctx.info(f"Deobfuscating {stype.upper()} script...")
        mod_path, cls_name = _DEOB_MAP[stype].rsplit(":", 1)

        def _run():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            return data | unit_cls() | bytes

        result = await asyncio.to_thread(_run)
    else:
        return {"error": f"Unknown script type '{script_type}'.", "supported": ["ps1", "vba", "js"]}

    return await _check_mcp_response_size(ctx, {
        "script_type": stype,
        "input_size": len(data),
        "output_size": len(result),
        "deobfuscated_text": _safe_decode(result)[:4000],
        "size_change": f"{len(data)} -> {len(result)} bytes",
    }, "refinery_deobfuscate_script")


# ===================================================================
#  9. HASHING
# ===================================================================

@tool_decorator
async def refinery_hash(
    ctx: Context,
    data_hex: Optional[str] = None,
    algorithms: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Compute hashes using Binary Refinery's hash units.

    Supports standard cryptographic hashes (md5, sha1, sha256, sha384, sha512)
    plus specialized hashes: crc32, adler32, imphash, fnv32, fnv64,
    murmur3-32, murmur3-128, xxhash32, xxhash64, xxhash128.

    See also: get_pe_info() for built-in PE file hashing (md5/sha1/sha256/imphash).

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        algorithms: (Optional[List[str]]) List of algorithms. Default: common set.

    Returns:
        Dictionary with computed hashes.
    """
    _require_refinery("refinery_hash")

    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
        data = _get_file_data()

    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256", "crc32"]

    await ctx.info(f"Computing hashes: {', '.join(algorithms)}")

    def _run():
        results = {}
        for algo in algorithms:
            try:
                from refinery.units.crypto.hash.cryptographic import (
                    md5, sha1, sha256, sha384, sha512,
                )
                from refinery.units.crypto.hash.checksums import crc32, adler32

                _hash_units = {
                    "md5": md5, "sha1": sha1, "sha256": sha256,
                    "sha384": sha384, "sha512": sha512,
                    "crc32": crc32, "adler32": adler32,
                }
                if algo in _hash_units:
                    h = data | _hash_units[algo]() | bytes
                    results[algo] = h.hex()
                else:
                    results[algo] = f"unsupported (try: {', '.join(sorted(_hash_units.keys()))})"
            except Exception as e:
                results[algo] = f"error: {e}"
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "data_size": len(data), "hashes": results,
    }, "refinery_hash")


# ===================================================================
#  10. TRANSFORMATION PIPELINE
# ===================================================================

@tool_decorator
async def refinery_pipeline(
    ctx: Context,
    data_hex: str,
    steps: List[str],
) -> Dict[str, Any]:
    """
    Execute a multi-step Binary Refinery transformation pipeline.

    Each step is a string like 'unit_name:arg1:arg2'. This is the most
    powerful tool — it chains multiple refinery operations sequentially.

    Supported step formats:
    - 'b64' — decode base64
    - 'xor:41' — XOR with key 0x41
    - 'xor:4d414c57' — XOR with multi-byte key
    - 'aes:key_hex:mode' — AES decrypt
    - 'rc4:key_hex' — RC4 decrypt
    - 'zl' — zlib decompress
    - 'hex' — hex decode
    - 'decompress' — auto-decompress
    - 'b32', 'b85', 'url', 'esc' — various decodings

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Input data as hex string.
        steps: (List[str]) Ordered list of transformation steps.

    Returns:
        Dictionary with final result and per-step size tracking.
    """
    _require_refinery("refinery_pipeline")

    data = _hex_to_bytes(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Running {len(steps)}-step pipeline: {' | '.join(steps)}")

    # Map of simple unit names to their import paths
    _UNIT_MAP = {
        "b64": ("refinery.units.encoding.b64", "b64", {}),
        "hex": ("refinery.units.encoding.hex", "hex", {}),
        "b32": ("refinery.units.encoding.b32", "b32", {}),
        "b85": ("refinery.units.encoding.b85", "b85", {}),
        "url": ("refinery.units.encoding.url", "url", {}),
        "esc": ("refinery.units.encoding.esc", "esc", {}),
        "u16": ("refinery.units.encoding.u16", "u16", {}),
        "zl": ("refinery.units.compression.zl", "zl", {}),
        "bz2": ("refinery.units.compression.bz2", "bz2", {}),
        "lzma": ("refinery.units.compression.lz", "lzma", {}),
        "lz4": ("refinery.units.compression.lz4", "lz4", {}),
        "decompress": ("refinery.units.compression.decompress", "decompress", {}),
        "rot": ("refinery.units.crypto.cipher.rot", "rot", {}),
    }

    def _run():
        import importlib
        current = data
        step_log = [{"step": "input", "size": len(current)}]

        for step_str in steps:
            parts = step_str.split(":")
            unit_name = parts[0].lower()

            if unit_name == "xor":
                from refinery.units.blockwise.xor import xor
                key = bytes.fromhex(parts[1]) if len(parts) > 1 else b"\x00"
                current = current | xor(key) | bytes
            elif unit_name in ("rc4", "aes", "des", "blowfish", "chacha", "salsa"):
                mod_path = f"refinery.units.crypto.cipher.{unit_name}"
                mod = importlib.import_module(mod_path)
                unit_cls = getattr(mod, unit_name)
                kwargs = {}
                if len(parts) > 1:
                    kwargs["key"] = bytes.fromhex(parts[1])
                if len(parts) > 2:
                    kwargs["mode"] = parts[2].upper()
                if len(parts) > 3:
                    kwargs["iv"] = bytes.fromhex(parts[3])
                current = current | unit_cls(**kwargs) | bytes
            elif unit_name in _UNIT_MAP:
                mod_path, cls_name, kwargs = _UNIT_MAP[unit_name]
                mod = importlib.import_module(mod_path)
                unit_cls = getattr(mod, cls_name)
                current = current | unit_cls(**kwargs) | bytes
            else:
                raise ValueError(f"Unknown pipeline unit: '{unit_name}'")

            step_log.append({"step": step_str, "size": len(current)})

        return current, step_log

    result, step_log = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "steps_executed": len(steps),
        "step_log": step_log,
        "final_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_pipeline")


# ===================================================================
#  11. LIST AVAILABLE UNITS
# ===================================================================

@tool_decorator
async def refinery_list_units(
    ctx: Context,
    category: Optional[str] = None,
) -> Dict[str, Any]:
    """
    List all available Binary Refinery unit categories and units.

    Use this to discover what transformations are available before calling
    other refinery tools. Each unit is a composable transformation that
    can be used in refinery_pipeline.

    Args:
        ctx: The MCP Context object.
        category: (Optional[str]) Filter to a specific category.
            Categories: blockwise, compression, crypto, encoding, formats,
            malware, meta, misc, obfuscation, pattern, sinks, strings.

    Returns:
        Dictionary with available units organized by category.
    """
    _require_refinery("refinery_list_units")

    def _run():
        import pkgutil
        import refinery.units as u
        base = os.path.dirname(u.__file__)
        cats = [name for _, name, ispkg in pkgutil.iter_modules([base]) if ispkg]

        result = {}
        for cat in sorted(cats):
            if category and cat != category.lower():
                continue
            try:
                mod = __import__(f"refinery.units.{cat}", fromlist=[""])
                cat_path = os.path.dirname(mod.__file__)
                units = sorted(name for _, name, _ in pkgutil.iter_modules([cat_path]))
                result[cat] = {
                    "unit_count": len(units),
                    "units": units,
                }
            except Exception as e:
                result[cat] = {"error": str(e)}
        return result

    result = await asyncio.to_thread(_run)

    total = sum(v.get("unit_count", 0) for v in result.values())
    return {
        "total_units": total,
        "total_categories": len(result),
        "categories": result,
    }
