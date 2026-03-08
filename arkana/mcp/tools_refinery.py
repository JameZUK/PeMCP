"""MCP tools powered by Binary Refinery for data transformation and analysis.

Binary Refinery (https://github.com/binref/refinery) provides 200+ composable
units for binary data transformation.  These MCP tools expose the most useful
refinery capabilities for malware triage and binary analysis workflows.
"""
import asyncio
import os

from typing import Dict, Any, Optional, List

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._refinery_helpers import (
    _require_refinery, _hex_to_bytes, _bytes_to_hex, _safe_decode,
    _get_file_data, _get_data_from_hex_or_file_with_offset,
    _write_output_and_register_artifact,
    _MAX_INPUT_SIZE_SMALL as _MAX_INPUT_SIZE,
    _MAX_OUTPUT_ITEMS,
)


# ===================================================================
#  1. ENCODING / DECODING (merged encode + decode)
# ===================================================================

@tool_decorator
async def refinery_codec(
    ctx: Context,
    data_hex: str,
    encoding: str = "b64",
    direction: str = "decode",
) -> Dict[str, Any]:
    """Encode or decode data using Binary Refinery encoding units.

    Encodings: b64, hex, b32, b58, b62, b85, a85, b92, url, esc, u16,
    uuenc, netbios, cp1252, wshenc, morse, htmlesc, z85.

    Args:
        ctx: MCP Context.
        data_hex: (str) Input data as hex string (or raw text for text-based encodings).
        encoding: (str) Encoding name. Default 'b64'.
        direction: (str) 'decode' (default) or 'encode'.

    Returns:
        Dictionary with transformed output (hex + text preview).
    """
    _require_refinery("refinery_codec")

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
        return {"error": f"Unknown encoding '{encoding}'.", "supported": sorted(_ENCODING_MAP.keys())}

    d = direction.lower()
    if d not in ("encode", "decode"):
        return {"error": f"Unknown direction '{direction}'.", "supported": ["decode", "encode"]}

    await ctx.info(f"{'Encoding' if d == 'encode' else 'Decoding'} with {encoding}")
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
        if d == "encode":
            return input_data | -unit_cls() | bytes
        return input_data | unit_cls() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "encoding": encoding,
        "direction": d,
        "input_size": len(input_data),
        "output_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }, "refinery_codec")


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
    """Decrypt data using Binary Refinery cipher units.

    Ciphers: aes, des, des3, rc4, blowfish, camellia, cast, chacha, salsa,
    serpent, tea, xtea, xxtea, rc2, rc5, rc6, sm4, rabbit, seal, gost,
    fernet, speck, hc128, hc256, isaac, sosemanuk, vigenere, rot, rijndael,
    chaskey, blabla, rncrypt, codebook, rc4mod, secstr.

    Args:
        ctx: MCP Context.
        data_hex: (str) Ciphertext as hex.
        algorithm: (str) Cipher name (e.g. 'aes', 'rc4').
        key_hex: (str) Key as hex.
        iv_hex: (Optional[str]) IV/nonce as hex (for CBC/CTR modes).
        mode: (Optional[str]) Block cipher mode: ECB, CBC, CTR, CFB, OFB, GCM.

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

    kwargs: Dict[str, Any] = {}
    if algo == "rot":
        try:
            kwargs["amount"] = int(key_hex, 10)
        except ValueError:
            kwargs["amount"] = key[0] if len(key) == 1 else int.from_bytes(key, "big")
    elif algo in ("vigenere", "codebook"):
        kwargs["key"] = key
    else:
        kwargs["key"] = key
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
#  3. XOR OPERATIONS (merged xor + xor_guess_key)
# ===================================================================

@tool_decorator
async def refinery_xor(
    ctx: Context,
    operation: str = "apply",
    data_hex: Optional[str] = None,
    key_hex: Optional[str] = None,
    file_offset: Optional[str] = None,
    length: Optional[int] = None,
    output_path: Optional[str] = None,
    key_start: Optional[int] = None,
    key_step: Optional[int] = None,
    key_max: Optional[int] = None,
    key_wrap: Optional[int] = None,
) -> Dict[str, Any]:
    """XOR operations via Binary Refinery.

    Operations:
    - 'apply': XOR data with a key (requires key_hex, plus data from data_hex or file_offset/length).
    - 'guess_key': Auto-guess the XOR key using statistical analysis.
    - 'rolling': Rolling XOR where key increments per byte (requires key_start,
      plus data from data_hex or file_offset/length). Key starts at key_start,
      increments by key_step (default 1) each byte, and wraps to key_wrap
      (default 0) when it exceeds key_max (default 255).

    Args:
        ctx: MCP Context.
        operation: (str) 'apply', 'guess_key', or 'rolling'. Default 'apply'.
        data_hex: (Optional[str]) Data as hex. For guess_key, if None uses loaded file.
        key_hex: (Optional[str]) XOR key as hex (required for 'apply').
        file_offset: (Optional[str]) Offset into loaded file (e.g. '0x3B80'). Alternative to data_hex.
        length: (Optional[int]) Number of bytes to read from file_offset.
        output_path: (Optional[str]) Save decoded output to this path and register as artifact.
        key_start: (Optional[int]) Initial key value for 'rolling' operation.
        key_step: (Optional[int]) Key increment per byte for 'rolling'. Default 1.
        key_max: (Optional[int]) Key wraps when exceeding this value for 'rolling'. Default 255.
        key_wrap: (Optional[int]) Key resets to this value on wrap for 'rolling'. Default 0.

    Returns:
        Dictionary with XOR result or guessed key + preview.
    """
    _require_refinery("refinery_xor")

    op = operation.lower()
    if op not in ("apply", "guess_key", "rolling"):
        return {"error": f"Unknown operation '{operation}'.", "supported": ["apply", "guess_key", "rolling"]}

    if op == "apply":
        if not key_hex:
            return {"error": "'apply' requires the key_hex parameter."}
        if not data_hex and file_offset is None:
            return {"error": "'apply' requires data_hex or file_offset to specify input data."}
        data = _get_data_from_hex_or_file_with_offset(data_hex, file_offset, length)
        key = _hex_to_bytes(key_hex)
        if len(data) > _MAX_INPUT_SIZE:
            raise RuntimeError(f"Input too large ({len(data)} bytes).")

        await ctx.info(f"XOR with {len(key)}-byte key: {key.hex()}")

        def _run_apply():
            from refinery.units.blockwise.xor import xor
            return data | xor(key) | bytes

        result = await asyncio.to_thread(_run_apply)

        response: Dict[str, Any] = {
            "operation": op,
            "key_hex": key.hex(),
            "key_length": len(key),
            "input_size": len(data),
            "output_size": len(result),
            "output_hex": _bytes_to_hex(result),
            "output_text": _safe_decode(result)[:2000],
        }

        if output_path:
            desc = f"XOR-decoded data (key={key.hex()}"
            if file_offset is not None:
                desc += f", offset={file_offset}"
            if length is not None:
                desc += f", length={length}"
            desc += ")"
            artifact_meta = await asyncio.to_thread(
                _write_output_and_register_artifact,
                output_path, result, "refinery_xor", desc,
            )
            response["artifact"] = artifact_meta

        return await _check_mcp_response_size(ctx, response, "refinery_xor")

    if op == "rolling":
        if key_start is None:
            return {"error": "'rolling' requires the key_start parameter."}
        if not data_hex and file_offset is None:
            return {"error": "'rolling' requires data_hex or file_offset to specify input data."}
        data = _get_data_from_hex_or_file_with_offset(data_hex, file_offset, length)
        if len(data) > _MAX_INPUT_SIZE:
            raise RuntimeError(f"Input too large ({len(data)} bytes).")

        step = key_step if key_step is not None else 1
        kmax = key_max if key_max is not None else 255
        kwrap = key_wrap if key_wrap is not None else 0

        await ctx.info(f"Rolling XOR: start={key_start}, step={step}, max={kmax}, wrap={kwrap}, size={len(data)}")

        def _run_rolling():
            result = bytearray(len(data))
            key = key_start
            for i in range(len(data)):
                result[i] = data[i] ^ (key & 0xFF)
                key += step
                if key > kmax:
                    key = kwrap
            return bytes(result)

        result = await asyncio.to_thread(_run_rolling)

        response: Dict[str, Any] = {
            "operation": op,
            "key_start": key_start,
            "key_step": step,
            "key_max": kmax,
            "key_wrap": kwrap,
            "input_size": len(data),
            "output_size": len(result),
            "output_hex": _bytes_to_hex(result),
            "output_text": _safe_decode(result)[:2000],
        }

        if output_path:
            desc = f"Rolling-XOR-decoded data (start={key_start}, step={step}, max={kmax}, wrap={kwrap}"
            if file_offset is not None:
                desc += f", offset={file_offset}"
            if length is not None:
                desc += f", length={length}"
            desc += ")"
            artifact_meta = await asyncio.to_thread(
                _write_output_and_register_artifact,
                output_path, result, "refinery_xor", desc,
            )
            response["artifact"] = artifact_meta

        return await _check_mcp_response_size(ctx, response, "refinery_xor")

    # op == "guess_key"
    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
        data = _get_data_from_hex_or_file_with_offset(None, file_offset, length)

    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]
        await ctx.warning(f"Data truncated to {_MAX_INPUT_SIZE} bytes for key guessing.")

    await ctx.info(f"Guessing XOR key for {len(data)} bytes of data...")

    def _run_guess():
        from refinery.units.misc.xkey import xkey
        keys = []
        for chunk in data | xkey():
            keys.append(bytes(chunk))
        return keys

    keys = await asyncio.to_thread(_run_guess)

    if not keys:
        return {"operation": op, "status": "no_key_found", "message": "Could not determine XOR key."}

    best_key = keys[0]

    def _decrypt():
        from refinery.units.blockwise.xor import xor
        return data[:512] | xor(best_key) | bytes

    preview = await asyncio.to_thread(_decrypt)

    return await _check_mcp_response_size(ctx, {
        "operation": op,
        "guessed_key_hex": best_key.hex(),
        "guessed_key_length": len(best_key),
        "guessed_key_ascii": _safe_decode(best_key),
        "decrypted_preview_hex": preview.hex(),
        "decrypted_preview_text": _safe_decode(preview)[:500],
        "total_candidates": len(keys),
    }, "refinery_xor")


# ===================================================================
#  4. COMPRESSION / DECOMPRESSION
# ===================================================================

@tool_decorator
async def refinery_decompress(
    ctx: Context,
    data_hex: Optional[str] = None,
    algorithm: str = "auto",
) -> Dict[str, Any]:
    """Decompress data using Binary Refinery.

    Algorithms: auto, zl, bz2, lzma, lz4, brotli, zstd, lznt1, lzo, ap,
    blz, lzf, lzg, lzip, lzjb, lzw, lzx, mscf, nrv, pkw, qlz, szdd, flz, jcalg.

    Args:
        ctx: MCP Context.
        data_hex: (Optional[str]) Compressed data as hex. If None, uses loaded file.
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
#  5. PATTERN EXTRACTION (IOCs)
# ===================================================================

@tool_decorator
async def refinery_extract_iocs(
    ctx: Context,
    data_hex: Optional[str] = None,
    indicator_type: str = "all",
    limit: int = 20,
) -> Dict[str, Any]:
    """Extract IOCs from data using Binary Refinery's xtp unit.

    Types: all, url, ipv4, ipv6, email, domain, path, hostname, md5, sha1, sha256, guid.

    Args:
        ctx: MCP Context.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        indicator_type: (str) Type of indicator or 'all'. Default 'all'.
        limit: (int) Max results. Default 200.

    Returns:
        Dictionary with extracted indicators grouped by type.
    """
    _require_refinery("refinery_extract_iocs")

    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
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
                found_set = set()
                for chunk in data | xtp(t):
                    val = bytes(chunk).decode("utf-8", errors="replace")
                    if val not in found_set:
                        found_set.add(val)
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
#  6. PATTERN CARVING (merged carve + carve_files)
# ===================================================================

@tool_decorator
async def refinery_carve(
    ctx: Context,
    operation: str = "pattern",
    pattern: str = "b64",
    file_type: str = "pe",
    data_hex: Optional[str] = None,
    decode: bool = True,
    limit: int = 20,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Carve embedded patterns or files from data via Binary Refinery.

    Operations:
    - 'pattern': Carve encoded blobs. pattern: b64/hex/b32/b85/url/intarray/string.
    - 'files': Carve embedded files. file_type: pe/zip/7z/rtf/json/xml/lnk/der.

    Args:
        ctx: MCP Context.
        operation: (str) 'pattern' or 'files'. Default 'pattern'.
        pattern: (str) Pattern to carve (for operation='pattern'). Default 'b64'.
        file_type: (str) File type to carve (for operation='files'). Default 'pe'.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        decode: (bool) Auto-decode carved patterns. Default True.
        limit: (int) Max items. Default 50.
        output_path: (Optional[str]) Save carved items to disk. For multiple items, appends _N suffix.

    Returns:
        Dictionary with carved data blobs or file metadata.
    """
    _require_refinery("refinery_carve")

    op = operation.lower()
    if op not in ("pattern", "files"):
        return {"error": f"Unknown operation '{operation}'.", "supported": ["pattern", "files"]}

    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
        data = _get_file_data()

    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]

    if op == "pattern":
        await ctx.info(f"Carving pattern '{pattern}' from {len(data)} bytes...")

        def _run_pattern():
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

        results = await asyncio.to_thread(_run_pattern)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "pattern": pattern,
            "items_found": len(results),
            "decode_applied": decode,
            "results": results,
        }, "refinery_carve")

    # op == "files"
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
        return {"error": f"Unknown file_type '{file_type}'.", "supported": sorted(_CARVE_MAP.keys())}

    await ctx.info(f"Carving embedded {ftype.upper()} files from {len(data)} bytes...")
    mod_path, cls_name = _CARVE_MAP[ftype].rsplit(":", 1)

    def _run_files():
        import importlib
        import hashlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)
        results = []
        raw_items = []
        for chunk in data | unit_cls():
            raw = bytes(chunk)
            results.append({
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "md5": hashlib.md5(raw).hexdigest(),
                "preview_hex": raw[:64].hex(),
            })
            raw_items.append(raw)
            if len(results) >= limit:
                break
        return results, raw_items

    results, raw_items = await asyncio.to_thread(_run_files)

    response: Dict[str, Any] = {
        "operation": op,
        "file_type": ftype,
        "files_found": len(results),
        "data_size": len(data),
        "results": results,
    }

    if output_path and raw_items:
        artifacts = []
        for i, raw in enumerate(raw_items):
            if len(raw_items) == 1:
                item_path = output_path
            else:
                base, ext = os.path.splitext(output_path)
                item_path = f"{base}_{i}{ext}"
            artifact_meta = await asyncio.to_thread(
                _write_output_and_register_artifact,
                item_path, raw, "refinery_carve",
                f"Carved {ftype.upper()} file #{i} ({len(raw)} bytes)",
            )
            artifacts.append(artifact_meta)
        response["artifacts"] = artifacts

    return await _check_mcp_response_size(ctx, response, "refinery_carve")


# ===================================================================
#  7. PE FILE OPERATIONS
# ===================================================================

@tool_decorator
async def refinery_pe_operations(
    ctx: Context,
    operation: str,
) -> Dict[str, Any]:
    """PE-specific operations via Binary Refinery.

    Operations: overlay, meta, resources, strip, debloat, signature, fix.

    Args:
        ctx: MCP Context.
        operation: (str) PE operation to perform.

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
        "fix": "refinery.units.formats.pe.pefix:pefix",
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
        try:
            for chunk in data | unit_cls():
                raw = bytes(chunk)
                if not raw:
                    continue
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
        except Exception as e:
            if op == "signature":
                return [{"error": f"No valid Authenticode signature found: {e}"}]
            raise
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
    """Deobfuscate scripts using Binary Refinery.

    Types: ps1 (PowerShell), vba (VBA macros), js (JavaScript).

    Args:
        ctx: MCP Context.
        data_hex: (str) Obfuscated script as hex.
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
    """Compute hashes using Binary Refinery.

    Supports: md5, sha1, sha256, sha384, sha512, crc32, adler32.

    Args:
        ctx: MCP Context.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        algorithms: (Optional[List[str]]) Hash algorithms. Default: md5, sha1, sha256, crc32.

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

_PIPELINE_UNIT_MAP = {
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

_MAX_BATCH_PIPELINE = 100


def _run_pipeline_single(data: bytes, steps: list) -> tuple:
    """Execute a pipeline on a single data blob. Returns (result_bytes, step_log)."""
    import importlib
    current = data
    step_log = [{"step": "input", "size": len(current)}]

    for step_str in steps:
        parts = step_str.split(":")
        unit_name = parts[0].lower()

        _CIPHER_NAMES = ("rc4", "aes", "des", "blowfish", "chacha", "salsa")

        if unit_name == "xor":
            from refinery.units.blockwise.xor import xor
            key = bytes.fromhex(parts[1]) if len(parts) > 1 else b"\x00"
            current = current | xor(key) | bytes

        # ── Ciphers (decrypt by default, enc_ prefix to encrypt) ──
        elif unit_name in _CIPHER_NAMES or (
            unit_name.startswith("enc_") and unit_name[4:] in _CIPHER_NAMES
        ):
            encrypt_mode = unit_name.startswith("enc_")
            cipher_name = unit_name[4:] if encrypt_mode else unit_name
            mod_path = f"refinery.units.crypto.cipher.{cipher_name}"
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cipher_name)
            kwargs = {}
            if len(parts) > 1:
                kwargs["key"] = bytes.fromhex(parts[1])
            if len(parts) > 2:
                kwargs["mode"] = parts[2].upper()
            if len(parts) > 3:
                kwargs["iv"] = bytes.fromhex(parts[3])
            if encrypt_mode:
                # Stream ciphers (rc4) are symmetric — reverse isn't needed/accepted.
                # Block ciphers (aes, des, blowfish) use reverse to switch direction.
                _STREAM_CIPHERS = {"rc4", "chacha", "salsa"}
                if cipher_name not in _STREAM_CIPHERS:
                    kwargs["reverse"] = True
            current = current | unit_cls(**kwargs) | bytes

        # ── Byte slicing ──
        elif unit_name == "snip":
            slice_args = parts[1:]
            if len(slice_args) == 0:
                pass  # no-op
            elif len(slice_args) == 1:
                current = current[int(slice_args[0]):]
            elif len(slice_args) == 2:
                start = int(slice_args[0]) if slice_args[0] else None
                stop = int(slice_args[1]) if slice_args[1] else None
                current = current[slice(start, stop)]
            else:
                start = int(slice_args[0]) if slice_args[0] else None
                stop = int(slice_args[1]) if slice_args[1] else None
                step = int(slice_args[2]) if slice_args[2] else None
                current = current[slice(start, stop, step)]

        # ── Chunking ──
        elif unit_name == "chop":
            if len(parts) < 2:
                raise ValueError("chop requires chunk size: 'chop:16' or 'chop:16:0'")
            chunk_size = int(parts[1])
            if chunk_size <= 0:
                raise ValueError("chop chunk size must be positive")
            chunks = [current[i:i + chunk_size] for i in range(0, len(current), chunk_size)]
            if len(parts) >= 3:
                idx = int(parts[2])
                if idx < 0 or idx >= len(chunks):
                    raise ValueError(f"chop index {idx} out of range ({len(chunks)} chunks)")
                current = chunks[idx]
            else:
                current = chunks[0] if chunks else b""

        elif unit_name == "pick":
            if len(parts) < 2:
                raise ValueError("pick requires byte count: 'pick:16'")
            current = current[:int(parts[1])]

        # ── Padding / termination ──
        elif unit_name == "pad":
            from refinery.units.meta.pad import pad as _pad
            if len(parts) < 2:
                raise ValueError("pad requires block size: 'pad:16'")
            block_size = int(parts[1])
            if block_size <= 0:
                raise ValueError("pad block size must be positive")
            current = current | _pad(block_size) | bytes

        elif unit_name == "terminate":
            if len(parts) >= 2 and parts[1] == "add":
                # Add null if missing (no refinery equivalent)
                if not current.endswith(b"\x00"):
                    current = current + b"\x00"
            else:
                from refinery.units.blockwise.terminate import terminate as _term
                current = current | _term() | bytes

        elif unit_name == "nop":
            pass

        # ── Bitwise operations (delegate to refinery blockwise units) ──
        elif unit_name == "ror":
            from refinery.units.blockwise.rotr import rotr
            if len(parts) < 2:
                raise ValueError("ror requires shift amount: 'ror:13' or 'ror:13:dword'")
            shift = int(parts[1])
            bs = 4 if (len(parts) > 2 and parts[2] == "dword") else 1
            current = current | rotr(shift, blocksize=bs) | bytes

        elif unit_name == "rol":
            from refinery.units.blockwise.rotl import rotl
            if len(parts) < 2:
                raise ValueError("rol requires shift amount: 'rol:3' or 'rol:3:dword'")
            shift = int(parts[1])
            bs = 4 if (len(parts) > 2 and parts[2] == "dword") else 1
            current = current | rotl(shift, blocksize=bs) | bytes

        elif unit_name == "shl":
            from refinery.units.blockwise.shl import shl as _shl
            if len(parts) < 2:
                raise ValueError("shl requires shift amount: 'shl:2'")
            current = current | _shl(int(parts[1])) | bytes

        elif unit_name == "shr":
            from refinery.units.blockwise.shr import shr as _shr
            if len(parts) < 2:
                raise ValueError("shr requires shift amount: 'shr:2'")
            current = current | _shr(int(parts[1])) | bytes

        elif unit_name in ("and", "bitand"):
            from refinery.units.blockwise.alu import alu
            if len(parts) < 2:
                raise ValueError("and requires hex mask: 'and:0F'")
            current = current | alu("B&A", int(parts[1], 16)) | bytes

        elif unit_name in ("or", "bitor"):
            from refinery.units.blockwise.alu import alu
            if len(parts) < 2:
                raise ValueError("or requires hex mask: 'or:80'")
            current = current | alu("B|A", int(parts[1], 16)) | bytes

        elif unit_name in ("not", "bitnot"):
            from refinery.units.blockwise.neg import neg
            current = current | neg() | bytes

        elif unit_name == "add":
            from refinery.units.blockwise.add import add as _add
            if len(parts) < 2:
                raise ValueError("add requires value: 'add:5'")
            current = current | _add(int(parts[1])) | bytes

        elif unit_name == "sub":
            from refinery.units.blockwise.sub import sub as _sub
            if len(parts) < 2:
                raise ValueError("sub requires value: 'sub:5'")
            current = current | _sub(int(parts[1])) | bytes

        # ── Refinery built-in units ──
        elif unit_name in _PIPELINE_UNIT_MAP:
            mod_path, cls_name, kwargs = _PIPELINE_UNIT_MAP[unit_name]
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            current = current | unit_cls(**kwargs) | bytes
        else:
            raise ValueError(f"Unknown pipeline unit: '{unit_name}'")

        step_log.append({"step": step_str, "size": len(current)})

    return current, step_log


@tool_decorator
async def refinery_pipeline(
    ctx: Context,
    data_hex: Optional[str] = None,
    data_hex_list: Optional[List[str]] = None,
    steps: Optional[List[str]] = None,
    file_offset: Optional[str] = None,
    length: Optional[int] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a multi-step Binary Refinery transformation pipeline.

    Each step is 'unit_name:arg1:arg2'.

    Available pipeline steps:
    - Encoding: b64, hex, b32, b85, url, esc, u16
    - Compression: zl, bz2, lzma, lz4, decompress
    - Crypto: xor:KEY, rc4:KEY, aes:KEY:MODE:IV, des, blowfish, chacha, salsa
      Prefix with enc_ to encrypt: enc_rc4:KEY, enc_aes:KEY:CBC:IV
    - Slicing: snip:start:stop (Python slice, negative indices OK), chop:size[:index], pick:N
    - Padding: pad:blocksize, terminate (strip nulls), terminate:add (add null)
    - Bitwise: ror:N[:dword], rol:N[:dword], shl:N, shr:N, and:HH, or:HH, not, add:N, sub:N
    - Utility: rot, nop (passthrough)

    Args:
        ctx: MCP Context.
        data_hex: (Optional[str]) Input data as hex. If None, uses file_offset/length or loaded file.
        data_hex_list: (Optional[List[str]]) Batch mode: list of hex-encoded inputs to
            process through the same pipeline steps. Up to 100 items. Cannot be combined
            with file_offset or output_path. Example: batch Base64+RC4 decrypt of 95
            config blobs using steps=["b64", "rc4:<key_hex>"].
        steps: (List[str]) Ordered list of transformation steps.
        file_offset: (Optional[str]) Offset into loaded file (e.g. '0x3B80'). Alternative to data_hex.
        length: (Optional[int]) Number of bytes to read from file_offset.
        output_path: (Optional[str]) Save final pipeline output to this path and register as artifact.

    Returns:
        Dictionary with final result and per-step size tracking.
        In batch mode: {"batch_results": [...], "steps": [...], "total": N, "succeeded": M, "failed": F}
    """
    _require_refinery("refinery_pipeline")

    if not steps:
        return {"error": "No pipeline steps provided. Pass a list of step strings."}
    steps = list(steps)

    # ── Batch mode ──
    if data_hex_list is not None:
        if file_offset is not None:
            return {"error": "file_offset is not supported in batch mode. Pass data via data_hex_list only."}
        if output_path is not None:
            return {"error": "output_path is not supported in batch mode. Process results individually if file output is needed."}

        items = list(data_hex_list[:_MAX_BATCH_PIPELINE])
        await ctx.info(f"Batch pipeline: {len(items)} items through {len(steps)} steps ({' | '.join(steps)})")

        def _run_batch():
            results = []
            for idx, item_hex in enumerate(items):
                entry: Dict[str, Any] = {"index": idx, "input_preview": item_hex[:40]}
                try:
                    item_data = bytes.fromhex(item_hex)
                    if len(item_data) > _MAX_INPUT_SIZE:
                        entry["error"] = f"Input too large ({len(item_data)} bytes)."
                    else:
                        out, _log = _run_pipeline_single(item_data, steps)
                        entry["output_hex"] = _bytes_to_hex(out)
                        entry["output_text"] = _safe_decode(out)[:2000]
                        entry["output_size"] = len(out)
                except Exception as e:
                    entry["error"] = str(e)
                results.append(entry)
            return results

        batch_results = await asyncio.to_thread(_run_batch)
        succeeded = sum(1 for r in batch_results if "error" not in r)
        response: Dict[str, Any] = {
            "batch_results": batch_results,
            "steps": steps,
            "total": len(batch_results),
            "succeeded": succeeded,
            "failed": len(batch_results) - succeeded,
        }
        return await _check_mcp_response_size(ctx, response, "refinery_pipeline")

    # ── Single-item mode (original behaviour) ──
    data = _get_data_from_hex_or_file_with_offset(data_hex, file_offset, length)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Running {len(steps)}-step pipeline: {' | '.join(steps)}")

    result, step_log = await asyncio.to_thread(_run_pipeline_single, data, steps)

    response = {
        "steps_executed": len(steps),
        "step_log": step_log,
        "final_size": len(result),
        "output_hex": _bytes_to_hex(result),
        "output_text": _safe_decode(result)[:2000],
    }

    if output_path:
        desc = f"Pipeline output ({' | '.join(steps)})"
        if file_offset is not None:
            desc += f" from offset {file_offset}"
        artifact_meta = await asyncio.to_thread(
            _write_output_and_register_artifact,
            output_path, result, "refinery_pipeline", desc,
        )
        response["artifact"] = artifact_meta

    return await _check_mcp_response_size(ctx, response, "refinery_pipeline")


# ===================================================================
#  11. LIST AVAILABLE UNITS
# ===================================================================

@tool_decorator
async def refinery_list_units(
    ctx: Context,
    category: Optional[str] = None,
) -> Dict[str, Any]:
    """List available Binary Refinery unit categories and units.

    Categories: blockwise, compression, crypto, encoding, formats,
    malware, meta, misc, obfuscation, pattern, sinks, strings.

    Args:
        ctx: MCP Context.
        category: (Optional[str]) Filter to a specific category.

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
