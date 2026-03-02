"""MCP tools for cryptographic analysis — algorithm identification, key extraction, and brute-force.

Extends the basic crypto constant scanning from tools_pe_extended with deeper
analysis: full S-box validation, key schedule detection, entropy-based key
extraction, and multi-algorithm brute-force decryption.
"""
import asyncio
import math
import struct

from typing import Dict, Any, List, Optional, Union

from pemcp.config import state, logger, Context, ANGR_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.mcp._input_helpers import _parse_int_param
from pemcp.mcp._progress_bridge import ProgressBridge


# ===================================================================
#  Crypto constant databases (extended from tools_pe_extended)
# ===================================================================

# Full 256-byte S-boxes and longer constant sequences for high-confidence matching.
_FULL_SBOXES = {
    "AES": bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    ]),
    "AES_INV": bytes([
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    ]),
}

# RC4 identity permutation (ascending 0..255)
_RC4_IDENTITY = bytes(range(256))

# CRC32 polynomial table (first 16 entries of IEEE 802.3 CRC32)
_CRC32_TABLE_PREFIX = struct.pack("<16I", *[
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91B, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBF, 0xE7B82D09, 0x90BF1D9F,
])

# SHA-256 initial hash values (H0-H7)
_SHA256_INIT = struct.pack(">8I",
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

# SHA-256 round constants (first 16 of 64)
_SHA256_K_PREFIX = struct.pack(">16I",
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
)

# Crypto-related import names for cross-referencing
_CRYPTO_IMPORTS = frozenset({
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
    "CryptDeriveKey", "CryptGenKey", "CryptCreateHash",
    "CryptHashData", "CryptImportKey", "CryptExportKey",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
    "BCryptOpenAlgorithmProvider", "BCryptDeriveKey",
    "RtlEncryptMemory", "RtlDecryptMemory",
})


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            ent -= p * math.log2(p)
    return ent


def _is_ascending_sequence(data: bytes, min_length: int = 16) -> bool:
    """Check if data contains an ascending byte sequence (RC4 key schedule indicator)."""
    if len(data) < min_length:
        return False
    ascending_count = 0
    max_ascending = 0
    for i in range(1, len(data)):
        if data[i] == (data[i - 1] + 1) & 0xFF:
            ascending_count += 1
            max_ascending = max(max_ascending, ascending_count)
        else:
            ascending_count = 0
    return max_ascending >= min_length


# ===================================================================
#  Tool 1: identify_crypto_algorithm
# ===================================================================

@tool_decorator
async def identify_crypto_algorithm(
    ctx: Context,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: explore] Identifies cryptographic algorithms used in the binary by
    scanning for S-boxes, key schedule patterns, hash constants, CRC tables,
    and crypto-related imports. Goes beyond detect_crypto_constants() with full
    S-box validation and confidence scoring.

    When to use: After triage shows crypto imports, or when investigating
    ransomware, C2 encryption, or credential theft.

    Next steps: Use auto_extract_crypto_keys() to find keys near identified
    constants, or decompile_function_with_angr() on code referencing the
    crypto offsets.

    Args:
        ctx: MCP Context.
        limit: Max findings to return. Default 20.
    """
    await ctx.info("Scanning for cryptographic algorithms (deep analysis)")
    _check_pe_loaded("identify_crypto_algorithm")

    pe = state.pe_object
    file_data = pe.__data__

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _scan():
        findings = []

        bridge.report_progress(5, 100)
        bridge.info("Scanning for S-boxes and crypto constants...")

        # --- 1. Full S-box matching ---
        _SBOX_SIGS = [
            (_FULL_SBOXES["AES"][:16], "AES", "S-box", 16),
            (_FULL_SBOXES["AES_INV"][:16], "AES", "Inverse S-box", 16),
            (_RC4_IDENTITY[:16], "RC4", "Identity permutation (key schedule init)", 16),
            (_CRC32_TABLE_PREFIX[:16], "CRC32", "IEEE 802.3 polynomial table", 16),
            (_SHA256_INIT[:16], "SHA-256", "Initial hash values H0-H3", 16),
            (_SHA256_K_PREFIX[:16], "SHA-256", "Round constants K[0..3]", 16),
            (bytes([0x67, 0x45, 0x23, 0x01]), "MD5/SHA-1", "Init vector (little-endian)", 4),
            (bytes([0x01, 0x23, 0x45, 0x67]), "MD5/SHA-1", "Init vector (big-endian)", 4),
            (bytes([0xd7, 0x6a, 0xa4, 0x78]), "SHA-256", "Initial hash H0 (big-endian)", 4),
            (bytes([0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8]), "SHA-512", "Initial hash", 8),
        ]

        for sig_bytes, algo, detail, min_match in _SBOX_SIGS:
            offset = 0
            while offset < len(file_data):
                idx = file_data.find(sig_bytes, offset)
                if idx == -1:
                    break

                # Calculate confidence based on match length and context
                confidence = 0.6
                if min_match >= 16:
                    # Check if more bytes match beyond the prefix
                    if algo == "AES" and detail == "S-box":
                        full_sbox = _FULL_SBOXES["AES"]
                        end = min(idx + len(full_sbox), len(file_data))
                        matched = 0
                        for i, b in enumerate(full_sbox):
                            if idx + i < end and file_data[idx + i] == b:
                                matched += 1
                        confidence = min(1.0, matched / len(full_sbox) + 0.1)
                    elif algo == "RC4":
                        # Check if it's a full 256-byte identity permutation
                        end = min(idx + 256, len(file_data))
                        chunk = file_data[idx:end]
                        if len(chunk) >= 256 and chunk == _RC4_IDENTITY:
                            confidence = 0.95
                        elif _is_ascending_sequence(chunk, 64):
                            confidence = 0.8
                        else:
                            confidence = 0.5
                    else:
                        confidence = 0.75
                elif min_match >= 8:
                    confidence = 0.65
                else:
                    confidence = 0.5

                # Get section info
                section_name = None
                try:
                    sec = pe.get_section_by_offset(idx)
                    if sec:
                        section_name = sec.Name.decode('utf-8', 'ignore').strip('\x00')
                        # Higher confidence in data sections
                        if '.data' in section_name or '.rdata' in section_name:
                            confidence = min(1.0, confidence + 0.1)
                except Exception:
                    pass

                findings.append({
                    "algorithm": algo,
                    "detail": detail,
                    "offset": hex(idx),
                    "section": section_name,
                    "matched_bytes": min_match,
                    "confidence": round(confidence, 2),
                })
                offset = idx + min_match
                if len(findings) >= limit * 2:  # Over-fetch for dedup
                    break
            if len(findings) >= limit * 2:
                break

        bridge.report_progress(60, 100)
        bridge.info("Cross-referencing crypto imports...")

        # --- 2. Crypto import cross-referencing ---
        crypto_imports_found = []
        pe_data = state.pe_data or {}
        imports = pe_data.get("imports", [])
        if isinstance(imports, list):
            for imp in imports:
                if isinstance(imp, dict):
                    for func in imp.get("functions", []):
                        fname = func if isinstance(func, str) else func.get("name", "")
                        for crypto_name in _CRYPTO_IMPORTS:
                            if crypto_name.lower() in fname.lower():
                                crypto_imports_found.append(fname)

        bridge.report_progress(80, 100)
        bridge.info("Deduplicating and ranking findings...")

        # --- 3. Deduplicate and sort by confidence ---
        seen = set()
        unique = []
        for f in findings:
            key = (f["algorithm"], f["offset"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        unique.sort(key=lambda x: x["confidence"], reverse=True)

        return unique[:limit], crypto_imports_found

    findings, crypto_imports = await asyncio.to_thread(_scan)

    result: Dict[str, Any] = {
        "algorithms_found": findings,
        "count": len(findings),
        "crypto_imports": crypto_imports[:20],
    }

    if findings:
        algos = list(set(f["algorithm"] for f in findings))
        result["summary"] = f"Identified: {', '.join(algos)}"
        result["next_steps"] = [
            "auto_extract_crypto_keys() — search for keys near these constants",
            "get_hex_dump(start_offset=<offset>, length=512) — inspect around crypto constants",
            "decompile_function_with_angr() — analyze code referencing these offsets",
        ]

    return await _check_mcp_response_size(ctx, result, "identify_crypto_algorithm")


# ===================================================================
#  Tool 2: auto_extract_crypto_keys
# ===================================================================

@tool_decorator
async def auto_extract_crypto_keys(
    ctx: Context,
    search_radius: int = 4096,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Searches for potential cryptographic keys near identified
    crypto constants, in data sections, and using entropy-based heuristics.

    When to use: After identify_crypto_algorithm() finds crypto constants, or
    when you suspect encryption but can't find the key through decompilation.

    Next steps: Try brute_force_simple_crypto() with found keys, or
    decompile_function_with_angr() on code near key locations.

    Args:
        ctx: MCP Context.
        search_radius: Bytes to search around crypto constants. Default 4096.
        limit: Max candidate keys to return. Default 20.
    """
    await ctx.info("Searching for cryptographic keys")
    _check_pe_loaded("auto_extract_crypto_keys")

    pe = state.pe_object
    file_data = pe.__data__

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _search():
        candidates = []

        bridge.report_progress(5, 100)
        bridge.info("Searching near crypto constants...")

        # --- 1. Search near crypto constants ---
        for sig, algo in [
            (_FULL_SBOXES["AES"][:8], "AES"),
            (_RC4_IDENTITY[:16], "RC4"),
        ]:
            idx = file_data.find(sig)
            while idx != -1:
                # Search before and after the constant
                start = max(0, idx - search_radius)
                end = min(len(file_data), idx + len(sig) + search_radius)
                region = file_data[start:end]

                # Look for key-sized aligned sequences with interesting entropy
                for key_size in [16, 24, 32, 8]:
                    for i in range(0, len(region) - key_size, 4):  # 4-byte aligned
                        chunk = region[i:i + key_size]
                        ent = _shannon_entropy(chunk)

                        # Keys typically have entropy between 3.5 and 8.0
                        # Pure random: ~7.5-8.0, ASCII passwords: ~3.5-5.5
                        if 3.0 < ent < 8.1:
                            # Skip all-zeros, all-same-byte, and obvious non-keys
                            if len(set(chunk)) < 4:
                                continue
                            # Skip if it matches common non-key patterns
                            if chunk == bytes(key_size) or chunk == bytes([0xFF] * key_size):
                                continue

                            abs_offset = start + i
                            sec_name = None
                            try:
                                sec = pe.get_section_by_offset(abs_offset)
                                if sec:
                                    sec_name = sec.Name.decode('utf-8', 'ignore').strip('\x00')
                            except Exception:
                                pass

                            confidence = 0.3
                            # Higher confidence for data sections
                            if sec_name and ('.data' in sec_name or '.rdata' in sec_name):
                                confidence += 0.2
                            # Higher confidence near crypto constants
                            dist = abs(abs_offset - idx)
                            if dist < 256:
                                confidence += 0.3
                            elif dist < 1024:
                                confidence += 0.15
                            # Higher for standard key sizes
                            if key_size in (16, 32):
                                confidence += 0.1

                            candidates.append({
                                "offset": hex(abs_offset),
                                "key_hex": chunk.hex(),
                                "key_size": key_size,
                                "entropy": round(ent, 2),
                                "near_algorithm": algo,
                                "distance_to_constant": dist,
                                "section": sec_name,
                                "confidence": round(min(1.0, confidence), 2),
                            })

                idx = file_data.find(sig, idx + 1)

        bridge.report_progress(55, 100)
        bridge.info("Trying XOR known-plaintext detection...")

        # --- 2. XOR key detection from known-plaintext ---
        # Check if first bytes XOR'd with common plaintexts yield consistent keys
        if len(file_data) >= 64:
            known_plaintexts = [
                (b"MZ", "PE header"),
                (b"\x00" * 16, "null bytes"),
                (b"This program", "DOS stub"),
            ]
            for plaintext, description in known_plaintexts:
                for section_start in _get_section_starts(pe):
                    if section_start + len(plaintext) > len(file_data):
                        continue
                    encrypted = file_data[section_start:section_start + len(plaintext)]
                    key_candidate = bytes(a ^ b for a, b in zip(encrypted, plaintext))
                    if len(set(key_candidate)) == 1 and key_candidate[0] != 0:
                        # Single-byte XOR key
                        candidates.append({
                            "offset": hex(section_start),
                            "key_hex": key_candidate[:1].hex(),
                            "key_size": 1,
                            "entropy": 0.0,
                            "near_algorithm": f"XOR (vs {description})",
                            "distance_to_constant": 0,
                            "section": None,
                            "confidence": 0.4,
                        })

        bridge.report_progress(85, 100)
        bridge.info("Ranking key candidates...")

        # Sort by confidence
        candidates.sort(key=lambda x: x["confidence"], reverse=True)
        return candidates[:limit]

    candidates = await asyncio.to_thread(_search)

    return await _check_mcp_response_size(ctx, {
        "key_candidates": candidates,
        "count": len(candidates),
        "next_steps": [
            "brute_force_simple_crypto(data_hex, key_hex=<key>) — try decryption with a candidate",
            "get_hex_dump(start_offset=<offset>) — inspect data around key location",
        ] if candidates else [
            "Try get_hex_dump() on high-entropy regions from analyze_entropy_by_offset()",
            "Decompile functions that reference crypto imports",
        ],
    }, "auto_extract_crypto_keys")


def _get_section_starts(pe) -> List[int]:
    """Get the file offsets of all PE sections."""
    starts = []
    try:
        for sec in pe.sections:
            starts.append(sec.PointerToRawData)
    except Exception:
        pass
    return starts


# ===================================================================
#  Tool 3: brute_force_simple_crypto
# ===================================================================

@tool_decorator
async def brute_force_simple_crypto(
    ctx: Context,
    data_hex: str,
    algorithms: Optional[List[str]] = None,
    max_key_length: int = 16,
    key_hex: Optional[str] = None,
    known_plaintext: Optional[str] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Brute-forces simple cryptographic transforms on the provided
    data. Tries XOR (single/multi-byte with frequency analysis), RC4, ADD/SUB/ROL/ROR
    and validates results by checking for PE headers, readable strings, and known
    patterns. Supports known-plaintext attacks for direct XOR key derivation.

    When to use: When you have encrypted data (from get_hex_dump or payload
    extraction) and want to try common decryption methods automatically.
    For known-plaintext XOR recovery, pass the known_plaintext parameter.

    Next steps: If decryption succeeds → open_file() for PE payloads,
    deobfuscate_xor_multi_byte() to decrypt full data with recovered key,
    add_note() for text/config data.

    Args:
        ctx: MCP Context.
        data_hex: Hex-encoded encrypted data to decrypt.
        algorithms: List of algorithms to try. Default: ['xor_single', 'xor_multi', 'rc4', 'add', 'sub', 'rol', 'ror'].
        max_key_length: Max key length for multi-byte operations. Default 16.
        key_hex: Optional specific key to try (hex-encoded). Skips brute-force.
        known_plaintext: Optional known plaintext string for direct XOR key
            derivation (e.g. 'MZ' for PE headers, 'This program').
        limit: Max successful results to return. Default 10.
    """
    if algorithms is None:
        algorithms = ["xor_single", "xor_multi", "rc4", "add", "sub", "rol", "ror"]

    await ctx.info(f"Brute-forcing {len(data_hex)//2} bytes with algorithms: {algorithms}")

    try:
        data = bytes.fromhex(data_hex.replace(" ", "").replace("0x", ""))
    except ValueError as e:
        raise ValueError(f"Invalid data_hex: {e}")

    if len(data) > 1024 * 1024:  # 1MB max
        raise ValueError("Data too large (max 1MB). Provide a smaller sample.")
    if len(data) < 4:
        raise ValueError("Data too small (min 4 bytes).")

    specific_key = None
    if key_hex:
        try:
            specific_key = bytes.fromhex(key_hex.replace(" ", "").replace("0x", ""))
        except ValueError as e:
            raise ValueError(f"Invalid key_hex: {e}")

    bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

    def _brute_force():
        results = []

        def _score_result(decrypted: bytes) -> float:
            """Score decrypted data: higher = more likely correct."""
            score = 0.0
            # PE header check
            if decrypted[:2] == b"MZ":
                score += 5.0
            # ELF header
            if decrypted[:4] == b"\x7fELF":
                score += 5.0
            # Printable ASCII ratio
            printable = sum(1 for b in decrypted if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
            ratio = printable / len(decrypted) if decrypted else 0
            if ratio > 0.8:
                score += 3.0
            elif ratio > 0.5:
                score += 1.5
            # Low entropy might indicate decompressed text
            ent = _shannon_entropy(decrypted)
            if ent < 5.0:
                score += 1.0
            # Known string patterns
            for pattern in [b"http", b"https", b".com", b".exe", b".dll", b"windows", b"KERNEL32"]:
                if pattern in decrypted.lower() if pattern.isalpha() else pattern in decrypted:
                    score += 0.5
            return score

        def _add_result(algo: str, key_info: str, decrypted: bytes, score: float):
            if score >= 1.0:  # Only keep promising results
                results.append({
                    "algorithm": algo,
                    "key": key_info,
                    "score": round(score, 2),
                    "decrypted_preview_hex": decrypted[:128].hex(),
                    "decrypted_preview_text": bytes(
                        b if 0x20 <= b <= 0x7e else 0x2e for b in decrypted[:128]
                    ).decode("ascii"),
                    "full_size": len(decrypted),
                })

        # --- Known-plaintext XOR key derivation (fast path) ---
        if known_plaintext and ("xor_single" in algorithms or "xor_multi" in algorithms):
            bridge.info("Trying known-plaintext XOR key derivation...")
            pt = known_plaintext.encode('ascii', 'ignore')
            if len(pt) > 0 and len(data) >= len(pt):
                derived_key = bytes(data[i] ^ pt[i % len(pt)] for i in range(len(pt)))
                # Try as full-length key
                klen = len(derived_key)
                dec = bytes(data[i] ^ derived_key[i % klen] for i in range(len(data)))
                score = _score_result(dec)
                _add_result("xor_known_plaintext", derived_key.hex(), dec, max(score, 2.0))
                # If derived key is all same byte, also note the single-byte key
                if len(set(derived_key)) == 1:
                    _add_result("xor_single_kp", f"0x{derived_key[0]:02x}", dec, max(score, 2.0))

        bridge.report_progress(5, 100)
        bridge.info("Trying XOR single-byte...")

        # --- XOR single byte ---
        if "xor_single" in algorithms:
            if specific_key and len(specific_key) == 1:
                key_range = [specific_key[0]]
            else:
                key_range = range(1, 256)
            for key in key_range:
                dec = bytes(b ^ key for b in data)
                score = _score_result(dec)
                _add_result("xor_single", f"0x{key:02x}", dec, score)
                if len(results) >= limit:
                    break

        bridge.report_progress(25, 100)
        bridge.info("Trying XOR multi-byte...")

        # --- XOR multi-byte ---
        if "xor_multi" in algorithms and len(results) < limit:
            if specific_key and len(specific_key) > 1:
                keys_to_try = [specific_key]
            else:
                keys_to_try = []
                # Strategy 1: null-byte assumption (data starts XOR'd against nulls)
                for klen in range(2, min(max_key_length + 1, 33)):
                    key = data[:klen]
                    if len(set(key)) >= 2:
                        keys_to_try.append(key)
                    if len(keys_to_try) >= 50:
                        break

                # Strategy 2: frequency analysis (from bruteforce_xor_key)
                # For each key length, find most common byte per position
                # and assume it XORs to null (0x00)
                if len(data) >= 16:
                    for klen in range(2, min(max_key_length + 1, 9)):
                        key = bytearray(klen)
                        for pos in range(klen):
                            freq = [0] * 256
                            for i in range(pos, len(data), klen):
                                freq[data[i]] += 1
                            key[pos] = freq.index(max(freq))  # XOR to 0x00
                        if bytes(key) not in keys_to_try:
                            keys_to_try.append(bytes(key))

            for key in keys_to_try:
                klen = len(key)
                dec = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
                score = _score_result(dec)
                _add_result("xor_multi", key.hex(), dec, score)
                if len(results) >= limit:
                    break

        bridge.report_progress(45, 100)
        bridge.info("Trying RC4...")

        # --- RC4 ---
        if "rc4" in algorithms and len(results) < limit:
            def _rc4_decrypt(data_bytes, key_bytes):
                S = list(range(256))
                j = 0
                for i in range(256):
                    j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
                    S[i], S[j] = S[j], S[i]
                i = j = 0
                out = bytearray()
                for byte in data_bytes:
                    i = (i + 1) % 256
                    j = (j + S[i]) % 256
                    S[i], S[j] = S[j], S[i]
                    out.append(byte ^ S[(S[i] + S[j]) % 256])
                return bytes(out)

            if specific_key:
                keys_to_try = [specific_key]
            else:
                # Common RC4 keys in malware
                keys_to_try = [
                    b"password", b"secret", b"key", b"admin",
                    b"\x01\x02\x03\x04", b"\x00\x01\x02\x03",
                ]
                # Add first N bytes of data as potential keys
                for klen in [4, 8, 16]:
                    if len(data) > klen:
                        keys_to_try.append(data[:klen])

            for key in keys_to_try:
                dec = _rc4_decrypt(data, key)
                score = _score_result(dec)
                _add_result("rc4", key.hex(), dec, score)
                if len(results) >= limit:
                    break

        bridge.report_progress(60, 100)
        bridge.info("Trying ADD/SUB/ROL/ROR...")

        # --- ADD/SUB single byte ---
        for algo_name in ["add", "sub"]:
            if algo_name in algorithms and len(results) < limit:
                if specific_key and len(specific_key) == 1:
                    key_range = [specific_key[0]]
                else:
                    key_range = range(1, 256)
                for key in key_range:
                    if algo_name == "add":
                        dec = bytes((b + key) & 0xFF for b in data)
                    else:
                        dec = bytes((b - key) & 0xFF for b in data)
                    score = _score_result(dec)
                    _add_result(algo_name, f"0x{key:02x}", dec, score)
                    if len(results) >= limit:
                        break

        # --- ROL/ROR single byte ---
        for algo_name in ["rol", "ror"]:
            if algo_name in algorithms and len(results) < limit:
                for shift in range(1, 8):
                    if algo_name == "rol":
                        dec = bytes(((b << shift) | (b >> (8 - shift))) & 0xFF for b in data)
                    else:
                        dec = bytes(((b >> shift) | (b << (8 - shift))) & 0xFF for b in data)
                    score = _score_result(dec)
                    _add_result(algo_name, f"shift={shift}", dec, score)
                    if len(results) >= limit:
                        break

        bridge.report_progress(90, 100)
        bridge.info("Ranking results...")

        # Sort by score descending
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:limit]

    results = await asyncio.to_thread(_brute_force)

    return await _check_mcp_response_size(ctx, {
        "results": results,
        "count": len(results),
        "data_size": len(data),
        "algorithms_tried": algorithms,
        "best_match": results[0] if results else None,
    }, "brute_force_simple_crypto")
