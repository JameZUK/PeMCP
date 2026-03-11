"""MCP tools for binary payload comparison and diffing."""
import asyncio

from typing import Dict, Any, List, Optional

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.utils import shannon_entropy


@tool_decorator
async def diff_payloads(
    ctx: Context,
    data_a_hex: str,
    data_b_hex: str,
    context_bytes: int = 16,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Compares two binary payloads byte-by-byte and reports
    identical regions, different regions, and percentage similarity. If both
    payloads are PE files, includes structural comparison (sections, imports).

    When to use: When you have two encrypted payloads, two versions of a
    sample, or extracted data to compare (e.g., stage2_payload.bin vs
    data hidden in a PNG).

    Next steps: Focus analysis on differing regions with get_hex_dump().
    If payloads are XOR'd versions of each other → derive the XOR key.

    Args:
        ctx: MCP Context.
        data_a_hex: First payload as hex string.
        data_b_hex: Second payload as hex string.
        context_bytes: Bytes of context around diff regions. Default 16.
        limit: Max diff regions to report. Default 20.
    """
    await ctx.info("Comparing two binary payloads")

    # Check hex string length BEFORE decoding to avoid allocating huge intermediates.
    # 2 hex chars = 1 byte, so _MAX_HEX_LEN hex chars = _MAX_HEX_LEN/2 decoded bytes.
    _MAX_HEX_LEN = 2 * 1024 * 1024  # 2MB hex chars = 1MB decoded bytes
    clean_a = data_a_hex.replace(" ", "").replace("0x", "")
    clean_b = data_b_hex.replace(" ", "").replace("0x", "")
    if len(clean_a) > _MAX_HEX_LEN or len(clean_b) > _MAX_HEX_LEN:
        raise ValueError(f"Payloads too large (max {_MAX_HEX_LEN // 2 // 1024}KB decoded each).")

    try:
        data_a = bytes.fromhex(clean_a)
        data_b = bytes.fromhex(clean_b)
        del clean_a, clean_b
    except ValueError as e:
        raise ValueError(f"Invalid hex data: {e}")

    def _diff():
        min_len = min(len(data_a), len(data_b))
        max_len = max(len(data_a), len(data_b))

        # Byte-level comparison
        identical_bytes = 0
        diff_regions = []
        in_diff = False
        diff_start = 0

        for i in range(min_len):
            if data_a[i] == data_b[i]:
                identical_bytes += 1
                if in_diff:
                    # End of diff region
                    diff_regions.append((diff_start, i))
                    in_diff = False
            else:
                if not in_diff:
                    diff_start = i
                    in_diff = True

        if in_diff:
            diff_regions.append((diff_start, min_len))

        # If sizes differ, the tail is one big diff
        if len(data_a) != len(data_b):
            diff_regions.append((min_len, max_len))

        similarity = (identical_bytes / max_len * 100) if max_len > 0 else 100.0

        # Build diff report
        regions = []
        for start, end in diff_regions[:limit]:
            region = {
                "offset": hex(start),
                "length": end - start,
            }

            if start < len(data_a) and end <= len(data_a):
                region["a_hex"] = data_a[start:min(end, start + 64)].hex()
            elif start < len(data_a):
                region["a_hex"] = data_a[start:min(len(data_a), start + 64)].hex() + "...(shorter)"
            else:
                region["a_hex"] = "(beyond end of A)"

            if start < len(data_b) and end <= len(data_b):
                region["b_hex"] = data_b[start:min(end, start + 64)].hex()
            elif start < len(data_b):
                region["b_hex"] = data_b[start:min(len(data_b), start + 64)].hex() + "...(shorter)"
            else:
                region["b_hex"] = "(beyond end of B)"

            # Check if diff is a simple XOR
            if start < len(data_a) and start < len(data_b):
                diff_len = min(end, len(data_a), len(data_b)) - start
                if diff_len > 0:
                    xor_bytes = bytes(
                        data_a[start + j] ^ data_b[start + j]
                        for j in range(min(diff_len, 64))
                    )
                    if len(set(xor_bytes)) == 1:
                        region["xor_key"] = f"0x{xor_bytes[0]:02x}"

            regions.append(region)

        # Check if entire files are XOR of each other
        xor_key_global = None
        if min_len > 0:
            first_xor = data_a[0] ^ data_b[0]
            if first_xor != 0:
                # Sample start, middle, and end to increase confidence
                sample_offsets = [0, min(min_len // 2, 512), min(min_len - 1, 1023)]
                all_match = all(
                    (data_a[i] ^ data_b[i]) == first_xor
                    for off in sample_offsets
                    for i in range(off, min(off + 256, min_len))
                )
                if all_match:
                    xor_key_global = f"0x{first_xor:02x}"

        return {
            "size_a": len(data_a),
            "size_b": len(data_b),
            "identical_bytes": identical_bytes,
            "diff_regions_count": len(diff_regions),
            "similarity_pct": round(similarity, 2),
            "entropy_a": round(shannon_entropy(data_a), 2),
            "entropy_b": round(shannon_entropy(data_b), 2),
            "xor_relationship": xor_key_global,
            "diff_regions": regions,
            "is_pe_a": data_a[:2] == b"MZ",
            "is_pe_b": data_b[:2] == b"MZ",
        }

    result = await asyncio.to_thread(_diff)

    if result.get("xor_relationship"):
        result["insight"] = (
            f"Payloads appear to be XOR'd versions of each other (key: {result['xor_relationship']}). "
            "Use deobfuscate_xor_single_byte() to decrypt."
        )

    return await _check_mcp_response_size(ctx, result, "diff_payloads")
