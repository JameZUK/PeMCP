"""MCP tool for AutoIt3 compiled script decryption and decompilation.

Supports both standard Mersenne Twister (MT19937) and modified RanRot PRNG
encryption used by modified AutoIt3 builds (DarkGate, StealC, AsgardProtector).
Works on standalone .a3x files, PE-embedded scripts, or raw data.
"""
import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

from arkana.config import state, Context
from arkana.mcp.server import tool_decorator, _check_mcp_response_size

logger = logging.getLogger("Arkana")

# Limits
_MAX_SOURCE_PREVIEW = 8000  # chars for source code preview in response
_MAX_ENTRY_DATA_PREVIEW = 200  # hex chars for non-script entry data


def _get_input_data(
    ctx: Context,
    data_hex: Optional[str],
    file_offset: Optional[str],
    length: Optional[int],
    file_path: Optional[str],
) -> bytes:
    """Resolve input data from hex, file offset, file path, or loaded file."""
    if data_hex:
        return bytes.fromhex(data_hex)

    if file_offset is not None:
        off = int(file_offset, 16) if isinstance(file_offset, str) and file_offset.startswith("0x") else int(file_offset)
        pe = state.pe_object
        if pe is None:
            raise RuntimeError("No PE file loaded. Use open_file() first or provide data_hex/file_path.")
        raw = pe.__data__
        end = off + length if length else len(raw)
        return bytes(raw[off:end])

    if file_path:
        resolved = file_path
        # Check common mount mappings
        for prefix in ("/samples/", "/output/"):
            if resolved.startswith(prefix):
                break
        if not os.path.isfile(resolved):
            raise FileNotFoundError(f"File not found: {resolved}")
        with open(resolved, "rb") as f:
            return f.read()

    # Fall back to full loaded file
    pe = state.pe_object
    if pe is None:
        raise RuntimeError("No input data. Provide data_hex, file_offset, file_path, or load a file first.")
    return bytes(pe.__data__)


def _get_pe_data_for_detection() -> Optional[bytes]:
    """Get PE binary data for PRNG auto-detection."""
    pe = state.pe_object
    if pe is not None:
        try:
            return bytes(pe.__data__)
        except Exception:
            pass
    return None


@tool_decorator
async def autoit_decrypt(
    ctx: Context,
    data_hex: Optional[str] = None,
    file_offset: Optional[str] = None,
    length: Optional[int] = None,
    file_path: Optional[str] = None,
    prng_type: str = "auto",
    output_path: Optional[str] = None,
    custom_key: Optional[int] = None,
) -> Dict[str, Any]:
    """[Phase: deep-dive] Decrypt and decompile AutoIt3 compiled scripts.

    Supports two PRNG algorithms:
    - **Mersenne Twister** (MT19937) with AutoIt3's custom tempering — standard
    - **RanRot PRNG** (rotate-and-add) — used by modified AutoIt3 builds

    Auto-detection scans the loaded PE for the RanRot LCG multiplier
    (0x53A9B4FB). If found, uses RanRot; otherwise uses MT.

    Input: data_hex > file_offset+length > file_path > full loaded file.

    When to use: When triage or strings reveal AU3!/EA05/EA06 magic, or when
    analyzing known AutoIt-compiled malware (DarkGate, StealC, CyberGate).

    Args:
        ctx: MCP Context.
        data_hex: (Optional[str]) Hex data containing the AutoIt script.
        file_offset: (Optional[str]) Offset into loaded file (hex string e.g. '0x12F').
        length: (Optional[int]) Bytes to read from file_offset.
        file_path: (Optional[str]) Path to standalone .a3x file.
        prng_type: (str) 'auto' (detect from loaded PE), 'mt' (Mersenne Twister),
            or 'ranrot' (RanRot PRNG). Default 'auto'.
        output_path: (Optional[str]) Directory to save extracted scripts/resources.
            Each entry saved as autoit_script_N.au3 or autoit_resource_N.bin.
        custom_key: (Optional[int]) Override au3_ResType decrypt key (e.g. 0x18EE).
            Use when the binary has a non-standard key. Find by comparing the
            binary's .text section with the original AutoIt3 stub.

    Returns:
        Dict with format, prng_type, entries (type, name, source preview),
        scripts_found, resources_found.
    """
    from arkana.parsers.autoit import (
        parse_autoit_script, detect_prng_type, find_autoit_script,
        EA05_CONSTANTS, EA06_CONSTANTS,
    )

    # Validate prng_type
    if prng_type not in ("auto", "mt", "ranrot"):
        return {"error": f"Invalid prng_type '{prng_type}'. Use 'auto', 'mt', or 'ranrot'."}

    # Get input data
    try:
        data = await asyncio.to_thread(
            _get_input_data, ctx, data_hex, file_offset, length, file_path
        )
    except Exception as e:
        return {"error": str(e)}

    if not data:
        return {"error": "No input data provided."}

    # Get PE data for auto-detection
    pe_data = _get_pe_data_for_detection() if prng_type == "auto" else None

    # Override constants if custom_key provided
    constants = None
    if custom_key is not None:
        # Clone the appropriate constants and override au3_ResType
        # We don't know format yet, so we'll pass custom_key through
        pass

    # Run parser
    def _run():
        nonlocal constants
        # Detect format first to choose base constants
        offset = find_autoit_script(data)
        if offset is not None and custom_key is not None:
            # Peek at format
            after_magic = offset + 20
            if after_magic + 4 <= len(data):
                marker = data[after_magic:after_magic + 4]
                base = dict(EA06_CONSTANTS) if marker in (b"EA06", b"AU3!") else dict(EA05_CONSTANTS)
            else:
                base = dict(EA06_CONSTANTS)
            base["au3_ResType"] = custom_key
            constants = base

        return parse_autoit_script(
            data=data,
            prng_type=prng_type,
            constants=constants,
            pe_data=pe_data,
        )

    result = await asyncio.to_thread(_run)

    # Save outputs if requested
    artifacts = []
    if output_path and result.get("entries"):
        os.makedirs(output_path, exist_ok=True)
        for i, entry in enumerate(result["entries"]):
            if entry.get("source"):
                out_file = os.path.join(output_path, f"autoit_script_{i}.au3")
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(entry["source"])
                artifacts.append({
                    "path": out_file,
                    "type": "script",
                    "size": len(entry["source"]),
                    "name": entry.get("name", ""),
                })
            elif entry.get("data"):
                ext = ".au3" if entry.get("is_script") else ".bin"
                out_file = os.path.join(output_path, f"autoit_resource_{i}{ext}")
                with open(out_file, "wb") as f:
                    f.write(entry["data"])
                artifacts.append({
                    "path": out_file,
                    "type": "resource",
                    "size": len(entry["data"]),
                    "name": entry.get("name", ""),
                })

    # Build response
    response: Dict[str, Any] = {
        "format": result.get("format", "unknown"),
        "prng_type": result.get("prng_type", prng_type),
        "total_entries": result.get("total_entries", 0),
        "scripts_found": result.get("scripts_found", 0),
        "resources_found": result.get("resources_found", 0),
        "checksum": result.get("checksum"),
    }

    if result.get("errors"):
        response["errors"] = result["errors"]

    # Entry summaries
    entries_summary: List[Dict[str, Any]] = []
    for entry in result.get("entries", []):
        summary: Dict[str, Any] = {
            "type": entry.get("type", ""),
            "name": entry.get("name", ""),
        }
        if entry.get("is_script"):
            summary["is_script"] = True
            summary["source_size"] = entry.get("source_size", 0)
            if entry.get("source"):
                preview = entry["source"][:_MAX_SOURCE_PREVIEW]
                summary["source_preview"] = preview
                if len(entry["source"]) > _MAX_SOURCE_PREVIEW:
                    summary["source_truncated"] = True
            summary["decompressed"] = entry.get("decompressed", False)
            summary["size_compressed"] = entry.get("size_compressed")
            summary["size_uncompressed"] = entry.get("size_uncompressed")
        elif entry.get("data"):
            summary["data_size"] = len(entry["data"])
            summary["data_preview_hex"] = entry["data"][:_MAX_ENTRY_DATA_PREVIEW // 2].hex()
        entries_summary.append(summary)

    response["entries"] = entries_summary

    if artifacts:
        response["artifacts"] = artifacts

    return response
