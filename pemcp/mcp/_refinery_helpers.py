"""Shared helpers for all Binary Refinery MCP tool modules.

Centralises common utilities so they are defined once instead of being
duplicated across every ``tools_refinery*.py`` file.
"""
import os
from typing import Optional

from pemcp.config import state, REFINERY_AVAILABLE
from pemcp.mcp._format_helpers import _check_lib

# ── Safety limits ────────────────────────────────────────────────────────
_MAX_INPUT_SIZE_SMALL = 10 * 1024 * 1024   # 10 MB – general transforms
_MAX_INPUT_SIZE_LARGE = 50 * 1024 * 1024   # 50 MB – archive / forensic ops
_MAX_OUTPUT_ITEMS = 500                     # Cap list results


def _require_refinery(tool_name: str):
    """Raise a clear error if binary-refinery is not installed."""
    _check_lib("binary-refinery", REFINERY_AVAILABLE, tool_name, pip_name="binary-refinery")


def _hex_to_bytes(hex_string: str) -> bytes:
    """Convert a hex string (with optional spaces/0x/\\x prefixes) to bytes."""
    cleaned = hex_string.replace(" ", "").replace("0x", "").replace("\\x", "")
    return bytes.fromhex(cleaned)


def _bytes_to_hex(data: bytes, max_len: int = 4096) -> str:
    """Convert bytes to a hex string, truncating if needed."""
    if len(data) > max_len:
        return data[:max_len].hex() + f"...[truncated, {len(data)} bytes total]"
    return data.hex()


def _safe_decode(data: bytes) -> str:
    """Attempt to decode bytes as UTF-8 text, falling back to latin-1."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def _get_file_data() -> bytes:
    """Get the raw bytes of the currently loaded file."""
    if not state.pe_object:
        raise RuntimeError("No file is loaded. Use open_file() first.")
    raw = getattr(state.pe_object, "__data__", None)
    if raw is None:
        raw = getattr(state.pe_object, "get_data", lambda: None)()
    if raw is None and state.filepath and os.path.isfile(state.filepath):
        with open(state.filepath, "rb") as f:
            raw = f.read()
    if raw is None:
        raise RuntimeError("Cannot access raw file data.")
    return bytes(raw)


def _get_data_from_hex_or_file(data_hex: Optional[str]) -> bytes:
    """Get data from a hex string or the currently loaded file."""
    if data_hex:
        return _hex_to_bytes(data_hex)
    return _get_file_data()
