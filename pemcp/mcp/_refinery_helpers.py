"""Shared helpers for all Binary Refinery MCP tool modules.

Centralises common utilities so they are defined once instead of being
duplicated across every ``tools_refinery*.py`` file.
"""
import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from pemcp.config import state, REFINERY_AVAILABLE
from pemcp.constants import MAX_ARTIFACT_FILE_SIZE
from pemcp.mcp._format_helpers import _check_lib
from pemcp.mcp._input_helpers import _parse_int_param

logger = logging.getLogger("PeMCP")

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


def _get_data_from_hex_or_file_with_offset(
    data_hex: Optional[str] = None,
    file_offset: Optional[str] = None,
    length: Optional[int] = None,
) -> bytes:
    """Get data from hex, or a slice of the loaded file, or the full loaded file.

    Priority: data_hex > file_offset+length from loaded file > full loaded file.
    ``file_offset`` supports ``0x`` prefixed hex strings (e.g. ``"0x3B80"``).
    """
    if data_hex:
        return _hex_to_bytes(data_hex)

    raw = _get_file_data()

    if file_offset is not None:
        offset = _parse_int_param(file_offset, "file_offset")
        if offset < 0 or offset >= len(raw):
            raise ValueError(
                f"file_offset {file_offset} (={offset}) is out of bounds "
                f"for file of size {len(raw)} (0x{len(raw):X}) bytes."
            )
        if length is not None:
            if length <= 0:
                raise ValueError(f"length must be positive, got {length}.")
            end = offset + length
            if end > len(raw):
                raise ValueError(
                    f"file_offset {file_offset} + length {length} = {end} exceeds "
                    f"file size {len(raw)} (0x{len(raw):X}) bytes."
                )
            return raw[offset:end]
        return raw[offset:]

    return raw


# --- Magic byte signatures for file type detection ---
_MAGIC_SIGNATURES = [
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "macho"),  # Mach-O 32-bit
    (b"\xfe\xed\xfa\xcf", "macho"),  # Mach-O 64-bit
    (b"\xce\xfa\xed\xfe", "macho"),  # Mach-O 32-bit (reversed)
    (b"\xcf\xfa\xed\xfe", "macho"),  # Mach-O 64-bit (reversed)
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"Rar!", "rar"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"%PDF", "pdf"),
]


def _detect_file_type(data: bytes) -> Optional[str]:
    """Detect file type from magic bytes. Returns type string or None."""
    for magic, ftype in _MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            return ftype
    return None


def _write_output_and_register_artifact(
    output_path: str,
    data: bytes,
    source_tool: str,
    description: str,
) -> Dict[str, Any]:
    """Write bytes to disk and register as a session artifact.

    Validates the path against allowed paths, computes hashes, detects
    file type, and registers the artifact in state.

    Returns a metadata dict with path, size, hashes, and detected_type.
    """
    if len(data) > MAX_ARTIFACT_FILE_SIZE:
        raise RuntimeError(
            f"Output size ({len(data)} bytes) exceeds the artifact limit "
            f"of {MAX_ARTIFACT_FILE_SIZE // (1024 * 1024)} MB."
        )

    abs_path = str(Path(output_path).resolve())
    state.check_path_allowed(abs_path)

    # Create parent directories
    parent = Path(abs_path).parent
    parent.mkdir(parents=True, exist_ok=True)

    # Compute hashes
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    # Detect file type
    detected_type = _detect_file_type(data)

    # Write to disk
    Path(abs_path).write_bytes(data)
    logger.info("Artifact written: %s (%d bytes, type=%s)", abs_path, len(data), detected_type)

    # Register in state
    artifact = state.register_artifact(
        path=abs_path,
        sha256=sha256,
        md5=md5,
        size=len(data),
        source_tool=source_tool,
        description=description,
        detected_type=detected_type,
    )

    return {
        "path": abs_path,
        "size": len(data),
        "sha256": sha256,
        "md5": md5,
        "detected_type": detected_type,
        "artifact_id": artifact["id"],
    }
