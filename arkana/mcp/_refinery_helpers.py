"""Shared helpers for all Binary Refinery MCP tool modules.

Centralises common utilities so they are defined once instead of being
duplicated across every ``tools_refinery*.py`` file.
"""
import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from arkana.config import state, REFINERY_AVAILABLE
from arkana.constants import MAX_ARTIFACT_FILE_SIZE
from arkana.mcp._format_helpers import _check_lib
from arkana.mcp._input_helpers import _parse_int_param

logger = logging.getLogger("Arkana")

# ── Safety limits ────────────────────────────────────────────────────────
_MAX_INPUT_SIZE_SMALL = 10 * 1024 * 1024   # 10 MB – general transforms
_MAX_INPUT_SIZE_LARGE = 50 * 1024 * 1024   # 50 MB – archive / forensic ops
_MAX_OUTPUT_ITEMS = 500                     # Cap list results


def _require_refinery(tool_name: str):
    """Raise a clear error if binary-refinery is not installed."""
    _check_lib("binary-refinery", REFINERY_AVAILABLE, tool_name, pip_name="binary-refinery")


_MAX_HEX_INPUT_LEN = 20_000_000  # 20MB hex = 10MB decoded


def _hex_to_bytes(hex_string: str) -> bytes:
    """Convert a hex string (with optional spaces/0x/\\x prefixes) to bytes."""
    if len(hex_string) > _MAX_HEX_INPUT_LEN:
        raise ValueError(
            f"Hex input too large ({len(hex_string):,} chars, "
            f"limit {_MAX_HEX_INPUT_LEN:,}). Max decoded size: "
            f"{_MAX_HEX_INPUT_LEN // 2:,} bytes."
        )
    cleaned = hex_string.replace(" ", "")
    # Strip leading 0x/0X prefix only (not all occurrences)
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    # Strip \x escape sequences throughout
    cleaned = cleaned.replace("\\x", "").replace("\\X", "")
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


_MAX_FILE_READ_SIZE = 500 * 1024 * 1024  # 500 MB safety limit


def _get_file_data() -> bytes:
    """Get the raw bytes of the currently loaded file."""
    if not state.pe_object:
        raise RuntimeError("No file is loaded. Use open_file() first.")
    raw = getattr(state.pe_object, "__data__", None)
    if raw is None:
        raw = getattr(state.pe_object, "get_data", lambda: None)()
    if raw is None and state.filepath and os.path.isfile(state.filepath):
        file_size = os.path.getsize(state.filepath)
        if file_size > _MAX_FILE_READ_SIZE:
            raise RuntimeError(
                f"File too large to read into memory ({file_size / (1024*1024):.0f} MB, "
                f"limit is {_MAX_FILE_READ_SIZE // (1024*1024)} MB)."
            )
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
# Magic signatures for types NOT covered by detect_format_from_magic
# (which handles PE, ELF, Mach-O).
_MAGIC_SIGNATURES = [
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"Rar!", "rar"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"%PDF", "pdf"),
]


def _detect_file_type(data: bytes) -> Optional[str]:
    """Detect file type from magic bytes. Returns type string or None."""
    from arkana.mcp._format_helpers import detect_format_from_magic
    result = detect_format_from_magic(data[:8])
    if result != "unknown":
        return result
    # Fallback for types not in format_helpers (zip, gzip, rar, ole, pdf)
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
    if Path(abs_path).exists():
        logger.warning("Overwriting existing file: %s", abs_path)
    Path(abs_path).write_bytes(data)
    logger.info("Artifact written: %s (%d bytes, type=%s)", abs_path, len(data), detected_type)

    # Register in state — clean up the file if registration fails
    try:
        artifact = state.register_artifact(
            path=abs_path,
            sha256=sha256,
            md5=md5,
            size=len(data),
            source_tool=source_tool,
            description=description,
            detected_type=detected_type,
        )
    except Exception:
        try:
            Path(abs_path).unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return {
        "path": abs_path,
        "size": len(data),
        "sha256": sha256,
        "md5": md5,
        "detected_type": detected_type,
        "artifact_id": artifact["id"],
    }
