"""MCP tool for parsing binary data according to a field schema."""
import asyncio
import struct as _struct

from typing import Dict, Any, List, Optional

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._refinery_helpers import (
    _hex_to_bytes, _bytes_to_hex,
    _get_data_from_hex_or_file_with_offset,
)


# Map type names to struct format characters and sizes
_STRUCT_TYPES = {
    "uint8": ("<B", 1),
    "int8": ("<b", 1),
    "uint16_le": ("<H", 2),
    "uint16_be": (">H", 2),
    "int16_le": ("<h", 2),
    "int16_be": (">h", 2),
    "uint32_le": ("<I", 4),
    "uint32_be": (">I", 4),
    "int32_le": ("<i", 4),
    "int32_be": (">i", 4),
    "uint64_le": ("<Q", 8),
    "uint64_be": (">Q", 8),
    "int64_le": ("<q", 8),
    "int64_be": (">q", 8),
}

# Maximum schema fields to prevent abuse
_MAX_SCHEMA_FIELDS = 200
# Maximum data size
_MAX_DATA_SIZE = 10 * 1024 * 1024  # 10 MB


def _parse_fields(data: bytes, schema: list) -> tuple:
    """Parse binary data according to schema. Returns (fields_dict, bytes_consumed)."""
    fields = {}
    offset = 0

    for field_def in schema:
        name = field_def.get("name")
        ftype = field_def.get("type", "")

        if not name and not ftype.startswith("padding:"):
            raise ValueError(f"Field definition missing 'name': {field_def}")

        # Handle padding:N — skip N bytes
        if ftype.startswith("padding:"):
            try:
                pad_size = int(ftype.split(":")[1])
            except (IndexError, ValueError):
                raise ValueError(f"Invalid padding format '{ftype}'. Use 'padding:N'.")
            if offset + pad_size > len(data):
                raise ValueError(
                    f"Insufficient data for padding:{pad_size} at offset {offset}. "
                    f"Have {len(data)} bytes, need {offset + pad_size}."
                )
            offset += pad_size
            continue

        # Handle bytes:N — fixed-length byte field
        if ftype.startswith("bytes:"):
            try:
                byte_count = int(ftype.split(":")[1])
            except (IndexError, ValueError):
                raise ValueError(f"Invalid bytes format '{ftype}'. Use 'bytes:N'.")
            if offset + byte_count > len(data):
                raise ValueError(
                    f"Insufficient data for field '{name}' ({ftype}) at offset {offset}. "
                    f"Have {len(data)} bytes, need {offset + byte_count}."
                )
            fields[name] = data[offset:offset + byte_count].hex()
            offset += byte_count
            continue

        # Handle cstring — null-terminated ASCII
        if ftype == "cstring":
            null_pos = data.find(b"\x00", offset)
            if null_pos == -1:
                fields[name] = data[offset:].decode("ascii", errors="replace")
                offset = len(data)
            else:
                fields[name] = data[offset:null_pos].decode("ascii", errors="replace")
                offset = null_pos + 1
            continue

        # Handle wstring — null-terminated UTF-16LE
        if ftype == "wstring":
            pos = offset
            while pos + 1 < len(data):
                if data[pos] == 0 and data[pos + 1] == 0:
                    break
                pos += 2
            raw = data[offset:pos]
            try:
                fields[name] = raw.decode("utf-16-le")
            except UnicodeDecodeError:
                fields[name] = raw.decode("utf-16-le", errors="replace")
            offset = pos + 2 if pos + 1 < len(data) else len(data)
            continue

        # Handle ipv4 — 4 bytes as dotted-quad
        if ftype == "ipv4":
            if offset + 4 > len(data):
                raise ValueError(
                    f"Insufficient data for field '{name}' (ipv4) at offset {offset}."
                )
            b = data[offset:offset + 4]
            fields[name] = f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"
            offset += 4
            continue

        # Handle standard struct types
        if ftype in _STRUCT_TYPES:
            fmt, size = _STRUCT_TYPES[ftype]
            if offset + size > len(data):
                raise ValueError(
                    f"Insufficient data for field '{name}' ({ftype}, {size} bytes) "
                    f"at offset {offset}. Have {len(data)} bytes, need {offset + size}."
                )
            value = _struct.unpack_from(fmt, data, offset)[0]
            fields[name] = value
            offset += size
            continue

        # Unknown type
        supported = sorted([*_STRUCT_TYPES.keys(),
            "cstring", "wstring", "bytes:N", "padding:N", "ipv4",
        ])
        raise ValueError(
            f"Unknown type '{ftype}' for field '{name}'. "
            f"Supported: {', '.join(supported)}"
        )

    return fields, offset


@tool_decorator
async def parse_binary_struct(
    ctx: Context,
    schema: List[Dict[str, str]],
    data_hex: Optional[str] = None,
    file_offset: Optional[str] = None,
    length: Optional[int] = None,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Parses binary data according to a field schema, like
    struct.unpack but with named fields and variable-length types.

    When to use: After decrypting a config blob, when you need to extract
    typed fields (integers, strings, IPs) from raw binary data. Ideal for
    parsing C2 configs, protocol headers, or custom binary formats.

    Next steps: Use the parsed fields to identify C2 servers, sleep timers,
    encryption keys, etc. Record findings with add_note().

    Args:
        ctx: MCP Context.
        schema: (List[Dict]) Field definitions. Each dict has 'name' (str) and 'type' (str).
            Types: uint8, int8, uint16_le/be, int16_le/be, uint32_le/be, int32_le/be,
            uint64_le/be, int64_le/be, cstring (null-terminated ASCII),
            wstring (null-terminated UTF-16LE), bytes:N (fixed N bytes as hex),
            padding:N (skip N bytes), ipv4 (4 bytes as dotted quad).
        data_hex: (Optional[str]) Input data as hex string.
        file_offset: (Optional[str]) Offset into loaded file (e.g. '0x3B80').
        length: (Optional[int]) Bytes to read from file_offset.

    Returns:
        Dictionary with parsed fields, bytes consumed, and remaining data info.
    """
    if not schema:
        return {"error": "No schema provided. Pass a list of field definitions."}

    if len(schema) > _MAX_SCHEMA_FIELDS:
        return {"error": f"Schema too large ({len(schema)} fields). Maximum is {_MAX_SCHEMA_FIELDS}."}

    # Validate schema structure
    for i, field_def in enumerate(schema):
        if not isinstance(field_def, dict):
            return {"error": f"Schema entry {i} is not a dict: {field_def}"}
        if "type" not in field_def:
            return {"error": f"Schema entry {i} missing 'type': {field_def}"}
        ftype = field_def["type"]
        if not ftype.startswith("padding:") and "name" not in field_def:
            return {"error": f"Schema entry {i} missing 'name' (required for non-padding fields): {field_def}"}

    data = _get_data_from_hex_or_file_with_offset(data_hex, file_offset, length)

    if len(data) > _MAX_DATA_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes). Maximum is {_MAX_DATA_SIZE}.")

    await ctx.info(f"Parsing {len(data)} bytes with {len(schema)}-field schema")

    fields, consumed = await asyncio.to_thread(_parse_fields, data, schema)

    remaining = len(data) - consumed
    response: Dict[str, Any] = {
        "fields": fields,
        "total_bytes_consumed": consumed,
        "remaining_bytes": remaining,
        "input_size": len(data),
    }

    if remaining > 0:
        tail = data[consumed:consumed + 64]
        response["remaining_preview_hex"] = tail.hex()

    return await _check_mcp_response_size(ctx, response, "parse_binary_struct")
