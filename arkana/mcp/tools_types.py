"""MCP tools for managing custom struct/enum type definitions."""
import asyncio
import re

from typing import Dict, Any, Optional, List

_VALID_FIELD_NAME_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

from arkana.config import state, logger, Context
from arkana.constants import MAX_STRUCT_FIELDS, MAX_ENUM_VALUES
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp.tools_struct import _parse_fields, _STRUCT_TYPES
from arkana.mcp._refinery_helpers import _get_data_from_hex_or_file_with_offset


def _validate_field_types(fields: list) -> None:
    """Validate that all field types are supported by _parse_fields."""
    supported_special = {"cstring", "wstring", "ipv4"}
    for i, field_def in enumerate(fields):
        if not isinstance(field_def, dict):
            raise ValueError(f"Field {i} is not a dict.")
        if "type" not in field_def:
            raise ValueError(f"Field {i} missing 'type'.")
        ftype = field_def["type"]
        if ftype.startswith("padding:") or ftype.startswith("bytes:"):
            continue
        if ftype in _STRUCT_TYPES or ftype in supported_special:
            continue
        raise ValueError(
            f"Field {i}: unknown type '{ftype}'. "
            f"Supported: {', '.join(sorted([*_STRUCT_TYPES.keys(), *supported_special, 'bytes:N', 'padding:N']))}"
        )


def _compute_struct_size(fields: list) -> int:
    """Compute the total static size of a struct from its fields."""
    size = 0
    for field_def in fields:
        ftype = field_def.get("type", "")
        if ftype.startswith("padding:"):
            size += int(ftype.split(":")[1])
        elif ftype.startswith("bytes:"):
            size += int(ftype.split(":")[1])
        elif ftype in _STRUCT_TYPES:
            size += _STRUCT_TYPES[ftype][1]
        elif ftype == "ipv4":
            size += 4
        elif ftype in ("cstring", "wstring"):
            # Variable-length — not included in static size
            pass
        else:
            pass
    return size


def _check_struct_cycles(struct_name: str, fields: list, path: Optional[List[str]] = None, depth: int = 0) -> None:
    """Detect recursive struct cycles. Raises ValueError if a cycle is found.

    Uses a list (not a set) to preserve insertion order so the exact cycle
    path is displayed in the error message.
    """
    if path is None:
        path = []
    if depth > 20:
        raise ValueError(
            f"Struct nesting depth exceeds maximum (20) — possible cycle or excessive nesting "
            f"(path: {' -> '.join(path)} -> {struct_name})"
        )
    if struct_name in path:
        cycle = [*path[path.index(struct_name):], struct_name]
        raise ValueError(
            f"Recursive struct reference detected: {' -> '.join(cycle)}"
        )
    path.append(struct_name)
    for field_def in fields:
        ftype = field_def.get("type", "")
        # Check if this field type references another custom struct
        ref_type = state.get_custom_type(ftype) if ftype else None
        if ref_type and ref_type.get("type") == "struct":
            _check_struct_cycles(ftype, ref_type["fields"], list(path), depth + 1)
    path.pop()


@tool_decorator
async def create_struct(
    ctx: Context,
    name: str,
    fields: List[Dict[str, str]],
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Define a named struct type with typed fields. The struct
    can then be applied to binary data at any offset using apply_type_at_offset.

    ---compact: define named struct type with typed fields | persists to cache | needs: file

    Uses the same field types as parse_binary_struct: uint8, int8, uint16_le/be,
    int16_le/be, uint32_le/be, int32_le/be, uint64_le/be, int64_le/be, cstring,
    wstring, bytes:N, padding:N, ipv4.

    When to use: After identifying a recurring data structure in the binary (e.g.
    C2 config struct, protocol header, internal data record).

    Args:
        ctx: The MCP Context object.
        name: (str) Name for the struct type (e.g. 'C2Config', 'PacketHeader').
        fields: (List[Dict]) Field definitions, each with 'name' and 'type' keys.
            Example: [{"name": "magic", "type": "uint32_le"}, {"name": "size", "type": "uint16_le"}]

    Returns:
        The created struct definition with computed size.
    """
    _check_pe_loaded("create_struct")
    if not name or not name.strip():
        raise ValueError("name must be a non-empty string.")
    name = name.strip()
    if not _VALID_FIELD_NAME_RE.match(name) or len(name) > 200:
        raise ValueError("Invalid type name: must match [a-zA-Z_][a-zA-Z0-9_]* and be ≤200 chars")
    if not fields:
        raise ValueError("fields must not be empty.")
    if len(fields) > MAX_STRUCT_FIELDS:
        raise ValueError(f"Too many fields ({len(fields)}). Maximum is {MAX_STRUCT_FIELDS}.")

    _validate_field_types(fields)

    # Validate field names
    for i, f in enumerate(fields):
        fname = f.get("name", "")
        ftype = f.get("type", "")
        if not fname and not ftype.startswith("padding:"):
            raise ValueError(f"Field {i}: name must not be empty (only padding fields may omit a name).")
        if fname and not _VALID_FIELD_NAME_RE.match(fname):
            raise ValueError(f"Field {i}: invalid name '{fname}'. Must match [a-zA-Z_][a-zA-Z0-9_]*")

    size = _compute_struct_size(fields)

    entry = state.create_struct(name, fields, size)
    return {"status": "success", "struct": entry}


@tool_decorator
async def create_enum(
    ctx: Context,
    name: str,
    values: Dict[str, int],
    size: int = 4,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Define a named enum type with name-to-integer mappings.
    Enums can be used to annotate integer fields when applying types.

    ---compact: define named enum type with integer mappings | needs: file

    When to use: After identifying a set of integer constants (e.g. command IDs,
    status codes, protocol opcodes) used throughout the binary.

    Args:
        ctx: The MCP Context object.
        name: (str) Name for the enum type (e.g. 'CommandID', 'StatusCode').
        values: (Dict[str, int]) Mapping of name to integer value.
            Example: {"CMD_PING": 1, "CMD_EXEC": 2, "CMD_UPLOAD": 3}
        size: (int) Size in bytes for the underlying integer (default 4).

    Returns:
        The created enum definition.
    """
    _check_pe_loaded("create_enum")
    if not name or not name.strip():
        raise ValueError("name must be a non-empty string.")
    name = name.strip()
    if not _VALID_FIELD_NAME_RE.match(name) or len(name) > 200:
        raise ValueError("Invalid type name: must match [a-zA-Z_][a-zA-Z0-9_]* and be ≤200 chars")
    if not values:
        raise ValueError("values must not be empty.")
    if len(values) > MAX_ENUM_VALUES:
        raise ValueError(f"Too many values ({len(values)}). Maximum is {MAX_ENUM_VALUES}.")
    if size not in (1, 2, 4, 8):
        raise ValueError("size must be 1, 2, 4, or 8 bytes.")

    # Validate enum value names
    for vname in values:
        if not _VALID_FIELD_NAME_RE.match(vname):
            raise ValueError(f"Invalid enum value name: '{vname}'. Must match [a-zA-Z_][a-zA-Z0-9_]*")

    # Validate all values are integers and in range
    for k, v in values.items():
        if not isinstance(v, int):
            raise ValueError(f"Value for '{k}' must be an integer, got {type(v).__name__}.")
        max_val = (2 ** (size * 8)) - 1
        if v < 0 or v > max_val:
            raise ValueError(f"Enum value {v} for '{k}' out of range for {size}-byte type (0-{max_val})")

    # Check for duplicate values
    seen_values = {}
    for k, v in values.items():
        if v in seen_values:
            raise ValueError(f"Duplicate enum value {v}: already used by '{seen_values[v]}', cannot reuse for '{k}'")
        seen_values[v] = k

    entry = state.create_enum(name, values, size)
    return {"status": "success", "enum": entry}


@tool_decorator
async def apply_type_at_offset(
    ctx: Context,
    type_name: str,
    file_offset: str,
    count: int = 1,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Parse binary data at an offset using a previously defined
    custom struct type. Returns the parsed field values.

    ---compact: apply custom struct at file offset | parse consecutive instances | needs: file

    When to use: After defining a struct with create_struct, apply it to one or
    more consecutive instances in the binary.

    Args:
        ctx: The MCP Context object.
        type_name: (str) Name of the custom struct to apply.
        file_offset: (str) Offset into the loaded file (e.g. '0x3B80').
        count: (int) Number of consecutive struct instances to parse (default 1, max 100).

    Returns:
        Parsed field values for each struct instance.
    """
    _check_pe_loaded("apply_type_at_offset")
    if count < 1 or count > 100:
        raise ValueError("count must be between 1 and 100.")

    type_def = state.get_custom_type(type_name)
    if type_def is None:
        available = list(state.get_all_custom_types()["structs"].keys())
        raise ValueError(
            f"Custom type '{type_name}' not found. "
            + (f"Available: {', '.join(available)}" if available else "No custom types defined yet.")
        )
    if type_def["type"] != "struct":
        raise ValueError(f"'{type_name}' is an enum, not a struct. Enums cannot be applied at offsets.")

    # Check for recursive struct cycles before parsing
    _check_struct_cycles(type_name, type_def["fields"])

    schema = type_def["fields"]
    struct_size = type_def["size"]

    # Calculate how much data to read (estimate — variable-length fields may need more)
    read_length = max(struct_size * count + 1024, 4096)  # extra buffer for variable-length

    data = _get_data_from_hex_or_file_with_offset(None, file_offset, read_length)

    results = []
    offset = 0
    for i in range(count):
        if offset >= len(data):
            break
        fields, consumed = await asyncio.to_thread(_parse_fields, data[offset:], schema)
        results.append({
            "index": i,
            "offset": hex(int(file_offset, 16) + offset) if file_offset.startswith("0x") else hex(int(file_offset) + offset),
            "fields": fields,
            "bytes_consumed": consumed,
        })
        offset += consumed

    result = {
        "type_name": type_name,
        "base_offset": file_offset,
        "count_requested": count,
        "count_parsed": len(results),
        "instances": results,
    }
    return await _check_mcp_response_size(ctx, result, "apply_type_at_offset")


@tool_decorator
async def list_custom_types(
    ctx: Context,
) -> Dict[str, Any]:
    """
    [Phase: context] List all defined custom struct and enum types.

    ---compact: list all custom struct and enum type definitions | needs: file

    When to use: To review available type definitions before applying them,
    or to check what types have been defined in the current session.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary of all custom types grouped by kind (structs, enums).
    """
    _check_pe_loaded("list_custom_types")
    types = state.get_all_custom_types()
    total = len(types.get("structs", {})) + len(types.get("enums", {}))
    result = {"custom_types": types, "total_count": total}
    return await _check_mcp_response_size(ctx, result, "list_custom_types")


@tool_decorator
async def delete_custom_type(
    ctx: Context,
    name: str,
) -> Dict[str, Any]:
    """
    [Phase: context] Remove a custom type definition.

    ---compact: delete custom struct or enum by name | needs: file

    Args:
        ctx: The MCP Context object.
        name: (str) Name of the type to delete.

    Returns:
        A dictionary confirming deletion.
    """
    _check_pe_loaded("delete_custom_type")
    deleted = state.delete_custom_type(name)
    if not deleted:
        return {"status": "not_found", "message": f"No custom type '{name}' found."}
    return {"status": "success", "message": f"Custom type '{name}' deleted."}
