"""MCP tools for managing function/variable renames and address labels."""
from typing import Dict, Any, Optional, List

from arkana.config import state, logger, Context, analysis_cache
from arkana.constants import MAX_BATCH_RENAMES
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._rename_helpers import normalize_address


def _persist_renames_to_cache() -> None:
    """Persist current renames to the disk cache (best-effort)."""
    if state.pe_data is None:
        return
    sha = (state.pe_data.get("file_hashes") or {}).get("sha256")
    if sha:
        analysis_cache.update_session_data(sha, renames=state.get_all_renames_snapshot())


@tool_decorator
async def rename_function(
    ctx: Context,
    address: str,
    new_name: str,
) -> Dict[str, Any]:
    """
    [Phase: context] Rename a function at the given address. The name persists
    in the analysis cache and is applied in decompilation and function map output.

    When to use: After identifying a function's purpose during reverse engineering.
    Use meaningful names like 'decrypt_config', 'resolve_api_by_hash', etc.

    Args:
        ctx: The MCP Context object.
        address: (str) Hex address of the function (e.g. '0x401000').
        new_name: (str) The new name to assign.

    Returns:
        A dictionary confirming the rename.
    """
    _check_pe_loaded("rename_function")
    if not new_name or not new_name.strip():
        raise ValueError("new_name must be a non-empty string.")
    if len(new_name) > 200:
        raise ValueError("Name too long (max 200 chars)")
    address = normalize_address(address)
    entry = state.rename_function(address, new_name.strip())
    _persist_renames_to_cache()
    return {"status": "success", "rename": entry}


@tool_decorator
async def rename_variable(
    ctx: Context,
    function_address: str,
    old_name: str,
    new_name: str,
) -> Dict[str, Any]:
    """
    [Phase: context] Rename a variable within a function scope. The rename is
    applied when decompiling that function.

    When to use: After understanding what a variable represents in a decompiled
    function. E.g. rename 'v12' to 'decrypted_buffer'.

    Args:
        ctx: The MCP Context object.
        function_address: (str) Hex address of the containing function (e.g. '0x401000').
        old_name: (str) The current variable name to replace.
        new_name: (str) The new name to assign.

    Returns:
        A dictionary confirming the variable rename.
    """
    _check_pe_loaded("rename_variable")
    if not old_name or not old_name.strip():
        raise ValueError("old_name must be a non-empty string.")
    if not new_name or not new_name.strip():
        raise ValueError("new_name must be a non-empty string.")
    if len(new_name) > 200:
        raise ValueError("Name too long (max 200 chars)")
    function_address = normalize_address(function_address)
    entry = state.rename_variable(function_address, old_name.strip(), new_name.strip())
    _persist_renames_to_cache()
    return {"status": "success", "rename": entry}


@tool_decorator
async def add_label(
    ctx: Context,
    address: str,
    label_name: str,
    category: str = "general",
) -> Dict[str, Any]:
    """
    [Phase: context] Add a labeled marker at an address. Labels appear in
    annotated disassembly output and persist across sessions.

    When to use: To mark important addresses — IOC locations, crypto routines,
    C2 entry points, or interesting code sections.

    Args:
        ctx: The MCP Context object.
        address: (str) Hex address to label (e.g. '0x401000').
        label_name: (str) The label text.
        category: (str) Category: 'general' (default), 'ioc', 'crypto', 'c2', 'function'.

    Returns:
        A dictionary confirming the label.
    """
    _check_pe_loaded("add_label")
    valid_categories = ("general", "ioc", "crypto", "c2", "function")
    if category not in valid_categories:
        raise ValueError(f"Invalid category '{category}'. Must be one of: {', '.join(valid_categories)}.")
    if not label_name or not label_name.strip():
        raise ValueError("label_name must be a non-empty string.")
    if len(label_name) > 200:
        raise ValueError("Label name too long (max 200 chars)")
    address = normalize_address(address)
    entry = state.add_label(address, label_name.strip(), category)
    _persist_renames_to_cache()
    return {"status": "success", "label": entry}


@tool_decorator
async def list_renames(
    ctx: Context,
    rename_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: context] List all renames and labels, optionally filtered by type.

    When to use: To review all user-assigned names before decompilation, or
    to check what has been annotated so far.

    Args:
        ctx: The MCP Context object.
        rename_type: (Optional[str]) Filter: 'functions', 'variables', or 'labels'. None for all.

    Returns:
        A dictionary of all renames grouped by type.
    """
    _check_pe_loaded("list_renames")
    if rename_type and rename_type not in ("functions", "variables", "labels"):
        raise ValueError("rename_type must be 'functions', 'variables', or 'labels'.")
    renames = state.get_renames(rename_type)
    total = sum(len(v) for v in renames.values())
    result = {"renames": renames, "total_count": total}
    return await _check_mcp_response_size(ctx, result, "list_renames")


@tool_decorator
async def delete_rename(
    ctx: Context,
    address: str,
    rename_type: str,
) -> Dict[str, Any]:
    """
    [Phase: context] Remove a specific rename or label.

    Args:
        ctx: The MCP Context object.
        address: (str) Hex address of the rename/label to remove.
        rename_type: (str) Type: 'function', 'variable', or 'label'.

    Returns:
        A dictionary confirming deletion.
    """
    _check_pe_loaded("delete_rename")
    if rename_type not in ("function", "variable", "label"):
        raise ValueError("rename_type must be 'function', 'variable', or 'label'.")
    address = normalize_address(address)
    deleted = state.delete_rename(address, rename_type)
    if not deleted:
        return {"status": "not_found", "message": f"No {rename_type} rename found at {address}."}
    _persist_renames_to_cache()
    return {"status": "success", "message": f"{rename_type.capitalize()} rename at {address} deleted."}


@tool_decorator
async def batch_rename(
    ctx: Context,
    renames: List[Dict[str, str]],
) -> Dict[str, Any]:
    """
    [Phase: context] Bulk-apply up to 50 renames in a single call.

    Each entry in the list must have: 'type' ('function', 'variable', or 'label'),
    'address', and type-specific fields.

    For functions: {"type": "function", "address": "0x401000", "new_name": "main"}
    For variables: {"type": "variable", "address": "0x401000", "old_name": "v1", "new_name": "buf"}
    For labels: {"type": "label", "address": "0x401000", "name": "entrypoint", "category": "general"}

    Args:
        ctx: The MCP Context object.
        renames: (List[Dict]) List of rename operations to apply.

    Returns:
        A summary of applied renames.
    """
    _check_pe_loaded("batch_rename")
    if not renames:
        raise ValueError("renames list must not be empty.")
    if len(renames) > MAX_BATCH_RENAMES:
        raise ValueError(f"Maximum {MAX_BATCH_RENAMES} renames per batch call.")

    # First pass: validate all entries without applying any changes
    valid_categories = ("general", "ioc", "crypto", "c2", "function")
    validation_errors = []
    validated_entries = []
    for i, entry in enumerate(renames):
        rtype = entry.get("type")
        addr = normalize_address(entry.get("address", ""))
        _MAX_NAME_LEN = 200
        if rtype == "function":
            name = entry.get("new_name", "").strip()
            if not name:
                validation_errors.append(f"[{i}] Missing new_name for function rename.")
            elif len(name) > _MAX_NAME_LEN:
                validation_errors.append(f"[{i}] Function name too long ({len(name)} chars). Maximum is {_MAX_NAME_LEN}.")
            else:
                validated_entries.append(("function", addr, {"name": name}))
        elif rtype == "variable":
            old = entry.get("old_name", "").strip()
            new = entry.get("new_name", "").strip()
            if not old or not new:
                validation_errors.append(f"[{i}] Missing old_name or new_name for variable rename.")
            elif len(new) > _MAX_NAME_LEN:
                validation_errors.append(f"[{i}] Variable name too long ({len(new)} chars). Maximum is {_MAX_NAME_LEN}.")
            else:
                validated_entries.append(("variable", addr, {"old": old, "new": new}))
        elif rtype == "label":
            name = entry.get("name", "").strip()
            cat = entry.get("category", "general")
            if not name:
                validation_errors.append(f"[{i}] Missing name for label.")
            elif cat not in valid_categories:
                validation_errors.append(f"[{i}] Invalid category '{cat}'. Must be one of: {', '.join(valid_categories)}.")
            else:
                validated_entries.append(("label", addr, {"name": name, "category": cat}))
        else:
            validation_errors.append(f"[{i}] Unknown type '{rtype}'. Must be 'function', 'variable', or 'label'.")

    # If any validation errors, return without applying any changes
    if validation_errors:
        return {
            "status": "validation_failed",
            "applied": 0,
            "total_requested": len(renames),
            "errors": validation_errors,
        }

    # Second pass: apply all validated renames
    applied = 0
    apply_errors = []
    for rtype, addr, params in validated_entries:
        try:
            if rtype == "function":
                state.rename_function(addr, params["name"])
            elif rtype == "variable":
                state.rename_variable(addr, params["old"], params["new"])
            elif rtype == "label":
                state.add_label(addr, params["name"], params["category"])
            applied += 1
        except Exception as e:
            apply_errors.append(f"Error applying {rtype} at {addr}: {e}")

    _persist_renames_to_cache()
    result = {"status": "success", "applied": applied, "total_requested": len(renames)}
    if apply_errors:
        result["errors"] = apply_errors
    return result
