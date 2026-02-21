"""MCP tools for managing analysis notes on the currently loaded file."""
from typing import Dict, Any, Optional
from pemcp.config import state, Context, analysis_cache
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size


def _persist_notes_to_cache() -> None:
    """Persist current notes to the disk cache (best-effort)."""
    if state.pe_data is None:
        return
    sha = (state.pe_data.get("file_hashes") or {}).get("sha256")
    if sha:
        analysis_cache.update_session_data(sha, notes=state.get_all_notes_snapshot())


@tool_decorator
async def add_note(
    ctx: Context,
    content: str,
    category: str = "general",
    address: Optional[str] = None,
    tool_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Add a note to the currently loaded file. Notes persist in the analysis
    cache and are restored when the same file is reopened later.

    Use notes to record observations, findings, or analysis context that
    should be preserved across sessions.

    Args:
        ctx: The MCP Context object.
        content: (str) The note text content.
        category: (str) Note category: 'general' (default), 'function', or 'tool_result'.
        address: (Optional[str]) For 'function' notes: a hex address (e.g. '0x401000').
        tool_name: (Optional[str]) For 'tool_result' notes: the tool that produced the finding.

    Returns:
        A dictionary with the created note including its ID.
    """
    _check_pe_loaded("add_note")
    if category not in ("general", "function", "tool_result"):
        raise ValueError(f"Invalid category '{category}'. Must be 'general', 'function', or 'tool_result'.")

    note = state.add_note(content=content, category=category, address=address, tool_name=tool_name)
    _persist_notes_to_cache()
    await ctx.info(f"Note added: {note['id']}")
    return {"status": "success", "note": note}


@tool_decorator
async def get_notes(
    ctx: Context,
    category: Optional[str] = None,
    address: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Retrieve notes for the currently loaded file, optionally filtered
    by category or address.

    Args:
        ctx: The MCP Context object.
        category: (Optional[str]) Filter by category: 'general', 'function', or 'tool_result'.
        address: (Optional[str]) Filter by hex address (e.g. '0x401000').
        limit: (int) Maximum number of notes to return. Default: 50.

    Returns:
        A dictionary with notes list and count.
    """
    _check_pe_loaded("get_notes")
    notes = state.get_notes(category=category, address=address)
    total = len(notes)
    notes = notes[:limit]
    result: Dict[str, Any] = {
        "status": "success",
        "notes": notes,
        "count": len(notes),
        "total": total,
    }
    return await _check_mcp_response_size(ctx, result, "get_notes")


@tool_decorator
async def update_note(
    ctx: Context,
    note_id: str,
    content: Optional[str] = None,
    category: Optional[str] = None,
    address: Optional[str] = None,
    tool_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Update an existing note by its ID. Only specified fields are changed.

    Args:
        ctx: The MCP Context object.
        note_id: (str) The note ID (e.g. 'n_1708300000_1') returned by add_note.
        content: (Optional[str]) New note text content.
        category: (Optional[str]) New category: 'general', 'function', or 'tool_result'.
        address: (Optional[str]) New hex address.
        tool_name: (Optional[str]) New associated tool name.

    Returns:
        A dictionary with the updated note, or an error if not found.
    """
    _check_pe_loaded("update_note")
    if category is not None and category not in ("general", "function", "tool_result"):
        raise ValueError(f"Invalid category '{category}'. Must be 'general', 'function', or 'tool_result'.")

    updated = state.update_note(
        note_id, content=content, category=category,
        address=address, tool_name=tool_name,
    )
    if updated is None:
        return {"status": "not_found", "message": f"No note found with ID '{note_id}'."}

    _persist_notes_to_cache()
    return {"status": "success", "note": updated}


@tool_decorator
async def delete_note(
    ctx: Context,
    note_id: str,
) -> Dict[str, Any]:
    """
    Delete a note by its ID.

    Args:
        ctx: The MCP Context object.
        note_id: (str) The note ID (e.g. 'n_1708300000_1') returned by add_note.

    Returns:
        A dictionary confirming deletion or indicating the note was not found.
    """
    _check_pe_loaded("delete_note")
    deleted = state.delete_note(note_id)
    if not deleted:
        return {"status": "not_found", "message": f"No note found with ID '{note_id}'."}

    _persist_notes_to_cache()
    await ctx.info(f"Note deleted: {note_id}")
    return {"status": "success", "message": f"Note '{note_id}' deleted."}
