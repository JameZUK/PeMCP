"""MCP tools for managing analysis notes on the currently loaded file."""
from typing import Dict, Any, Optional, List
from pemcp.config import state, logger, Context, analysis_cache, ANGR_AVAILABLE
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
    should be preserved across sessions. Notes are the primary mechanism
    for managing context in long-running binary analysis — they feed into
    get_analysis_digest() which aggregates all findings into a single
    context-efficient summary.

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


@tool_decorator
async def auto_note_function(
    ctx: Context,
    function_address: str = "",
    custom_summary: Optional[str] = None,
    address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Auto-generates a one-line behavioral summary of a function and saves it as a
    persistent note. Uses API call pattern matching (not LLM inference) based on
    the function's callees in the CFG.

    Call this after decompiling a function to build up the analysis digest —
    later, get_analysis_digest() will aggregate all function notes without
    needing the full decompilation output in context.

    Args:
        ctx: The MCP Context object.
        function_address: (str) Hex address of the function (e.g. '0x401000').
        address: (Optional[str]) Alias for function_address.
        custom_summary: (Optional[str]) If provided, use this as the summary
            instead of auto-generating. Useful when you've read the decompilation
            and want to record a specific finding.

    Returns:
        A dictionary with the function name, auto-generated summary, APIs called,
        and the note ID.
    """
    from pemcp.mcp._category_maps import CATEGORIZED_IMPORTS_DB, CATEGORY_DESCRIPTIONS

    if address is not None and not function_address:
        function_address = address
    if not function_address:
        raise ValueError("Either 'function_address' or 'address' must be provided.")

    _check_pe_loaded("auto_note_function")

    apis_called: List[str] = []
    category_tags: List[str] = []
    func_name = f"sub_{function_address.replace('0x', '')}"

    if ANGR_AVAILABLE and state.angr_project is not None and state.angr_cfg is not None:
        from pemcp.mcp._angr_helpers import _parse_addr, _resolve_function_address, _ensure_project_and_cfg

        target_addr = _parse_addr(function_address)

        try:
            _ensure_project_and_cfg()
            func, addr_used = _resolve_function_address(target_addr)
            func_name = func.name

            # Get callees from CFG
            callgraph = state.angr_cfg.functions.callgraph
            cats_seen: set = set()
            try:
                for callee_addr in callgraph.successors(addr_used):
                    if callee_addr in state.angr_cfg.functions:
                        cname = state.angr_cfg.functions[callee_addr].name
                        for api_name, (_risk, cat) in CATEGORIZED_IMPORTS_DB.items():
                            if api_name in cname:
                                apis_called.append(cname)
                                cats_seen.add(cat)
                                break
            except Exception:
                pass
            category_tags = sorted(cats_seen)
        except Exception as e:
            logger.debug("auto_note_function: angr lookup failed: %s", e)

    # Generate auto summary
    if custom_summary:
        summary = custom_summary
    elif apis_called:
        cat_descs = []
        for cat in category_tags[:3]:
            desc = CATEGORY_DESCRIPTIONS.get(cat, cat).split(" — ")[0]
            cat_descs.append(desc)
        api_list = ', '.join(apis_called[:5])
        if cat_descs:
            summary = f"{'; '.join(cat_descs)} using {api_list}"
        else:
            summary = f"Calls {api_list}"
    else:
        summary = custom_summary or f"Function at {function_address} (no suspicious APIs detected)"

    # Upsert: update existing function note at this address, or create new
    existing = state.get_notes(category="function", address=function_address)
    if existing:
        latest = existing[-1]
        updated = state.update_note(latest["id"], content=summary)
        if updated:
            note = updated
            was_update = True
        else:
            note = state.add_note(
                content=summary, category="function", address=function_address,
            )
            was_update = False
    else:
        note = state.add_note(
            content=summary, category="function", address=function_address,
        )
        was_update = False
    _persist_notes_to_cache()

    return {
        "address": function_address,
        "function_name": func_name,
        "auto_summary": summary,
        "note_id": note["id"],
        "was_update": was_update,
        "apis_called": apis_called[:10],
        "category_tags": category_tags,
    }
