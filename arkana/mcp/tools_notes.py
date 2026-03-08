"""MCP tools for managing analysis notes on the currently loaded file."""
from typing import Dict, Any, Optional, List
from arkana.config import state, logger, Context, analysis_cache, ANGR_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size


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
    [Phase: context] Add a note to the currently loaded file. Notes persist in
    the analysis cache and are restored when the same file is reopened later.

    When to use: After any analysis step that produces important findings — IOCs,
    behavioral observations, function purposes, or tool results. Notes are the
    primary context management mechanism in long-running binary analysis.

    Notes feed into get_analysis_digest() which aggregates all findings into a
    single context-efficient summary.

    Args:
        ctx: The MCP Context object.
        content: (str) The note text content.
        category: (str) Note category: 'general' (default), 'function', 'tool_result',
            'ioc' (for IOC findings), 'hypothesis' (for unconfirmed theories),
            or 'manual' (for manually researched findings).
        address: (Optional[str]) For 'function' notes: a hex address (e.g. '0x401000').
        tool_name: (Optional[str]) For 'tool_result' notes: the tool that produced the finding.

    Returns:
        A dictionary with the created note including its ID.
    """
    _check_pe_loaded("add_note")
    valid_categories = ("general", "function", "tool_result", "ioc", "hypothesis", "manual")
    if category not in valid_categories:
        raise ValueError(f"Invalid category '{category}'. Must be one of: {', '.join(valid_categories)}.")

    note = state.add_note(content=content, category=category, address=address, tool_name=tool_name)
    _persist_notes_to_cache()
    await ctx.info(f"Note added: {note['id']}")
    return {"status": "success", "note": note}


@tool_decorator
async def get_notes(
    ctx: Context,
    category: Optional[str] = None,
    address: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: context] Retrieve notes for the currently loaded file, optionally
    filtered by category or address.

    When to use: When you need to review specific notes (e.g. all function notes,
    or notes at a specific address). For a full findings overview, prefer
    get_analysis_digest() which aggregates notes with other context.

    Args:
        ctx: The MCP Context object.
        category: (Optional[str]) Filter by category: 'general', 'function', 'tool_result',
            'ioc', 'hypothesis', or 'manual'.
        address: (Optional[str]) Filter by hex address (e.g. '0x401000').
        limit: (int) Maximum number of notes to return. Default: 20.

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
    [Phase: context] Update an existing note by its ID. Only specified fields
    are changed.

    When to use: When you have new information about a previously noted finding
    and want to update rather than create a duplicate note.

    Args:
        ctx: The MCP Context object.
        note_id: (str) The note ID (e.g. 'n_1708300000_1') returned by add_note.
        content: (Optional[str]) New note text content.
        category: (Optional[str]) New category: 'general', 'function', 'tool_result',
            'ioc', 'hypothesis', or 'manual'.
        address: (Optional[str]) New hex address.
        tool_name: (Optional[str]) New associated tool name.

    Returns:
        A dictionary with the updated note, or an error if not found.
    """
    _check_pe_loaded("update_note")
    valid_categories = ("general", "function", "tool_result", "ioc", "hypothesis", "manual")
    if category is not None and category not in valid_categories:
        raise ValueError(f"Invalid category '{category}'. Must be one of: {', '.join(valid_categories)}.")

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
    [Phase: context] Delete a note by its ID.

    When to use: When a previous finding has been superseded or was incorrect.

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


_MAX_BATCH_AUTO_NOTE = 20


def _auto_note_single(function_address: str, custom_summary=None):
    """Core logic for auto-noting a single function. Returns result dict.

    Performs angr lookup if available, generates summary, and upserts the note.
    Does NOT persist to cache — caller is responsible for that.
    """
    from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB, CATEGORY_DESCRIPTIONS

    apis_called: List[str] = []
    category_tags: List[str] = []
    func_name = f"sub_{function_address.replace('0x', '')}"

    if ANGR_AVAILABLE and state.angr_project is not None and state.angr_cfg is not None:
        from arkana.mcp._angr_helpers import _parse_addr, _resolve_function_address, _ensure_project_and_cfg

        target_addr = _parse_addr(function_address)

        try:
            _ensure_project_and_cfg()
            func, addr_used = _resolve_function_address(target_addr)
            func_name = func.name

            callgraph = state.angr_cfg.functions.callgraph
            cats_seen: set = set()
            # M13: Use precompiled regex as fast pre-filter
            from arkana.mcp.tools_triage import _SUSPICIOUS_IMPORTS_PATTERN
            try:
                for callee_addr in callgraph.successors(addr_used):
                    if callee_addr in state.angr_cfg.functions:
                        cname = state.angr_cfg.functions[callee_addr].name
                        if not _SUSPICIOUS_IMPORTS_PATTERN.search(cname):
                            continue
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

    # Upsert
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

    return {
        "address": function_address,
        "function_name": func_name,
        "auto_summary": summary,
        "note_id": note["id"],
        "was_update": was_update,
        "apis_called": apis_called[:10],
        "category_tags": category_tags,
    }


@tool_decorator
async def auto_note_function(
    ctx: Context,
    function_address: str = "",
    function_addresses: Optional[List[str]] = None,
    custom_summary: Optional[str] = None,
    address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Auto-generates a one-line behavioral summary of a function
    and saves it as a persistent note. Uses API call pattern matching (not LLM)
    based on the function's callees in the CFG.

    When to use: After decompile_function_with_angr() — call this to record what
    the function does without keeping full pseudocode in context. Essential for
    building up get_analysis_digest() over the course of analysis.

    Next steps: Continue decompiling other functions from get_function_map(),
    or call get_analysis_digest() to review accumulated findings.

    Args:
        ctx: The MCP Context object.
        function_address: (str) Hex address of the function (e.g. '0x401000').
        function_addresses: (Optional[List[str]]) Batch mode: list of hex function
            addresses to auto-note in one call. Up to 20 items. Each gets an
            auto-generated summary. custom_summary is not supported in batch mode.
        address: (Optional[str]) Alias for function_address.
        custom_summary: (Optional[str]) If provided, use this as the summary
            instead of auto-generating. Useful when you've read the decompilation
            and want to record a specific finding. Not supported in batch mode.

    Returns:
        A dictionary with the function name, auto-generated summary, APIs called,
        and the note ID. In batch mode: {"batch_results": [...], "total": N, "succeeded": M}
    """
    _check_pe_loaded("auto_note_function")

    # ── Batch mode ──
    if function_addresses is not None:
        if custom_summary:
            return {"error": "custom_summary is not supported in batch mode. Each function gets an auto-generated summary."}

        items = list(function_addresses[:_MAX_BATCH_AUTO_NOTE])
        await ctx.info(f"Batch auto-noting {len(items)} functions")

        batch_results = []
        succeeded = 0
        for addr in items:
            try:
                entry = _auto_note_single(addr)
                batch_results.append(entry)
                succeeded += 1
            except Exception as e:
                batch_results.append({"address": addr, "error": str(e)})

        _persist_notes_to_cache()

        response: Dict[str, Any] = {
            "batch_results": batch_results,
            "total": len(batch_results),
            "succeeded": succeeded,
            "failed": len(batch_results) - succeeded,
        }
        return await _check_mcp_response_size(ctx, response, "auto_note_function")

    # ── Single-address mode (original behaviour) ──
    if address is not None and not function_address:
        function_address = address
    if not function_address:
        raise ValueError("Either 'function_address' or 'address' must be provided.")

    result = _auto_note_single(function_address, custom_summary)
    _persist_notes_to_cache()
    return result
