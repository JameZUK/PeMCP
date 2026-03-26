"""MCP tools for managing analysis notes on the currently loaded file."""
import asyncio
import json
from typing import Dict, Any, Optional, List
from arkana.config import state, logger, Context, analysis_cache, ANGR_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.constants import MAX_TOOL_LIMIT
from arkana.state import MAX_HYPOTHESIS_EVIDENCE


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
    confidence: Optional[float] = None,
    status: Optional[str] = None,
    evidence: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    [Phase: context] Add a note to the currently loaded file. Notes persist in
    the analysis cache and are restored when the same file is reopened later.

    When to use: After any analysis step that produces important findings — IOCs,
    behavioral observations, function purposes, or tool results. Notes are the
    primary context management mechanism in long-running binary analysis.

    Notes feed into get_analysis_digest() which aggregates all findings into a
    single context-efficient summary.

    For hypothesis notes (category='hypothesis'), additional fields are supported:
    - confidence: Initial confidence score (0.0-1.0, default 0.5)
    - status: Lifecycle status (proposed/investigating/supported/refuted/confirmed, default proposed)
    - evidence: List of evidence items (or JSON string), each with
      {"tool": str, "finding": str, "supports": bool}

    Use update_hypothesis() to evolve hypothesis confidence and status as evidence
    accumulates during analysis.

    Args:
        ctx: The MCP Context object.
        content: (str) The note text content.
        category: (str) Note category: 'general' (default), 'function', 'tool_result',
            'ioc' (for IOC findings), 'hypothesis' (for condensed verdict with
            confidence tracking), 'conclusion' (for full detailed analysis write-up
            with markdown), or 'manual' (for manually researched findings).
        address: (Optional[str]) For 'function' notes: a hex address (e.g. '0x401000').
        tool_name: (Optional[str]) For 'tool_result' notes: the tool that produced the finding.
        confidence: (Optional[float]) For 'hypothesis' notes: initial confidence 0.0-1.0.
            Ignored for non-hypothesis categories.
        status: (Optional[str]) For 'hypothesis' notes: initial lifecycle status.
            One of 'proposed', 'investigating', 'supported', 'refuted', 'confirmed'.
            Ignored for non-hypothesis categories.
        evidence: For 'hypothesis' notes: list of evidence dicts or JSON string encoding a list.
            Each item: {"tool": "...", "finding": "...", "supports": true/false}.
            Ignored for non-hypothesis categories.

    Returns:
        A dictionary with the created note including its ID.
    """
    _check_pe_loaded("add_note")
    valid_categories = ("general", "function", "tool_result", "ioc", "hypothesis", "conclusion", "manual")
    if category not in valid_categories:
        raise ValueError(f"Invalid category '{category}'. Must be one of: {', '.join(valid_categories)}.")
    if len(content) > 50_000:
        raise ValueError("Note content exceeds 50KB limit.")

    # Parse hypothesis-specific fields — accept list (from MCP JSON) or str
    evidence_list: Optional[List[Dict[str, Any]]] = None
    if category == "hypothesis" and evidence is not None:
        if isinstance(evidence, list):
            evidence_list = evidence[:MAX_HYPOTHESIS_EVIDENCE]
        elif isinstance(evidence, str):
            try:
                parsed = json.loads(evidence)
                if not isinstance(parsed, list):
                    raise ValueError("Evidence must be a JSON array.")
                evidence_list = parsed[:MAX_HYPOTHESIS_EVIDENCE]
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid evidence JSON: {e}") from e
        else:
            raise ValueError("Evidence must be a list or JSON string.")

    note = state.add_note(
        content=content, category=category, address=address, tool_name=tool_name,
        confidence=confidence if category == "hypothesis" else None,
        status=status if category == "hypothesis" else None,
        evidence=evidence_list,
    )
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
            'ioc', 'hypothesis', 'conclusion', or 'manual'.
        address: (Optional[str]) Filter by hex address (e.g. '0x401000').
        limit: (int) Maximum number of notes to return. Default: 20.

    Returns:
        A dictionary with notes list and count.
    """
    _check_pe_loaded("get_notes")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
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
            'ioc', 'hypothesis', 'conclusion', or 'manual'.
        address: (Optional[str]) New hex address.
        tool_name: (Optional[str]) New associated tool name.

    Returns:
        A dictionary with the updated note, or an error if not found.
    """
    _check_pe_loaded("update_note")
    valid_categories = ("general", "function", "tool_result", "ioc", "hypothesis", "conclusion", "manual")
    if category is not None and category not in valid_categories:
        raise ValueError(f"Invalid category '{category}'. Must be one of: {', '.join(valid_categories)}.")
    # L: Enforce same 50KB content limit as add_note (was missing, allowing bypass via update)
    if content is not None and len(content) > 50_000:
        raise ValueError("Note content exceeds 50KB limit.")

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


@tool_decorator
async def update_hypothesis(
    ctx: Context,
    note_id: str,
    confidence: Optional[float] = None,
    status: Optional[str] = None,
    add_evidence: Optional[Any] = None,
    superseded_by: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: context] Update a hypothesis note's confidence, status, or evidence.
    Hypotheses are living notes that evolve as analysis progresses.

    When to use: After each analysis step that produces evidence for or against
    a hypothesis. Update confidence and status as findings accumulate. This
    creates a clear audit trail of how conclusions were reached.

    Typical workflow:
      1. add_note(category='hypothesis', content='Binary is a RAT', confidence=0.3, status='proposed')
      2. After finding C2 indicators: update_hypothesis(note_id, confidence=0.6, status='investigating',
         add_evidence={"tool": "match_c2_indicators", "finding": "Found C2 beacon pattern", "supports": true})
      3. After confirming: update_hypothesis(note_id, confidence=0.9, status='confirmed')

    Args:
        ctx: The MCP Context object.
        note_id: (str) The hypothesis note ID (e.g. 'n_1708300000_1') returned by add_note.
        confidence: (Optional[float]) Updated confidence score 0.0-1.0. Clamped to valid range.
        status: (Optional[str]) Updated lifecycle status. One of:
            'proposed' (initial), 'investigating' (actively testing),
            'supported' (evidence supports), 'refuted' (evidence contradicts),
            'confirmed' (high confidence conclusion).
        add_evidence: Evidence item to append — a dict with 'tool', 'finding', 'supports'
            keys, or a JSON string encoding such a dict.
            Evidence is appended to the existing list (max 50 items).
        superseded_by: (Optional[str]) Note ID of a newer hypothesis that replaces this one.
            The target note must exist.

    Returns:
        A dictionary with the updated hypothesis note, or an error if not found
        or if the note is not a hypothesis.
    """
    _check_pe_loaded("update_hypothesis")

    # Validate the note exists and is a hypothesis
    notes = state.get_notes()
    target_note = None
    for n in notes:
        if n["id"] == note_id:
            target_note = n
            break
    if target_note is None:
        return {"status": "not_found", "message": f"No note found with ID '{note_id}'."}
    if target_note.get("category") != "hypothesis":
        return {
            "status": "error",
            "message": f"Note '{note_id}' has category '{target_note.get('category')}', not 'hypothesis'. "
                       "Use update_note() for non-hypothesis notes.",
        }

    # Validate status if provided
    valid_statuses = ("proposed", "investigating", "supported", "refuted", "confirmed")
    if status is not None and status not in valid_statuses:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(valid_statuses)}.")

    # Parse add_evidence — accept dict (from MCP JSON) or str (JSON string)
    evidence_item: Optional[Dict[str, Any]] = None
    if add_evidence is not None:
        if isinstance(add_evidence, dict):
            evidence_item = add_evidence
        elif isinstance(add_evidence, str):
            try:
                evidence_item = json.loads(add_evidence)
                if not isinstance(evidence_item, dict):
                    raise ValueError("Evidence must be a JSON object with 'tool', 'finding', and 'supports' keys.")
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid add_evidence JSON: {e}") from e
        else:
            raise ValueError("add_evidence must be a dict or JSON string.")

    # Validate superseded_by target exists
    if superseded_by is not None:
        found = False
        for n in notes:
            if n["id"] == superseded_by:
                found = True
                break
        if not found:
            return {
                "status": "error",
                "message": f"Superseded-by target note '{superseded_by}' not found.",
            }

    # Build kwargs for state.update_note
    kwargs: Dict[str, Any] = {}
    if confidence is not None:
        kwargs["confidence"] = confidence
    if status is not None:
        kwargs["hypothesis_status"] = status
    if evidence_item is not None:
        kwargs["evidence"] = evidence_item
    if superseded_by is not None:
        kwargs["superseded_by"] = superseded_by

    updated = state.update_note(note_id, **kwargs)
    if updated is None:
        return {"status": "error", "message": f"Failed to update note '{note_id}'."}

    _persist_notes_to_cache()
    await ctx.info(f"Hypothesis updated: {note_id}")
    return {"status": "success", "note": updated}


_MAX_BATCH_AUTO_NOTE = 20


def _scan_pseudocode_patterns(code: str) -> Dict[str, Any]:
    """Scan decompiled pseudocode for behavioural patterns and notable strings.

    Returns a dict with 'patterns' (list of str) and 'strings' (list of str).
    Deterministic regex-based analysis — no LLM.
    """
    import re

    patterns: List[str] = []
    if re.search(r'\^|xor\b', code, re.IGNORECASE):
        patterns.append("xor_operation")
    if re.search(r'>>|<<|shr\b|shl\b', code, re.IGNORECASE):
        patterns.append("bit_shift")
    if re.search(r'\bwhile\b|\bfor\b|\bdo\b', code):
        patterns.append("loop")
    if re.search(r'VirtualAlloc|HeapAlloc|malloc|calloc|new\b', code, re.IGNORECASE):
        patterns.append("memory_allocation")
    if re.search(r'memcpy|memmove|RtlCopyMemory|CopyMemory', code, re.IGNORECASE):
        patterns.append("memory_copy")
    if re.search(r'CreateFile|fopen|open\b', code, re.IGNORECASE):
        patterns.append("file_access")
    if re.search(r'connect\b|send\b|recv\b|WSA|InternetOpen|HttpOpen|WinHttp|socket\b', code, re.IGNORECASE):
        patterns.append("network_activity")
    if re.search(r'RegOpenKey|RegSetValue|RegCreateKey', code, re.IGNORECASE):
        patterns.append("registry_access")
    if re.search(r'CreateProcess|ShellExecute|WinExec|system\b', code, re.IGNORECASE):
        patterns.append("process_creation")
    if re.search(r'CreateRemoteThread|WriteProcessMemory|VirtualAllocEx', code, re.IGNORECASE):
        patterns.append("process_injection")
    if re.search(r'Crypt|AES|DES|RC4|SHA|MD5|encrypt|decrypt', code, re.IGNORECASE):
        patterns.append("crypto_operation")

    # Extract notable string literals (URLs, paths, commands, etc.)
    string_pattern = re.compile(r'"([^"\\]|\\.){1,200}"')
    strings: List[str] = []
    for match in string_pattern.finditer(code):
        s = match.group(0)[1:-1]  # Strip quotes
        if s and len(s) >= 4 and s not in strings:
            strings.append(s)
    strings = strings[:10]  # Cap to avoid bloated notes

    return {"patterns": patterns, "strings": strings}


def _auto_note_single(function_address: str, custom_summary=None):
    """Core logic for auto-noting a single function. Returns result dict.

    Performs angr lookup if available, scans cached pseudocode for behavioural
    patterns, generates summary, and upserts the note.
    Does NOT persist to cache — caller is responsible for that.
    """
    from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB, CATEGORY_DESCRIPTIONS

    apis_called: List[str] = []
    category_tags: List[str] = []
    func_name = f"sub_{function_address.replace('0x', '')}"
    code_findings: List[str] = []
    code_patterns: List[str] = []
    code_strings: List[str] = []

    angr_proj, angr_cfg = state.get_angr_snapshot()
    if ANGR_AVAILABLE and angr_proj is not None and angr_cfg is not None:
        from arkana.mcp._angr_helpers import _parse_addr, _resolve_function_address, _ensure_project_and_cfg

        target_addr = _parse_addr(function_address)

        try:
            _ensure_project_and_cfg()
            func, addr_used = _resolve_function_address(target_addr)
            func_name = func.name

            callgraph = angr_cfg.functions.callgraph
            cats_seen: set = set()
            # M13: Use precompiled regex as fast pre-filter
            from arkana.mcp.tools_triage import _SUSPICIOUS_IMPORTS_PATTERN
            try:
                for callee_addr in callgraph.successors(addr_used):
                    if callee_addr in angr_cfg.functions:
                        cname = angr_cfg.functions[callee_addr].name
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

    # --- Scan cached pseudocode for behavioural patterns ---
    try:
        from arkana.mcp.tools_angr import _get_cached_lines, _make_decompile_key
        from arkana.mcp._angr_helpers import _parse_addr as _pa
        addr_int = _pa(function_address)
        cache_key = _make_decompile_key(addr_int)
        cached_lines = _get_cached_lines(cache_key)
        if cached_lines:
            code_text = "\n".join(cached_lines)
            scan = _scan_pseudocode_patterns(code_text)
            code_patterns = scan["patterns"]
            code_strings = scan["strings"]
            # Build human-readable findings fragments
            if code_patterns:
                code_findings.append(", ".join(code_patterns[:5]))
            if code_strings:
                # Include up to 3 notable strings inline
                str_previews = [f"'{s[:50]}'" for s in code_strings[:3]]
                code_findings.append(f"string{'s' if len(str_previews) > 1 else ''} {', '.join(str_previews)}")
    except Exception as e:
        logger.debug("auto_note_function: pseudocode scan failed: %s", e)

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
        # Append code findings if available
        if code_findings:
            summary += f". Code contains: {'; '.join(code_findings)}."
    else:
        if code_findings:
            summary = f"Function at {function_address}: {'; '.join(code_findings)}"
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

    result: Dict[str, Any] = {
        "address": function_address,
        "function_name": func_name,
        "auto_summary": summary,
        "note_id": note["id"],
        "was_update": was_update,
        "apis_called": apis_called[:10],
        "category_tags": category_tags,
    }
    if code_patterns:
        result["code_patterns"] = code_patterns
    if code_strings:
        result["code_strings"] = code_strings[:10]
    return result


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
                entry = await asyncio.to_thread(_auto_note_single, addr)
                batch_results.append(entry)
                succeeded += 1
            except Exception as e:
                batch_results.append({"address": addr, "error": str(e)[:200]})

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

    result = await asyncio.to_thread(_auto_note_single, function_address, custom_summary)
    _persist_notes_to_cache()
    return result
