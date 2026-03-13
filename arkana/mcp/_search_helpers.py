"""Shared search-with-context helpers for decompilation and disassembly tools.

Provides regex grep with configurable context lines, producing merged
regions of matching lines/instructions suitable for paginated MCP responses.
"""
import re
from typing import Any, Dict, List, Optional

from arkana.constants import (
    DEFAULT_SEARCH_CONTEXT_LINES,
    MAX_SEARCH_CONTEXT_LINES,
    MAX_SEARCH_MATCHES,
)
from arkana.utils import validate_regex_pattern, safe_regex_search


def _build_context_regions(
    items: List[Any],
    match_indices: List[int],
    context_lines: int,
    *,
    format_item,
    one_based: bool = True,
) -> List[Dict[str, Any]]:
    """Merge overlapping context windows around *match_indices*.

    Args:
        items: The full list of items (lines or instruction dicts).
        match_indices: Sorted indices of items that matched the pattern.
        context_lines: Number of context items before/after each match.
        format_item: Callable ``(index, item, is_match) -> dict`` that
            formats a single item for output.
        one_based: If True, region start/end use 1-based numbering.

    Returns:
        List of merged region dicts, each containing ``start``, ``end``,
        and ``items`` (list of formatted item dicts).
    """
    if not match_indices:
        return []

    match_set = set(match_indices)
    total = len(items)
    regions: List[Dict[str, Any]] = []

    # Build raw (start, end) windows and merge overlapping/adjacent
    windows: List[tuple] = []
    for idx in match_indices:
        start = max(0, idx - context_lines)
        end = min(total - 1, idx + context_lines)
        if windows and start <= windows[-1][1] + 1:
            # Extend previous window
            windows[-1] = (windows[-1][0], end)
        else:
            windows.append((start, end))

    offset = 1 if one_based else 0
    for start, end in windows:
        region_items = []
        for i in range(start, end + 1):
            region_items.append(format_item(i, items[i], i in match_set))
        regions.append({
            "start": start + offset,
            "end": end + offset,
            "items": region_items,
        })

    return regions


def search_lines_with_context(
    lines: List[str],
    pattern: str,
    context_lines: int = DEFAULT_SEARCH_CONTEXT_LINES,
    case_sensitive: bool = False,
    max_matches: int = MAX_SEARCH_MATCHES,
) -> Dict[str, Any]:
    """Search *lines* for *pattern* and return matching regions with context.

    Args:
        lines: List of text lines (e.g. decompiled pseudocode).
        pattern: Regex pattern to search for.
        context_lines: Number of context lines before/after each match.
        case_sensitive: Whether the search is case-sensitive.
        max_matches: Maximum number of matches before truncation.

    Returns:
        Dict with ``matched_regions``, ``total_matches``, ``total_lines``,
        and ``truncated`` flag.

    Raises:
        ValueError: If the pattern is invalid or unsafe (ReDoS).
    """
    validate_regex_pattern(pattern)
    context_lines = max(0, min(context_lines, MAX_SEARCH_CONTEXT_LINES))
    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = re.compile(pattern, flags)

    match_indices: List[int] = []
    truncated = False
    for i, line in enumerate(lines):
        if safe_regex_search(compiled, line):
            if len(match_indices) >= max_matches:
                truncated = True
                break
            match_indices.append(i)

    def _format_line(idx, line, is_match):
        return {
            "line_number": idx + 1,
            "text": line,
            "is_match": is_match,
        }

    regions = _build_context_regions(
        lines, match_indices, context_lines,
        format_item=_format_line, one_based=True,
    )

    return {
        "matched_regions": regions,
        "total_matches": len(match_indices),
        "total_lines": len(lines),
        "truncated": truncated,
    }


def search_instructions_with_context(
    instructions: List[Dict[str, Any]],
    pattern: str,
    context_lines: int = DEFAULT_SEARCH_CONTEXT_LINES,
    case_sensitive: bool = False,
    max_matches: int = MAX_SEARCH_MATCHES,
) -> Dict[str, Any]:
    """Search instruction dicts for *pattern* and return matching regions.

    Searches each instruction's ``mnemonic + " " + op_str``, plus
    ``call_target`` and ``label`` fields (handles dict labels via
    ``.get("name")``).

    Args:
        instructions: List of instruction dicts from annotated disassembly.
        pattern: Regex pattern to search for.
        context_lines: Number of context instructions before/after each match.
        case_sensitive: Whether the search is case-sensitive.
        max_matches: Maximum number of matches before truncation.

    Returns:
        Dict with ``matched_regions``, ``total_matches``,
        ``total_instructions``, and ``truncated`` flag.

    Raises:
        ValueError: If the pattern is invalid or unsafe (ReDoS).
    """
    validate_regex_pattern(pattern)
    context_lines = max(0, min(context_lines, MAX_SEARCH_CONTEXT_LINES))
    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = re.compile(pattern, flags)

    match_indices: List[int] = []
    truncated = False
    for i, insn in enumerate(instructions):
        # Build searchable text from instruction fields
        text = f"{insn.get('mnemonic', '')} {insn.get('op_str', '')}"
        call_target = insn.get("call_target", "")
        if call_target:
            text += f" {call_target}"
        label = insn.get("label")
        if label:
            if isinstance(label, dict):
                label_name = label.get("name", "")
            else:
                label_name = str(label)
            if label_name:
                text += f" {label_name}"

        if safe_regex_search(compiled, text):
            if len(match_indices) >= max_matches:
                truncated = True
                break
            match_indices.append(i)

    def _format_insn(idx, insn, is_match):
        out = dict(insn)
        out["is_match"] = is_match
        out["instruction_index"] = idx
        return out

    regions = _build_context_regions(
        instructions, match_indices, context_lines,
        format_item=_format_insn, one_based=False,
    )

    # Rename region keys for instruction context
    for region in regions:
        region["start_index"] = region.pop("start")
        region["end_index"] = region.pop("end")
        region["instructions"] = region.pop("items")

    return {
        "matched_regions": regions,
        "total_matches": len(match_indices),
        "total_instructions": len(instructions),
        "truncated": truncated,
    }
