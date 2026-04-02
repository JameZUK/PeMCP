"""Trace query parser and evaluator for debug API call filtering.

Self-contained module usable from both the debug_runner subprocess (Qiling
venv) and the main MCP process for validation.  No external dependencies
beyond the stdlib.

Query syntax
------------
Comma-separated predicates::

    api=VirtualAlloc,args.p3=0x40
    api~WriteProcess,retval!=0x0
    seq>100,seq<200

Operators: ``=``, ``!=``, ``~`` (substring), ``>``, ``<``, ``>=``, ``<=``

Supported fields: ``api``, ``args.<key>``, ``retval``, ``address``, ``seq``,
``timestamp``.

Sequence matching
-----------------
Semicolon-separated API name patterns that must appear in order (not
necessarily consecutively)::

    VirtualAlloc;WriteProcessMemory;CreateRemoteThread

Returns groups of matching call sequences.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Operators in longest-first order for tokenisation
_OPERATORS = (">=", "<=", "!=", "~", ">", "<", "=")

# Max predicates per query to prevent abuse
_MAX_PREDICATES = 20

# Max sequence steps
_MAX_SEQUENCE_STEPS = 20

# Max results from sequence matching
_MAX_SEQUENCE_MATCHES = 50


# ---------------------------------------------------------------------------
# Predicate parsing
# ---------------------------------------------------------------------------

class Predicate:
    """A single query predicate: ``field op value``."""
    __slots__ = ("field", "op", "value", "numeric_value")

    def __init__(self, field: str, op: str, value: str):
        self.field = field
        self.op = op
        self.value = value
        # Pre-compute numeric value for comparison operators
        self.numeric_value: Optional[int | float] = _try_numeric(value)


def _try_numeric(value: str) -> Optional[int | float]:
    """Attempt to parse *value* as an integer (including hex) or float."""
    if not value:
        return None
    v = value.strip()
    try:
        if v.startswith("0x") or v.startswith("0X"):
            return int(v, 16)
        return int(v)
    except (ValueError, OverflowError):
        pass
    try:
        return float(v)
    except (ValueError, OverflowError):
        pass
    return None


def parse_query(query: str) -> List[Predicate]:
    """Parse a query string into a list of predicates.

    Args:
        query: Comma-separated predicates (e.g. ``"api=VirtualAlloc,seq>10"``).

    Returns:
        List of ``Predicate`` objects.

    Raises:
        ValueError: If the query syntax is invalid.
    """
    if not query or not query.strip():
        return []

    predicates: List[Predicate] = []
    parts = query.split(",")

    if len(parts) > _MAX_PREDICATES:
        raise ValueError(
            f"Too many predicates ({len(parts)}); maximum is {_MAX_PREDICATES}"
        )

    for part in parts:
        part = part.strip()
        if not part:
            continue
        pred = _parse_single_predicate(part)
        predicates.append(pred)

    return predicates


def _parse_single_predicate(text: str) -> Predicate:
    """Parse a single ``field op value`` predicate."""
    for op in _OPERATORS:
        idx = text.find(op)
        if idx > 0:  # field must be non-empty (idx > 0)
            field = text[:idx].strip()
            value = text[idx + len(op):].strip()
            if not field:
                raise ValueError(f"Empty field in predicate: {text!r}")
            _validate_field(field)
            return Predicate(field, op, value)
    raise ValueError(
        f"Invalid predicate (no operator found): {text!r}. "
        f"Valid operators: {', '.join(_OPERATORS)}"
    )


def _validate_field(field: str) -> None:
    """Validate that a field name is safe and supported."""
    # Allow: api, retval, address, seq, timestamp, args.<key>
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_.]*$', field):
        raise ValueError(
            f"Invalid field name: {field!r}. "
            "Fields must start with a letter/underscore and contain only "
            "letters, digits, underscores, and dots."
        )
    # Block excessively deep field paths
    if field.count('.') > 3:
        raise ValueError(f"Field path too deep: {field!r} (max 3 dots)")


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------

def _resolve_field(entry: Dict[str, Any], field: str) -> Any:
    """Resolve a dotted field path on a trace entry dict.

    Supports: ``api``, ``retval``, ``address``, ``seq``, ``timestamp``,
    ``args.p0``, ``args.p1``, etc.
    """
    parts = field.split(".", 1)
    key = parts[0]
    value = entry.get(key)

    if len(parts) == 1:
        return value

    # Nested access (e.g., args.p0)
    sub_key = parts[1]
    if isinstance(value, dict):
        return value.get(sub_key)
    return None


def evaluate_predicate(entry: Dict[str, Any], pred: Predicate) -> bool:
    """Test whether a single trace entry matches a predicate.

    Args:
        entry: A trace entry dict (seq, api, args, retval, ...).
        pred: A parsed ``Predicate``.

    Returns:
        True if the entry matches the predicate.
    """
    field_val = _resolve_field(entry, pred.field)
    if field_val is None:
        # Field not present — only != matches
        return pred.op == "!="

    op = pred.op
    pred_val = pred.value

    if op == "=":
        return _compare_equal(field_val, pred_val)
    elif op == "!=":
        return not _compare_equal(field_val, pred_val)
    elif op == "~":
        return _compare_substring(field_val, pred_val)
    elif op in (">", "<", ">=", "<="):
        return _compare_ordered(field_val, pred.numeric_value, pred_val, op)

    return False


def _compare_equal(field_val: Any, pred_val: str) -> bool:
    """Equality comparison with hex-aware coercion."""
    field_str = str(field_val)

    # Try numeric comparison first (handles hex strings)
    field_num = _try_numeric(field_str)
    pred_num = _try_numeric(pred_val)
    if field_num is not None and pred_num is not None:
        return field_num == pred_num

    # Fall back to case-insensitive string comparison
    return field_str.lower() == pred_val.lower()


def _compare_substring(field_val: Any, pred_val: str) -> bool:
    """Case-insensitive substring match (NOT regex to avoid ReDoS)."""
    return pred_val.lower() in str(field_val).lower()


def _compare_ordered(
    field_val: Any,
    pred_num: Optional[int | float],
    pred_str: str,
    op: str,
) -> bool:
    """Ordered comparison (>, <, >=, <=) with numeric coercion."""
    field_num = _try_numeric(str(field_val))
    if field_num is None or pred_num is None:
        # Cannot compare non-numeric values with ordered operators
        return False

    if op == ">":
        return field_num > pred_num
    elif op == "<":
        return field_num < pred_num
    elif op == ">=":
        return field_num >= pred_num
    elif op == "<=":
        return field_num <= pred_num
    return False


# ---------------------------------------------------------------------------
# Trace filtering
# ---------------------------------------------------------------------------

def filter_trace(
    entries: List[Dict[str, Any]],
    predicates: List[Predicate],
) -> List[Dict[str, Any]]:
    """Filter trace entries against all predicates (AND logic).

    Args:
        entries: List of trace entry dicts.
        predicates: Parsed predicate list (all must match).

    Returns:
        Filtered list of matching entries.
    """
    if not predicates:
        return entries

    return [
        entry for entry in entries
        if all(evaluate_predicate(entry, pred) for pred in predicates)
    ]


# ---------------------------------------------------------------------------
# Sequence matching
# ---------------------------------------------------------------------------

def parse_sequence(sequence: str) -> List[str]:
    """Parse a sequence pattern string into API name patterns.

    Args:
        sequence: Semicolon-separated API name substrings
            (e.g. ``"VirtualAlloc;WriteProcessMemory"``).

    Returns:
        List of lowercase API name patterns.

    Raises:
        ValueError: If the sequence is empty or has too many steps.
    """
    if not sequence or not sequence.strip():
        return []

    steps = [s.strip() for s in sequence.split(";") if s.strip()]
    if not steps:
        return []

    if len(steps) > _MAX_SEQUENCE_STEPS:
        raise ValueError(
            f"Too many sequence steps ({len(steps)}); "
            f"maximum is {_MAX_SEQUENCE_STEPS}"
        )

    return [s.lower() for s in steps]


def match_sequences(
    entries: List[Dict[str, Any]],
    steps: List[str],
    *,
    gap_max: int = 0,
) -> List[Dict[str, Any]]:
    """Find ordered API call sequences in trace entries.

    Scans the trace for occurrences where each step's substring appears
    in the API name of successive entries, in order.

    Args:
        entries: List of trace entry dicts.
        steps: Lowercase API name substrings (from ``parse_sequence``).
        gap_max: Maximum entries allowed between consecutive steps.
            0 means unlimited gap.

    Returns:
        List of match group dicts, each containing:
            ``start_seq``, ``end_seq``, ``entries`` (the matching calls),
            ``step_indices`` (trace indices of each matched step).
    """
    if not steps or not entries:
        return []

    gap_max = max(0, min(gap_max, 100_000))
    matches: List[Dict[str, Any]] = []

    # Sliding scan: for each potential start position, try to match the
    # full sequence.  O(n * k) where n = entries, k = steps.
    i = 0
    while i < len(entries) and len(matches) < _MAX_SEQUENCE_MATCHES:
        api_name = str(entries[i].get("api", "")).lower()
        if steps[0] in api_name:
            # Try to match remaining steps starting after this entry
            match = _try_match_sequence(entries, steps, i, gap_max)
            if match is not None:
                matches.append(match)
                # Advance past the last matched entry to avoid overlapping
                i = match["_last_idx"] + 1
                continue
        i += 1

    # Remove internal tracking field
    for m in matches:
        m.pop("_last_idx", None)

    return matches


def _try_match_sequence(
    entries: List[Dict[str, Any]],
    steps: List[str],
    start_idx: int,
    gap_max: int,
) -> Optional[Dict[str, Any]]:
    """Try to match a full sequence starting at *start_idx*."""
    matched_entries = [entries[start_idx]]
    step_indices = [start_idx]
    step_pos = 1  # Next step to match
    prev_idx = start_idx

    for j in range(start_idx + 1, len(entries)):
        if step_pos >= len(steps):
            break

        # Check gap constraint
        if gap_max > 0 and (j - prev_idx - 1) > gap_max:
            return None  # Gap too large, abandon this start

        api_name = str(entries[j].get("api", "")).lower()
        if steps[step_pos] in api_name:
            matched_entries.append(entries[j])
            step_indices.append(j)
            prev_idx = j
            step_pos += 1

    if step_pos < len(steps):
        return None  # Not all steps matched

    return {
        "start_seq": matched_entries[0].get("seq"),
        "end_seq": matched_entries[-1].get("seq"),
        "entries": matched_entries,
        "step_indices": step_indices,
        "_last_idx": step_indices[-1],
    }


# ---------------------------------------------------------------------------
# Validation (for use in MCP layer before sending to subprocess)
# ---------------------------------------------------------------------------

def validate_query(query: str) -> Optional[str]:
    """Validate query syntax without evaluating.

    Returns None on success, or an error message string on failure.
    """
    try:
        parse_query(query)
        return None
    except ValueError as e:
        return str(e)


def validate_sequence(sequence: str) -> Optional[str]:
    """Validate sequence syntax without evaluating.

    Returns None on success, or an error message string on failure.
    """
    try:
        parse_sequence(sequence)
        return None
    except ValueError as e:
        return str(e)
