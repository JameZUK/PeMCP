"""Helpers for applying user-defined renames to decompiled/disassembled output."""
import re
from typing import List, Optional

from arkana.state import get_current_state


# Pattern for auto-generated function names: sub_HEXADDR, FUN_HEXADDR, etc.
_AUTO_FUNC_NAME_RE = re.compile(r'\b(sub_|FUN_)([0-9a-fA-F]+)\b')


def apply_function_renames_to_lines(lines: List[str]) -> List[str]:
    """Replace auto-generated function names (sub_HEXADDR) with user-assigned names."""
    state = get_current_state()
    func_renames = state.renames.get("functions", {})
    if not func_renames:
        return lines

    # Build lookup: normalised hex (no prefix) -> user name
    lookup = {}
    for addr_hex, name in func_renames.items():
        # Strip 0x prefix and lowercase for matching
        clean = addr_hex.lower().lstrip("0x").lstrip("0") or "0"
        lookup[clean] = name

    if not lookup:
        return lines

    def _replace(match):
        hex_part = match.group(2).lower().lstrip("0") or "0"
        if hex_part in lookup:
            return lookup[hex_part]
        return match.group(0)

    return [_AUTO_FUNC_NAME_RE.sub(_replace, line) for line in lines]


def apply_variable_renames_to_lines(lines: List[str], func_address: str) -> List[str]:
    """Replace variable names within a function scope using user-defined renames."""
    state = get_current_state()
    var_renames = state.renames.get("variables", {})
    addr = func_address.lower()
    if addr not in var_renames or not var_renames[addr]:
        return lines

    result = []
    for line in lines:
        for old_name, new_name in var_renames[addr].items():
            # Word-boundary replacement to avoid partial matches
            line = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, line)
        result.append(line)
    return result


def get_display_name(address: str, default_name: str) -> str:
    """Return user-assigned function name or fall back to default."""
    state = get_current_state()
    user_name = state.get_function_display_name(address)
    return user_name if user_name else default_name
