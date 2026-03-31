"""Validation test: every @tool_decorator function must have a ---compact: line.

This test scans all MCP tool modules and verifies that each tool function
includes a compact shorthand description for --brief-descriptions mode.

If this test fails, add a ---compact: line to the docstring of the listed
tool(s). Grammar:

    ---compact: <action> [| <details>] [| needs: <prereqs>]

Place it after the first paragraph, before the blank line preceding
"When to use:". See CLAUDE.md for the full specification.
"""
import ast
from pathlib import Path

import pytest

_TOOLS_DIR = Path(__file__).resolve().parent.parent / "arkana" / "mcp"


def _find_tool_functions():
    """Yield (filename, function_name) for every @tool_decorator function."""
    for path in sorted(_TOOLS_DIR.glob("tools_*.py")):
        source = path.read_text()
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            for dec in node.decorator_list:
                # Match both bare `tool_decorator` and attribute access
                name = getattr(dec, "id", None) or getattr(dec, "attr", None)
                if name == "tool_decorator":
                    yield path.name, node.name, ast.get_docstring(node) or ""


def test_all_tools_have_compact_description():
    """Every @tool_decorator function must have a ---compact: line in its docstring."""
    missing = []
    for filename, funcname, docstring in _find_tool_functions():
        if "---compact:" not in docstring:
            missing.append(f"  {filename}:{funcname}")

    assert not missing, (
        f"{len(missing)} tool(s) missing ---compact: line:\n"
        + "\n".join(missing)
        + "\n\nAdd a ---compact: line after the first paragraph of each docstring."
    )


def test_compact_lines_are_not_empty():
    """---compact: lines must have actual content, not just the marker."""
    empty = []
    for filename, funcname, docstring in _find_tool_functions():
        for line in docstring.splitlines():
            stripped = line.strip()
            if stripped.startswith("---compact:"):
                content = stripped[len("---compact:"):].strip()
                if not content:
                    empty.append(f"  {filename}:{funcname}")
                break

    assert not empty, (
        f"{len(empty)} tool(s) have empty ---compact: lines:\n"
        + "\n".join(empty)
    )


def test_compact_lines_under_max_length():
    """Compact descriptions should be concise — warn if over 150 chars."""
    long_lines = []
    max_len = 150
    for filename, funcname, docstring in _find_tool_functions():
        for line in docstring.splitlines():
            stripped = line.strip()
            if stripped.startswith("---compact:"):
                content = stripped[len("---compact:"):].strip()
                if len(content) > max_len:
                    long_lines.append(
                        f"  {filename}:{funcname} ({len(content)} chars): {content[:80]}..."
                    )
                break

    assert not long_lines, (
        f"{len(long_lines)} compact description(s) exceed {max_len} chars:\n"
        + "\n".join(long_lines)
    )


def test_tool_count_sanity():
    """Sanity check: we should find approximately 284 tools."""
    tools = list(_find_tool_functions())
    # Allow some flexibility for tools being added/removed
    assert len(tools) >= 280, f"Expected ~284 tools, found only {len(tools)}"
    assert len(tools) <= 300, f"Expected ~284 tools, found {len(tools)}"
