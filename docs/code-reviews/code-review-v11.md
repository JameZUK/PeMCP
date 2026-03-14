# Code Review v11

**Date**: 2026-03-14
**Scope**: Full codebase scan — security, efficiency, stability, memory
**Findings**: 11 confirmed issues (3 HIGH, 5 MEDIUM, 3 LOW) across 16 files
**All fixed in this pass.**

## Summary

Key themes:
- **Untruncated exception text** in MCP responses and task metadata (~20 locations missed by v10)
- **List concatenation** creating unnecessary copies (missed instance of v10 M9 pattern)
- **CLI-path gaps** where guards exist in MCP path but not CLI preload
- **Private API usage** and **O(n log n) eviction** in utility code

## Findings

### HIGH

| ID | File(s) | Category | Issue | Fix |
|----|---------|----------|-------|-----|
| H1 | `background.py` | Security | `angr_background_worker` error paths store unbounded `str(e)` in task metadata and stderr | Added `[:200]` truncation at 5 locations |
| H2 | `state_api.py` | Efficiency | `generate_report_text()` uses list concat `+` creating full copy (v10 M9 missed this) | Replaced with `itertools.chain()` |
| H3 | 10 tool files | Security | ~20 MCP tools return untruncated `str(e)` in error responses | Added `[:200]` at all locations |

### MEDIUM

| ID | File(s) | Category | Issue | Fix |
|----|---------|----------|-------|-----|
| M1 | `main.py` | Stability | CLI preload file size guard only applies to shellcode/elf/macho, not PE | Moved size check above mode switch; all modes now guarded |
| M2 | `utils.py` | Stability | Private `ThreadPoolExecutor._threads` access could break in future Python | Replaced with consecutive timeout counter (`_regex_consecutive_timeouts`) |
| M3 | `tools_pe.py` | Memory | `previous_session_history` loaded from cache without length bound | Sliced to `[:MAX_TOOL_HISTORY]` (500) |
| M4 | `main.py` | Security | Full API key printed to stderr (captured in Docker/systemd logs) | Show full key only when `stderr.isatty()`; mask otherwise |
| M5 | `tools_session.py` | Efficiency | `_phase_caches` uses O(n log n) `sorted()` eviction + no thread safety | Replaced with `OrderedDict` + `threading.Lock` for O(1) eviction |

### LOW

| ID | File(s) | Category | Issue | Fix |
|----|---------|----------|-------|-----|
| L1 | `utils.py` | Efficiency | `get_symbol_storage_class_str()` rebuilds dict every call | Lazy-init module-level cache (`_STORAGE_CLASS_MAP`) |
| L2 | `tools_session.py` | Stability | `_phase_caches` dict not thread-safe | Addressed as part of M5 |
| L3 | `background.py` | Security | stderr print includes untruncated exception | Addressed as part of H1 |

## Files Modified (16)

1. `arkana/background.py` — H1, L3
2. `arkana/dashboard/state_api.py` — H2
3. `arkana/mcp/tools_angr.py` — H3
4. `arkana/mcp/tools_angr_forensic.py` — H3
5. `arkana/mcp/tools_strings.py` — H3
6. `arkana/mcp/tools_pe_forensic.py` — H3
7. `arkana/mcp/tools_pe_structure.py` — H3
8. `arkana/mcp/tools_dotnet.py` — H3
9. `arkana/mcp/tools_go.py` — H3
10. `arkana/mcp/tools_refinery.py` — H3
11. `arkana/mcp/tools_new_libs.py` — H3
12. `arkana/mcp/tools_notes.py` — H3
13. `arkana/main.py` — M1, M4
14. `arkana/utils.py` — M2, L1
15. `arkana/mcp/tools_pe.py` — M3
16. `arkana/mcp/tools_session.py` — M5, L2

## Rejected / False Positives

| Finding | Verdict | Reason |
|---------|---------|--------|
| `_current_tool_var` not cleared after tool | FP | Reset via `_current_tool_var.reset(_tool_token)` in `server.py:239` |
| PE file size not guarded in MCP path | FP | Already guarded at `tools_pe.py:253` |
| `triage_status` unbounded dict | FP | Capped at `state.py:567-568` |
| Warning handler missing `_closing` check | FP | `get_current_state()` returns None for closing sessions |
| Jinja2 missing autoescape | FP | `autoescape=True` at `app.py:75` |

## Verification

- **Tests**: 1117 passed, 36 skipped (3.15s)
- **Lint**: All checks passed (ruff)
