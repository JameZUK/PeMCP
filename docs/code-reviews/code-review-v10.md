# Code Review v10 — Consolidated Findings (Security + Efficiency + Stability)

**Date**: 2026-03-14
**Scope**: Full codebase review — security, efficiency, stability, memory safety
**Method**: Systematic file-by-file review with 3-agent parallel scan (security, efficiency, stability) + 3-agent validation against source code. Pattern search across all MCP tool modules, helpers, parsers, dashboard, and core files
**Status**: 29 confirmed issues (5 HIGH, 13 MEDIUM, 11 LOW) across 18 files
**Previous**: Builds on v9 (20 issues, all FIXED). All v10 findings are NEW issues not covered in v4-v9.

## Legend

- **Status**: `FIXED` = confirmed and resolved | `FP` = false positive | `WONTFIX` = accepted risk
- **Limits**: Whether the fix could impose functionality limitations

---

## HIGH (5)

### H1: `hashlib.md5()` without `usedforsecurity=False` in 7 locations (FIPS breakage)
- **File**: `parsers/pe.py:776`, `tools_batch.py:73`, `tools_pe_forensic.py:146`, `tools_refinery_extract.py:153,419`, `tools_refinery.py:755`, `_refinery_helpers.py:186`
- **Status**: FIXED
- **Limits**: No
- **Category**: Security
- **Description**: v7 L15 fixed `parsers/pe.py` lines 62+157 but missed line 776 (overlay hash). Six more files also call `hashlib.md5()` without the flag. On FIPS-enabled systems, `hashlib.md5()` without `usedforsecurity=False` raises `ValueError`. All uses are for file identification, not cryptographic security.
- **Fix**: Added `usedforsecurity=False` to all 7 remaining `hashlib.md5()` calls.

### H2: Python traceback leaked to MCP clients via `traceback_tail` field
- **File**: `arkana/mcp/tools_angr_dataflow.py:135,584`
- **Status**: FIXED
- **Limits**: No
- **Category**: Security
- **Description**: Two error responses include `"traceback_tail": tb[-500:]`, leaking internal file paths, library versions, and code structure to the MCP client. Other tools in the same file correctly log the traceback server-side without exposing it.
- **Fix**: Removed `traceback_tail` from both error response dicts.

### H3: `export_project` calls snapshot methods twice (double lock + copy)
- **File**: `arkana/mcp/tools_export.py:93-97,111-115`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: `export_project` calls `get_all_notes_snapshot()`, `get_tool_history_snapshot()`, `get_all_renames_snapshot()`, and `get_all_types_snapshot()` twice each — once for manifest counts (lines 93-97), again for wrapper data (lines 111-115). Each snapshot acquires locks and produces copies. Only `artifacts_snapshot` was stored and reused.
- **Fix**: Store all 4 snapshots in variables before building manifest, reuse in wrapper.

### H4: `get_functions_data` calls `get_renames()` and `get_all_triage_snapshot()` twice
- **File**: `arkana/dashboard/state_api.py:959-960,979`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: Called every ~2s by dashboard htmx polling. Takes snapshots at lines 959-960 for the cache version key, then takes them again at line 979 on cache miss — redundant lock-guarded copies.
- **Fix**: Reuse `_renames` and `_triage_snap` from version key computation in the cache-miss path.

### H5: `_parse_with_dotnetfile` never closes DotNetPE object (resource leak)
- **File**: `arkana/mcp/tools_dotnet.py:215-297`
- **Status**: FIXED
- **Limits**: No
- **Category**: Stability
- **Description**: Creates `dotnetfile.DotNetPE(target)` but never calls close or uses try/finally. The primary `dnfile` path correctly uses try/finally with `dn.close()`. Each call leaks a file handle.
- **Fix**: Wrapped function body in try/finally with `dn.close()`.

---

## MEDIUM (13)

### M1: `~/.arkana/` directory created without restrictive permissions
- **File**: `arkana/dashboard/app.py:275`, `arkana/mcp/tools_export.py:373,414,438`
- **Status**: FIXED
- **Limits**: No
- **Category**: Security
- **Description**: `_TOKEN_FILE.parent.mkdir()` and 3 additional `mkdir()` calls in `tools_export.py` create directories under `~/.arkana/` with default 0o755 (world-readable). Pattern search found the additional instances.
- **Fix**: Added `mode=0o700` to all 4 `mkdir()` calls.

### M2: Token file TOCTOU — written then chmod'd
- **File**: `arkana/dashboard/app.py:280-285`
- **Status**: FIXED
- **Limits**: No
- **Category**: Security
- **Description**: Token file is written with `write_text()` (default 0o644), then `os.chmod()` to 0o600 — briefly world-readable. Low practical risk but trivially fixable.
- **Fix**: Use `os.open()` with `O_CREAT|O_WRONLY` and 0o600 mode for atomic secure creation.

### M3: BSim DB directory created without restrictive permissions
- **File**: `arkana/mcp/_bsim_features.py:433`
- **Status**: FIXED
- **Limits**: No
- **Category**: Security
- **Description**: `BSIM_DB_DIR.mkdir()` creates `~/.arkana/bsim/` with default permissions. Contains function signatures and binary metadata.
- **Fix**: Added `mode=0o700` to `mkdir()`.

### M4: Raw exception text exposed in task failure metadata
- **File**: `arkana/enrichment.py:285`, `arkana/mcp/tools_pe.py:117`, `arkana/background.py:194`
- **Status**: FIXED
- **Limits**: No
- **Category**: Security
- **Description**: `progress_message=f"Failed: {e}"` and `error=str(e)` store raw exception text in task metadata exposed via `check_task_status`. Library exceptions can contain internal file paths and state.
- **Fix**: Truncate exception messages to 200 chars in task failure metadata.

### M5: `suggest_next_action` redundantly calls `state.get_notes()`
- **File**: `arkana/mcp/tools_session.py:791,936`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: `_build_suggestions()` calls `state.get_notes()` at line 791, then `suggest_next_action()` calls it again at line 936 just for `len(notes)`. Two redundant lock-guarded copies.
- **Fix**: Have `_build_suggestions()` return notes count alongside suggestions.

### M6: `_get_decompiled_addresses()` copies all keys then filters
- **File**: `arkana/dashboard/state_api.py:1612-1614`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: Copies all `_decompile_meta` keys (up to 2000) into a list, then filters by session outside the lock. Should filter inside the lock.
- **Fix**: Filter keys inside the lock, building the set directly.

### M7: `_detect_analysis_phase` duplicated 3x with drifting tool sets
- **File**: `arkana/mcp/tools_session.py:28-67`, `arkana/dashboard/state_api.py:1572-1599,3523-3557`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: Three implementations with slightly different tool membership lists and different caching strategies. The two state_api.py versions use full `get_tool_history()` (deque copy) and recreate set literals on every call.
- **Fix**: Both state_api.py functions now delegate to a shared `_detect_phase_for_state(st)` helper that uses `get_ran_tool_names()` and module-level frozensets.

### M8: `_phase_caches` not cleaned on session reap
- **File**: `arkana/mcp/tools_session.py:25`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: Module-level dict keyed by `state._state_uuid` — entries for reaped sessions linger until the 100-entry eviction cap triggers.
- **Fix**: Added `cleanup_phase_cache(state_uuid)` function, called from session reaper.

### M9: `generate_analysis_report` concatenates full history lists
- **File**: `arkana/mcp/tools_workflow.py:132`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: `state.previous_session_history + state.get_tool_history()` creates a combined list that can contain thousands of entries. Only used for `len()`, `Counter()`, and iteration.
- **Fix**: Use `itertools.chain` instead of list concatenation. Count via sum of lengths.

### M10: `get_analysis_digest` copies full warnings list to count errors
- **File**: `arkana/mcp/tools_session.py:484`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: Calls `state.get_warnings()` (full list copy of up to 500 items) just to count entries with ERROR/CRITICAL level.
- **Fix**: Added `get_error_warning_count()` method to AnalyzerState.

### M11: Decompile-on-demand counter race — enrichment finally resets to 0
- **File**: `arkana/enrichment.py:290`
- **Status**: FIXED
- **Limits**: No
- **Category**: Stability
- **Description**: Enrichment's finally block unconditionally sets `state._decompile_on_demand_count = 0`. If an on-demand decompile has the counter incremented when enrichment ends, the counter becomes corrupted (negative), breaking subsequent cooperative yielding.
- **Fix**: Removed the unconditional reset. The counter is self-balancing (each increment has a matching decrement).

### M12: `update_session_data` read-modify-write race in cache
- **File**: `arkana/cache.py:465-496`
- **Status**: FIXED
- **Limits**: No — slightly increased lock hold time but cache writes are infrequent
- **Category**: Stability
- **Description**: Lock is released after reading (line 474) but before writing (line 496). Concurrent updates to the same SHA256 cause the second write to silently overwrite the first.
- **Fix**: Hold lock through the entire read-modify-write cycle.

### M13: Mach-O security scan missing empty-file guard before mmap
- **File**: `arkana/mcp/tools_triage.py:1342-1344`
- **Status**: FIXED
- **Limits**: No
- **Category**: Stability
- **Description**: ELF path checks `os.path.getsize() == 0` before `mmap.mmap()`, but Mach-O path does not. `mmap()` on empty file raises `ValueError`.
- **Fix**: Added same empty-file guard before Mach-O mmap.

---

## LOW (11)

### L1: Dead conditional lock pattern in `_collect_all_string_values`
- **File**: `arkana/mcp/tools_triage.py:84-91`
- **Status**: FIXED
- **Limits**: No
- **Category**: Stability
- **Description**: Uses `getattr(state, '_pe_lock', None)` to conditionally acquire the lock, with a duplicate else branch. `_pe_lock` is always initialized in `__init__()`, making the else branch dead code.
- **Fix**: Removed conditional check, always use `with state._pe_lock:`.

### L2: Dashboard decompile missing on-demand counter signal
- **File**: `arkana/dashboard/state_api.py:1452`
- **Status**: FIXED
- **Limits**: No
- **Category**: Stability
- **Description**: `trigger_decompile()` acquires the decompile lock without incrementing the on-demand counter. Enrichment sweep won't yield cooperatively for dashboard requests.
- **Fix**: Added counter increment/decrement pattern matching `tools_angr.py`.

### L3: Flat strings cache key missing sifter version
- **File**: `arkana/mcp/tools_strings.py:64`
- **Status**: FIXED
- **Limits**: No
- **Category**: Stability
- **Description**: Cache key includes FLOSS counts and basic count but not sifter score state. After sifter completes, cached results don't include new scores.
- **Fix**: Added sifter score count to the versioned cache key.

### L4: Untruncated exception in `get_data_dependencies` error
- **File**: `arkana/mcp/tools_angr_dataflow.py:291`
- **Status**: FIXED
- **Limits**: No
- **Category**: Security
- **Description**: `str(e)` without truncation in error response. angr exceptions can contain internal details.
- **Fix**: Truncated exception message to 200 chars.

### L5: OS error messages contain full paths in batch tool
- **File**: `arkana/mcp/tools_batch.py:57-69`
- **Status**: FIXED
- **Limits**: No
- **Category**: Security
- **Description**: `f"Cannot stat file: {e}"` — OS error strings include the full file path. v9 L3 fixed the filename field but not error messages.
- **Fix**: Use `e.strerror` instead of `str(e)` for OS errors.

### L6: `len(list(func.blocks))` instead of O(1) `number_of_nodes()`
- **File**: `tools_angr.py:261`, `tools_angr_disasm.py:657`, `_angr_helpers.py:263`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: Materializes entire blocks iterator into a list just to count. `func.graph.number_of_nodes()` is O(1) via NetworkX.
- **Fix**: Use `number_of_nodes()` with fallback to `len(list(func.blocks))`.

### L7: `len(list(func.graph.edges()))` instead of O(1) `number_of_edges()`
- **File**: `arkana/dashboard/state_api.py:1969`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: Materializes edge iterator into list to count. `number_of_edges()` is O(1).
- **Fix**: Use `func.graph.number_of_edges()` with try/except fallback.

### L8: Set literals recreated every call in `_detect_phase` functions
- **File**: `arkana/dashboard/state_api.py:1582-1591,3537-3549`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: Inline set literals created on every call instead of module-level constants. Fixed as part of M7 (phase detection consolidation).

### L9: `get_session_summary` iterates notes multiple times
- **File**: `arkana/mcp/tools_session.py:133,159,243`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: Notes list iterated 2-3 times for category Counter and function-category filter. Could build both in a single pass.
- **Fix**: Single-pass categorization building Counter + func_notes simultaneously.

### L10: Unnecessary `list()` around `loop.body_nodes` set
- **File**: `arkana/background.py:328`, `arkana/mcp/tools_angr.py:1032`
- **Status**: FIXED
- **Limits**: No
- **Category**: Efficiency
- **Description**: `len(list(loop.body_nodes))` — `body_nodes` is already a set; `len()` works directly on sets.
- **Fix**: Removed `list()` wrapper.

### L11: `_classify_core` accesses `state.pe_data` without null check
- **File**: `arkana/mcp/tools_classification.py:55`
- **Status**: FIXED
- **Limits**: No
- **Category**: Stability
- **Description**: `state.pe_data.get('mode', 'pe')` raises `AttributeError` if `pe_data` is None. All callers guard against this, but the function itself isn't defensive.
- **Fix**: Added null check returning error dict.

---

## False Positives / WONTFIX

| Finding | Verdict | Reason |
|---------|---------|--------|
| `get_config` exposes `loaded_filepath`, `samples_path`, `pid` | WONTFIX | By design — diagnostic tool for authenticated MCP clients |
| `list_samples` returns full absolute paths | WONTFIX | By design — paths needed for `open_file()` |
| `"filepath": state.filepath` in 24+ MCP responses | WONTFIX | Established project pattern — contextual info for AI client |
| `_triage_file_info` includes filepath | WONTFIX | Same pattern as above |
| `_parse_single_file` reads file twice (v9 M1 design) | WONTFIX | Intentional memory optimization — holds only one copy at a time |
| `get_overview_data` copies lists for counts | FP | Full copies are reused later in the function |
| `_build_function_lookup` called twice in overview | LOW IMPACT | Second call hits 5s TTL cache (negligible overhead) |
| `json.dumps` safety-net on every tool call | LOW IMPACT | Sub-millisecond for small responses; necessary backstop |
| `deepcopy` on overview cache read | LOW IMPACT | Correct for thread safety — concurrent requests could see mutations |
| `get_callgraph_data` duplicates function snapshots | FP | Separate request paths, never called together |
| `get_analysis_timeline` copies before cache check | FP | Copies needed to build cache key |
| `_start_session_reaper` TOCTOU on flag | FP | All callers hold `_registry_lock` |
| `_regex_pool_recreations` counter atomicity | FP | Already inside lock |
| `_TRIAGE_URL_RE` unbounded URL regex | LOW IMPACT | No ReDoS risk; simple character class |
| `_decompile_meta` FIFO cross-session eviction | LOW IMPACT | 2000 entry cache + reaper cleanup |
| `_build_function_lookup` no angr_lock | LOW IMPACT | angr objects read-only after CFG; snapshot pattern sufficient |
| `format_timestamp` raw value in error | LOW IMPACT | PE timestamps are bounded uint32 |

---

## Pattern Summary

| Pattern | Count | Files |
|---------|-------|-------|
| `hashlib.md5()` without `usedforsecurity=False` | 7 | 6 files |
| Redundant lock-guarded snapshot calls | 3 | tools_export.py, state_api.py, tools_session.py |
| Resource objects without close/cleanup | 1 | tools_dotnet.py |
| Directory creation without restrictive permissions | 2 | app.py, _bsim_features.py |
| Raw exception text in responses/metadata | 4 | tools_angr_dataflow.py, enrichment.py, tools_pe.py, background.py |
| Code duplication with drift | 1 (3 copies) | tools_session.py, state_api.py |
| `len(list(iterable))` instead of O(1) accessor | 5 | 4 files |
| Concurrent counter corruption | 1 | enrichment.py |
| Read-modify-write race across lock boundary | 1 | cache.py |

## Files Modified (18)

1. `arkana/parsers/pe.py` — H1
2. `arkana/mcp/tools_batch.py` — H1, L5
3. `arkana/mcp/tools_pe_forensic.py` — H1
4. `arkana/mcp/tools_refinery_extract.py` — H1
5. `arkana/mcp/tools_refinery.py` — H1
6. `arkana/mcp/_refinery_helpers.py` — H1
7. `arkana/mcp/tools_angr_dataflow.py` — H2, L4
8. `arkana/mcp/tools_export.py` — H3
9. `arkana/dashboard/state_api.py` — H4, M6, M7, L2, L7, L8
10. `arkana/mcp/tools_dotnet.py` — H5
11. `arkana/dashboard/app.py` — M1, M2
12. `arkana/mcp/_bsim_features.py` — M3
13. `arkana/enrichment.py` — M4, M11
14. `arkana/mcp/tools_pe.py` — M4
15. `arkana/background.py` — M4, L10
16. `arkana/mcp/tools_session.py` — M5, M8, M10, L9
17. `arkana/mcp/tools_triage.py` — M13, L1
18. `arkana/mcp/tools_angr.py` — L6, L10
19. `arkana/mcp/tools_angr_disasm.py` — L6
20. `arkana/mcp/_angr_helpers.py` — L6
21. `arkana/mcp/tools_workflow.py` — M9
22. `arkana/cache.py` — M12
23. `arkana/mcp/tools_strings.py` — L3
24. `arkana/mcp/tools_classification.py` — L11
25. `arkana/state.py` — M10 (new accessor)

## Functional Limitation Assessment

None of the v10 fixes impose meaningful functionality limitations:
- H1 (FIPS flag): No behavioral change — `usedforsecurity=False` is a metadata flag
- M2 (token TOCTOU): Same token generation, different file creation method
- M4 (exception truncation): 200-char limit preserves error type + key message
- M12 (cache lock scope): Slightly longer lock hold but cache writes are infrequent
- All efficiency fixes: Same outputs, fewer copies/allocations
