# PeMCP Project Review (Fourth Iteration)

## Overview

PeMCP is a comprehensive binary analysis toolkit and MCP (Model Context Protocol) server that bridges AI assistants with low-level binary instrumentation. It exposes 105+ specialized MCP tools for analyzing PE, ELF, Mach-O, .NET, Go, Rust, and shellcode binaries. The codebase is approximately 15,800 lines of Python across 48 source files, with an additional 2,365-line integration test suite.

This fourth-iteration review covers the full codebase as of February 2026, building on three prior iterations. It verifies the status of previously reported issues and identifies new findings across security, correctness, performance, and maintainability dimensions.

---

## Architecture Assessment

### Strengths

**1. Clean Modular Architecture**
The codebase follows a well-organized separation of concerns:
- `pemcp/state.py` -- Centralized, thread-safe state management with per-session isolation via `contextvars`
- `pemcp/config.py` -- Import hub with availability flags for 20+ optional libraries
- `pemcp/parsers/` -- Format-specific parsing logic (PE, FLOSS, capa, strings, signatures)
- `pemcp/mcp/` -- 24 tool modules organized by domain (PE, strings, angr, forensic, multi-format, etc.)
- `pemcp/background.py` -- Background task management with heartbeat monitoring and progress tracking
- `pemcp/cache.py` -- Disk-based analysis cache with gzip compression and LRU eviction

Each MCP tool module registers its tools via a shared `tool_decorator` in `server.py`, making the system easy to extend. Adding a new tool category requires only a new file and an import in `main.py`.

**2. Per-Session State Isolation (HTTP Mode)**
The `StateProxy` + `contextvars` pattern in `state.py` is well-designed. The `tool_decorator` in `server.py` activates per-session state before every tool invocation, meaning concurrent HTTP clients each get isolated analysis state without any changes to the 105 tool implementations. Session TTL cleanup prevents memory leaks from abandoned sessions.

**3. Graceful Degradation**
The optional dependency pattern in `config.py` is well-executed. Each of 20+ optional libraries is guarded by try/except with `*_AVAILABLE` flags, and tools return clear, actionable error messages when a library is absent. This is the correct approach for a toolkit with heavy, platform-sensitive dependencies like angr, FLOSS, vivisect, and speakeasy.

**4. Intelligent MCP Response Management**
The auto-truncation system in `server.py` uses `copy.deepcopy` to avoid mutating shared state, then iteratively identifies and shrinks the largest element (list, string, or dict) to fit within the 64KB MCP response limit. The 5-iteration approach with aggressive reduction factor is pragmatic.

**5. Production-Quality Caching**
`cache.py` implements a robust disk cache with git-style two-character prefix directories, gzip compression (5-15x reduction on JSON), LRU eviction, version-based invalidation, and thread-safe atomic file writes.

**6. Background Task Management**
Long-running operations are properly offloaded to background threads with progress tracking, heartbeat monitoring, task registry with eviction, and session state propagation.

**7. Security-Conscious Design**
- Path sandboxing via `AnalyzerState.check_path_allowed()` with symlink resolution
- API key storage with `0o600` permissions
- Warning when running in network mode without `--allowed-paths`
- Environment variable priority over config file for sensitive values
- File size limit on `open_file` (default 256MB)

**8. Comprehensive Triage Engine**
The `tools_triage.py` module (1,553 lines) implements a 25+-dimension triage report with well-factored helper functions. Each triage section is a separate function returning `(data, risk_delta)`, making the system easy to extend and test independently. The risk scoring model with CRITICAL/HIGH/MEDIUM/LOW severity levels and format-aware tool suggestions is well-designed for the AI-analyst use case.

**9. Docker and Deployment**
The Docker setup handles the notoriously difficult unicorn 1.x/2.x namespace collision (angr vs speakeasy) through venv isolation, with a build assertion to verify the correct unicorn version is active.

---

## Previous Review Issues -- Status Check

### Third-Iteration Issues

| # | Issue | Status | Notes |
|---|-------|--------|-------|
| H1 | Unguarded sub-parsers in `_parse_pe_to_dict` | **Open** | Still no per-sub-parser try/except guards in `parsers/pe.py` |
| H2 | Race condition in background angr state writes | **Open** | No synchronization between `set_angr_results` and `_ensure_project_and_cfg` |
| H3 | `open_file` double-reads file data for PE mode | **Open** | Still reads file twice (once for hash, once for pefile) |
| M1 | Truncation fallback references unbound variable | **Open** | `data_size_bytes` still potentially unbound in exception handler |
| M2 | Cache meta inconsistency after `_remove_entry` | **Open** | Meta index not updated after disk deletion |
| M3 | Format auto-detection falls back silently to PE | **Open** | No warning emitted for unknown formats |
| M4 | `config.py` import-time side effects | **Open** | `logging.basicConfig()` still called at import time |
| M5 | No rate limiting in HTTP mode | **Open** | No concurrent analysis limits |
| L1 | Dense code formatting in `parsers/pe.py` | **Open** | Still uses semicolons and compressed formatting |
| L2 | `_evict_old_tasks` sorts by ISO string | **Open** | ISO string sort instead of numeric timestamp |
| L4 | Speakeasy availability check is filesystem-based | **Open** | Still checks file existence, not import health |
| L5 | Dense summary dict in `get_analyzed_file_summary` | **Open** | Still uses compressed formatting |

### First/Second-Iteration Issues (Previously Verified Fixed)

All 14 issues from iterations 1 and 2 remain fixed and are not regressed:
- StateProxy + contextvars (was: global singleton)
- `reset_angr()` clears hooks on `close_file`
- `int(hex_string, 0)` for address parsing
- Architecture-aware register lookup
- `asyncio.wait_for()` timeouts on angr decompile/CFG
- `_monitor_lock` for heartbeat thread
- `check_path_allowed()` on `save_patched_binary` and `diff_binaries`
- Session TTL cleanup and task eviction
- File size limit on `open_file`

---

## New Issues Identified

### High Priority

**H4. Deprecated `datetime.utcfromtimestamp` / `utcnow` still used in triage**

Location: `tools_triage.py:153-155`

```python
compile_dt = datetime.datetime.utcfromtimestamp(int(raw_ts))
...
now = datetime.datetime.utcnow()
```

The third-iteration review marked issue #3 (deprecated `datetime.utcfromtimestamp`) as fixed, and indeed `tools_pe_extended.py:128` correctly uses `datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)`. However, the triage module at `tools_triage.py:153` and `tools_triage.py:155` still uses the deprecated `utcfromtimestamp()` and `utcnow()` calls. These were deprecated in Python 3.12 and will be removed in a future version.

**H5. Missing path sandbox checks on file-reading tools**

Multiple tools accept a `file_path` parameter but do not call `state.check_path_allowed()` before reading:

| Tool | Location | Issue |
|------|----------|-------|
| `parse_binary_with_lief` | `tools_new_libs.py:88-89` | Reads `file_path` without sandbox check |
| `compute_similarity_hashes` | `tools_new_libs.py:445-446` | Reads `file_path` without sandbox check |
| `compare_file_similarity` | `tools_new_libs.py:498-501` | Reads `file_path_b` without sandbox check |

In HTTP mode with `--allowed-paths`, a client could use these tools to read arbitrary files outside the sandbox. For comparison, `diff_binaries` correctly validates `file_path_b` via `check_path_allowed()` at `tools_angr_forensic.py:38`.

**H6. Operator precedence bug in capa status check**

Location: `tools_strings.py:284`, `tools_strings.py:439`

```python
if capa_status != "Analysis complete (adapted workflow)" and capa_status != "Analysis complete" or not capa_full_results:
```

Due to Python operator precedence (`and` binds tighter than `or`), this evaluates as:

```python
if (capa_status != "..." and capa_status != "...") or (not capa_full_results):
```

This means if `capa_full_results` is falsy (e.g., an empty dict `{}`), the condition is true regardless of the status string, causing valid "Analysis complete" results with an empty rules dict to be treated as errors. The condition should use explicit parentheses:

```python
if (capa_status != "Analysis complete (adapted workflow)" and capa_status != "Analysis complete") or not capa_full_results:
```

While the current behavior happens to be correct for `None` (the initial value), it would fail if the capa analysis returns `{"rules": {}}` (no capabilities detected) because `{}` is falsy.

### Medium Priority

**M6. `_triage_high_value_strings` contains dead code**

Location: `tools_triage.py:1186-1193`

```python
for s_text in all_string_values:
    if not s_text:
        continue
    # Check for high-value patterns in strings
    for s in (state.pe_data.get('basic_ascii_strings', []) +
              list(all_string_values)):
        pass  # Already collected above
    break
```

This loop iterates once (due to the unconditional `break`), contains a nested loop that does nothing (`pass`), and never produces any output. The function relies entirely on the sifter score checks below it (lines 1196-1214). The dead code should be removed to avoid confusion.

**M7. Entropy calculation duplicated across four locations**

The same Shannon entropy calculation (byte frequency counting + `p * log2(p)` summation) appears verbatim in:
- `tools_pe_extended.py:214-221` (resource entropy)
- `tools_pe_extended.py:758-766` (sliding window entropy)
- `tools_angr_forensic.py:335-341` (section entropy for packing detection)
- `tools_triage.py` (indirectly, via section data)

This should be extracted to a utility function in `utils.py` for DRY and to avoid subtle divergence bugs (e.g., if one copy is updated to handle edge cases but others are not).

**M8. BFS in `get_call_graph` uses list as queue (O(n^2))**

Location: `tools_angr_forensic.py:1007-1008`

```python
queue = [(root, 0)]
while queue:
    node, depth = queue.pop(0)
```

`list.pop(0)` is O(n) because it shifts all remaining elements. For large call graphs (thousands of functions), this creates O(n^2) behavior. Using `collections.deque` with `popleft()` provides O(1) dequeue operations.

**M9. `scan_for_embedded_files` restricted to PE files unnecessarily**

Location: `tools_new_libs.py:787`

The `_check_pe_loaded("scan_for_embedded_files")` guard prevents binwalk from scanning ELF, Mach-O, or raw binary files. Binwalk is format-agnostic by design and its primary use case (firmware analysis) often involves non-PE files. The guard should check for `state.filepath` being loaded rather than requiring a PE object specifically.

**M10. `emulate_with_watchpoints` step counting is inaccurate**

Location: `tools_angr_forensic.py:804`

```python
simgr.run(n=chunk_size)
steps_taken += chunk_size
```

`simgr.run(n=chunk_size)` may execute fewer than `chunk_size` steps if all active states deadend, error, or reach the target. However, `steps_taken` always increments by the full `chunk_size`, causing the reported `steps_taken` in the output to exceed the actual number of steps executed.

**M11. Inconsistent timeout coverage on angr tools**

The previous review noted that decompilation and CFG extraction tools use `asyncio.wait_for(..., timeout=300)`. However, several other computationally expensive angr tools use only `asyncio.to_thread()` without a timeout wrapper:

- `detect_self_modifying_code` (`tools_angr_forensic.py:201`)
- `find_code_caves` (`tools_angr_forensic.py:307`)
- `detect_packing` (`tools_angr_forensic.py:435`)
- `get_call_graph` (`tools_angr_forensic.py:1069`)

While these tools are typically faster than decompilation, pathological binaries could cause them to hang indefinitely (especially CFG-dependent tools that call `_ensure_project_and_cfg()`).

### Low Priority

**L6. Inconsistent `import` placement**

Several modules import standard library modules inside function bodies rather than at the top of the file:
- `tools_pe_extended.py:125`: `import datetime` inside `get_pe_metadata`
- `tools_pe_extended.py:272`: `import re as re_mod` inside `extract_manifest`
- `tools_pe_extended.py:837`: `import binascii` inside `_crc32_hash`
- `tools_angr_forensic.py:334`: `import math` inside `detect_packing._detect`
- `tools_triage.py:1089,1142`: `import struct as _struct` inside triage helpers

While not functionally incorrect, this pattern is contrary to PEP 8 and makes it harder to see a module's dependencies at a glance. The standard library imports should be at the top of each file.

**L7. `compare_file_similarity` reads both files entirely into memory**

Location: `tools_new_libs.py:504-506`

Both `data_a` and `data_b` are read entirely into memory. With the 256MB file size limit, this could use up to 512MB for a single comparison. The ssdeep and TLSH libraries both support file-based hashing, which would be more memory-efficient.

**L8. `_safe_slice` helper doesn't handle all edge cases**

Location: `tools_new_libs.py:54-68`

The helper handles `list`, `tuple`, `dict`, and `str`, but doesn't handle `set`, `frozenset`, or generator objects, which could appear in speakeasy report fields. Adding a catch-all `try: return list(value)[:n]` would make it more robust.

**L9. Dense formatting persists in tool modules beyond parsers**

The previous review flagged dense formatting in `parsers/pe.py`. This pattern also appears in several MCP tool modules:

- `tools_strings.py:681`: `file_data=state.pe_object.__data__; found_offsets_dict=_search_specific_strings_in_data(file_data,search_terms)`
- `tools_strings.py:689`: `except Exception as e: await ctx.error(...); raise RuntimeError(...)from e`
- `tools_strings.py:174`: `if floss_data_block.get("error"): response_data["error_details"] = floss_data_block.get("error")`

While these are individually minor, the cumulative effect reduces readability across security-critical code paths.

---

## Test Suite Assessment

The test suite (`mcp_test_client.py`, 2,365 lines) remains comprehensive for integration testing:
- 19 test classes covering all 105+ tools
- Supports both streamable-http and SSE transports with auto-detection
- Configurable via environment variables
- Proper pytest markers for categorization

**Continued gap: no unit tests.** The integration-only testing approach means:
- Every test requires a running MCP server and sample binary
- Parser logic handling adversarial input is untestable in isolation
- Cache operations, state management, and truncation logic have no automated coverage
- Refactoring any internal module requires full stack integration testing

The triage module (`tools_triage.py`) is a particularly good candidate for unit testing, as each `_triage_*` helper is a pure function of `state.pe_data` and could be tested with fixture data without an MCP server.

---

## Security Assessment Summary

| Area | Status | Notes |
|------|--------|-------|
| Path sandboxing | **Partial** | `diff_binaries` and `save_patched_binary` check paths; `parse_binary_with_lief`, `compute_similarity_hashes`, `compare_file_similarity` do not (H5) |
| API key storage | **Good** | 0o600 permissions, env var priority |
| File size limits | **Good** | Configurable via `PEMCP_MAX_FILE_SIZE_MB` |
| Input validation | **Good** | Address parsing, hex validation, parameter bounds checking |
| Rate limiting | **Missing** | No concurrent analysis limit in HTTP mode (M5, carried from prior review) |
| Subprocess safety | **Good** | Speakeasy runner uses stdin/stdout JSON protocol, not shell commands |
| Docker security | **Good** | Non-root execution, world-writable home intentional for UID mapping |

---

## Summary Scorecard

| Category | Rating | Notes |
|----------|--------|-------|
| Architecture | **Strong** | Clean separation, modular design, extensible, per-session isolation |
| Code Quality | **Good** | Well-organized; dense formatting and dead code in triage are concerns |
| Security | **Good** | Path sandboxing has gaps in 3 tools (H5); otherwise solid |
| Correctness | **Good** | Operator precedence bug in capa check (H6); deprecated datetime calls (H4) |
| Error Handling | **Strong** | Graceful degradation, descriptive errors, auto-truncation |
| Performance | **Good** | Caching, background tasks, lazy loading; O(n^2) BFS and double-read |
| Testing | **Adequate** | Comprehensive integration tests; no unit tests |
| Documentation | **Strong** | Thorough README, inline docstrings, DEPENDENCIES.md |
| Docker/Deployment | **Strong** | Layered builds, speakeasy isolation, multi-transport support |

---

## Recommended Priority Order

1. **H5** -- Add `check_path_allowed()` to `parse_binary_with_lief`, `compute_similarity_hashes`, and `compare_file_similarity`. This is a security fix with minimal code change (3 lines).

2. **H4** -- Replace deprecated `datetime.utcfromtimestamp` / `utcnow` in `tools_triage.py` with timezone-aware equivalents. Simple find-and-replace.

3. **H6** -- Add explicit parentheses to the capa status check in `tools_strings.py`. One-line fix that prevents a subtle logic bug.

4. **H1** (carried) -- Wrap sub-parsers in `_parse_pe_to_dict` with individual try/except. Most impactful for the tool's core value proposition.

5. **M6** -- Remove dead code in `_triage_high_value_strings`.

6. **M7** -- Extract entropy calculation to a shared utility.

7. **M9** -- Relax `_check_pe_loaded` guard on `scan_for_embedded_files` to support non-PE formats.

8. Unit tests for triage helpers, cache operations, and path sandboxing.

---

## Conclusion

PeMCP is a well-engineered, production-grade binary analysis toolkit. The architecture decisions -- modular tools, graceful degradation for 20+ optional libraries, disk-based caching, per-session state isolation, and background task management -- are sound and reflect real-world deployment considerations.

This fourth review found 3 new high-priority issues (missing path sandbox checks on 3 tools, deprecated datetime still in triage, operator precedence bug in capa check), 6 medium-priority items (dead code in triage, duplicated entropy calculation, O(n^2) BFS, binwalk restricted to PE, inaccurate step counting, inconsistent timeouts), and 4 low-priority items (import placement, memory usage, edge case handling, dense formatting).

All 12 issues from the third-iteration review remain open, though none have regressed. The most impactful fix remains H5 (path sandbox gaps) as it is a security issue requiring only 3 added lines. The most impactful architectural improvement remains H1 (unguarded sub-parsers) from the prior review, as it directly affects resilience when analyzing malformed binaries.
