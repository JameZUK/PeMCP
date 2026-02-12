# PeMCP Project Review (Third Iteration)

## Overview

PeMCP is a comprehensive binary analysis toolkit and MCP (Model Context Protocol) server that bridges AI assistants with low-level binary instrumentation. It exposes 105+ specialized MCP tools for analyzing PE, ELF, Mach-O, .NET, Go, Rust, and shellcode binaries. The codebase is approximately 17,000 lines of Python across 48 files (plus a 2,300-line integration test suite).

This review covers the full codebase as of February 2026 and builds on two prior review iterations, verifying that previously identified issues have been addressed and identifying new findings.

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
The `StateProxy` + `contextvars` pattern in `state.py:255-272` is well-designed. The `tool_decorator` in `server.py:20-38` activates per-session state before every tool invocation, meaning concurrent HTTP clients each get isolated analysis state without any changes to the 105 tool implementations. Session TTL cleanup (`state.py:201-220`) prevents memory leaks from abandoned sessions.

**3. Graceful Degradation**
The optional dependency pattern in `config.py` is well-executed. Each of 20+ optional libraries is guarded by try/except with `*_AVAILABLE` flags, and tools return clear, actionable error messages when a library is absent. This is the correct approach for a toolkit with heavy, platform-sensitive dependencies like angr, FLOSS, vivisect, and speakeasy.

**4. Intelligent MCP Response Management**
The auto-truncation system in `server.py:99-201` uses `copy.deepcopy` to avoid mutating shared state, then iteratively identifies and shrinks the largest element (list, string, or dict) to fit within the 64KB MCP response limit. The 5-iteration approach with aggressive reduction factor is pragmatic.

**5. Production-Quality Caching**
`cache.py` implements a robust disk cache:
- Git-style two-character prefix directories to avoid flat-dir performance issues
- Gzip compression (5-15x reduction on JSON)
- LRU eviction with configurable size limits (default 500MB)
- Version-based invalidation (PeMCP version and cache format version)
- Thread-safe operations with atomic file replacement via `tmp.replace()`
- Partial results survive across sessions -- re-opening a previously analyzed file loads in milliseconds

**6. Background Task Management**
Long-running operations (angr CFG generation, symbolic execution, loop analysis) are properly offloaded to background threads with:
- Progress tracking with percentage and message updates
- Heartbeat monitoring thread for console feedback across all sessions (`background.py:28-30`)
- Task registry with thread-safe access via `_task_lock` and eviction of old tasks (`state.py:94-109`)
- Session state propagation to background threads via `set_current_state()` (`background.py:101-102`)

**7. Security-Conscious Design**
- Path sandboxing via `AnalyzerState.check_path_allowed()` using `os.path.realpath()` to resolve symlinks (`state.py:73-88`)
- `diff_binaries` and `save_patched_binary` validate paths against the sandbox
- API key storage with `0o600` permissions (`user_config.py:58`)
- Warning when running in network mode without `--allowed-paths` (`main.py:216-219`)
- Environment variable priority over config file for sensitive values (`user_config.py:64-83`)
- File size limit on `open_file` (default 256MB, configurable via `PEMCP_MAX_FILE_SIZE_MB`)
- Zip-slip protection and non-root Docker container execution

**8. Timeouts on Expensive Operations**
Decompilation and CFG extraction tools use `asyncio.wait_for(..., timeout=300)` (`tools_angr.py:178, 208`), preventing pathological binaries from blocking indefinitely. Symbolic execution uses step limits (2000 steps) and active state pruning (max 30 active states).

**9. Docker and Deployment**
The Docker setup is well-engineered:
- Heavy dependencies (angr, FLOSS, capa, vivisect) in early layers for optimal caching
- Speakeasy isolated in a separate venv to handle unicorn 1.x vs 2.x conflict
- Best-effort installation (`|| true`) for libraries with complex dependencies
- Capa rules pre-downloaded at build time to avoid runtime network access
- oscrypto patched for OpenSSL 3.x compatibility
- `run.sh` helper script (200+ lines) auto-detects Docker/Podman, handles SELinux mount options, and supports HTTP, stdio, and CLI modes

---

## Previous Review Issues -- Verification

The prior two review iterations identified 25 issues total. All high-priority items were confirmed fixed during this review:

| # | Issue | Status |
|---|-------|--------|
| 1 | Global singleton state concurrency risk | **Fixed** -- `StateProxy` + `contextvars` |
| 2 | `close_file` does not reset `angr_hooks` | **Fixed** -- `reset_angr()` clears hooks |
| 3 | Deprecated `datetime.utcfromtimestamp` | **Fixed** -- Uses timezone-aware `datetime.fromtimestamp` |
| 4 | `diff_binaries` path traversal risk | **Fixed** -- `check_path_allowed()` validation |
| 5 | Shallow copy in truncation logic | **Fixed** -- `copy.deepcopy()` |
| 6 | `_parse_addr` accepts only hex strings | **Fixed** -- `int(hex_string, 0)` |
| 7 | Hardcoded `eax` register in emulation | **Fixed** -- Architecture-aware register lookup |
| 8 | No timeout on sync angr operations | **Fixed** -- `asyncio.wait_for()` with 300s timeout |
| 9 | `monitor_thread_started` race condition | **Fixed** -- `_monitor_lock` + `_monitor_started` |
| 10 | `save_patched_binary` missing sandbox check | **Fixed** -- `check_path_allowed()` before write |
| 11 | Session registry grows indefinitely | **Fixed** -- TTL-based cleanup (1 hour) |
| 12 | Background tasks accumulate without bound | **Fixed** -- `_evict_old_tasks()` with limit of 50 |
| 13 | No file size limit on `open_file` | **Fixed** -- `PEMCP_MAX_FILE_SIZE_MB` env var (default 256MB) |
| 14 | Heartbeat only sees default session tasks | **Fixed** -- `get_all_session_states()` |

---

## New Issues Identified

### High Priority

**H1. Unguarded sub-parsers in `_parse_pe_to_dict` -- partial analysis loss on any parser failure**

Location: `parsers/pe.py:542-673`

The main PE parsing function calls ~18 sub-parsers (`_parse_dos_header`, `_parse_nt_headers`, `_parse_sections`, `_parse_imports`, etc.) sequentially without individual try/except guards. If any single sub-parser raises an unexpected exception (e.g., a corrupted section table causes `_parse_sections` to fail), the entire `_parse_pe_to_dict` call fails and no analysis data is produced.

For a tool designed to analyze potentially malformed or malicious binaries, this is a significant risk. Each sub-parser should be individually guarded so that partial results are available even when some structures are corrupted:

```python
# Current (fragile):
pe_info_dict['sections'] = _parse_sections(pe)
pe_info_dict['imports'] = _parse_imports(pe)

# Recommended:
try:
    pe_info_dict['sections'] = _parse_sections(pe)
except Exception as e:
    pe_info_dict['sections'] = {"error": f"Section parsing failed: {e}"}
    logger.warning(f"Section parsing failed: {e}")
```

**H2. Race condition in background angr state writes**

Location: `background.py:120-147`

The `angr_background_worker` writes to `state.angr_project`, `state.angr_cfg`, and `state.angr_loop_cache` from a background thread without any synchronization. The `_ensure_project_and_cfg` helper in `_angr_helpers.py:62-69` reads these fields from MCP tool coroutines. There is a window where:
1. Background thread sets `state.angr_project = project` (line 120)
2. MCP tool calls `_ensure_project_and_cfg()`, sees `angr_project` is not None
3. MCP tool tries to use `state.angr_cfg` which is still None (background thread hasn't reached line 125 yet)

The `_check_angr_ready` guard checks for a running startup task, but there is no guard for the moment between individual field assignments within the worker. A threading lock or an atomic "analysis complete" flag would close this window.

**H3. `open_file` double-reads file data for PE mode**

Location: `tools_pe.py:173-292`

At line 178, the entire file is read into `_raw_file_data` for SHA256 hashing and cache lookup. If the cache misses and the file is a PE, `pefile.PE(abs_path)` at line 290 reads the file from disk again. For large files (up to 256MB), this means 512MB of memory usage during the loading phase. The `_raw_file_data` could be passed to `pefile.PE(data=_raw_file_data)` instead to avoid the second read.

### Medium Priority

**M1. Truncation fallback references potentially unbound variable**

Location: `server.py:192-201`

In the exception handler at line 192, the fallback error message references `data_size_bytes` (line 200). However, if the exception occurred before line 113 (where `data_size_bytes` is assigned), this variable is unbound and will raise `UnboundLocalError`, masking the original error. The fallback should use a safe default:

```python
except Exception as e:
    await ctx.error(f"Auto-truncation failed: {e}")
    size_info = f"{data_size_bytes} bytes" if 'data_size_bytes' in dir() else "unknown size"
```

**M2. Cache meta inconsistency after `_remove_entry` in `get()`**

Location: `cache.py:137, 161`

When `get()` detects a version mismatch or corrupt entry, it calls `_remove_entry(sha256)` at lines 137 and 161 to delete the file from disk. However, it does not update the meta index to remove the entry. The meta file still references the deleted entry, causing:
- Inflated `entry_count` in `get_stats()`
- Future `get()` calls attempt to read the deleted file (harmless but generates warnings)
- Incorrect `total_size` calculation affecting eviction decisions

The `get()` method should also update the meta after removing an entry, or `_remove_entry` should be extended to accept an optional meta dict parameter.

**M3. Format auto-detection fallback silently treats unknown files as PE**

Location: `main.py:254-255`, `tools_pe.py:152-153`

When auto-detection cannot identify the file format from magic bytes, both `main.py` and `tools_pe.py` fall back to PE mode without warning. This means a random data file, a PDF, or any non-PE/ELF/Mach-O binary will be passed to `pefile.PE()`, which will either produce confusing errors about malformed PE structures or (for files that happen to start with `MZ`) produce misleading partial analysis.

A better approach would be to check for the `MZ` signature before committing to PE mode and return a clear "unrecognized binary format" error for truly unknown files.

**M4. `config.py` import-time side effects interfere with testing**

Location: `config.py:89`

The module calls `logging.basicConfig()` at module import time and immediately emits info/warning log messages for every optional library check. This means:
- Importing `pemcp.config` (even for unit testing) produces console output
- The root logger is configured, which can interfere with test frameworks like pytest
- Test output is polluted with 15+ "library found/not found" messages

Standard practice is to defer `basicConfig()` to the application entry point (`main()`) and have library modules create loggers without configuring the root handler.

**M5. No rate limiting or concurrent analysis limit in HTTP mode**

The `open_file` tool in HTTP mode allows any connected client to trigger full PE analysis (including FLOSS and capa, which are CPU-intensive). There is no:
- Rate limiting per session or IP
- Concurrent analysis limit (multiple clients could trigger simultaneous full analyses)
- Queue or backpressure mechanism

A malicious or misbehaving client could exhaust server resources by calling `open_file` repeatedly with different files. This is primarily a concern for network-exposed deployments.

### Low Priority

**L1. Dense code formatting in `parsers/pe.py`**

Multiple functions in `parsers/pe.py` compress complex logic into single lines with multiple semicolons, e.g.:

```python
# Line 142-148 (imports parser):
dll_info:Dict[str,Any]={'dll_name':"Unknown"};
try:dll_info['dll_name']=entry.dll.decode('utf-8','ignore')if entry.dll else"N/A"
except Exception:pass
dll_info['struct']=entry.struct.dump_dict();dll_info['symbols']=[]
```

This pattern appears throughout `_parse_imports`, `_parse_exports`, `_parse_resources_summary`, `_parse_version_info`, `_parse_rich_header`, `_parse_delay_load_imports`, and others (~200 lines). While functionally correct, this formatting:
- Makes code review for security issues significantly harder
- Complicates debugging (breakpoints can only be set per-line)
- Reduces diff readability in version control
- Violates PEP 8 conventions (multiple statements per line)

For a security-focused binary analysis tool, code readability is more important than compactness.

**L2. `_evict_old_tasks` sorts by ISO string instead of numeric timestamp**

Location: `state.py:106`

Tasks are sorted by `created_at` which is an ISO 8601 string (e.g., `"2026-02-12T14:30:00+00:00"`). ISO 8601 is lexicographically sortable when using consistent formatting, but if any task has a non-standard or missing `created_at` value, the sort produces unpredictable results. Using a numeric epoch timestamp for sorting would be more robust.

**L3. ~~Docker `chmod 777 /app/home` is overly permissive~~ (Retracted)**

Location: `Dockerfile:113`

**Retracted**: The `chmod 777` is intentional and necessary. The container runs as an arbitrary non-root UID via `--user "$(id -u):$(id -g)"` in `run.sh`, so the directory must be world-writable for the host user to create `~/.pemcp/cache` and `config.json`. Using `755` breaks container startup for non-root users.

**L4. Speakeasy availability check is filesystem-based, not functional**

Location: `config.py:329-338`

Speakeasy availability is determined by checking if `/app/speakeasy-venv/bin/python` and the runner script exist, but not whether speakeasy actually works (the venv could be corrupt, missing packages, etc.). A quick import check via subprocess would provide a more reliable availability signal at startup.

**L5. `get_analyzed_file_summary` has very dense, fragile dictionary construction**

Location: `tools_pe.py:626-648`

The summary dict construction uses extremely dense inline expressions with no whitespace around operators, chained `.get()` calls, and complex ternary expressions. For example:

```python
"has_dos_header":'dos_header'in state.pe_data and state.pe_data['dos_header']is not None and"error"not in state.pe_data['dos_header'],
```

This is difficult to read and error-prone. Breaking these into multiple lines would improve maintainability.

---

## Test Suite Assessment

The test suite (`mcp_test_client.py`, 2,300+ lines) is comprehensive for integration testing:
- 19 test classes covering all 105+ tools
- Supports both streamable-http and SSE transports with auto-detection
- Configurable via environment variables (`PEMCP_TEST_URL`, `PEMCP_TEST_TRANSPORT`, `PEMCP_TEST_SAMPLE`)
- Proper pytest markers for categorization (`no_file`, `pe_file`, `angr`, `optional_lib`)
- Robust session management with retry logic and graceful error extraction

However, the test suite remains **integration-only** -- it requires a running MCP server and a loaded sample binary. There are no unit tests for:
- Parser logic (`parsers/pe.py`, `parsers/floss.py`, `parsers/strings.py`) -- the most likely source of bugs given the dense formatting
- Cache operations (`cache.py` -- put/get/evict/clear/version-invalidation)
- State management (`state.py` -- session creation/cleanup, proxy delegation, TTL eviction)
- Helper functions (`_angr_helpers.py` -- address parsing, function resolution, RVA-to-VA correction)
- Truncation logic (`server.py` -- `_check_mcp_response_size` with various data shapes)
- Path sandboxing (`state.py` -- `check_path_allowed` with symlinks, edge cases)

Unit tests for these components would provide faster feedback during development, catch regressions without requiring a full MCP server stack, and improve confidence in the parser code that handles adversarial input.

---

## Summary Scorecard

| Category | Rating | Notes |
|----------|--------|-------|
| Architecture | **Strong** | Clean separation, modular design, extensible, per-session isolation |
| Code Quality | **Good** | Well-organized; dense formatting in parsers is a maintainability concern |
| Security | **Good** | Path sandboxing, secure key storage, file size limits; no rate limiting in HTTP mode |
| Error Handling | **Strong** | Graceful degradation, descriptive errors, auto-truncation, timeouts on angr ops |
| Performance | **Good** | Caching, background tasks, lazy loading; double-read in PE open_file |
| Testing | **Adequate** | Comprehensive integration tests (19 classes, 100+ methods); no unit tests |
| Documentation | **Strong** | Thorough README (1,000+ lines), inline docstrings, tool help text, REVIEW.md |
| Docker/Deployment | **Strong** | Layered builds, speakeasy isolation, volume persistence, multi-transport support |

---

## Conclusion

PeMCP is a well-engineered, production-grade binary analysis toolkit. The architecture decisions -- modular tools, graceful degradation for 20+ optional libraries, disk-based caching, per-session state isolation via `contextvars`, and background task management with progress tracking -- are sound and reflect real-world deployment considerations.

The two prior review iterations identified 25 issues, and all high-priority items have been verified as fixed. This third review identified 3 high-priority issues (unguarded sub-parsers, angr state race condition, double file read), 5 medium-priority items (truncation fallback, cache meta inconsistency, silent PE fallback, import-time side effects, no rate limiting), and 5 low-priority items (code formatting, task eviction sort, Docker permissions, speakeasy check, dense summary construction).

The most impactful improvement would be wrapping individual sub-parsers in `_parse_pe_to_dict` with try/except guards (H1), as this directly affects the tool's core value proposition of analyzing potentially malformed/malicious binaries. The second priority should be adding unit tests for the parser and cache layers, which would catch regressions in the most critical code paths.
