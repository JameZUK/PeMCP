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
| H1 | Unguarded sub-parsers in `_parse_pe_to_dict` | **Fixed** | `_safe_parse()` wrapper at `pe.py:42-49`, used for all sub-parsers at lines 914-936 |
| H2 | Race condition in background angr state writes | **Fixed** | `_angr_lock` in `state.py:112-123`, `set_angr_results`/`get_angr_snapshot` use lock |
| H3 | `open_file` double-reads file data for PE mode | **Fixed** | `pefile.PE(data=_raw_file_data)` reuses early read at `tools_pe.py:297` |
| M1 | Truncation fallback references unbound variable | **Fixed** | `data_size_bytes = 0` default at `server.py:110` |
| M2 | Cache meta inconsistency after `_remove_entry` | **Fixed** | `_remove_entry_and_meta()` at `cache.py:269-274` removes both file and meta |
| M3 | Format auto-detection falls back silently to PE | **Fixed** | `ctx.warning()` at `tools_pe.py:156-158`, `logger.warning()` at `main.py:259` |
| M4 | `config.py` import-time side effects | **Fixed** | Only `logging.getLogger()` at import (no `basicConfig()`); standard practice |
| M5 | No rate limiting in HTTP mode | **Fixed** | `_analysis_semaphore` at `tools_pe.py:25` (configurable via `PEMCP_MAX_CONCURRENT_ANALYSES`) |
| L1 | Dense code formatting in `parsers/pe.py` | **Fixed** | Reformatted `_safe_parse` calls, sub-parsers refactored into separate functions |
| L2 | `_evict_old_tasks` sorts by ISO string | **Fixed** | Uses `created_at_epoch` numeric field at `state.py:107` |
| L4 | Speakeasy availability check is filesystem-based | **Fixed** | Subprocess import check at `config.py:350-356` |
| L5 | Dense summary dict in `get_analyzed_file_summary` | **Fixed** | Summary dict at `tools_pe.py:649-675` uses one key per line |

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

## Fourth-Iteration Issues -- Resolution Status

All issues identified in this fourth-iteration review have been resolved:

| # | Issue | Status | Resolution |
|---|-------|--------|------------|
| H4 | Deprecated `datetime.utcfromtimestamp`/`utcnow` in triage | **Fixed** | Replaced with `datetime.fromtimestamp(..., tz=datetime.timezone.utc)` and `datetime.now(datetime.timezone.utc)` |
| H5 | Missing path sandbox checks on 3 tools | **Fixed** | Added `state.check_path_allowed()` in `parse_binary_with_lief`, `compute_similarity_hashes`, and `compare_file_similarity` |
| H6 | Operator precedence bug in capa status check | **Fixed** | Added explicit parentheses around `and` clause at both locations |
| M6 | Dead code in `_triage_high_value_strings` | **Fixed** | Removed the no-op loop (lines 1186-1193) |
| M7 | Entropy calculation duplicated 4x | **Fixed** | Extracted `shannon_entropy()` to `utils.py`; all 3 call sites updated |
| M8 | BFS uses `list.pop(0)` (O(n^2)) | **Fixed** | Replaced with `collections.deque` + `popleft()` |
| M9 | `scan_for_embedded_files` restricted to PE | **Fixed** | Guard now checks `state.filepath` instead of requiring PE object |
| M10 | Step counting inaccurate in watchpoint emulation | **Fixed** | Tracks actual steps based on `simgr.active` state |
| M11 | Inconsistent timeout coverage on angr tools | **Fixed** | Added `asyncio.wait_for(..., timeout=300)` on 4 forensic tools |
| L6 | Inline imports in function bodies | **Fixed** | Moved `struct`, `datetime`, `binascii`, `re`, `math` to module-level |
| L7 | Both files read into memory for similarity | **Open** | Accepted trade-off; ssdeep/TLSH APIs require full data |
| L8 | `_safe_slice` missing edge cases | **Fixed** | Added `set`/`frozenset` handling and catch-all for other iterables |
| L9 | Dense formatting in tool modules and utils | **Fixed** | Reformatted `_dump_aux_symbol_to_dict`, `get_symbol_type_str`, capa checks |

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
| Path sandboxing | **Good** | All file-reading tools now validate via `check_path_allowed()` (H5 fixed) |
| API key storage | **Good** | 0o600 permissions, env var priority |
| File size limits | **Good** | Configurable via `PEMCP_MAX_FILE_SIZE_MB` |
| Input validation | **Good** | Address parsing, hex validation, parameter bounds checking |
| Rate limiting | **Good** | `_analysis_semaphore` limits concurrent analyses (M5 fixed) |
| Subprocess safety | **Good** | Speakeasy runner uses stdin/stdout JSON protocol, not shell commands |
| Docker security | **Good** | Non-root execution, world-writable home intentional for UID mapping |

---

## Summary Scorecard

| Category | Rating | Notes |
|----------|--------|-------|
| Architecture | **Strong** | Clean separation, modular design, extensible, per-session isolation |
| Code Quality | **Strong** | Well-organized; dead code removed, dense formatting resolved |
| Security | **Strong** | All file-reading tools validate paths; rate limiting added |
| Correctness | **Strong** | Operator precedence fixed; deprecated datetime replaced; step counting corrected |
| Error Handling | **Strong** | Graceful degradation, descriptive errors, auto-truncation, per-parser guards |
| Performance | **Strong** | Caching, background tasks, lazy loading; O(1) BFS; deduped entropy util |
| Testing | **Adequate** | Comprehensive integration tests; no unit tests |
| Documentation | **Strong** | Thorough README, inline docstrings, DEPENDENCIES.md |
| Docker/Deployment | **Strong** | Layered builds, speakeasy isolation, multi-transport support |

---

## Recommended Next Steps

1. **Unit tests** for triage helpers, cache operations, and path sandboxing. The integration-only testing approach remains the primary gap.

2. **L7** (open) -- Consider streaming hashes for `compare_file_similarity` to reduce peak memory for large files.

---

## Conclusion

PeMCP is a well-engineered, production-grade binary analysis toolkit. The architecture decisions -- modular tools, graceful degradation for 20+ optional libraries, disk-based caching, per-session state isolation, and background task management -- are sound and reflect real-world deployment considerations.

All issues from the third-iteration review (12 items) and all but one from the fourth-iteration review (13 items) have been resolved. The fixes span security (path sandbox checks on 3 tools), correctness (operator precedence, deprecated datetime, step counting), performance (O(1) BFS via deque, deduped entropy utility, timeout coverage), and code quality (dead code removal, import consolidation, dense formatting cleanup).

The remaining open item is L7 (streaming file hashes for memory efficiency), which is an optimization accepted as a trade-off given current file size limits. The primary remaining gap is the lack of unit tests for the triage, cache, and state management modules.
