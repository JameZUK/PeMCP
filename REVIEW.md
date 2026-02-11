# PeMCP Project Review

## Overview

PeMCP is a comprehensive binary analysis toolkit and MCP (Model Context Protocol) server that bridges AI assistants with low-level binary instrumentation. It exposes 105 specialized tools for analyzing PE, ELF, Mach-O, .NET, Go, Rust, and shellcode binaries. The codebase is approximately 17,000 lines of Python across 48 files.

This review covers the full codebase as of February 2026, including verification that the 14 issues identified in the prior review have been addressed.

---

## Architecture Assessment

### Strengths

**1. Clean Modular Architecture**
The codebase follows a well-organized separation of concerns:
- `pemcp/state.py` — Centralized, thread-safe state management with per-session isolation
- `pemcp/config.py` — Import hub with availability flags for 20+ optional libraries
- `pemcp/parsers/` — Format-specific parsing logic (PE, FLOSS, capa, strings, signatures)
- `pemcp/mcp/` — 25 tool modules organized by domain, each self-contained
- `pemcp/background.py` — Background task management with progress tracking

Each MCP tool module registers its tools via a shared `tool_decorator` in `server.py`, making the system easy to extend. Adding a new tool category requires only a new file and an import in `main.py`.

**2. Per-Session State Isolation (HTTP Mode)**
The `StateProxy` pattern in `state.py:161-178` is well-designed. It uses Python's `contextvars` to transparently delegate attribute access to the correct `AnalyzerState` for the current async context. The `tool_decorator` in `server.py:20-36` activates per-session state before every tool invocation. This means concurrent HTTP clients each get isolated analysis state without any changes to the 105 tool implementations.

**3. Graceful Degradation**
The optional dependency pattern in `config.py` is well-executed. Each of 20+ optional libraries is guarded by try/except with `*_AVAILABLE` flags, and tools return clear, actionable error messages rather than crashing when a library is absent. This is the correct approach for a toolkit with heavy, platform-sensitive dependencies like angr, FLOSS, and vivisect.

**4. Intelligent MCP Response Management**
The auto-truncation system in `server.py:97-199` is thoughtfully designed. It uses `copy.deepcopy` to avoid mutating shared state, then iteratively identifies the largest element (list, string, or dict) and progressively shrinks it to fit within the 64KB MCP response limit. The 5-iteration approach with a 10% aggressive reduction factor is pragmatic.

**5. Caching System**
`cache.py` implements a production-quality disk cache:
- Git-style two-character prefix directories to avoid flat-dir performance issues
- Gzip compression (5-15x reduction on JSON)
- LRU eviction with configurable size limits
- Version-based invalidation (both PeMCP version and cache format version)
- Thread-safe operations with atomic file replacement via `tmp.replace()`

**6. Background Task Management**
Long-running operations (angr CFG generation, symbolic execution, loop analysis) are properly offloaded to background threads with:
- Progress tracking with percentage and message updates
- Heartbeat monitoring thread for console feedback
- Task registry with thread-safe access via `_task_lock`
- Proper `asyncio.to_thread` integration for non-blocking MCP tools
- Session state propagation to background threads via `set_current_state()` (`background.py:103-104`)

**7. Security-Conscious Design**
- Path sandboxing via `AnalyzerState.check_path_allowed()` using `os.path.realpath()` to resolve symlinks
- `diff_binaries` validates `file_path_b` against the sandbox (`tools_angr_forensic.py:38`)
- API key storage with `0o600` permissions (`user_config.py:58`)
- Warning when running in network mode without `--allowed-paths` (`main.py:216-219`)
- Env-var priority over config file for sensitive values

**8. Timeouts on Expensive Operations**
The decompilation and CFG extraction tools now use `asyncio.wait_for(..., timeout=300)` (`tools_angr.py:178, 208`), preventing pathological binaries from blocking indefinitely.

---

### Previous Review Issues — Status

The prior review identified 14 issues. All high-priority and most medium/low-priority items have been addressed:

| # | Issue | Status | Evidence |
|---|-------|--------|----------|
| 1 | Global singleton state concurrency risk | **Fixed** | `StateProxy` + `contextvars` in `state.py:161-178`; `tool_decorator` activates per-session state |
| 2 | `close_file` does not reset `angr_hooks` | **Fixed** | `state.angr_hooks = {}` at `tools_pe.py:404` and `tools_pe.py:163` |
| 3 | Deprecated `datetime.utcfromtimestamp` | **Fixed** | Now uses `datetime.fromtimestamp(ts, tz=datetime.timezone.utc)` at `tools_pe_extended.py:128` |
| 4 | `diff_binaries` path traversal risk | **Fixed** | `state.check_path_allowed(abs_path_b)` at `tools_angr_forensic.py:38` |
| 5 | Shallow copy in truncation logic | **Fixed** | Uses `copy.deepcopy(data_to_return)` at `server.py:124` |
| 6 | `scan_for_api_hashes` linear scan | Not changed | Performance concern remains; acceptable for typical PE sizes |
| 7 | Cache meta file read on every `get()` | Not changed | LRU timestamp update on every hit; acceptable for MCP tool call frequency |
| 8 | `_parse_addr` accepts only hex strings | **Fixed** | Now uses `int(hex_string, 0)` at `_angr_helpers.py:76` |
| 9 | Hardcoded `eax` register in emulation | **Fixed** | Uses `arch.register_names.get(arch.ret_offset)` at `tools_angr.py:391-394` |
| 10 | No timeout on sync angr operations | **Fixed** | `asyncio.wait_for(..., timeout=300)` at `tools_angr.py:178, 208` |
| 11 | Redundant `networkx` imports | **Fixed** | Module-level import only; local `nx` references use the module-level binding |
| 12 | Magic number for Capstone operand type | **Mitigated** | `CS_OP_IMM = 2` defined as named constant at `tools_angr.py:870` |
| 13 | Dense formatting in PE parser | Not changed | Cosmetic; no functional impact |
| 14 | `monitor_thread_started` race condition | **Fixed** | Now uses `_monitor_lock` + `_monitor_started` at `background.py:68-73` |

---

### New Issues Identified — All Fixed

All 11 issues from this review have been resolved:

| # | Issue | Fix |
|---|-------|-----|
| 1 | `save_patched_binary` missing path sandbox validation | Added `state.check_path_allowed()` before write. Also added to `modify_pe_section` and `auto_unpack_pe`. |
| 2 | Session registry grows indefinitely (memory leak) | Added TTL-based cleanup (`SESSION_TTL_SECONDS = 3600`). Stale sessions are pruned on new session creation. `touch()` tracks last activity. |
| 3 | Background task results accumulate without bound | Added `_evict_old_tasks()` with `MAX_COMPLETED_TASKS = 50` limit. Oldest completed/failed tasks are removed when exceeded. |
| 4 | No file size limit on `open_file` | Added `PEMCP_MAX_FILE_SIZE_MB` env var check (default 256 MB) before reading file into memory. |
| 5 | Heartbeat monitor only sees default session tasks | Heartbeat loop now uses `get_all_session_states()` to iterate tasks from all sessions including per-session HTTP states. |
| 6 | Duplicate availability flag patterns | All 17 availability flags consolidated into `config.py`. Tool modules import flags from config and conditionally import library objects. |
| 7 | `reanalyze_loaded_pe_file` doesn't clear loop cache | Added `state.angr_loop_cache = None` and `state.angr_loop_cache_config = None` after CFG rebuild. |
| 8 | Non-atomic state swap in `open_file` | Replaced inline field-by-field cleanup with `state.close_pe()` + `state.reset_angr()` methods. |
| 9 | Unused stdlib imports in `config.py` | Removed 22 unused stdlib imports (kept only `os`, `sys`, `logging`, `shutil`). |
| 10 | Generic `"angr_tool"` in error messages | All 10 occurrences replaced with actual tool names (e.g., `"analyze_binary_loops"`, `"get_function_xrefs"`). |
| 11 | `binwalk` CLI fallback without subprocess timeout | Already had `timeout=60` — no change needed. |

---

## Docker Configuration Review

The Dockerfile is well-structured:
- Heavy dependencies (angr, FLOSS, capa, vivisect) are installed in early layers for optimal caching
- Best-effort installation (`|| true`) for libraries with complex dependencies
- Capa rules pre-downloaded at build time to avoid runtime network access
- oscrypto patched for OpenSSL 3.x compatibility
- Non-root execution supported via `--user "$(id -u):$(id -g)"`

One concern: `chmod 777 /app/home` is overly permissive. Since the container runs as the host UID, `chmod 755` would suffice with proper ownership set via `chown`.

---

## Test Suite Assessment

The test suite (`mcp_test_client.py`, 1,818 lines) is comprehensive:
- 19 test classes covering all 105 tools
- 94 test functions across the full tool surface
- Supports both streamable-http and SSE transports
- Configurable via environment variables (`PEMCP_TEST_URL`, `PEMCP_TEST_FILE`, etc.)
- Proper markers for categorization (`no_file`, `pe_file`, `angr`, `optional_lib`)

However, it remains an **integration test suite only** — it requires a running server and a loaded sample binary. There are no unit tests for:
- Parser logic (`parsers/pe.py`, `parsers/floss.py`, `parsers/strings.py`)
- Cache operations (`cache.py` — put/get/evict/clear)
- State management (`state.py` — session creation, proxy delegation)
- Helper functions (`_angr_helpers.py` — address parsing, function resolution)
- Truncation logic (`server.py` — `_check_mcp_response_size`)

Unit tests would provide faster feedback during development and catch regressions without needing a full MCP server + sample binary.

---

## Summary Scorecard

| Category | Rating | Notes |
|----------|--------|-------|
| Architecture | Strong | Clean separation, modular design, extensible, per-session isolation |
| Code Quality | Good | Well-organized; some inconsistency in availability flag patterns |
| Security | Good | Path sandboxing, secure key storage; `save_patched_binary` gap |
| Error Handling | Strong | Graceful degradation, descriptive errors, auto-truncation, timeouts |
| Performance | Good | Caching, background tasks, lazy loading; unbounded session/task growth |
| Testing | Adequate | Comprehensive integration tests; no unit tests |
| Documentation | Strong | Thorough README (1,000+ lines), inline docstrings, tool help text |
| Docker/Deployment | Strong | Layered builds, volume persistence, multi-mode support |

**Overall:** This is a well-engineered, production-grade binary analysis toolkit. The prior review's high-priority issues have all been addressed — notably the session isolation via `StateProxy`/`contextvars`, angr hook cleanup, path validation on `diff_binaries`, and deep-copy in truncation logic. The architecture decisions (modular tools, graceful degradation, disk caching, background analysis with progress tracking) are sound and reflect real-world usage considerations.

The main areas for improvement are:
1. **Security**: Validating output paths in `save_patched_binary`
2. **Resource management**: Cleaning up stale HTTP sessions and completed background tasks
3. **Testing**: Adding unit tests for parsers, cache, state management, and helpers
4. **Consolidation**: Unifying the availability flag pattern across `config.py` and `tools_new_libs.py`
