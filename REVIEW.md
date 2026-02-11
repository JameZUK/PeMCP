# PeMCP Project Review

## Overview

PeMCP is a comprehensive binary analysis toolkit and MCP (Model Context Protocol) server that bridges AI assistants with low-level binary instrumentation. It exposes 105 specialized tools for analyzing PE, ELF, Mach-O, .NET, Go, Rust, and shellcode binaries. The codebase is approximately 17,000 lines of Python across 46 files.

---

## Architecture Assessment

### Strengths

**1. Clean Modular Architecture**
The codebase follows a well-organized separation of concerns:
- `pemcp/state.py` — Centralized, thread-safe state management
- `pemcp/config.py` — Import hub with availability flags
- `pemcp/parsers/` — Format-specific parsing logic
- `pemcp/mcp/` — Tool modules organized by domain
- `pemcp/background.py` — Background task management

Each MCP tool module (`tools_angr.py`, `tools_pe.py`, `tools_elf.py`, etc.) is self-contained and registers its tools via a shared decorator, making the system easy to extend.

**2. Graceful Degradation**
The optional dependency pattern in `config.py` is well-executed. Each of 20+ optional libraries is guarded by try/except with `*_AVAILABLE` flags, and tools return clear error messages rather than crashing when a library is absent. This is the right approach for a toolkit with heavy, platform-sensitive dependencies like angr, FLOSS, and vivisect.

**3. Intelligent MCP Response Management**
The auto-truncation system in `server.py:_check_mcp_response_size()` is thoughtfully designed. It iteratively identifies the largest element (list, string, or dict) and progressively shrinks it to fit within the 64KB MCP response limit, rather than simply failing. This keeps the tool usable even with large binaries.

**4. Caching System**
`cache.py` implements a production-quality disk cache:
- Git-style two-character prefix directories to avoid flat-dir performance issues
- Gzip compression (5-15x reduction on JSON)
- LRU eviction with configurable size limits
- Version-based invalidation (both PeMCP version and cache format version)
- Thread-safe operations with atomic file replacement via `tmp.replace()`

**5. Background Task Management**
Long-running operations (angr CFG generation, symbolic execution, loop analysis) are properly offloaded to background threads with:
- Progress tracking with percentage and message updates
- Heartbeat monitoring thread for console feedback
- Task registry with thread-safe access
- Proper `asyncio.to_thread` integration for non-blocking MCP tools

**6. Security-Conscious Design**
- Path sandboxing via `AnalyzerState.check_path_allowed()` using `os.path.realpath()` to resolve symlinks
- API key storage with `0o600` permissions
- Warning when running in network mode without `--allowed-paths`
- Env-var priority over config file for sensitive values

---

### Issues and Concerns

#### High Priority

**1. Global Singleton State — Concurrency Risk**
`config.py:45` creates a single `state = AnalyzerState()` at module level. In HTTP mode (`streamable-http`), multiple concurrent MCP clients could race on `state.filepath`, `state.pe_data`, and `state.angr_project`. While the background task fields are protected by `_task_lock`, the core analysis state (filepath, pe_data, pe_object, angr_project, angr_cfg) has no synchronization. If two clients call `open_file` concurrently, one will silently overwrite the other's loaded binary.

**Recommendation:** For HTTP mode, either:
- Add a lock around file load/close operations and document single-client semantics, or
- Move to a session-scoped state model where each MCP session gets its own `AnalyzerState`

**2. `close_file` Does Not Reset `angr_hooks`**
`tools_pe.py:393-401` — `close_file` resets `angr_project`, `angr_cfg`, `angr_loop_cache`, and `angr_loop_cache_config`, but does not clear `state.angr_hooks`. If a user hooks functions in one binary and then opens a new binary, the stale hooks dictionary persists. When `_rebuild_project_with_hooks()` runs, it will attempt to re-apply hooks from the old binary to the new one, which could corrupt analysis or crash.

**3. Deprecated `datetime.utcfromtimestamp` Usage**
`tools_pe_extended.py:128` uses `datetime.datetime.utcfromtimestamp()`, which is deprecated since Python 3.12 and returns a naive datetime. The codebase correctly uses `datetime.datetime.now(datetime.timezone.utc)` elsewhere (e.g., `background.py:20`), so this is an inconsistency. It should use `datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)`.

**4. `diff_binaries` Path Traversal Risk**
The `diff_binaries` tool (in `tools_angr_forensic.py`) accepts an `other_file_path` argument for a second binary. Unlike `open_file`, which runs `state.check_path_allowed()`, `diff_binaries` should also validate this path against the sandbox when `allowed_paths` is configured.

#### Medium Priority

**5. Shallow Copy in Truncation Logic May Mutate Shared State**
`server.py:103-109` — The `_check_mcp_response_size` function makes a shallow copy of `data_to_return` when it's a dict. If the oversized value is a nested list (e.g., `data["imports"]`), the truncation (`val[:new_len]`) creates a new list, but only for the outer dict key. If any tool returns `state.pe_data` directly (rather than a copy), and truncation hits a nested dict, the actual global state could be mutated. Review callers to ensure they don't pass `state.pe_data` directly, or use `copy.deepcopy`.

**6. `scan_for_api_hashes` Linear Scan Performance**
`tools_pe_extended.py:863` — The API hash scanner does a byte-by-byte scan (`for i in range(len(file_data) - 3)`), reading a 4-byte value at every offset. For a 10MB binary, this is ~10M iterations with `struct.unpack_from` calls. Consider scanning at alignment boundaries (4-byte aligned) or using `mmap` for better performance.

**7. Cache Meta File Is Read on Every `get()`**
`cache.py:148-151` — Each cache hit loads and re-saves `meta.json` to update the `last_accessed` timestamp. For MCP tools that are called frequently, this generates unnecessary disk I/O. Consider batching LRU timestamp updates or using in-memory tracking with periodic flush.

**8. `_parse_addr` Accepts Only Hex Strings**
`_angr_helpers.py:72-77` — The address parser only accepts hex strings (e.g., `0x401000`). Decimal addresses will fail with an unhelpful error. Consider accepting both formats with `int(hex_string, 0)` instead of `int(hex_string, 16)`.

**9. Hardcoded `eax` Register in Emulation**
`tools_angr.py:383` — The function emulation result reads `final.regs.eax` to get the return value. This is x86-specific and will fail or return incorrect results on x64 (should be `rax`), ARM (`r0`), or ARM64 (`x0`). The return register should be determined from `state.angr_project.arch`.

**10. No Timeout on Synchronous angr Operations**
When `run_in_background=False`, tools like `decompile_function_with_angr` and `get_function_cfg` run `asyncio.to_thread` without a timeout. A pathological binary or function could block indefinitely. Consider wrapping with `asyncio.wait_for()`.

#### Low Priority

**11. Redundant `networkx` Import**
`tools_angr.py:17` imports `networkx` at module level, and several functions (`get_backward_slice`, `get_forward_slice`, `get_dominators`) import it again locally with `import networkx as nx`. The local imports are unnecessary.

**12. Magic Number for Capstone Operand Type**
`tools_angr.py:864` uses `if op.type == 2` (X86_OP_IMM) as a raw integer. This should reference `capstone.x86_const.X86_OP_IMM` for readability and correctness across architectures.

**13. Dense Formatting in PE Parser**
`parsers/pe.py` uses extensively compressed single-line formatting (e.g., line 48: `try: hashes["ssdeep"] = ssdeep_hasher.hash(data)` and line 54: `if hasattr(pe, 'DOS_HEADER') and pe.DOS_HEADER: return pe.DOS_HEADER.dump_dict()`). While functional, this reduces readability for a complex parser and makes debugging harder.

**14. `monitor_thread_started` Race Condition**
`background.py:63-67` — The `monitor_thread_started` flag is checked and set without a lock. In theory, two concurrent first-time background tasks could each start a heartbeat thread. This is benign (extra heartbeat prints) but technically a race.

---

## Docker Configuration Review

The Dockerfile is well-structured:
- Heavy dependencies (angr, FLOSS, capa, vivisect) are installed in early layers for optimal caching
- Best-effort installation (`|| true`) for libraries with complex dependencies
- Capa rules pre-downloaded at build time to avoid runtime network access
- oscrypto patched for OpenSSL 3.x compatibility
- Non-root execution supported via `--user "$(id -u):$(id -g)"`

One concern: `chmod 777 /app/home` (line 97) is overly permissive. Since the container runs as the host UID, `chmod 755` would suffice with proper ownership set via `chown`.

---

## Test Suite Assessment

The test suite (`mcp_test_client.py`, 1,818 lines) is comprehensive:
- 19 test classes covering all 105 tools
- Supports both streamable-http and SSE transports
- Configurable via environment variables
- Proper markers for categorization (`no_file`, `pe_file`, `angr`, etc.)

However, it is an **integration test suite only** — it requires a running server and a loaded sample. There are no unit tests for the parsers, cache, state management, or helper functions. Unit tests would provide faster feedback during development and catch regressions in the parsing logic without needing a full MCP server.

---

## Summary Scorecard

| Category | Rating | Notes |
|----------|--------|-------|
| Architecture | Strong | Clean separation, modular design, extensible |
| Code Quality | Good | Well-organized, some dense formatting in parsers |
| Security | Good | Path sandboxing, secure key storage; HTTP concurrency gap |
| Error Handling | Strong | Graceful degradation, descriptive errors, auto-truncation |
| Performance | Good | Caching, background tasks, lazy loading; some linear scans |
| Testing | Adequate | Comprehensive integration tests; no unit tests |
| Documentation | Strong | Thorough README, inline docstrings, help text |
| Docker/Deployment | Strong | Layered builds, volume persistence, multi-mode support |

**Overall:** This is a well-engineered, production-grade tool. The architecture decisions (modular tools, graceful degradation, disk caching, background analysis) are sound and reflect real-world usage considerations. The main areas for improvement are HTTP-mode concurrency safety, adding unit tests, and the specific code issues noted above.
