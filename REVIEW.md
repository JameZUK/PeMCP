# PeMCP Project Review

**Date**: 2026-02-21
**Scope**: Full codebase review — architecture, code quality, security, concurrency, testing, documentation
**Tests**: 113 passed, 11 skipped (1.29s) on Python 3.11 (unit tests only, no heavy deps)

---

## Executive Summary

PeMCP is a ~20,400-line Python toolkit for multi-format binary analysis (PE, ELF, Mach-O, .NET, Go, Rust, shellcode) that operates as both a CLI report generator and an MCP server exposing 113 specialized tools. The project demonstrates strong architectural decisions: per-session state isolation, graceful dependency degradation for 20+ optional libraries, smart response truncation, disk-based analysis caching, and Docker-first deployment with venv isolation for incompatible unicorn versions.

**Previous review (2026-02-18)** identified 25 issues across critical/high/medium/low categories. Many have been addressed in subsequent commits. This follow-up review validates those fixes, identifies remaining issues, and re-evaluates the overall state of the project.

---

## 1. Architecture & Design: Strong

### Strengths

- **Clean modular separation**: `pemcp/parsers/` (format-specific parsing), `pemcp/mcp/` (113 tools across 27 modules), `pemcp/cli/` (output formatting), and core modules (`state.py`, `cache.py`, `config.py`) have clear responsibilities.
- **Per-session state isolation** (`state.py`): `StateProxy` + `contextvars` transparently routes attribute access to the correct `AnalyzerState`. Stdio mode collapses to a singleton; HTTP mode creates isolated sessions. The `_inherited_pe_object` flag prevents cross-session resource corruption.
- **Graceful dependency degradation** (`config.py`): 20+ optional libraries are detected at startup with individual availability flags. Missing libraries produce clear error messages rather than crashes.
- **Smart response truncation** (`server.py:170-283`): MCP responses are auto-truncated to 64KB using an iterative heuristic that finds the largest element and reduces it proportionally, preserving structural integrity.
- **Analysis caching** (`cache.py`): SHA256-keyed, gzip-compressed disk cache with LRU eviction, version-based invalidation, and mtime/size verification. Re-opening a previously analyzed file loads from cache near-instantly.
- **Background task management** (`background.py`): Long-running operations (angr CFG) run asynchronously with progress tracking, heartbeat monitoring, and status polling via `check_task_status`.
- **Dependency isolation**: Docker build uses three separate venvs to resolve unicorn version conflicts between angr (2.x), speakeasy (1.x), unipacker (1.x), and qiling (1.x).

### Observations

1. **`tools_triage.py` is 1,904 lines.** This file contains the entire triage report generation logic in a single module. Splitting into sub-modules (timestamp analysis, import analysis, section analysis) would improve maintainability.

2. **Code duplication in format detection.** The magic-byte detection logic (`MZ`, `\x7fELF`, Mach-O magic values) is duplicated in `main.py:276-292`, `tools_pe.py:166-182`, `tools_samples.py:10-35`, and `tools_format_detect.py`. This should be a single function in a shared utility module.

3. **The `config.py` module is overloaded.** At 537 lines, it handles library imports, availability flags, constants, lazy-checking functions, exception class definitions, AND global state creation. Consider splitting into `config.py` (constants/flags), `imports.py` (library probing).

---

## 2. Previous Issues — Status

### Fixed since last review

- **`StateProxy.__setattr__`** now handles `_proxy_` prefixed attributes correctly (`state.py:447-449`).
- **Session state cleanup** now marks sessions as closing inside the lock to prevent TOCTOU races (`state.py:359-360`).
- **`open_file` state assignment** now builds complete dicts locally before atomic assignment (`tools_pe.py:247-261`).
- **Cache eviction** now handles `_remove_entry` failures gracefully by skipping and logging (`cache.py:304-308`).
- **`BearerAuthMiddleware`** now handles both HTTP and WebSocket scopes (`auth.py:30, 37-39`).
- **Lazy availability checks** now use `threading.Lock` for synchronization (`config.py:366, 398, 431`).
- **Background task injection** now inspects function signature before injecting `task_id_for_progress` (`background.py:97-102`).
- **Task status constants** are defined as module-level constants (`state.py:28-29`).
- **`open_file` error handler** now calls `state.close_pe()` properly (`tools_pe.py:455`).
- **Registry hive creation** is extracted to a shared script (`scripts/create_registry_hives.py`).

### Remaining from previous review

1. **Unpinned Docker base image** (`Dockerfile:6`): Still uses `FROM python:3.11-bookworm` without digest pinning. Comments explain how to pin but the default is unpinned.

2. **`chmod -R 777` on directories** (`Dockerfile:154, 207`): World-writable directories are documented as necessary for arbitrary UID support, but could use `775` with a dedicated group.

3. **CI coverage threshold at 60%**: Current measured coverage is 50% (unit tests only). The parser and utility modules remain at 0% coverage.

4. **Ruff lint rules too narrow**: Only `E9,F63,F7,F82` — no unused variable detection (F841) or unreachable code checks.

5. **f-strings in logging calls**: Multiple files use `logger.warning(f"...")` instead of `logger.warning("...", arg)`.

---

## 3. New Issues Found

### 3.1 `import_project` path traversal check could be stronger

**File:** `pemcp/mcp/tools_export.py:176`

```python
if member.name.startswith("/") or ".." in member.name:
```

The check uses substring matching for `..`, which is functional but could be more robust. Using `os.path.normpath()` comparison or Python 3.12's `tarfile.data_filter` would be more defensive. The current check works for common attack vectors but may miss unusual path encodings.

### 3.2 Cache `get()` acquires the lock multiple times

**File:** `pemcp/cache.py:135, 165, 188`

On a cache miss due to corruption, the lock is acquired to remove the entry, then released. Later, the lock is acquired again for mtime/size validation, and again for the LRU timestamp update. This is correct (no deadlock) but adds unnecessary lock contention on the hot path.

### 3.3 Potential data race in `open_file` shellcode loading

**File:** `pemcp/mcp/tools_pe.py:260-261`

Inside `_load_shellcode()` (running in a thread), `state.pe_object` and `state.filepath` are still assigned sequentially. The analysis semaphore makes this unlikely to cause issues in practice, but it's a theoretical race.

### 3.4 `_check_pe_loaded` reads state non-atomically

**File:** `pemcp/mcp/server.py:107`

Reads `state.pe_data` and `state.filepath` in two separate attribute accesses through the proxy. A concurrent state reset between the two checks is possible (though unlikely due to semaphore).

### 3.5 Signify import prints to stderr unconditionally

**File:** `pemcp/config.py:83`

```python
print(f"[!] Signify Import Error: {e}", file=sys.stderr)
```

This runs at import time, producing output even when signify is genuinely optional. Should use `logger.warning()` consistent with other import failures (e.g., YARA at line 91 uses the YARA_IMPORT_ERROR pattern without printing).

### 3.6 `safe_regex_search` creates a new ThreadPoolExecutor per call

**File:** `pemcp/utils.py:94`

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
```

Each regex search creates and tears down a thread pool. Under high concurrency this could spawn many OS threads. A module-level shared executor with bounded workers would be more efficient.

### 3.7 `reanalyze_loaded_pe_file` has 25 parameters

**File:** `pemcp/mcp/tools_pe.py:510-537`

This function signature is extremely wide. Consider accepting a configuration dict or dataclass to reduce parameter count and improve maintainability.

### 3.8 `import_project` writes to `~/.pemcp/imported/` without disk quota

**File:** `pemcp/mcp/tools_export.py:264-266`

In a multi-tenant HTTP scenario, users can import archives containing large binaries. There's no size limit on the extracted binary or total imported data. The `IMPORT_DIR` is hardcoded and doesn't go through `check_path_allowed()`.

---

## 4. Security Assessment

### Strengths

1. **Path sandboxing** (`state.check_path_allowed()`) uses `os.path.realpath()` to resolve symlinks. Tests cover symlink resolution, prefix confusion, nested paths, and similar-prefix directories.
2. **HTTP authentication** via `BearerAuthMiddleware` uses `hmac.compare_digest()` for constant-time token comparison on both HTTP and WebSocket scopes.
3. **No `shell=True`** in any subprocess calls.
4. **No `eval()`/`exec()` on user input.** All `.eval()` calls are angr's `solver.eval()`.
5. **No pickle deserialization.** Cache uses gzip-compressed JSON exclusively.
6. **ReDoS protection** with pattern validation and execution timeout.
7. **Zip-slip protection** in archive import.
8. **API key storage** with 0o600 file permissions.
9. **HTTP mode requires `--allowed-paths`** (mandatory, enforced at startup).
10. **Non-root Docker** via `--user "$(id -u):$(id -g)"`.

### Observations

- `PEMCP_API_KEY` is only a warning (not mandatory) for HTTP mode. Document the risk or consider requiring it.
- `list_samples` returns full filesystem paths, which could leak server directory structure to MCP clients.

---

## 5. Test Coverage

| Module | Coverage | Notes |
|--------|----------|-------|
| `auth.py` | 90% | Good; WebSocket close path untested |
| `user_config.py` | 96% | Excellent |
| `hashing.py` | 86% | Good |
| `cache.py` | 61% | Core paths covered; eviction/session update paths less so |
| `state.py` | 65% | Good for basic ops; note/history accessors less covered |
| `mock.py` | 100% | Complete |
| `parsers/strings.py` | 0% | No unit tests; covered by integration tests only |
| `utils.py` | 0% | No unit tests |
| `_category_maps.py` | 0% | Data module, less critical |
| **Overall** | **50%** | Below CI threshold of 60% (CI uses full deps) |

### Recommendations

1. Add unit tests for `utils.py` — especially `validate_regex_pattern`, `safe_regex_search`, `shannon_entropy`.
2. Add unit tests for `parsers/strings.py` — `_extract_strings_from_data`, `_perform_unified_string_sifting`.
3. Add edge-case tests for `_check_mcp_response_size` truncation with nested dicts, lists, and strings.
4. Gradually raise CI coverage threshold to 70%.

---

## 6. Documentation: Excellent

- **README.md** (~1000 lines): Comprehensive. Covers installation (Docker/local/minimal), Claude Code integration (CLI and JSON), all 113 tools with descriptions, architecture, security, testing, and configuration.
- **Tool docstrings**: Consistent pattern with Args/Returns/Raises sections.
- **"Recommended AI Workflow"** section: Thoughtful guide for MCP clients on efficient analysis progression.
- **TESTING.md**: Detailed testing guide.
- **Docker/run.sh documentation**: Well-documented helper with SELinux support, custom mounts, and environment variable configuration.

---

## 7. Summary

| Category | Rating | Key Observations |
|----------|--------|------------------|
| **Architecture** | Strong | Clean modular design, smart caching, graceful degradation |
| **Security** | Good | Path sandboxing, constant-time auth, no dangerous patterns |
| **Code Quality** | Good | Consistent patterns, thread-safe state, actionable errors |
| **Testing** | Adequate | Core modules covered; utility/parser gaps remain |
| **Documentation** | Excellent | Comprehensive README, consistent docstrings, AI workflow guide |

### Priority Improvements

1. **Increase test coverage** for `utils.py` and `parsers/strings.py` (currently 0%)
2. **Consolidate duplicated magic-byte detection** into a shared utility function
3. **Split large files** (`tools_triage.py` at 1,904 lines, `config.py` at 537 lines)
4. **Fix signify import stderr printing** (use `logger.warning()` instead)
5. **Consider per-call `ThreadPoolExecutor` in `safe_regex_search`** — use shared executor
6. **Pin Docker base image** by digest for reproducible builds
7. **Strengthen `import_project` path traversal** validation with `os.path.normpath()`

### Overall Assessment

PeMCP is a mature, production-quality binary analysis platform. The 113-tool MCP interface, multi-format support, session isolation, and Docker-first deployment model are substantial achievements. The codebase handles significant complexity (20+ optional libraries, incompatible dependency versions, concurrent multi-session access) with clean, well-documented patterns. Most critical issues from the previous review have been addressed. The remaining issues are targeted improvements rather than systemic problems.
