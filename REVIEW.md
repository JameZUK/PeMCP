# PeMCP Project Review

**Date**: 2026-02-18
**Scope**: Full codebase review — architecture, code quality, security, concurrency, testing, documentation
**Tests**: 355 passed, 3 skipped (2.96s) on Python 3.11

---

## Executive Summary

PeMCP is a ~24,500-line Python toolkit for multi-format binary analysis (PE, ELF, Mach-O, .NET, Go, Rust, shellcode) that operates as both a CLI report generator and an MCP server exposing 113 specialized tools. The project demonstrates strong architectural decisions: per-session state isolation, graceful dependency degradation for 20+ optional libraries, smart response truncation, disk-based analysis caching, and Docker-first deployment with venv isolation for incompatible unicorn versions.

This review identified **25 issues**: 3 critical, 5 high, 10 medium, and 7 low severity. The most impactful are concurrency bugs in angr state management, a logic error in the Qiling runner, and an authentication gap on WebSocket scopes. The project's fundamentals are solid — these are targeted issues rather than systemic problems.

---

## 1. Architecture & Design

### Strengths

- **Clean modular separation**: `pemcp/parsers/` (format-specific parsing), `pemcp/mcp/` (113 tools across 25 modules), `pemcp/cli/` (output formatting), and core modules (`state.py`, `cache.py`, `config.py`) have clear responsibilities.
- **Per-session state isolation** (`state.py:274-291`): `StateProxy` + `contextvars` transparently routes attribute access to the correct `AnalyzerState`. Stdio mode collapses to a singleton; HTTP mode creates isolated sessions.
- **Graceful dependency degradation** (`config.py:58-467`): 20+ optional libraries are detected at startup with individual availability flags. Missing libraries produce clear error messages rather than crashes.
- **Smart response truncation** (`server.py:107-220`): MCP responses are auto-truncated to 64KB using an iterative heuristic that finds the largest element and reduces it proportionally.
- **Analysis caching** (`cache.py`): SHA256-keyed, gzip-compressed disk cache with LRU eviction and version-based invalidation. Re-opening a previously analyzed file loads in ~10ms instead of 5-30s.
- **Background task management** (`background.py`): Long-running operations run asynchronously with progress tracking, heartbeat monitoring, and status polling.
- **Dependency isolation**: Docker build uses three separate venvs to resolve unicorn version conflicts between angr (2.x), speakeasy (1.x), unipacker (1.x), and qiling (1.x).

### Observations

- **String-based mode dispatch**: Mode strings (`"pe"`, `"elf"`, `"macho"`, `"shellcode"`) are compared throughout the codebase. An `enum.Enum` would prevent typo bugs and provide IDE autocomplete.
- **`config.py` serves dual duty**: It handles both library availability detection and global singleton creation. Splitting these would reduce import-time side effects.
- **Deep dict nesting in `pe_data`**: A large nested dict accessed via `.get()` chains. A `TypedDict` or dataclass definition would catch key typos at type-check time.

---

## 2. Critical Issues

### 2.1 Bug: `'maps' in dir()` always evaluates incorrectly — `scripts/qiling_runner.py:934`

```python
"memory_regions_scanned": len(maps) if 'maps' in dir() else 0,
```

`dir()` in a function returns local scope names, but if `maps` was never assigned before an exception, this will either find the name in the enclosing scope (wrong value) or raise `NameError` (because `dir()` may list it as a local but it's unbound). The intent is to check whether `maps` was assigned before the exception.

**Fix**: Use `'maps' in locals()` instead.

### 2.2 Race condition: `get_global_data_refs` bypasses angr state lock — `pemcp/mcp/tools_angr.py:952-956`

```python
def _scan_refs():
    if state.angr_project is None:
        state.angr_project = angr.Project(state.filepath, auto_load_libs=False)
    if state.angr_cfg is None:
        state.angr_cfg = state.angr_project.analyses.CFGFast(
            normalize=True, collect_data_references=True)
```

This directly assigns to `state.angr_project` and `state.angr_cfg` without using the `_angr_lock` or `set_angr_results()` method. A concurrent tool call could observe a partially updated state. Additionally, this builds a CFG with `collect_data_references=True`, silently replacing the standard CFG and potentially breaking other angr tools.

**Fix**: Use `_init_lock` for serialization and `set_angr_results()` for atomic updates, or build a separate local CFG rather than replacing the shared one.

### 2.3 Unvalidated file paths in subprocess runner scripts

**Files**: `scripts/qiling_runner.py`, `scripts/speakeasy_runner.py`, `scripts/unipacker_runner.py`

The runner scripts read file paths from JSON on stdin and pass them directly to emulation engines without any path validation. While the parent MCP tool layer enforces `check_path_allowed()`, the subprocess scripts have no defense-in-depth. Direct invocation of these scripts (e.g., during development) bypasses all path restrictions.

**Fix**: Add basic file existence and path validation within each runner script.

---

## 3. High Severity Issues

### 3.1 `StateProxy.__setattr__` bypasses own `__dict__` — `pemcp/state.py:294-298`

```python
def __setattr__(self, name: str, value):
    setattr(get_current_state(), name, value)
```

ALL attribute sets are delegated to the underlying `AnalyzerState`. Any future maintainer adding an instance attribute to `StateProxy` will silently set it on the proxied state instead.

**Fix**: Use `object.__setattr__` for `StateProxy`'s own private attributes, or document the limitation prominently.

### 3.2 Session state cleanup race — `pemcp/state.py:209-250`

Stale session cleanup runs inside `get_or_create_session_state`, meaning one client's connection triggers cleanup of another's session. The cleanup calls `stale.close_pe()` outside the registry lock, creating a TOCTOU race: session keys based on `id(session)` can be reused by Python's memory allocator, potentially reactivating a stale session between `pop` and cleanup.

**Fix**: Mark sessions as "closing" inside the lock, or use a separate periodic cleanup task.

### 3.3 Concurrent modification of `state.pe_data` dict — `pemcp/mcp/tools_pe.py:240-260`

In `open_file`, the shellcode loading path modifies `state.pe_data` in a background thread while FLOSS analysis (also threaded) later mutates the same dict. Since `pe_data` is a plain dict with no lock, concurrent tool calls during loading could see partially-written data.

**Fix**: Assemble the complete dict in the background thread and assign atomically, or add a lock around `pe_data` mutations.

### 3.4 `_evict_if_needed` fragile iteration pattern — `pemcp/cache.py:260-268`

The eviction loop iterates over `sorted_entries` (derived from `meta.items()`) while deleting from `meta`. The sorted list is a copy so this is safe in CPython, but the pattern is fragile. More importantly, `_remove_entry` can fail silently (filesystem errors), leaving metadata inconsistent with the filesystem.

**Fix**: Handle `_remove_entry` failures by skipping the metadata deletion for that entry.

### 3.5 Authentication bypass on WebSocket scopes — `pemcp/auth.py:50`

```python
# Non-HTTP scopes (lifespan, websocket) pass through
await self.app(scope, receive, send)
```

The `BearerAuthMiddleware` only checks `scope["type"] == "http"`. WebSocket connections bypass authentication entirely. If the MCP SDK or a future transport uses WebSocket upgrading, API key protection would be silently absent.

**Fix**: Also validate `scope["type"] == "websocket"` by inspecting handshake headers.

---

## 4. Medium Severity Issues

### 4.1 Lazy availability checks lack synchronization — `pemcp/config.py:366-444`

`_check_speakeasy_available()`, `_check_unipacker_available()`, and `_check_qiling_available()` use a global flag pattern without thread synchronization. In HTTP mode, two threads could run the subprocess check simultaneously.

**Fix**: Use a `threading.Lock` to ensure the check runs exactly once.

### 4.2 Exception swallowing in emulation runners — `scripts/speakeasy_runner.py:64-67`

```python
try:
    se.run_module(module, timeout=timeout_seconds)
except Exception:
    pass
```

All exceptions from emulation are silently swallowed, including `MemoryError` and `KeyboardInterrupt`. This makes debugging emulation failures extremely difficult.

**Fix**: Catch specific expected exceptions, or at minimum log the exception to stderr.

### 4.3 `_run_background_task_wrapper` injects unexpected keyword — `pemcp/background.py:92`

```python
kwargs['task_id_for_progress'] = task_id
```

This unconditionally injects `task_id_for_progress` into kwargs. If the wrapped function doesn't accept `**kwargs` or this specific parameter, a `TypeError` occurs at runtime.

**Fix**: Inspect the function signature before injecting, or document this contract.

### 4.4 Unpinned Docker base image — `Dockerfile:6`

```dockerfile
FROM python:3.11-bookworm
```

The comments explain how to pin by digest but the actual FROM line uses an unpinned tag. Builds are not reproducible.

**Fix**: Pin by digest for production builds.

### 4.5 `chmod -R 777` on directories — `Dockerfile:196, 249`

World-writable directories are a security concern. While the rationale is documented (arbitrary UID via `--user`), this grants write access to any process in the container.

**Fix**: Use `chmod -R 775` with a dedicated group.

### 4.6 `open_file` does not close PE object on error path — `pemcp/mcp/tools_pe.py:408-411`

When loading from cache, a `pefile.PE` object is created at line 226. If the function later fails, the exception handler sets `state.pe_object = None` without calling `.close()`, orphaning the PE object.

**Fix**: Call `state.close_pe()` in the exception handler instead of just clearing the reference.

### 4.7 Missing timeout for CFG builds under lock — `pemcp/mcp/_angr_helpers.py:83`

```python
cfg = project.analyses.CFGFast(normalize=True)
```

CFG construction can hang on pathological binaries. This runs inside `_init_lock`, blocking ALL angr-based tools across ALL sessions.

**Fix**: Move CFG construction outside the lock (after project creation), or add a timeout mechanism.

### 4.8 Task status tracked via plain strings — `pemcp/mcp/server.py:77`

```python
if startup_task and startup_task["status"] == "running":
```

No central enum or constant definition for status values. A typo would silently break the check.

**Fix**: Define status constants as an enum or module-level constants.

### 4.9 Duplicated `_safe_slice` function — three locations

`_safe_slice` is duplicated in `scripts/qiling_runner.py:66`, `scripts/speakeasy_runner.py:18`, and `pemcp/mcp/tools_new_libs.py:92` with slightly different implementations. The runner script duplication is acceptable (isolated venvs), but the main package version should live in `pemcp/utils.py`.

### 4.10 Duplicated registry hive creation code

The `_create_minimal_registry_hive` function is duplicated between `Dockerfile:131-170` (inline Python) and `scripts/qiling_runner.py:948-1047` with different implementations.

**Fix**: Extract into a standalone script and invoke from both locations.

---

## 5. Low Severity Issues

### 5.1 CI coverage threshold at 60%

For a security-focused tool analyzing untrusted binaries, 60% is low. Recommend gradually increasing to 80%.

### 5.2 Ruff lint rules too narrow

Only syntax errors and undefined names are checked (`E9,F63,F7,F82`). Common bugs like unused variables (F841) and unreachable code are not caught.

**Fix**: Expand to include at least `F` (pyflakes) and `E` (pycodestyle) categories.

### 5.3 `QL_INTERCEPT` import at module bottom — `scripts/qiling_runner.py:1054`

The constant is imported at the bottom of the file but used at line 89. This works because it's called at runtime, not import time, but the ordering is misleading.

### 5.4 Circular import concern in `cache.py:26-34`

Lazy import of `pemcp.__version__` to avoid circular imports (`config.py` -> `cache.py` -> `__init__.py`). Consider a standalone `_version.py` module.

### 5.5 Expensive truncation re-serialization — `pemcp/mcp/server.py:107-220`

The size-checking function serializes to JSON, checks size, deep-copies, and re-serializes up to 5 times. For large responses this causes significant CPU/memory overhead.

### 5.6 f-strings in logging calls — multiple files

```python
logger.warning(f"Failed to import: {CAPA_IMPORT_ERROR}")
```

The string formatting always happens even if the log level filters the message. Standard practice is `logger.warning("Failed: %s", err)`.

### 5.7 Global analysis semaphore lacks per-session fairness — `pemcp/mcp/tools_pe.py:43`

The analysis semaphore is shared across all HTTP sessions. One client could monopolize all slots while others hang indefinitely.

---

## 6. Testing

### Strengths

- **355 unit tests** across 19 files, running in ~3 seconds with no external dependencies.
- **Good marker system** (`pytest.ini`): Tests categorized with markers (`no_file`, `pe_file`, `angr`, `optional_lib`, `unit`).
- **Parametrized edge cases** (`test_parametrized.py`): Systematic boundary testing with 95+ parametrized cases.
- **Concurrency testing** (`test_concurrency.py`): Thread-safety validation for state management.
- **CI/CD pipeline**: GitHub Actions on Python 3.10/3.11/3.12 with coverage enforcement.
- **Integration test suite** (`mcp_test_client.py`): 129 end-to-end tests covering all 113 tools.

### Gaps

1. **Path sandboxing edge cases**: No tests for symbolic links, relative traversal (`../..`), or Unicode path normalization.
2. **Malformed binary resilience**: No tests feeding adversarial binaries to verify `_safe_parse` fallback behavior.
3. **Cache concurrency**: No multi-threaded stress tests for cache integrity under concurrent reads/writes.
4. **Auth middleware**: No tests for WebSocket scope handling or edge cases in token comparison.

---

## 7. Documentation

### Strengths

- **Comprehensive README** (~44KB): Covers installation, all 113 tools, Docker deployment, and configuration.
- **TESTING.md** (16KB): Detailed guide for running unit and integration tests.
- **DEPENDENCIES.md** (14KB): Documents the unicorn version conflict and venv isolation solution.
- **FastPrompt.txt**: Pre-built security analyst prompt for automated analysis workflow.

### Gaps

- **Security hardening guide**: No documentation on TLS termination, network isolation, or secret management for production deployments.
- **Architecture document**: The `StateProxy` delegation pattern, session lifecycle, and cache invalidation strategy are well-implemented but not documented for contributors.

---

## 8. Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| **Critical** | 3 | `dir()` bug in qiling runner, angr state race condition, unvalidated runner paths |
| **High** | 5 | StateProxy fragility, session cleanup race, pe_data mutation race, cache eviction, WebSocket auth bypass |
| **Medium** | 10 | Lazy check synchronization, exception swallowing, background task injection, unpinned Docker image, PE leak on error, CFG timeout, others |
| **Low** | 7 | Coverage threshold, lint rules, import ordering, circular imports, truncation cost, logging format, semaphore fairness |
| **Total** | **25** | |

### Priority Recommendations

1. **Fix the `'maps' in dir()` bug** in `qiling_runner.py` — will cause `NameError` on failure paths.
2. **Add locking to `get_global_data_refs`** or use a separate local CFG — race condition that can silently corrupt shared angr state.
3. **Validate WebSocket scopes** in `BearerAuthMiddleware` — authentication gap for HTTP transport mode.
4. **Add a lock around `pe_data` mutations** during file loading — concurrent readers can see partial state.
5. **Close PE objects on error paths** in `open_file` — resource leak.
6. **Gradually expand test coverage** — target 80% and add edge-case tests for security boundaries.

### Overall Assessment

PeMCP is a well-engineered, feature-rich binary analysis platform. The 113-tool MCP interface, multi-format support, and Docker-first deployment model are substantial achievements. The architecture handles significant complexity (20+ optional libraries, incompatible dependency versions, concurrent multi-session access) with clean patterns. The critical and high issues are targeted concurrency and validation bugs rather than systemic design problems — they should be straightforward to address.
