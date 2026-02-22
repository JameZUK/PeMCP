# PeMCP Project Review

**Date**: 2026-02-22
**Reviewer**: Claude (Opus 4.6)
**Scope**: Full codebase review — architecture, code quality, security, concurrency, testing, documentation, and comparison with prior review (2026-02-21)
**Tests**: 113 passed, 11 skipped (1.03s) on Python 3.11 (unit tests only, no heavy deps)
**Codebase Size**: ~32,600 lines of Python across 80 files

---

## Executive Summary

PeMCP is a ~32,600-line Python toolkit for multi-format binary analysis (PE, ELF, Mach-O, .NET, Go, Rust, shellcode) that operates as both a CLI report generator and an MCP server exposing **184 specialized tools**. Since the last review (2026-02-21), the project has grown substantially — from ~20,400 lines / 113 tools to ~32,600 lines / 184 tools — primarily through the addition of 56 Binary Refinery tools and 7 Qiling emulation tools.

The project demonstrates mature engineering: per-session state isolation via `contextvars`, graceful degradation for 20+ optional libraries, smart MCP response truncation, gzip-compressed disk caching with LRU eviction, Docker-first deployment with venv isolation for incompatible unicorn versions, and bearer token authentication for HTTP mode.

**Key finding**: Most issues from the prior review have been addressed. The project is in strong shape. The remaining items are refinements rather than structural problems.

---

## 1. Architecture & Design: Strong

### Strengths

- **Clean modular separation**: `pemcp/parsers/` (format-specific parsing), `pemcp/mcp/` (184 tools across 33 modules + 4 helper modules), `pemcp/cli/` (output formatting), and core modules (`state.py`, `cache.py`, `config.py`, `auth.py`) have clear responsibilities.
- **Per-session state isolation** (`state.py:302-455`): `StateProxy` + `contextvars` transparently routes attribute access to the correct `AnalyzerState`. Stdio mode collapses to a singleton; HTTP mode creates isolated sessions with TTL-based cleanup (1 hour). The `_inherited_pe_object` flag prevents cross-session resource corruption when sessions share a pre-loaded PE.
- **Graceful dependency degradation** (`config.py`): 20+ optional libraries are probed at startup with individual `*_AVAILABLE` flags. Tools that require unavailable libraries return actionable error messages. Lazy-checking with double-checked locking is used for venv-isolated tools (Speakeasy, Unipacker, Qiling).
- **Smart response truncation** (`server.py:177-294`): MCP responses are auto-truncated to 64KB using an iterative heuristic (up to 5 attempts) that finds the largest element and reduces it proportionally, with a final fallback to string truncation. Deep-copy prevents mutation of shared state.
- **Analysis caching** (`cache.py`): SHA256-keyed, gzip-compressed disk cache with LRU eviction, version-based invalidation (both PeMCP version and cache format version), and mtime/size verification. Cache entries use git-style two-char prefix directories to avoid flat-dir performance issues.
- **Background task management** (`background.py`): Long-running operations (angr CFG) run in daemon threads with progress tracking, heartbeat monitoring across all sessions, and done-callback logging. Session state is properly propagated into worker threads via `set_current_state()`.
- **Dependency isolation**: Docker build uses three separate venvs (`speakeasy-venv`, `unipacker-venv`, `qiling-venv`) to resolve unicorn version conflicts between angr (2.x) and tools requiring unicorn 1.x.
- **Concurrency control**: `asyncio.Semaphore` limits concurrent heavy analyses (`tools_pe.py:46`) to prevent resource exhaustion in multi-tenant HTTP deployments. Configurable via `PEMCP_MAX_CONCURRENT_ANALYSES` env var.
- **Tool history recording**: The `tool_decorator` (`server.py:62-102`) transparently records every tool invocation with parameters, result summary, and duration. Meta-tools are excluded to prevent recursion/noise.

### Observations

1. **`tools_triage.py` is 1,901 lines.** This is the largest tool module by a wide margin. It contains the entire triage report generation — suspicious import database, timestamp analysis, section anomaly detection, ELF/Mach-O security features, risk scoring, and auto-note saving. While internally well-organized with section comments, splitting into focused sub-modules would improve navigability.

2. **`config.py` at 554 lines is overloaded.** It handles library imports/probing, availability flags, constants, lazy-checking functions, exception class definitions, mock MCP classes, AND global state creation. This is a bottleneck for understanding startup behavior. Splitting into `config.py` (constants/flags) and `imports.py` (library probing) would help.

3. **Format detection is centralized in `_format_helpers.py`** (`detect_format_from_magic()`). The previous review noted duplication — this has been partially addressed. The `tools_samples.py` module still has its own lightweight `_detect_format_hint()` function (`tools_samples.py:10-35`), but this is justified since it operates on 4-byte reads for directory listing performance rather than full binary analysis.

---

## 2. Previous Issues — Status

### Fixed since last review (2026-02-21)

| # | Issue | Status |
|---|-------|--------|
| 3.5 | Signify import prints to stderr unconditionally | **Fixed** — `config.py:83-88` now catches non-ImportError exceptions and stores the error string in `SIGNIFY_IMPORT_ERROR` without printing. Uses `logger`-compatible pattern. |
| 3.6 | `safe_regex_search` creates a new ThreadPoolExecutor per call | **Fixed** — `utils.py:15-16` now uses a module-level shared executor (`max_workers=2`) with `atexit` cleanup. |
| Remaining #1 | Unpinned Docker base image | **Fixed** — `Dockerfile:6` now uses `python:3.11-bookworm@sha256:94c2dca...` with digest pinning. Comments explain the update procedure. |
| Remaining #2 | `chmod -R 777` on directories | **Partially addressed** — The review notes mention 775 with a dedicated group (gid 1500). The Dockerfile now creates a `pemcp` group for runtime permissions. |
| Remaining #4 | Ruff lint rules too narrow | **Fixed** — `ci.yml:85` now includes `F841` (unused variables), `W291-W293` (whitespace), `B006-B018` (common bugs), `UP031-UP032` (upgrade suggestions), and `RUF005/RUF010/RUF019` rules. |

### Still remaining from prior reviews

1. **CI coverage threshold (60%) vs actual coverage (~50%)**: The CI enforces `--cov-fail-under=60` but this only passes because CI installs the full dependency set (including pefile, which makes parser modules importable). In the minimal test environment, coverage is likely below 50%.

2. **f-strings in logging calls**: Multiple files still use `logger.warning(f"...")` instead of `logger.warning("...", arg)`. This prevents lazy evaluation of the format string when the log level is disabled. Not a functional bug, but a performance anti-pattern for high-frequency code paths.

3. **`import_project` path traversal** (`tools_export.py:176`): Still uses substring `".." in member.name` rather than `os.path.normpath()` comparison. Functional but could miss edge cases with unusual path encodings.

---

## 3. New Issues Found

### 3.1 [Medium] `_check_pe_loaded` reads state non-atomically

**File:** `pemcp/mcp/server.py:113`

```python
pe_data, filepath = state.pe_data, state.filepath
```

The comment at line 108-112 acknowledges this: "Snapshots both `pe_data` and `filepath` in a single read to avoid a potential (though unlikely) race." However, this is still two separate `__getattr__` calls through the `StateProxy`, each independently resolving the `AnalyzerState` via `contextvars`. In theory, a concurrent `open_file` or `close_file` could reset one between the two reads.

**Impact**: Low — the analysis semaphore makes concurrent modification extremely unlikely. The existing comment shows awareness of the issue.

**Recommendation**: Accept as-is or add a single `get_current_state()` call to read from the resolved state directly.

### 3.2 [Low] Cache metadata is read/written under lock but gzip decompression is not

**File:** `pemcp/cache.py:119-206`

The `get()` method intentionally reads and decompresses the gzip file *outside* the lock (documented in the docstring at line 117-118), then acquires the lock for metadata validation and LRU updates. This is correct and improves concurrency, but there's a narrow window where a concurrent `put()` could overwrite the file between the read and the metadata check.

**Impact**: Minimal — the race would result in a stale cache hit being validated against updated metadata, which would fail the mtime/size check and trigger invalidation (correct behavior).

### 3.3 [Low] `main.py` has a long function with deep nesting

**File:** `pemcp/main.py:66-492`

The `main()` function is 426 lines with up to 5 levels of nesting (argument parsing -> mode detection -> MCP server -> pre-loading -> format detection -> error handling). While comprehensive, this function handles too many concerns: argument parsing, logging configuration, path resolution, FLOSS configuration, file pre-loading, MCP server startup, and CLI mode execution.

**Recommendation**: Extract helper functions for: (1) argument parsing and validation, (2) FLOSS configuration resolution, (3) MCP server startup, (4) CLI mode execution. The pre-loading logic in lines 274-387 duplicates much of what `open_file` does in `tools_pe.py`.

### 3.4 [Info] Tool module sizes vary widely

| Module | Lines | Tools |
|--------|-------|-------|
| `tools_triage.py` | 1,901 | 1 |
| `tools_angr.py` | 1,231 | 16 |
| `tools_refinery.py` | 1,147 | 14 |
| `tools_strings.py` | 1,147 | 11 |
| `tools_angr_forensic.py` | 1,163 | 9 |
| `tools_pe.py` | 1,101 | 7 |
| `tools_pe_extended.py` | 931 | 14 |
| `tools_history.py` | 70 | 2 |
| `tools_cache.py` | 75 | 3 |

The triage module at 1,901 lines for a single tool is the clearest candidate for decomposition. The angr module family shows good modular splitting by concern (core, dataflow, disassembly, hooks, forensic).

### 3.5 [Info] `reanalyze_loaded_pe_file` has an extremely wide parameter list

**File:** `pemcp/mcp/tools_pe.py` (referenced in prior review as issue 3.7)

Still present. The function accepts 25+ parameters for skip flags, FLOSS options, PEiD options, capa options, etc. Consider grouping into a `@dataclass AnalysisConfig` for cleaner signatures. The `dataclass` import is already present in the file (`tools_pe.py:7`).

---

## 4. Security Assessment

### Strengths

1. **Path sandboxing** (`state.py:110-126`): Uses `os.path.realpath()` for symlink resolution. `is_relative_to()` for containment checking. Tests cover symlinks, prefix confusion, traversal, and nested paths.
2. **HTTP mode requires `--allowed-paths`** (`main.py:240-246`): Enforced at startup with `sys.exit(1)` if missing. This is a hard security boundary, not a warning.
3. **Bearer token authentication** (`auth.py`): `hmac.compare_digest()` for constant-time comparison. Handles both HTTP and WebSocket scopes. Clear 401 response with `WWW-Authenticate: Bearer` header.
4. **No `shell=True`** in any subprocess call. Speakeasy, Unipacker, and Qiling runners use explicit argument lists.
5. **No `eval()`/`exec()` on user input.** All `.eval()` calls are angr's `solver.eval()` for symbolic execution.
6. **No pickle deserialization.** Cache uses gzip-compressed JSON exclusively.
7. **ReDoS protection** (`utils.py:44-109`): Two-layer defense — pattern validation (nested quantifier detection, length limit) + execution timeout (5s via `ThreadPoolExecutor`).
8. **Zip-slip protection** in archive import (`tools_export.py:176`).
9. **API key storage** with `0o600` file permissions (`user_config.py`).
10. **Non-root Docker** via `--user "$(id -u):$(id -g)"` with dedicated `pemcp` group (gid 1500).
11. **Docker base image pinned by SHA256 digest** (`Dockerfile:6`) for reproducible builds.
12. **Sensitive config masking** (`user_config.py`): Keys containing "api_key", "token", "secret", or "password" are masked in `get_masked_config()` (first 3 + last 3 chars + asterisks).
13. **Analysis semaphore** (`tools_pe.py:46`): Prevents resource exhaustion from concurrent heavy analyses in HTTP mode.
14. **Regex pattern validation** runs before any processing (`main.py:182-187`, `utils.py:52-74`).

### Observations

1. **`PEMCP_API_KEY` is a warning, not mandatory, for HTTP mode** (`main.py:255-259`): Running HTTP without authentication allows any network client to use all 184 tools. The warning is clear, but consider making this mandatory or at minimum logging a more prominent security notice.

2. **`list_samples` returns full filesystem paths** (`tools_samples.py`): This could leak server directory structure to MCP clients. Consider returning relative paths from the samples root.

3. **`import_project` extraction directory** (`tools_export.py`): Writes to `~/.pemcp/imported/` without checking `allowed_paths`. In HTTP mode, a malicious client could use this to write files outside the sandbox. The tar member validation mitigates path traversal, but the destination itself is not sandboxed.

4. **subprocess timeouts for venv tools**: Speakeasy runner, Unipacker runner, and Qiling runner all use subprocess calls with timeouts. The Qiling runner timeout is 120s (`tools_qiling.py`). Ensure these are appropriate for the expected workloads.

---

## 5. Code Quality

### Strengths

1. **Consistent tool registration pattern**: Every MCP tool uses `@tool_decorator` which handles session activation, history recording, and last-active timestamp updates. This is a clean decorator pattern that ensures all cross-cutting concerns are handled uniformly.

2. **Thread-safe state management** (`state.py`): Separate locks for PE object (`_pe_lock`), angr state (`_angr_lock`), background tasks (`_task_lock`), notes (`_notes_lock`), and tool history (`_history_lock`). No nested locking, which eliminates deadlock risk.

3. **Actionable error messages**: `_check_pe_loaded()`, `_check_angr_ready()`, and `_check_data_key_available()` provide specific, actionable guidance. E.g., when angr is still loading, the error includes current progress percentage and a suggestion to use `check_task_status()`.

4. **Defensive data access**: `_build_quick_indicators()` (`tools_pe.py:52-112`) uses `isinstance()` checks on every data access, handling cases where PE data structures may be malformed or unexpected types.

5. **Background task lifecycle**: Clean creation -> progress updates -> completion/failure pattern. Eviction of old completed tasks prevents unbounded growth (`state.py:132-147`, max 50 completed tasks retained).

6. **Tool history bounded**: `MAX_TOOL_HISTORY = 500` with FIFO eviction (`state.py:234-235`).

7. **Notes system**: Clean CRUD with thread-safe accessors, timestamp tracking, and category-based filtering. Counter-based IDs prevent collisions.

### Areas for improvement

1. **`main.py:main()` is 426 lines**: This single function handles argument parsing, logging setup, path resolution, FLOSS configuration, file pre-loading (for 4 different format modes), MCP server startup (with auth middleware), and CLI mode. This should be decomposed.

2. **Some tool modules import at module level conditionally** (`tools_triage.py:20-27`): `if PYELFTOOLS_AVAILABLE: from elftools...`. This is necessary for optional dependencies but makes the import graph harder to trace. The pattern is consistent, which is good.

3. **Magic numbers in triage scoring**: `tools_triage.py` contains numerous hardcoded threshold values (entropy > 7.0, import count < 10, etc.) embedded in the scoring logic. These could be extracted as named constants for clarity and tuning.

---

## 6. Test Coverage

### Test Inventory

| Test File | Lines | Focus |
|-----------|-------|-------|
| `test_review_fixes.py` | 872 | Integration tests for 12+ bug fix iterations |
| `test_streamline.py` | 409 | Analysis tools, phase detection, string categorization |
| `test_state.py` | 321 | Session management, path sandboxing, angr state |
| `test_utils.py` | 283 | Utility functions (entropy, timestamps) |
| `test_parametrized.py` | 265 | Parametrized edge cases |
| `test_parsers_strings.py` | 258 | String extraction and analysis |
| `test_concurrency.py` | 213 | Thread safety, concurrent access |
| `test_cache.py` | 210 | Disk-based analysis caching |
| `test_truncation.py` | 195 | MCP response size checking |
| `test_user_config.py` | 187 | Persistent config management |
| `test_triage_helpers.py` | 165 | Triage helper functions |
| `test_mcp_helpers.py` | 159 | MCP server validation functions |
| `test_format_detect.py` | 125 | Binary format detection |
| `test_hashing.py` | 124 | SSDeep fuzzy hashing |
| `test_auth.py` | 114 | Bearer token authentication |
| `test_rust_tools.py` | 96 | Rust binary analysis |
| `test_mock.py` | 68 | MockPE class |
| `test_go_tools.py` | 61 | Go binary analysis |
| **Total** | **4,125** | **18 test files** |

### Results: 113 passed, 11 skipped

All tests pass. The 11 skips are due to optional dependencies not installed in the test environment (pefile not available for some parametrized tests).

### Coverage Assessment

| Module | Coverage | Notes |
|--------|----------|-------|
| `auth.py` | ~90% | WebSocket close path untested |
| `user_config.py` | ~96% | Excellent |
| `hashing.py` | ~86% | Good |
| `cache.py` | ~65% | Core paths covered; concurrent get/put, session data update less covered |
| `state.py` | ~70% | Basic ops well covered; `close_pe` edge cases less so |
| `mock.py` | ~100% | Complete |
| `utils.py` | ~60% | `validate_regex_pattern`, `safe_regex_search`, `shannon_entropy` now tested |
| `parsers/strings.py` | ~40% | String extraction covered; sifting less so |
| `config.py` | ~30% | Import probing runs at import time; lazy checks untested |
| `background.py` | ~0% | Background worker requires angr; hard to unit test |
| `mcp/*.py` (tool modules) | ~0% | Covered by integration tests (`mcp_test_client.py`) only |

**Overall estimated coverage**: ~50% (unit tests only). CI reports higher because it installs full dependencies.

### Test Quality Highlights

1. **Parametrized edge cases** (`test_parametrized.py`): 50+ variations covering timestamp boundaries, entropy thresholds, empty inputs, and Unicode handling.
2. **Concurrent safety** (`test_concurrency.py`): 7+ threaded scenarios testing thread-isolated sessions, concurrent task updates, concurrent angr state access, and path sandbox checks in parallel.
3. **Bug fix regression tests** (`test_review_fixes.py`): 872 lines covering 12+ iterations of specific bug fixes. This is excellent engineering practice — every fix gets a test.
4. **Cache corruption handling** (`test_cache.py`): Tests corrupt gzip entries, version mismatches, and eviction behavior.

### Recommendations

1. **Add integration test for `import_project` path traversal**: The zip-slip protection should have explicit test coverage with crafted tar entries containing `../` sequences.
2. **Add test for `BearerAuthMiddleware` WebSocket rejection**: The 4003 close code path is currently untested.
3. **Add test for `_check_mcp_response_size` with deeply nested structures**: The truncation logic handles 5 iterations; test that it converges.
4. **Gradually raise CI coverage threshold to 65%**: Achievable with current tests under full deps; prevents regression.

---

## 7. CI/CD Pipeline

### GitHub Actions (`ci.yml`)

**Unit Tests Job:**
- Matrix: Python 3.10, 3.11, 3.12 on Ubuntu latest
- Coverage enforcement: 60% minimum
- Coverage artifact upload (Python 3.11 only)

**Lint Job:**
- Python syntax check (all `.py` files in `pemcp/` and `tests/`)
- Ruff with comprehensive rule selection: `E9,F63,F7,F82,F841,W291-W293,B006-B018,UP031-UP032,RUF005,RUF010,RUF019,G010`

### Observations

1. **No Docker build verification in CI**: The Dockerfile is complex (multi-stage, 3 isolated venvs, optional dependency installation). A build step — even without running the container — would catch broken apt packages, pip resolution failures, and missing scripts.

2. **No security scanning**: Consider adding `bandit` for Python security linting and/or `safety` for known-vulnerability dependency checking.

3. **No type checking**: The codebase uses type annotations extensively but `mypy` or `pyright` is not run in CI. This would catch type errors in the 18,500-line MCP tool layer.

4. **Integration tests not in CI**: The `mcp_test_client.py` (109,240 lines — likely the largest file in the project) runs 184 tool tests against a running server. This isn't practical for CI without Docker, but a smoke test subset could be valuable.

---

## 8. Documentation: Excellent

### README.md (~1,130 lines)

- **Comprehensive tool reference**: All 184 tools documented with descriptions organized by category (File Management, PE Structure, Strings, Angr Core/Extended, Qiling, Refinery, etc.)
- **Multiple installation paths**: Docker (with `run.sh` helper), Docker Compose, local pip, minimal installation
- **Claude Code integration**: Both CLI (`claude mcp add`) and JSON configuration methods documented
- **Typical Workflow**: 11-step guided workflow for AI clients
- **AI-Optimised Analysis**: Progressive disclosure tools with recommended workflow
- **Session Persistence & Notes**: Comprehensive documentation of the note system, auto-note behavior, and cross-session restoration
- **Security section**: Path sandboxing, authentication, Docker non-root, zip-slip protection

### Supporting Documentation

- **TESTING.md** (17,911 bytes): Detailed testing guide covering unit tests, integration tests, environment variables, markers, and troubleshooting
- **DEPENDENCIES.md** (15,788 bytes): Dependency documentation
- **FastPrompt.txt** (8,385 bytes): AI analysis strategy guide
- **docs/QILING_ROOTFS.md**: Qiling rootfs setup instructions

### Observation

- The `mcp_test_client.py` at 109,240 lines is unusually large. It appears to be a comprehensive integration test suite. Consider whether this could be split into per-category test files mirroring the tool module structure.

---

## 9. Docker Configuration

### Strengths

1. **Base image pinned by SHA256 digest** (`Dockerfile:6`): Prevents supply-chain issues from unpinned tags.
2. **Multi-layer dependency caching**: Heavy deps (angr, FLOSS, capa) are installed in early layers for build cache efficiency.
3. **Three isolated venvs**: `speakeasy-venv`, `unipacker-venv`, `qiling-venv` each with unicorn 1.x, keeping the main environment's unicorn 2.x intact for angr.
4. **Pre-populated resources**: Capa rules (v9.3.0) and Qiling rootfs are downloaded at build time, avoiding runtime delays.
5. **Non-root runtime**: `--user "$(id -u):$(id -g)"` with dedicated `pemcp` group (gid 1500) for file permissions.
6. **Health check**: HTTP mode includes a health check on port 8082.
7. **`run.sh` helper** (11,144 bytes): Comprehensive shell script with auto-detection of Docker/Podman, SELinux support, custom volume mounts, and `.env` file loading.

### Docker Compose

Two services defined:
- `pemcp-http`: Network-accessible MCP server with healthcheck and restart policy
- `pemcp-stdio`: For Claude Code / MCP client integration (behind the `stdio` profile)

Both services use a named `pemcp-data` volume for persistent cache and configuration.

---

## 10. Summary

| Category | Rating | Change vs Prior | Key Observations |
|----------|--------|-----------------|------------------|
| **Architecture** | Strong | Stable | Clean modular design, smart caching, graceful degradation. Now 184 tools across 33 modules. |
| **Security** | Good | Improved | Docker image pinned, group permissions, shared regex executor fixed. HTTP auth still optional. |
| **Code Quality** | Good | Stable | Consistent patterns, thread-safe state, actionable errors. `main.py` and `tools_triage.py` remain long. |
| **Testing** | Good | Improved | 18 test files, 4,125 lines, 113 passing. Prior `utils.py` gap partially addressed. Bug fix regression tests are excellent. |
| **Documentation** | Excellent | Stable | ~1,130-line README, comprehensive tool reference, AI workflow guide, testing docs. |
| **CI/CD** | Adequate | Improved | Ruff rules expanded. Still lacks Docker build verification, security scanning, and type checking. |
| **Docker** | Strong | Improved | Base image pinned, group permissions, 3 isolated venvs, pre-populated resources. |

### Priority Improvements (ranked)

1. **Decompose `main.py:main()`** — 426 lines handling 6+ concerns. Extract into focused helpers.
2. **Split `tools_triage.py`** — 1,901 lines for a single tool. Break into sub-modules by analysis dimension.
3. **Add Docker build to CI** — Catch Dockerfile regressions before merge.
4. **Make HTTP auth mandatory** (or require explicit `--no-auth` opt-out) to prevent accidental exposure.
5. **Add `mypy` or `pyright` to CI** — The codebase uses type annotations extensively; validate them.
6. **Strengthen `import_project` path validation** — Use `os.path.normpath()` and ensure extraction respects `allowed_paths`.
7. **Raise CI coverage threshold to 65%** — Achievable with current tests under full deps; prevents regression.

### Overall Assessment

PeMCP is a **mature, production-quality** binary analysis platform. The 184-tool MCP interface, multi-format support, session isolation, and Docker-first deployment model are substantial achievements. The codebase handles significant complexity (20+ optional libraries, incompatible dependency versions, concurrent multi-session access, 7 different binary format modes) with clean, well-documented patterns.

The growth from 113 to 184 tools (primarily Binary Refinery and Qiling) has been well-managed — the new modules follow established patterns and are properly organized. The core architecture has scaled without degradation.

Most issues from the prior review have been addressed (Docker pinning, signify import, regex executor, ruff rules). The remaining items are targeted refinements: decomposing large files, strengthening CI, and tightening HTTP security defaults. No critical or blocking issues were found.
