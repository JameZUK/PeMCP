# PeMCP Project Review

**Date:** 2026-02-27
**Reviewer:** Claude (Automated Code Review)
**Scope:** Full codebase review — architecture, code quality, security, testing, documentation, deployment

---

## Executive Summary

PeMCP is a **professional-grade binary analysis toolkit** that exposes 171 specialised tools via the Model Context Protocol (MCP), bridging AI reasoning with low-level reverse engineering. The codebase is well-structured, thoughtfully documented, and production-ready for its Docker-first deployment model. The architecture demonstrates mature engineering patterns — per-session state isolation via `contextvars`, graceful degradation for 20+ optional libraries, and an elegant subprocess-venv strategy to resolve incompatible unicorn engine versions across four emulation frameworks.

**Overall Assessment: Strong** — with a handful of targeted improvements that would elevate it further.

---

## 1. Architecture & Design

### Strengths

- **Clean module decomposition.** The 40 MCP tool modules (`pemcp/mcp/tools_*.py`) are organised by domain (PE, ELF, angr, strings, crypto, refinery, etc.), each registering with the FastMCP server via a shared `tool_decorator`. This keeps each file focused and independently testable.

- **Per-session state isolation** (`pemcp/state.py`). The `StateProxy` + `contextvars` pattern transparently supports both single-client stdio mode and multi-tenant HTTP mode without any tool code needing to know the difference. Session TTL cleanup (1 hour) and LRU eviction of completed background tasks (`MAX_COMPLETED_TASKS = 50`) prevent memory leaks in long-running deployments.

- **Background task architecture** (`pemcp/background.py`). Heavy angr analysis runs in daemon threads with a `ProgressBridge` that safely posts async MCP notifications from worker threads via `asyncio.run_coroutine_threadsafe`. The heartbeat system (10s initial delay, 15s intervals) keeps clients informed without flooding fast-completing tools.

- **Unicorn dependency isolation.** The Dockerfile creates three separate venvs (speakeasy, unipacker, qiling) to resolve the incompatible unicorn 1.x vs 2.x requirements — the most technically demanding aspect of the build. Each is invoked via subprocess JSON IPC, cleanly separating the main angr env (unicorn 2.x) from the emulation tools (unicorn 1.x).

- **Response size management.** The 64KB MCP response size guard (`_check_mcp_response_size` in `server.py`) intelligently truncates the largest list/string/dict in a response rather than failing, with up to 5 iterative passes and a final string-fallback safety net. Combined with the universal `offset`/`limit` pagination system (`_input_helpers.py`), this gives AI clients fine-grained control over data volume.

- **Disk cache** (`pemcp/cache.py`). SHA256-keyed, gzip-compressed, git-style 2-char prefix directories. Auto-invalidation on PeMCP version change or file modification. LRU eviction with configurable size limit (default 500MB). Well-designed for the single-process deployment model.

### Areas for Improvement

1. **`config.py` is doing too much (569 lines).** It serves as the central import hub, availability flag registry, constant store, fallback class definitions, and library availability logger. Consider splitting into:
   - `pemcp/imports.py` — optional library probing and availability flags
   - `pemcp/constants.py` — URLs, paths, timeouts, size limits
   - `pemcp/config.py` — just the `state` proxy, cache instance, and `log_library_availability()`

2. **`main.py` argument resolution is monolithic (521 lines).** The single `main()` function handles argument parsing, FLOSS config resolution, path resolution, file pre-loading, angr startup, MCP server launch, and CLI mode — all in one function. Extracting `_resolve_floss_config(args)`, `_preload_file(args, state)`, and `_start_mcp_server(args, state)` would improve readability without changing behaviour.

3. **Shared mutable state via `StateProxy`.** While `StateProxy` is clever, the indirection can make debugging tricky — `state.pe_data` silently resolves to a different `AnalyzerState` depending on the calling context. Consider adding a `__repr__` that includes the session key for debugging, and ensuring all state mutations go through named methods (e.g. `state.set_filepath(path)`) rather than bare attribute assignment, to make the mutation points greppable.

4. **No type stubs or `py.typed` marker.** The codebase uses type hints extensively but doesn't ship a `py.typed` marker or stub files. For a library that could be imported by other tools, this would improve IDE support.

---

## 2. Code Quality

### Strengths

- **Consistent patterns.** Every MCP tool follows the same pattern: `@tool_decorator` → validate inputs → call `_check_pe_loaded`/`_check_angr_ready` → do work → return dict. This consistency makes it easy to audit and add new tools.

- **ReDoS protection** (`pemcp/utils.py`). Regex patterns are validated for nested quantifiers before compilation, and execution uses a thread-pool timeout (5s default). This is a thoughtful defence for a tool that accepts user-supplied regex.

- **Pure-Python SSDeep** (`pemcp/hashing.py`). A complete, dependency-free ssdeep implementation with performance optimisations (list accumulation instead of string concatenation, hash-indexed common substring search). Well-tested.

- **No `TODO`/`FIXME` markers.** The codebase is clean of outstanding work markers.

- **Minimal bare `except: pass` usage.** Only 5 instances across 2 files (`resources.py`, `cli/printers.py`), and those are in non-critical download/print paths.

### Areas for Improvement

1. **`mcp_test_client.py` is 110K lines in a single file.** This integration test client is enormous and lives at the project root rather than in `tests/`. Consider splitting by tool category and moving into `tests/integration/`.

2. **`userdb.txt` (1.5MB) is committed to the repo.** This PEiD signature database is binary data that inflates clone size. Consider downloading it at build time (like the YARA/capa rules) or using Git LFS.

3. **Some tool modules exceed 1,000 lines.** `tools_triage.py` (2,015), `tools_angr_forensic.py` (1,491), `tools_strings.py` (1,440), `tools_angr.py` (1,270). While each is cohesive, the largest could benefit from extracting helper functions into private modules (e.g. `_triage_helpers.py`).

4. **Deprecated `asyncio.get_event_loop()` in tests.** `test_review_fixes.py:24` uses `asyncio.get_event_loop().run_until_complete(coro)` which emits a deprecation warning on Python 3.12+. Replace with `asyncio.run(coro)`.

5. **`run.sh:98` duplicates env var.** `PEMCP_HOST_SAMPLES` is set twice in `common_args()`:
   ```bash
   args+=(-e "PEMCP_HOST_SAMPLES=$SAMPLES_DIR")
   args+=(-e "PEMCP_HOST_SAMPLES=$SAMPLES_DIR")  # duplicate
   ```

---

## 3. Security

### Strengths

- **Path sandboxing** (`AnalyzerState.check_path_allowed`). HTTP-mode MCP servers require `--allowed-paths`, and every file-opening tool validates against the whitelist using resolved real paths (preventing symlink escapes via `os.path.realpath`).

- **API key authentication** (`pemcp/auth.py`). The ASGI `BearerAuthMiddleware` uses `hmac.compare_digest()` for constant-time comparison, preventing timing side-channel attacks. Both HTTP and WebSocket connections are validated.

- **No `os.system()` or `subprocess.call(shell=True)`.** All subprocess invocations use `asyncio.create_subprocess_exec()` with explicit argument lists — no shell injection vectors.

- **Config file permissions.** `save_user_config()` sets `chmod 0o600` on `~/.pemcp/config.json` to protect API keys.

- **HTTP transport requires `--allowed-paths`.** The server refuses to start in network mode without explicit path restrictions — secure by default.

- **Regex validation before compilation.** User-supplied patterns are checked for ReDoS patterns (nested quantifiers) and bounded by length (1,000 chars).

### Areas for Improvement

1. **Download checksum verification is opt-in and currently empty.** `resources.py:24` defines `_EXPECTED_CHECKSUMS = {}` with a comment "Add sha256 hex digests here when known." The YARA rules, capa rules, and PEiD database are all downloaded without integrity verification. For a security tool, pinning checksums for known-good versions of rule sets is important — especially since a compromised YARA rule set could cause false negatives.

2. **Dockerfile downloads from GitHub at build time without pinned commits.** The Qiling rootfs, YARA rules, and capa rules are fetched from `refs/heads/master` or `refs/heads/develop` — floating branches. If these repos are compromised, a Docker rebuild would pull malicious content. Pin to specific commit SHAs or release tags with checksums.

3. **No rate limiting on HTTP endpoints.** The `streamable-http` transport has no request rate limiting. A single client could exhaust server resources by issuing rapid heavy-analysis requests. The `_analysis_semaphore` (default 3) limits concurrent analyses, but doesn't limit queued requests.

4. **VT API key in environment/config.** While the config file is `chmod 0o600`, the API key is also accepted via environment variable (`VT_API_KEY`), which may be visible in `/proc/PID/environ` or Docker inspect output. Consider documenting that secrets should be passed via Docker secrets or bind-mounted files in production.

---

## 4. Testing

### Strengths

- **Solid unit test coverage.** 18 test modules covering state management, caching, concurrency, hashing, authentication, format detection, string parsing, triage helpers, user config, and response truncation. The `test_review_fixes.py` (871 lines) serves as a regression test suite for prior review findings.

- **CI matrix.** GitHub Actions runs on Python 3.10, 3.11, and 3.12 with coverage enforcement at 60%.

- **Lint pipeline.** `ruff` checks for common bugs (F-codes), unused variables (F841), mutable default arguments (B006), and print statement hygiene (G010).

- **Concurrency tests** (`test_concurrency.py`). Tests for thread-safe state access patterns — a critical area given the multi-session HTTP model.

### Areas for Improvement

1. **Coverage exclusions are very broad.** The `.coveragerc` omits all `tools_*.py`, `server.py`, `parsers/*`, `config.py`, `main.py`, `cli/*`, `background.py`, and `resources.py` — essentially everything except `state.py`, `cache.py`, `utils.py`, `hashing.py`, `auth.py`, `user_config.py`, and `mock.py`. While many of these need the Docker environment, consider:
   - Moving pure-logic helper functions out of tool modules into testable helpers
   - Adding mock-based tests for tool modules' input validation and error paths
   - Gradually reducing exclusions as the test suite matures

2. **No integration test in CI.** The 171-tool `mcp_test_client.py` exists but isn't run in CI (it requires the full Docker environment). Consider a lighter smoke test that starts the server in stdio mode with a synthetic PE file and exercises core tools.

3. **Test data.** The `samples/` directory appears empty. Tests rely on synthetic data or source-code inspection rather than real binaries. While this avoids licensing issues, adding a few purpose-built test binaries (compiled from known source) would strengthen parser coverage.

4. **Coverage target of 60% is modest.** For a security tool, 75-80% would be more appropriate. The current exclusions make the 60% threshold easier to meet, but also mean significant code paths are untested in CI.

---

## 5. Documentation

### Strengths

- **Comprehensive README (100KB+).** Covers motivation, key features, 5 real-world analysis scenarios, comparison matrix (vs Ghidra/IDA/pestudio/CyberChef), installation, configuration, MCP tools reference, and architecture. Professional quality.

- **`TESTING.md` (17KB).** Clear guide for running tests locally and understanding the CI pipeline.

- **`DEPENDENCIES.md` (18KB).** Detailed explanation of the unicorn version conflict and the subprocess-venv isolation strategy. Essential reading for maintainers.

- **Inline documentation.** Module docstrings, tool parameter descriptions, and enriched error messages with actionable hints (`_PREREQUISITE_HINTS`, `_ERROR_HINTS` in `server.py`).

### Areas for Improvement

1. **No API/developer documentation.** The README targets end-users (analysts using the MCP tools). A developer guide covering "how to add a new tool module" would lower the barrier for contributors — covering the `@tool_decorator` pattern, the `_check_pe_loaded`/`_check_angr_ready` guards, pagination helpers, and testing expectations.

2. **No changelog.** Given the active development (94+ commits), a `CHANGELOG.md` would help users understand what changed between versions.

3. **README length.** At 100KB+, the README is extremely long. Consider extracting the MCP Tools Reference and Architecture sections into separate docs (e.g. `docs/TOOLS_REFERENCE.md`, `docs/ARCHITECTURE.md`) and linking from the README.

---

## 6. Deployment & Operations

### Strengths

- **Docker-first design.** The `Dockerfile` is well-structured with layer caching for heavy dependencies, pinned base image by SHA256 digest, and build-time verification of unicorn versions. The `run.sh` helper auto-detects Docker/Podman, handles SELinux labelling, and runs as the host UID (not root).

- **Health check.** Both the `Dockerfile` and `docker-compose.yml` include HTTP health checks with appropriate timeouts and retry configuration.

- **Persistent state.** Cache, config, and notes survive container restarts via bind-mounted `~/.pemcp`.

- **Multiple deployment modes.** stdio (Claude Code), streamable-HTTP (network), Docker Compose, and direct Python invocation are all first-class.

### Areas for Improvement

1. **No multi-stage Docker build.** The final image includes build tools (`build-essential`, `cmake`, `libffi-dev`) that aren't needed at runtime. A multi-stage build would reduce image size significantly.

2. **No image size optimisation.** With angr, three isolated venvs, YARA/capa rules, Qiling rootfs, and 20+ Python packages, the image is likely 4-6GB+. Documenting the expected image size and providing a "minimal" Dockerfile (without angr/qiling/speakeasy) for resource-constrained environments would be helpful.

3. **No logging to structured format.** Logs use plain-text formatting (`%(asctime)s - %(levelname)s - %(name)s - %(message)s`). For production deployments, structured JSON logging (e.g. via `python-json-logger`) would improve log aggregation and monitoring.

4. **No graceful shutdown handling.** The MCP server catches `KeyboardInterrupt` but doesn't implement proper SIGTERM handling for container orchestration. In Docker, the default stop signal is SIGTERM; without a handler, the container may be killed after the grace period.

---

## 7. Performance

### Strengths

- **Background analysis.** Angr CFG construction (the heaviest operation) runs in a background thread, allowing the MCP server to respond to lighter queries immediately.

- **LRU caching.** Both the disk cache (`AnalysisCache`) and in-memory result cache (`_ToolResultCache`) prevent redundant computation.

- **Throttled progress reporting.** `ProgressBridge` throttles notifications to 1/second by default, avoiding event-loop flooding.

- **Pagination everywhere.** All list-returning tools support `offset`/`limit` parameters, preventing massive responses that would consume AI context tokens.

### Areas for Improvement

1. **Cache `put()` holds the lock during gzip compression.** For large analyses, gzip compression can take seconds. The `get()` method already performs decompression outside the lock — applying the same pattern to `put()` (compress to a temp buffer, then acquire the lock only for the file write + metadata update) would reduce lock contention.

2. **`_check_mcp_response_size` re-serialises on every truncation iteration.** Each of the 5 truncation passes calls `json.dumps()` and `.encode('utf-8')` to re-measure. For very large responses this is expensive. Consider estimating the reduction rather than re-measuring.

3. **Global `_analysis_semaphore`.** The concurrent analysis limit (`PEMCP_MAX_CONCURRENT_ANALYSES`, default 3) is a global `asyncio.Semaphore`. In multi-session HTTP mode, one user's heavy analysis blocks other users' analyses. A per-session limit or priority queue would be fairer.

---

## Summary of Recommendations

### High Priority
| # | Issue | Location | Recommendation |
|---|-------|----------|----------------|
| 1 | Empty download checksums | `resources.py:24` | Pin SHA256 checksums for YARA/capa/PEiD downloads |
| 2 | Floating branch downloads in Dockerfile | `Dockerfile:118,229,244` | Pin to commit SHAs or release tags |
| 3 | `run.sh` duplicate env var | `run.sh:98` | Remove the duplicate `PEMCP_HOST_SAMPLES` line |

### Medium Priority
| # | Issue | Location | Recommendation |
|---|-------|----------|----------------|
| 4 | `config.py` overloaded | `pemcp/config.py` | Split into imports, constants, and config modules |
| 5 | Deprecated `get_event_loop()` | `tests/test_review_fixes.py:24` | Replace with `asyncio.run()` |
| 6 | Coverage exclusions too broad | `.coveragerc` | Extract testable logic from tool modules |
| 7 | No integration test in CI | `.github/workflows/ci.yml` | Add lightweight stdio smoke test |
| 8 | No SIGTERM handler | `pemcp/main.py` | Add signal handler for graceful shutdown |

### Low Priority
| # | Issue | Location | Recommendation |
|---|-------|----------|----------------|
| 9 | No multi-stage Docker build | `Dockerfile` | Separate build and runtime stages |
| 10 | No changelog | Project root | Add `CHANGELOG.md` |
| 11 | `mcp_test_client.py` at root | Project root | Move to `tests/integration/` |
| 12 | `userdb.txt` in repo | Project root | Download at build time or use Git LFS |
| 13 | No developer guide | `docs/` | Document "how to add a new tool" |

---

## Conclusion

PeMCP is an impressive, well-engineered project that successfully solves a genuinely hard problem — making the full breadth of malware analysis tooling accessible through a single AI-driven interface. The codebase demonstrates mature patterns (session isolation, graceful degradation, background task management, response size control) and professional-quality documentation. The identified issues are refinements rather than fundamental flaws. With the security hardening of download verification and the operational improvements around logging and shutdown handling, this project would be production-ready for enterprise deployment.
