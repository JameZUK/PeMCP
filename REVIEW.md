# PeMCP Project Review

## Overview

PeMCP is a comprehensive multi-format binary analysis toolkit written in Python (~14.5K LOC). It provides two operational modes: a CLI mode for generating full analysis reports, and an MCP (Model Context Protocol) server mode exposing 104+ tools for interactive binary exploration by AI agents. The project integrates numerous binary analysis libraries including pefile, angr, FLOSS, capa, YARA, LIEF, Capstone, Keystone, Speakeasy, and StringSifter.

**Reviewed structure:** `pemcp/` package (12 modules across `pemcp/`, `pemcp/parsers/`, `pemcp/cli/`, `pemcp/mcp/`), `mcp_test_client.py`, `Dockerfile`, `docker-compose.yml`, `run.sh`, `requirements.txt`

---

## Architecture & Design

### Strengths

1. **Clean modular structure**: The codebase is well-organized into a proper Python package:
   - `pemcp/config.py` — Central imports and availability flags
   - `pemcp/state.py` — Thread-safe `AnalyzerState` with locking
   - `pemcp/cache.py` — Disk-based analysis cache with gzip compression and LRU eviction
   - `pemcp/parsers/` — PE, FLOSS, capa, signatures, strings parsers
   - `pemcp/cli/` — CLI output formatting
   - `pemcp/mcp/` — MCP server and 8 tool modules

2. **Graceful degradation model**: 30+ optional libraries detected at startup with availability flags. Tools return clear error messages when dependencies are missing rather than crashing.

3. **Thread-safe state management**: `AnalyzerState` uses `threading.Lock` for background task access (`_task_lock`). Task operations (`get_task`, `set_task`, `update_task`) are properly synchronized.

4. **Smart response size management**: The `_check_mcp_response_size()` function implements intelligent truncation with a 64KB limit, using iterative heuristics to shrink responses rather than hard-failing.

5. **Analysis caching**: Results cached to `~/.pemcp/cache/` as gzip-compressed JSON (~12x compression), keyed by SHA256. LRU eviction, version-aware invalidation, and 2-char prefix directory layout (git-style sharding).

6. **Path sandboxing**: The `--allowed-paths` option restricts `open_file` to specified directories, providing security for HTTP-mode deployments.

7. **Docker/Podman support**: Docker Compose for standard deployments and a `run.sh` helper script that auto-detects Docker vs Podman for quick usage.

8. **Multi-format binary support**: Auto-detects PE, ELF, Mach-O from magic bytes, plus shellcode mode — all sharing common infrastructure.

### Areas for Improvement

1. **No `pyproject.toml`**: The project can't be installed with `pip install -e .`. A modern `pyproject.toml` would improve the development workflow.

2. **No version pinning**: Dependencies in `requirements.txt` are unpinned, making builds non-reproducible. Consider a constraints file or lock file.

3. **Pure-Python SSDeep implementation**: The `hashing.py` module contains ~229 lines of reimplemented ssdeep. The project already depends on `ppdeep` — this module serves as a fallback but could be simplified.

---

## Code Quality

### Fixed Issues (Previously Identified)

These issues from the original review have been resolved:

- **Variable shadowing in `find_path_to_address`**: Fixed — uses `entry_st` instead of `state` (`tools_angr.py:281`)
- **Mutable default `args_hex: List[str] = []`**: Fixed — now `Optional[List[str]] = None` (`tools_angr.py:363`)
- **Bare `except:` clauses**: All replaced with `except Exception:` throughout
- **Monolithic single-file architecture**: Fully refactored into a proper package structure
- **No non-root Docker user**: Added `pemcp:pemcp` user (uid 1000)
- **Missing files in Docker image**: `userdb.txt` and `FastPrompt.txt` now copied
- **Docker healthcheck**: Added for HTTP mode
- **Zip-slip vulnerability**: Fixed with path traversal validation in `resources.py`
- **Test server URL hardcoded**: Now configurable via `PEMCP_TEST_SERVER_URL` env var
- **Duplicate angr worker code**: Consolidated into single `angr_background_worker()` in `background.py`
- **Dead code in `parsers/floss.py`**: Removed `perform_floss_analysis()` (unreachable, referenced undefined `args`)
- **Regex matching bug in FLOSS**: Fixed `all_strings_with_context` (undefined variable) to `all_found_strings`
- **Naive `datetime.now()`**: All task timestamps now use `datetime.timezone.utc`
- **Silent exception swallowing**: Key `except Exception: pass` blocks now use `logger.debug()` for diagnostics

### Remaining Items

1. **Broad `except Exception:` in data parsing**: ~30 instances across MCP tool modules where exceptions are caught broadly. Most are in defensive feature-extraction blocks (acceptable pattern for binary analysis where malformed inputs are common), but some could be narrowed.

2. **Inconsistent error handling**: Some tools raise `RuntimeError`, others return error dictionaries. MCP clients must handle both. A consistent approach would improve the API.

3. **Compressed code blocks**: Some lines in `tools_pe.py` use very dense formatting (`"has_dos_header":'dos_header'in state.pe_data and...`) which impacts readability.

---

## Security

1. **API key handling**: VT_API_KEY via environment variable or `~/.pemcp/config.json` (0o600 permissions). No hardcoded secrets.

2. **Path sandboxing**: `--allowed-paths` restricts file access in HTTP mode. Warning logged when running network transport without it.

3. **Zip extraction**: Zip-slip protection validates member paths before extraction.

4. **Non-root Docker**: Container runs as `pemcp` user (uid 1000).

5. **HTTP downloads**: PEiD database and capa rules downloaded over HTTPS but without hash verification. Low practical risk (hardcoded GitHub URLs) but defense-in-depth would benefit from checksums.

---

## Dockerfile

- **Base**: Python 3.11 on Debian Bookworm (stable, OpenSSL 3.x compatible)
- **Layer caching**: Heavy deps (angr, FLOSS, capa) in separate layer from core deps
- **oscrypto patch**: Pinned to specific commit for OpenSSL 3.x compatibility — fragile if commit disappears
- **Best-effort installs**: Complex deps (speakeasy, unipacker) installed with `|| true` fallback
- **`.dockerignore`**: Excludes `.git`, docs, tests, IDE files from build context
- **Docker Compose**: HTTP and stdio service profiles with named volumes
- **`run.sh` helper**: Auto-detects Docker/Podman, handles builds and common run patterns

---

## Test Suite

### Strengths

- Good integration test coverage of MCP tool surface area
- Robust helper function `call_tool_and_assert_success()` with JSON/text handling
- Error-path testing via `call_tool_and_expect_server_error_in_result()`
- Configurable server URL via `PEMCP_TEST_SERVER_URL` environment variable
- Test dependencies documented in `requirements-test.txt`

### Areas for Improvement

1. **No unit tests**: All tests are integration tests requiring a running server. Core parsing, hashing, and utility functions have no unit test coverage.
2. **No angr tool tests**: The 36 angr-based tools have zero test coverage.
3. **No multi-format tests**: ELF, Mach-O, .NET, Go, and Rust analysis tools are untested.
4. **No CI pipeline**: No GitHub Actions or similar for automated testing.

---

## Summary

PeMCP is a well-architected, feature-rich binary analysis toolkit with a clean modular structure and thoughtful integration patterns for AI agents via MCP. The codebase demonstrates good engineering practices: graceful degradation for optional dependencies, thread-safe state management, disk-based analysis caching, and intelligent response size management. The Docker/Podman tooling provides accessible deployment options. Key areas for further improvement are dependency version pinning, unit test coverage, and a CI pipeline.
