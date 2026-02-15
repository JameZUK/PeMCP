# PeMCP Project Review — Iteration 8

**Date:** 2026-02-15
**Reviewer:** Claude (Opus 4.6)
**Scope:** Full project review — architecture, code quality, security, testing, documentation
**Codebase:** ~30,000 lines Python, 105 MCP tools, 276 unit tests

---

## Executive Summary

PeMCP is a well-architected binary analysis platform that exposes 105 specialized tools via the Model Context Protocol. The project demonstrates strong engineering fundamentals: modular design, graceful degradation across 20+ optional dependencies, thread-safe state management, disk-based caching, and comprehensive Docker support. All 276 unit tests pass (273 passed, 3 skipped).

This review identifies **3 functional bugs** in the triage report, **1 critical security gap** in HTTP mode, and several medium-severity code quality issues. The most impactful finding is that the triage report's packing detection and section anomaly analysis are silently broken due to key name mismatches between the parser and triage modules.

---

## 1. Architecture Assessment

### Strengths

1. **Clean separation of concerns** — Parsers (`pemcp/parsers/`), MCP tool wrappers (`pemcp/mcp/tools_*.py`), state management (`state.py`), and caching (`cache.py`) are properly separated. Adding a new analysis domain requires only a new tool file and an import.

2. **Per-session state isolation** — The `StateProxy` + `contextvars` pattern provides transparent session isolation in HTTP mode without modifying any of the 105 tool implementations. Session TTL cleanup (1 hour) prevents memory leaks.

3. **Graceful degradation** — Each of 20+ optional libraries is guarded by `try/except` at import time with `*_AVAILABLE` flags. Tools return clear error messages when a library is absent. This is the correct approach for a toolkit with heavy platform-sensitive dependencies.

4. **Production-quality caching** — `cache.py` implements disk-based caching with SHA256 keys, gzip compression (~12x reduction), LRU eviction (default 500MB), version-based invalidation, and atomic writes via temp-then-rename.

5. **Background task management** — Long-running operations (angr CFG, symbolic execution) run asynchronously with heartbeat monitoring and progress tracking.

6. **Docker-first design** — Multi-stage Dockerfile, Compose services for both HTTP and stdio, a `run.sh` helper script with Docker/Podman autodetection, and a healthcheck endpoint.

### Areas for Improvement

1. **File sizes** — Several files are extremely large. `parsers/pe.py` (45,241 lines from exploration, ~1,001 source lines based on coverage), `tools_triage.py` (~1,639 lines), and `tools_angr.py` (~1,060 lines) could benefit from further decomposition.

2. **No packaging metadata** — There is no `pyproject.toml` or `setup.py`. The project is run directly via `python PeMCP.py`. Adding proper packaging would enable `pip install -e .` for development and simplify distribution.

3. **Import-time side effects in `config.py`** — This 467-line module executes 20+ `try/except ImportError` blocks, instantiates global state, and calls `sys.exit(1)` if pefile is missing — all at import time. This makes testing modules that depend on `config.py` difficult and kills test runners in environments without pefile.

---

## 2. Functional Bugs

### 2.1 [HIGH] Triage Report: PEiD Packer Detection Always Returns Empty

**File:** `pemcp/mcp/tools_triage.py:254`

The triage report's `_triage_packing_assessment` function expects PEiD matches to be dicts:

```python
packer_names = [m.get('name', m.get('match', 'unknown'))
                for m in (ep_matches + heuristic_matches) if isinstance(m, dict)]
```

But the PEiD scanner in `parsers/pe.py` stores matches as plain strings:

```python
peid_results["ep_matches"].append(match_name)  # match_name is a string
```

The `isinstance(m, dict)` filter silently excludes all real PEiD matches, making packer detection in the triage report non-functional.

**Fix:** Change the list comprehension to handle both strings and dicts, or update the parser to emit dicts.

### 2.2 [HIGH] Triage Report: Section Anomaly Detection Uses Wrong Key Names

**File:** `pemcp/mcp/tools_triage.py:512-516`

The triage code reads section data using keys `'name'`, `'characteristics_str'`, `'virtual_size'`, and `'raw_size'`:

```python
name = sec.get('name', '').strip()
chars = str(sec.get('characteristics_str', sec.get('characteristics', '')))
vsize = sec.get('virtual_size', sec.get('Misc_VirtualSize', 0))
rsize = sec.get('raw_size', sec.get('SizeOfRawData', 0))
```

But the PE parser stores `'name_str'` (not `'name'`) and `'characteristics_list'` (not `'characteristics_str'`). All lookups fall through to defaults, meaning section anomalies (writable+executable, zero-size, high-entropy) are never detected.

**Fix:** Update the triage code to use the actual key names from the parser output (`name_str`, `characteristics_list`, etc.), or add compatibility aliases in the parser.

### 2.3 [HIGH] Triage Report: Packer Section Name Detection Uses Wrong Key

**File:** `pemcp/mcp/tools_triage.py:263-264`

Same root cause as 2.2 — uses `sec.get('name')` instead of `sec.get('name_str')`, so known packer section names like `UPX0`, `.aspack`, `.nsp0` are never matched.

---

## 3. Security Findings

### 3.1 [CRITICAL] No Authentication on HTTP Transport

**File:** `pemcp/main.py:354-365`

When running with `--mcp-transport streamable-http`, the server has no authentication, no CORS restrictions, and no rate limiting. Any client that can reach the endpoint can:
- Open and analyze arbitrary files on the server (if `--allowed-paths` is not set)
- Read file metadata, strings, and hashes
- Write files via `save_patched_binary`
- Execute symbolic execution consuming unbounded server resources
- Set/read API keys

The default bind to `127.0.0.1` mitigates remote attacks, but users running with `--mcp-host 0.0.0.0` are fully exposed.

**Recommendation:** Add bearer token authentication. Make `--allowed-paths` mandatory for HTTP mode. Document that TLS termination via reverse proxy is required for production use.

### 3.2 [HIGH] Path Sandboxing Off by Default in HTTP Mode

**File:** `pemcp/main.py:215-222`

HTTP mode without `--allowed-paths` logs a warning but allows full filesystem access. This should be a mandatory flag when using network transports.

### 3.3 [MEDIUM] No Timeout on PE Analysis in `open_file`

**File:** `pemcp/mcp/tools_pe.py:296-337`

The `open_file` PE analysis path runs `_parse_pe_to_dict` in a thread without a timeout. A maliciously crafted PE file could cause pefile, capa, or FLOSS to hang indefinitely. Angr tools properly use `asyncio.wait_for(..., timeout=300)`, but core PE parsing does not.

### 3.4 [MEDIUM] API Key Transmitted in Cleartext Over HTTP

**File:** `pemcp/mcp/tools_config.py:75-111`

The `set_api_key` MCP tool accepts API keys as plaintext parameters. In HTTP mode without TLS, keys are sent in the clear.

### 3.5 [LOW] Cache Directory Permissions Not Explicitly Set

**File:** `pemcp/cache.py:69`

The cache directory (`~/.pemcp/cache/`) is created with default umask permissions rather than explicit `0o700`. Other users on the system could potentially read cached analysis results.

---

## 4. Code Quality Issues

### 4.1 [HIGH] Race Conditions in Angr State Management

**File:** `pemcp/mcp/_angr_helpers.py:62-74`, `pemcp/mcp/tools_angr.py:474-502`

The `_ensure_project_and_cfg()` function uses a check-then-act pattern that is not atomic. Two concurrent tool calls could both see `project is None`, both create separate `angr.Project` instances, and one would silently overwrite the other — duplicating the expensive CFG build.

Additionally, `analyze_binary_loops()` directly sets `state.angr_project` bypassing `state.set_angr_results()` and its lock, creating a data race with concurrent reads via `get_angr_snapshot()`.

### 4.2 [HIGH] Unguarded `import angr` in `patch_with_assembly`

**File:** `pemcp/mcp/tools_new_libs.py:401-402`

```python
from pemcp.config import ANGR_AVAILABLE
import angr  # crashes with ImportError if angr not installed
```

The `import angr` statement is at the top of the function body, before any availability check. If angr is not installed, calling this tool crashes with `ImportError` instead of returning a user-friendly error message. The `ANGR_AVAILABLE` flag is imported but never checked.

### 4.3 [MEDIUM] Per-String Thread Dispatch in Fuzzy Search

**File:** `pemcp/mcp/tools_strings.py:1018`

```python
ratio = await asyncio.to_thread(fuzz.ratio, query_string, target_string)
```

Each string comparison creates a new thread pool task. For thousands of strings, this creates thousands of submissions. Since `fuzz.ratio` is microsecond-level CPU-bound work, the thread scheduling overhead dominates. This should batch all comparisons into a single `to_thread` call.

### 4.4 [MEDIUM] Double JSON Serialization for Size Check

**File:** `pemcp/mcp/server.py:119-198`

Every MCP tool response is serialized to JSON to check its size against the 64KB limit, then the framework serializes it again for transport. For oversized responses, the truncation loop may re-serialize up to 5 additional times. Combined with a `copy.deepcopy` on large responses, this creates significant overhead on the hot path.

### 4.5 [MEDIUM] Unhandled `ValueError` in String VA Parsing

**File:** `pemcp/mcp/tools_strings.py:890-895`

```python
elif 'function_va' in item and int(item.get('function_va', '0x0'), 16) == function_va:
```

If `function_va` contains a non-hex string, `int(..., 16)` raises `ValueError` and crashes the entire tool call. Each `int()` call in this loop should be wrapped in `try/except`.

### 4.6 [MEDIUM] Inconsistent Address Parsing in `tools_new_libs.py`

**File:** `pemcp/mcp/tools_new_libs.py:272, 346`

Uses `int(base_address, 16)` which fails on decimal strings like `"4096"`. The `_parse_addr` helper in `_angr_helpers.py` correctly uses `int(x, 0)` to handle both hex and decimal formats. These tools should use the same approach.

### 4.7 [LOW] Unused Imports

- `pemcp/mcp/tools_triage.py:3` — `import mmap` (unused)
- `pemcp/mcp/tools_new_libs.py:4` — `import struct` (unused)

### 4.8 [LOW] Duplicated Architecture Mapping Dicts

**File:** `pemcp/mcp/tools_new_libs.py`

The `ARCH_MAP` dictionary mapping architecture names to Capstone/Keystone constants is defined independently in three functions: `disassemble_raw_bytes()`, `assemble_instruction()`, and `patch_with_assembly()`. Each copy is slightly different. This should be a shared module-level constant.

---

## 5. Testing Assessment

### Unit Tests

- **276 tests collected, 273 passed, 3 skipped** — All tests pass cleanly
- **Coverage:** 10% overall (many MCP tool modules have 0% coverage because they require a running server and sample binaries)
- **Well-tested core modules:** `cache.py` (80%), `hashing.py` (85%), `state.py` (83%), `user_config.py` (96%), `mock.py` (100%)
- **Parametrized edge-case tests** (`test_parametrized.py`) covering 95+ scenarios is excellent
- **Concurrency tests** (`test_concurrency.py`) verify thread isolation and concurrent state updates

### Integration Tests

- **`mcp_test_client.py`** (2,409 lines) covers all 105 MCP tools across 19 categories
- Requires a running MCP server and sample binaries — appropriate for integration testing

### Gaps

1. **Coverage floor enforcement** — CI enforces 60% but actual overall coverage is ~10%. The 60% threshold likely only applies to the modules that can be tested without the server. Consider splitting coverage targets by module tier.

2. **No integration test in CI** — The CI pipeline only runs unit tests. Consider adding a lightweight integration test with a small sample binary.

3. **Lint job is minimal** — The `lint` job in CI only does `py_compile` on 6 specific files. No type checking (mypy), no linting (ruff/flake8), no import sorting. This misses the unused imports and type issues found in this review.

---

## 6. Documentation Assessment

### Strengths

1. **Comprehensive README** (943 lines) covering installation, all 105 tools, usage examples, Docker setup, and configuration
2. **Dedicated TESTING.md** (431 lines) with clear instructions for running both unit and integration tests
3. **DEPENDENCIES.md** (308 lines) documenting all dependencies with version requirements and purposes
4. **Previous review reports** in `reports/` showing iterative improvement history

### Gaps

1. **No API documentation** — The 105 MCP tools lack a generated API reference. Tool descriptions are embedded in docstrings but not extracted into docs.
2. **No architecture diagram** — The modular structure is well-organized but undocumented visually. A diagram showing the data flow (MCP client -> server -> tool -> parser -> state) would help new contributors.
3. **No CHANGELOG** — Version history is tracked via git but there's no structured changelog.
4. **HTTP security warnings could be stronger** — The README mentions `--allowed-paths` but doesn't emphasize that HTTP mode without authentication is insecure.

---

## 7. CI/CD Assessment

### Current Setup

- GitHub Actions with Python 3.10/3.11/3.12 matrix
- Unit tests with coverage enforcement (60% floor)
- Syntax checking on 6 core modules
- Coverage artifact upload on Python 3.11

### Recommendations

1. **Add a proper linter** — `ruff` would catch unused imports, unreachable code, and common bugs with near-zero configuration
2. **Add type checking** — `mypy` in strict mode on core modules would catch the `None` vs `bool` issues and type mismatches
3. **Expand lint scope** — Currently only compiles 6 of 48 source files. At minimum, compile all files under `pemcp/`
4. **Pin CI action versions** — Using `actions/checkout@v4` is good, but consider pinning to exact SHA for supply chain security

---

## 8. Summary of Findings by Priority

| Priority | Count | Key Issues |
|----------|-------|------------|
| **CRITICAL** | 1 | No authentication on HTTP transport |
| **HIGH** | 5 | Triage packer detection broken (3 findings), angr race conditions, unguarded `import angr` |
| **MEDIUM** | 6 | No PE analysis timeout, cleartext API keys, fuzzy search performance, double serialization, ValueError risk, inconsistent address parsing |
| **LOW** | 4 | Cache permissions, unused imports, duplicated arch maps, lint gaps |

### Recommended Priority Order

1. **Fix triage report key mismatches** (items 2.1, 2.2, 2.3) — These are functional bugs where core analysis is silently producing empty results
2. **Add HTTP authentication** (item 3.1) — Critical for any network-exposed deployment
3. **Guard angr imports** (item 4.2) — Crashes instead of graceful error
4. **Add analysis timeout** (item 3.3) — Defense against malicious binaries
5. **Fix angr race conditions** (item 4.1) — Risk of duplicate expensive work
6. **Add ruff to CI** — Catches many issues automatically with minimal effort
