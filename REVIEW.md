# PeMCP Project Review

**Date**: 2026-02-16
**Scope**: Full codebase review — architecture, code quality, security, testing, documentation

---

## Executive Summary

PeMCP is a well-engineered ~14.5K-line Python toolkit for multi-format binary analysis and malware research. It operates as both a CLI report generator and an MCP (Model Context Protocol) server exposing 105 specialized tools for AI assistants. The project demonstrates strong architectural decisions — per-session state isolation, graceful dependency degradation, smart response truncation, and disk-based analysis caching. Several areas warrant attention: regex input validation, test coverage for integration paths, and minor concurrency edge cases.

**Overall Assessment**: Production-quality project with a mature, security-conscious design. The issues identified below are improvements rather than blockers.

---

## 1. Architecture & Design

### Strengths

- **Clean modular separation**: `pemcp/parsers/` (format-specific parsing), `pemcp/mcp/` (105 MCP tools across 22 modules), `pemcp/cli/` (output formatting), and core modules (`state.py`, `cache.py`, `config.py`) are clearly separated by responsibility.
- **Per-session state isolation** (`state.py:274-291`): `StateProxy` + `contextvars` transparently routes attribute access to the correct `AnalyzerState` for each MCP session. Stdio mode collapses to a singleton; HTTP mode creates isolated sessions. This is a strong pattern for concurrent client support.
- **Graceful dependency degradation** (`config.py:58-467`): 20+ optional libraries are detected at startup with individual availability flags. Missing libraries produce clear error messages rather than crashes. This is essential for a tool with this many optional dependencies.
- **Smart response truncation** (`server.py:107-220`): MCP responses are auto-truncated to fit 64KB limits using an iterative heuristic that finds the largest element and reduces it proportionally. This prevents silent failures when tools produce large results.
- **Analysis caching** (`cache.py`): SHA256-keyed, gzip-compressed disk cache with LRU eviction, version-based invalidation, and throttled LRU timestamp updates. Re-opening a previously analyzed file loads in ~10ms instead of 5-30s.
- **Background task management** (`background.py`): Long-running operations (angr CFG, symbolic execution) run asynchronously with progress tracking, heartbeat monitoring, and status polling via MCP tools.

### Observations

- **String-based mode dispatch**: Mode strings (`"pe"`, `"elf"`, `"macho"`, `"shellcode"`) are compared throughout the codebase. An `enum.Enum` would provide IDE autocomplete, prevent typo bugs, and make the valid modes self-documenting. Low severity but would improve maintainability.
- **`config.py` serves dual duty**: It handles both library availability detection and global singleton creation (state, cache). Splitting availability detection into a separate module would reduce the import-time side effects and make testing easier.
- **Fallback classes for FLOSS** (`config.py:158-159`): `DebugLevelFallbackFloss` and `StringTypeFallbackFloss` use inline class attributes rather than proper `Enum` definitions. These work but lose the semantic benefits of enums.

---

## 2. Security

### Strengths

- **Constant-time token comparison** (`auth.py:35`): Uses `hmac.compare_digest()` to prevent timing side-channel attacks on Bearer tokens.
- **Path sandboxing** (`state.py:83-98`): Enforces `--allowed-paths` with `os.path.realpath()` resolution to prevent path traversal. HTTP mode requires explicit `--allowed-paths` configuration.
- **File permission enforcement**: Cache directory created with `mode=0o700` (`cache.py:69`), config files set to `chmod(0o600)` (`user_config.py:58`).
- **Zip extraction validation** (`resources.py:72-77`): Validates that zip members don't escape the target directory (zip-slip prevention).
- **File size limits** (`tools_pe.py:140-147`): Configurable upper bound (default 256MB) prevents memory exhaustion from oversized inputs.
- **Session TTL cleanup** (`state.py:201-237`): Stale sessions auto-evict after 3600 seconds, preventing memory leaks from abandoned HTTP sessions.
- **Concurrency semaphore** (`tools_pe.py:28`): Limits concurrent analyses to prevent resource exhaustion (configurable via `PEMCP_MAX_CONCURRENT_ANALYSES`).

### Issues

1. **Unvalidated regex patterns** — `main.py:94` accepts arbitrary regex via `--regex` without pre-compilation or timeout. This is a ReDoS (Regular Expression Denial of Service) vector. Crafted patterns like `(a+)+b` can cause exponential backtracking. **Recommendation**: Pre-compile with `re.compile()` inside a try/except, and consider applying a timeout to regex operations on untrusted input.

2. **Path check uses `startswith()`** — `state.py:92`:
   ```python
   if resolved == allowed_resolved or resolved.startswith(allowed_resolved + os.sep):
   ```
   While `os.sep` is appended (preventing `/allowed/dir` matching `/allowed/dir_evil`), using `pathlib.Path.is_relative_to()` (Python 3.9+) would be more idiomatic and less error-prone.

3. **No cryptographic verification of downloaded rules** — `resources.py` downloads PEiD signatures, YARA rules, and capa rules from remote URLs without signature verification. In a malware analysis context, a compromised rule set could produce misleading results. **Recommendation**: Consider pinning expected checksums for downloaded rule archives.

4. **API key in environment variables**: `VT_API_KEY` and `PEMCP_API_KEY` can appear in process listings (`/proc/PID/environ`). The `user_config.py` persistent storage mitigates this partially, but documentation should recommend secret management approaches for production deployments.

---

## 3. Error Handling

### Strengths

- **`_safe_parse` pattern** (`parsers/pe.py:42-49`): Wraps individual parser functions and returns error dicts instead of crashing the entire analysis pipeline. A single parser failure doesn't prevent other analyses from completing.
- **Actionable error messages**: MCP tool errors include specific guidance. For example, `_check_pe_loaded()` tells the client to use `open_file`, and `_check_angr_ready()` tells the client to check `startup-angr` task status.
- **Recovery from corrupt cache** (`cache.py:162-164`): Bad gzip or JSON in cache entries triggers automatic removal rather than persistent errors.

### Issues

1. **Broad exception catches**: Several locations catch bare `Exception`:
   - `main.py:355` during pre-loading
   - `background.py:100-102` in task execution
   - `state.py:151` during PE close

   While this prevents server crashes, it can mask programming errors. **Recommendation**: Log the exception type at WARNING level for broad catches, and narrow where practical.

2. **Incomplete cleanup on `open_file` failure** (`tools_pe.py:173-179`): If `open_file` fails after resetting state (line 175-178), the session is left with `pe_data=None` and `filepath=None` but no error record. A subsequent tool call would get a generic "no file loaded" error rather than knowing the last open attempt failed. **Recommendation**: Consider storing a brief error state in `pe_data` on failure.

3. **Resource downloads lack integrity validation** (`resources.py:26-42`): Partial downloads (network interruption mid-transfer) are deleted, but there's no checksum verification of completed downloads. A truncated but valid gzip could pass through.

---

## 4. Code Quality

### Strengths

- **Consistent style**: CamelCase classes, snake_case functions, clear prefixes (`_parse_`, `_check_`, `_safe_parse`). The codebase reads uniformly.
- **Comprehensive docstrings**: Most public functions have Args/Returns documentation. MCP tool docstrings serve double duty as user-facing tool descriptions.
- **Type hints**: Good coverage across function signatures using `typing` module (`Dict`, `List`, `Optional`, `Any`). Class attributes are explicitly typed in `AnalyzerState`.
- **Thread-safety**: State management uses per-resource locks (`_pe_lock`, `_angr_lock`, `_task_lock`) with clean lock scoping. The `_evict_old_tasks()` method is documented to require lock held.

### Observations

- **Deep dict nesting**: `pe_data` is a large nested dict accessed via chains of `.get()` calls. This works but is fragile — a typo in a key name silently returns `None`. `TypedDict` definitions or a dataclass for `pe_data` structure would catch these at type-check time.
- **`_MAX_LIMIT = 100_000`** (`tools_pe.py:23`): This bounds `limit` parameters to prevent excessive memory allocation, which is good. However, individual tools should document this ceiling in their parameter descriptions so MCP clients know the constraint exists.
- **Monolithic `main.py`** (468 lines): The argument parser definition, mode dispatching, and server startup are all in one file. Extracting the argparse setup into a builder function would improve readability.

---

## 5. Testing

### Strengths

- **276 unit tests** across 16 test files, running in ~2 seconds with no external dependencies (no server, no binaries, no heavy libraries required).
- **Good marker system** (`pytest.ini`): Tests are categorized with markers (`no_file`, `pe_file`, `angr`, `optional_lib`, `unit`) for selective execution.
- **Parametrized edge cases** (`test_parametrized.py`): Uses `@pytest.mark.parametrize` for systematic boundary testing.
- **Concurrency testing** (`test_concurrency.py`): Validates thread-safety of state management.
- **CI/CD pipeline** (`.github/workflows/ci.yml`): Runs on Python 3.10/3.11/3.12 with 60% coverage floor enforcement.
- **Integration test suite** (`mcp_test_client.py`): 109KB end-to-end test client covering all 105 tools across 19 categories (requires running server).

### Gaps

1. **Path sandboxing edge cases**: `check_path_allowed()` is tested for basic success/failure, but tests for symbolic links, relative traversal (`../..`), and Unicode path normalization would strengthen confidence in this security boundary.

2. **Malformed binary resilience**: The parsers handle errors via `_safe_parse`, but there are no tests feeding deliberately malformed or adversarial binaries to verify the error-dict fallback actually works for every parser.

3. **Cache concurrency**: `cache.py` uses threading locks and atomic file replacement, but there are no multi-threaded stress tests verifying cache integrity under concurrent reads/writes.

4. **MCP response truncation**: The smart truncation logic (`server.py:107-220`) handles multiple data types and iterates up to 5 times. This deserves dedicated unit tests with oversized dicts, lists, strings, and nested structures.

---

## 6. Documentation

### Strengths

- **Comprehensive README** (~42KB): Covers installation, usage, all 105 tools, Docker deployment, and configuration examples.
- **TESTING.md**: Detailed guide for running unit and integration tests.
- **DEPENDENCIES.md**: Documents the unicorn/speakeasy dependency conflict and its workaround — useful institutional knowledge.
- **`.env.example`** and **`.mcp.json`**: Configuration templates reduce setup friction.

### Gaps

- **Security hardening guide**: No documentation on recommended deployment practices — TLS termination proxy, network isolation, secret management, or least-privilege file system configuration.
- **Architecture overview**: The `StateProxy` delegation pattern, session lifecycle, and cache invalidation strategy are well-implemented but undocumented. A brief architecture document would help new contributors.

---

## 7. Specific Findings

### 7.1 `state.py:92` — Path check improvement

```python
# Current
if resolved == allowed_resolved or resolved.startswith(allowed_resolved + os.sep):

# Recommended (Python 3.9+)
if Path(resolved).is_relative_to(allowed_resolved):
```

`is_relative_to()` is purpose-built for this check and avoids edge cases with string prefix matching.

### 7.2 `cache.py:96` — Atomic write portability

```python
tmp.replace(META_FILE)  # atomic on POSIX
```

The comment correctly notes this is atomic on POSIX. On Windows, `replace()` is not atomic and can fail if the target is locked. Since PeMCP primarily targets Linux/Docker deployments, this is low risk, but worth noting for cross-platform use.

### 7.3 `config.py:158-159` — Fallback class style

```python
class DebugLevelFallbackFloss: NONE, DEFAULT, TRACE, SUPERTRACE = 0, 1, 2, 3
class StringTypeFallbackFloss: STATIC, STACK, TIGHT, DECODED = "static", "stack", "tight", "decoded"
```

These use tuple unpacking into class variables. While functional, `IntEnum` / `StrEnum` (Python 3.11+) would provide proper enum semantics and better IDE support.

### 7.4 `tools_pe.py:162` — Fallback mode for unrecognized formats

When auto-detection fails to match known magic bytes, the code falls back to PE mode:

```python
mode = "pe"  # fallback to PE, pefile will report errors if invalid
```

This is reasonable behavior with an appropriate warning to the client. The warning message at line 163-166 clearly tells the user to specify an explicit mode.

### 7.5 `server.py:30` — Context extraction approach

```python
for arg in list(args) + list(kwargs.values()):
    if isinstance(arg, Context):
```

Iterating over all arguments to find the Context object is pragmatic but fragile if a tool ever receives a non-Context argument that is an instance of Context. Since FastMCP guarantees Context is always passed, this is safe in practice.

### 7.6 Session state inheritance (`state.py:221-228`)

New HTTP sessions inherit pre-loaded file data from `_default_state` via direct attribute copying. This is a shared reference — both the new session and the default state point to the same `pe_object`. The `close_pe()` method at line 148 correctly checks for this:

```python
if self is _default_state or self.pe_object is not _default_state.pe_object:
```

This is a subtle but correctly handled ownership pattern.

---

## 8. Summary of Recommendations

| Priority | Issue | Location | Recommendation |
|----------|-------|----------|----------------|
| **High** | Unvalidated regex input | `main.py:94` | Pre-compile with try/except; add timeout for regex operations |
| **Medium** | Path check uses `startswith()` | `state.py:92` | Use `Path.is_relative_to()` (Python 3.9+) |
| **Medium** | No integrity check on downloaded rules | `resources.py` | Pin expected checksums for rule archives |
| **Medium** | Missing truncation unit tests | `server.py:107-220` | Add parametrized tests for oversized responses |
| **Medium** | Missing path sandboxing edge-case tests | `state.py:83-98` | Add symlink and Unicode path tests |
| **Low** | Broad exception catches | Multiple files | Narrow exception types where practical |
| **Low** | String-based mode dispatch | Multiple files | Consider `enum.Enum` for mode values |
| **Low** | Fallback classes not using Enum | `config.py:158-159` | Use `IntEnum`/`StrEnum` for fallback types |
| **Low** | `open_file` leaves no error state on failure | `tools_pe.py:173-179` | Store error summary in state on failure |
| **Low** | Cache atomic write on Windows | `cache.py:96` | Document POSIX-only atomicity; add Windows note |

---

## 9. Conclusion

PeMCP is a well-structured, security-conscious project that successfully bridges AI assistants and low-level binary analysis. The architecture handles the inherent complexity of 27 dependencies, 105 tools, and multi-format support with clean patterns for isolation, caching, and degradation. The high-priority item (regex validation) should be addressed; the remaining items are quality improvements that would strengthen an already solid codebase.
