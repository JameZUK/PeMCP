# PeMCP Project Review — Iteration 10

**Date:** 2026-02-16
**Reviewer:** Claude (Opus 4.6)
**Scope:** Full project review — architecture, code quality, security, testing, CI/CD, Docker
**Codebase:** ~14,400 lines Python across 48 files, 105+ MCP tools, 276 unit tests
**Context:** Review after iteration 9 fixes were applied (mode normalization, Rich header keys, auth timing, angr race)

---

## Executive Summary

PeMCP is a well-architected, production-grade binary analysis toolkit that bridges AI assistants with low-level binary instrumentation. The iteration 9 fixes addressed the most critical issues (PE mode mismatch, Rich header bugs, auth timing attack, angr race condition), and the core infrastructure is now solid.

This review identifies **1 unfixed issue from iteration 9**, **3 high-severity new findings** (state corruption on hook failure, silent data loss in dataflow analysis, unsafe dictionary access in string tools), and **9 medium/low findings** spanning input validation, error handling, and subprocess management. Testing remains the project's weakest area — 77% of modules (33/43) have zero unit test coverage.

**Overall assessment:** The project is impressive in scope and architectural quality. The remaining issues are in the "long tail" of tool implementations rather than core infrastructure.

---

## 0. Iteration 9 Fix Verification

| # | Issue | Status |
|---|-------|--------|
| 1.1 | Mode mismatch (`pe_executable` vs `pe`) | **FIXED** — `pe.py:898` now sets `"pe"` |
| 1.2 | Rich header key (`decoded_entries` vs `decoded_values`) | **FIXED** — Fallback chain added |
| 1.3 | Rich header field names (`comp_id` → `raw_comp_id`) | **FIXED** — Fallback chain added |
| 2.1 | Auth timing attack | **FIXED** — Uses `hmac.compare_digest()` |
| 2.3 | Environment variable int parsing unguarded | **NOT FIXED** — 3 locations remain |
| 3.1 | Angr loop race condition | **FIXED** — `_init_lock` added |
| 3.3 | Silent exception swallowing | **PARTIALLY** — Some remain, new instances found |

---

## 1. High-Severity Findings

### 1.1 [HIGH] State Corruption on Hook Failure

**File:** `pemcp/mcp/tools_angr_hooks.py:77-84`

When `proj.hook_symbol()` fails, the hook is already registered in `state.angr_hooks` before the actual hooking occurs. The code adds to the tracking dict at lines 80-84, then invalidates the CFG at lines 86-88, but if the hook operation itself fails, there's no rollback:

```python
state.angr_hooks[hook_label] = {    # Tracked BEFORE success is verified
    "target": hook_label, ...
}
state.angr_cfg = None                # CFG invalidated regardless
```

**Impact:** Failed hooks leave ghost entries in state. Subsequent `list_hooks` shows hooks that don't exist in the angr project. `unhook_function` will attempt to unhook non-existent hooks, causing further errors.

**Fix:** Register the hook in state only after successful `proj.hook_symbol()`.

### 1.2 [HIGH] Silent Data Loss in Dataflow Analysis

**File:** `pemcp/mcp/tools_angr_dataflow.py` — lines 142-143, 170-171, 285-286, 310-311

Four broad `except Exception: pass` blocks silently swallow errors during critical data extraction:
- Definition enumeration (line 142)
- Observation extraction (line 170)
- Definition graph processing (line 285)
- Live definition extraction (line 310)

**Impact:** Users receive incomplete reaching-definition or data-dependency results with no indication that data was lost. An analysis that finds "3 definitions" may actually have 20, with 17 silently discarded due to exceptions. This is particularly dangerous for security analysis where missing a definition could mean missing a vulnerability.

**Fix:** At minimum, count suppressed exceptions and include in the response: `"warnings": "17 definitions skipped due to processing errors"`.

### 1.3 [HIGH] Unsafe Dictionary Key Access in String Tools

**File:** `pemcp/mcp/tools_strings.py` — lines 127, 794, 804, 967, 976

Direct dictionary key access (`item["string"]`) without validation after only checking `isinstance(item, dict)`:

```python
for item in all_strings_with_context:
    string_to_search = item["string"]  # KeyError if "string" key missing
```

If FLOSS analysis data is malformed (corrupted cache, incompatible library version, or partial analysis), this crashes the tool instead of skipping the bad entry.

**Impact:** A single malformed entry in the string data crashes the entire tool call. Since the cache stores analysis results, a corrupted cache entry could make string tools permanently fail for that file until the cache is cleared.

**Fix:** Use `.get("string", "")` with a skip-and-warn pattern for missing keys.

---

## 2. Medium-Severity Findings

### 2.1 [MEDIUM] Environment Variable Parsing Still Unguarded (Unfixed from v9)

**File:** `pemcp/mcp/tools_pe.py` — lines 28, 140, 340

Three `int()` calls on environment variables without try-except:
```python
_analysis_semaphore = asyncio.Semaphore(int(os.environ.get("PEMCP_MAX_CONCURRENT_ANALYSES", "3")))
MAX_FILE_SIZE = int(os.environ.get("PEMCP_MAX_FILE_SIZE_MB", "256")) * 1024 * 1024
_PE_ANALYSIS_TIMEOUT = int(os.environ.get("PEMCP_ANALYSIS_TIMEOUT", "600"))
```

Note: Line 28 executes at import time — a bad env var value crashes the server before it starts with an unhelpful `ValueError` traceback.

**Fix:** Wrap each in try-except with fallback to default, matching the pattern already used in `config.py:34`:
```python
try:
    _cache_max_mb_int = int(_cache_max_mb) if _cache_max_mb else 500
except (ValueError, TypeError):
    _cache_max_mb_int = 500
```

### 2.2 [MEDIUM] Speakeasy Cascade Failure on Shellcode Load

**File:** `scripts/speakeasy_runner.py:103-112`

If `se.load_shellcode()` fails (e.g., unsupported architecture), the exception is caught but execution continues to `se.run_shellcode()`, which operates on uninitialized state:

```python
try:
    se.load_shellcode(...)
except Exception:
    pass                    # Failure silently ignored
# Execution continues...
se.run_shellcode(sc_data)   # Runs on uninitialized state
```

**Impact:** Produces misleading emulation reports. Users may trust results from a failed emulation.

### 2.3 [MEDIUM] Unipacker Event Not Guaranteed to Signal

**File:** `pemcp/mcp/tools_new_libs.py:705-713`

The UnpackerEngine's `done_event.wait(timeout=300)` may time out without signaling, but the function still returns a "success" result:

```python
done_event.wait(timeout=300)
# No check of done_event.is_set() after wait!
```

**Impact:** Incomplete unpacking silently treated as success. Users may analyze a partially-unpacked binary without knowing.

**Fix:** Check `done_event.is_set()` and return a warning if timed out.

### 2.4 [MEDIUM] Late Regex Validation in Deobfuscation

**File:** `pemcp/mcp/tools_deobfuscation.py:372-378`

Regex patterns in `decoded_regex_patterns` are validated inside the processing loop rather than at parameter validation time. Invalid patterns waste CPU on decode-then-match cycles before being caught:

```python
# Line 372-378: Pattern validated during iteration, not upfront
try:
    if not any(re.search(p, final_decoded_text) for p in decoded_regex_patterns):
        continue
except re.error:
    await ctx.warning("An invalid regex was skipped during search.")
```

**Fix:** Validate all patterns upfront before entering the processing loop.

### 2.5 [MEDIUM] Binwalk Subprocess Failure Treated as Success

**File:** `pemcp/mcp/tools_new_libs.py:869-874`

When binwalk CLI exits with a non-zero code, the error is logged but the function returns results anyway:

```python
if proc.returncode != 0:
    logger.warning("binwalk CLI exited with code %d: %s", proc.returncode, proc.stderr[:200])
# Returns results anyway — potentially empty or corrupted
```

**Impact:** Users receive empty scan results with no indication that binwalk failed.

---

## 3. Low-Severity Findings

### 3.1 [LOW] Missing Parameter Range Validation in String Tools

**File:** `pemcp/mcp/tools_strings.py:837-838, 863-864`

`function_va` and `string_offset` parameters in `get_strings_for_function()` and `get_string_usage_context()` accept any integer without range checking against PE image bounds.

### 3.2 [LOW] Subprocess Cleanup Race on Timeout

**File:** `pemcp/mcp/tools_new_libs.py:577-603`

If `proc.wait()` raises after `proc.kill()` during speakeasy timeout, the process handle leaks. In long-running servers, this could accumulate zombie processes.

### 3.3 [LOW] Unchecked Offset in PE Extended Tools

**File:** `pemcp/mcp/tools_pe_extended.py:315-316`

`start_offset` used in `get_section_by_offset()` without bounds checking. Failure is caught by try-except but suppressed silently, causing degraded confidence scores with no explanation.

### 3.4 [LOW] Inconsistent Regex Validation Pattern

**File:** `pemcp/mcp/tools_strings.py:775-780`

`_validate_regex_pattern()` is called followed by a separate `re.compile()` — the validation function already compiles the regex internally, so this is redundant. While not a bug, it's a code smell suggesting the validation interface isn't clear.

---

## 4. Testing Assessment

### Current State
- **276 tests** across 17 files — all passing
- **60% coverage threshold** enforced in CI
- **~2 second** test runtime (fast unit tests only)

### Critical Coverage Gaps

| Category | Modules | Test Coverage |
|----------|---------|--------------|
| **Core infrastructure** | state, cache, auth, utils, hashing, mock | Good (80-100%) |
| **Parsers** | pe.py, floss.py, capa.py, signatures.py | **None** |
| **MCP tools** | 24 tool modules | **None** |
| **CLI / main** | main.py, printers.py | **None** |
| **Background tasks** | background.py | **None** |

**77% of modules have zero test coverage.** The well-tested 23% is infrastructure that rarely changes — the untested 77% is where bugs actually live (as demonstrated by every critical bug found in iterations 8-10).

### Structural Test Issues

1. **No `conftest.py`** — Fixtures are duplicated across test files (e.g., `MockContext` in `test_truncation.py`, `clean_state` in `test_mcp_helpers.py`)

2. **Pytest markers defined but unused** — `pytest.ini` defines `no_file`, `pe_file`, `angr`, `optional_lib`, `unit` markers, but no test file uses them

3. **Coverage threshold too low** — 60% allows entire critical modules to be untested. Industry standard for production code is 80%+

4. **CI lint job too narrow** — Only syntax-checks 6 out of 48 Python files:
   ```yaml
   python -m py_compile pemcp/state.py    # Only 6 files checked
   python -m py_compile pemcp/cache.py
   python -m py_compile pemcp/hashing.py
   python -m py_compile pemcp/mock.py
   python -m py_compile pemcp/user_config.py
   python -m py_compile pemcp/utils.py
   ```

5. **No integration test automation** — `mcp_test_client.py` exists but requires a running server and is not part of CI

### Recommended Test Additions (Highest Impact)

1. **Tool smoke tests** — For each MCP tool, a single test that calls it with mock state and verifies it returns without error
2. **Parser unit tests** — `pe.py` functions with small synthetic PE data
3. **Shared conftest.py** — Centralize MockContext, clean_state, mock pe_data
4. **Marker usage** — Tag existing tests so CI can run `pytest -m unit` vs `pytest -m "not angr"`

---

## 5. Architecture Assessment

### Strengths

1. **Session isolation via StateProxy + contextvars** — Elegant, transparent per-session delegation that works identically in stdio and HTTP modes. This is production-quality design.

2. **Graceful library degradation** — All 20+ optional libraries detected at startup with clear availability flags. Tools return actionable error messages when dependencies are missing. This is the right way to handle a complex dependency tree.

3. **Smart analysis caching** — SHA256-keyed, gzip-compressed, LRU-evicted, version-invalidated cache. Properly handles session-specific fields (filepath patched on cache hit). Atomic writes via POSIX rename.

4. **Async architecture** — Heavy operations (`_parse_pe_to_dict`, angr CFG) run in `asyncio.to_thread()` with proper timeout handling. Concurrent analysis limited by semaphore. Background tasks with heartbeat monitoring.

5. **MCP response truncation** — Intelligent structural truncation (lists sliced, dicts trimmed, strings cut) with 5-iteration reduction loop and fallback to string preview. Prevents 64KB limit from crashing tools.

6. **Docker dependency management** — The Dockerfile handles the unicorn 1.x/2.x conflict (speakeasy in separate venv), the oscrypto OpenSSL 3.x patch, and best-effort installs for fragile packages — all documented in DEPENDENCIES.md.

### Areas for Improvement

1. **Tool module size** — `tools_triage.py` and `tools_angr.py` are large files with many responsibilities. Consider splitting triage into sub-modules (triage_pe.py, triage_sections.py, etc.).

2. **Duplicated format detection** — Magic byte detection is implemented separately in `main.py:271-287`, `tools_pe.py:150-162`, and `tools_format_detect.py`. Should be a single shared function.

3. **Inconsistent error patterns** — Some tools raise `RuntimeError`, others return `{"error": ...}` dicts. A consistent pattern would improve the MCP client experience.

4. **No request/response logging** — In HTTP mode, there's no structured logging of which tools are called, by whom, or how long they take. This makes debugging production issues difficult.

---

## 6. Docker & CI Assessment

### Dockerfile — Good

- Multi-layer caching for heavy dependencies (angr, floss, capa)
- Speakeasy isolation in separate venv (unicorn 1.x/2.x conflict)
- Build-time verification of unicorn versions
- Pre-populated capa rules (no runtime download)
- Security: non-root user via `--user`, writable home for cache

**Suggestions:**
- Pin base image by digest (commented but not enforced)
- Add `.dockerignore` to exclude `reports/`, `.git/`, `tests/` from build context
- The `chmod -R 777 /app/home` is documented but still broad — consider 770 with a dedicated group

### CI Pipeline — Needs Improvement

**Current:**
- Matrix testing on Python 3.10, 3.11, 3.12 ✓
- Coverage report upload ✓
- 60% coverage threshold ✓

**Missing:**
- No linting (ruff, flake8, or pylint)
- No type checking (mypy)
- No security scanning (bandit, safety)
- Lint job only checks 6/48 files
- No Docker build verification
- No integration test job (even as a manual workflow)

---

## 7. Documentation Assessment

### Strengths
- **README.md** (944 lines) — Comprehensive installation, usage, tool reference
- **TESTING.md** (432 lines) — Detailed test guide with categories and troubleshooting
- **DEPENDENCIES.md** (309 lines) — Explains every dependency conflict and workaround
- **FastPrompt.txt** — Quick-start prompt for AI assistants

### Suggestions
- Add a CHANGELOG.md tracking iteration changes
- The README tool reference should link to actual tool docstrings
- Add a CONTRIBUTING.md with code style and testing requirements

---

## 8. Summary of All Findings

| Priority | Count | Key Issues |
|----------|-------|------------|
| **HIGH** | 3 | Hook state corruption, silent dataflow data loss, unsafe dict access in strings |
| **MEDIUM** | 5 | Env var parsing (unfixed), speakeasy cascade, unipacker timeout, late regex validation, binwalk silent failure |
| **LOW** | 4 | Missing parameter range checks, subprocess cleanup race, unchecked offset, redundant regex compile |

### Recommended Fix Order

1. **Fix hook state corruption** (1.1) — Move state registration after successful hook
2. **Fix unsafe dict access** (1.3) — Use `.get()` with defaults in string tools
3. **Add exception counters to dataflow** (1.2) — Surface suppressed errors to users
4. **Guard env var parsing** (2.1) — Wrap in try-except with defaults
5. **Fix speakeasy cascade** (2.2) — Check load success before run
6. **Expand CI** — Add lint for all files, increase coverage threshold to 70%+
7. **Create conftest.py** — Centralize test fixtures

---

## 9. Project Maturity Assessment

| Dimension | Rating | Notes |
|-----------|--------|-------|
| **Architecture** | Excellent | Session isolation, async design, caching all well-designed |
| **Core stability** | Good | Infrastructure modules are solid after iteration 9 fixes |
| **Tool correctness** | Fair | Silent data loss, state corruption in edge cases |
| **Security** | Good | Auth fixed, path sandboxing, ReDoS protection, env vars remain |
| **Testing** | Needs work | 23% module coverage, no integration tests in CI |
| **Documentation** | Very good | Comprehensive README, TESTING, DEPENDENCIES docs |
| **CI/CD** | Fair | Matrix testing good, missing lint/type/security checks |
| **Docker** | Good | Complex dependency management handled well |

**Overall: This is a well-engineered project with strong foundations. The remaining issues are in the tool implementation layer, not architecture. Increasing test coverage would catch most of the bugs found across iterations 8-10.**
