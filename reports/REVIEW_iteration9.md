# PeMCP Project Review — Iteration 9

**Date:** 2026-02-16
**Reviewer:** Claude (Opus 4.6)
**Scope:** Full project review — architecture, code quality, security, testing, documentation
**Codebase:** ~30,000 lines Python, 105 MCP tools, 276 unit tests
**Context:** Review after iteration 8 fixes were applied

---

## Executive Summary

The iteration 8 fixes improved HTTP security (auth middleware, mandatory `--allowed-paths`), fixed PEiD string handling, added section key aliases in the parser, and improved angr thread safety. However, this review identifies **3 critical functional bugs** that render most PE triage analysis non-functional, **1 security vulnerability** in the new auth middleware, and several medium-severity issues.

The most impactful finding is that the PE parser sets `mode = "pe_executable"` while all triage code checks `mode == 'pe'`, causing every PE-specific triage section to be silently skipped.

---

## 1. Critical Functional Bugs

### 1.1 [CRITICAL] Triage Mode String Mismatch — All PE Analysis Skipped

**File:** `pemcp/parsers/pe.py:898` vs `pemcp/mcp/tools_triage.py` (50+ locations)

The PE parser sets:
```python
pe_info_dict["mode"] = "pe_executable"   # pe.py:898
```

But every triage function checks:
```python
if analysis_mode == 'pe':   # tools_triage.py:151, 326, 542, 603, 656, etc.
```

Since `"pe_executable" != "pe"`, **every PE-specific triage section is silently skipped**: timestamp analysis, packing assessment, digital signatures, Rich header, suspicious imports, section anomalies, overlay analysis, resources, header anomalies, TLS callbacks, security mitigations, delay-load detection, version info, .NET indicators, and export anomalies.

The `_triage_file_info` function defaults to `'pe'` only when mode is missing: `state.pe_data.get('mode', 'pe')`. Since the parser always sets mode, the default never triggers.

**Fix:** Normalize mode to `'pe'` in `_triage_file_info` or at the parser level.

### 1.2 [CRITICAL] Rich Header Key Mismatch — `decoded_entries` vs `decoded_values`

**File:** `pemcp/mcp/tools_triage.py:329` vs `pemcp/parsers/pe.py:533`

The triage code reads:
```python
entries = rich_data.get('decoded_entries', rich_data.get('entries', []))
```

But the parser outputs:
```python
'decoded_values': decoded   # pe.py:533
```

Neither `'decoded_entries'` nor `'entries'` exist, so `entries` is always `[]`. Rich header compiler fingerprinting (compiler IDs, product names) produces empty results.

The same bug exists in `_triage_compiler_language` (line 1369) which was added in the iteration 8 fixes.

### 1.3 [CRITICAL] Rich Header Entry Field Name Mismatch

**File:** `pemcp/mcp/tools_triage.py:334-335` vs `pemcp/parsers/pe.py:522-527`

Even if 1.2 were fixed, the triage code reads fields that don't exist:
```python
comp_id = entry.get('comp_id', entry.get('CompID'))         # Neither exists
prod = entry.get('product_name', entry.get('product', ''))   # Neither exists
```

Parser actually produces:
```python
{"product_id_hex": hex(prod_id), "product_id_dec": prod_id,
 "build_number": build_num, "count": count, "raw_comp_id": hex(comp_id)}
```

**Fix:** Use `'product_id_dec'` and `'raw_comp_id'` to match parser output.

---

## 2. Security Findings

### 2.1 [HIGH] Timing Attack on Bearer Token Comparison

**File:** `pemcp/auth.py:30`

```python
if auth_header != expected:
```

The `!=` operator short-circuits on first mismatched character, allowing attackers to determine the API key character-by-character via response timing. This is a well-known timing side-channel attack against authentication tokens.

**Fix:** Use `hmac.compare_digest()` for constant-time comparison.

### 2.2 [MEDIUM] No Parameter Bounds Validation on Timeouts

**File:** `pemcp/mcp/tools_new_libs.py:609,639`

The `timeout_seconds` parameter in `emulate_pe_with_windows_apis` and `emulate_shellcode_with_speakeasy` accepts arbitrary integers from MCP clients with no bounds checking. Negative values or extremely large values could cause unexpected behavior.

### 2.3 [LOW] Environment Variable Integer Parsing Unguarded

**File:** `pemcp/mcp/tools_pe.py:28,140,340`

```python
_analysis_semaphore = asyncio.Semaphore(int(os.environ.get("PEMCP_MAX_CONCURRENT_ANALYSES", "3")))
MAX_FILE_SIZE = int(os.environ.get("PEMCP_MAX_FILE_SIZE_MB", "256")) * 1024 * 1024
_PE_ANALYSIS_TIMEOUT = int(os.environ.get("PEMCP_ANALYSIS_TIMEOUT", "600"))
```

Non-numeric environment variable values will crash the application at import time with an unhandled `ValueError`.

---

## 3. Code Quality Issues

### 3.1 [HIGH] `analyze_binary_loops` Still Has Check-Then-Act Race

**File:** `pemcp/mcp/tools_angr.py:504-525`

While `_ensure_project_and_cfg()` was fixed with `_init_lock`, the `analyze_binary_loops` function bypasses this entirely with its own project/CFG initialization logic. The check `if state.angr_loop_cache is None:` followed by expensive loop analysis and state mutation has no lock protection. Two concurrent callers could both see `None` and both perform the expensive computation.

### 3.2 [MEDIUM] New `_triage_compiler_language` Inherits Rich Header Bug

**File:** `pemcp/mcp/tools_triage.py:1369-1372`

The new compiler/language detection function added in iteration 8 has the same Rich header key mismatches as 1.2 and 1.3 above:
```python
entries = rich_data.get('decoded_entries', rich_data.get('entries', []))
prod = str(entry.get('product_name', entry.get('product', ''))).lower()
```

Delphi and MSVC detection via Rich header will never work.

### 3.3 [MEDIUM] Silent Exception Swallowing in Triage

**File:** `pemcp/mcp/tools_triage.py:130`, `tools_angr.py:408,523`

Multiple bare `except Exception: pass` blocks that silently hide real errors:
- File size lookup failure (triage line 130)
- Return register lookup (angr line 408)
- Loop analysis iteration (angr line 523)

These should at minimum log the exception to aid debugging.

---

## 4. Testing Assessment

### Test Results
- **276 tests collected, 273 passed, 3 skipped** — All pass cleanly

### Critical Gaps

1. **`auth.py` has zero tests** — The new bearer token middleware has no unit tests. The timing attack vulnerability would be caught by a test comparing expected constant-time behavior.

2. **`_triage_compiler_language()` has zero tests** — The new language detection added in iteration 8 has no test coverage. The Rich header key mismatch would have been caught.

3. **All MCP tool modules have 0% coverage** — The critical mode mismatch (1.1) has existed undetected because there are no integration tests exercising the triage report with a real PE file.

4. **No test for mode normalization** — A simple unit test verifying `_triage_file_info` returns the correct mode for PE files would have caught bug 1.1.

### Well-Tested Core
- `mock.py` (100%), `user_config.py` (96%), `hashing.py` (85%), `state.py` (83%), `cache.py` (80%)

---

## 5. Architecture Assessment

### Strengths (Maintained from Iteration 8)

1. **Session isolation** via `StateProxy` + `contextvars` — excellent design
2. **Thread-safe state** with three-lock pattern per session
3. **Smart caching** with SHA256 keys, gzip compression, LRU eviction, version invalidation
4. **Graceful degradation** across 20+ optional dependencies
5. **Clean tool registration** with consistent decorator pattern

### Improvements Since Iteration 8

1. **HTTP auth middleware** (new `auth.py`) — correct architecture, needs timing fix
2. **Mandatory `--allowed-paths`** for HTTP mode — good security posture
3. **PE analysis timeout** — prevents hangs from malicious binaries
4. **Batched fuzzy search** — significant performance improvement
5. **Init lock on angr** — prevents duplicate project creation in `_ensure_project_and_cfg`
6. **Compiler/language detection** — good feature, needs key fixes

---

## 6. Summary of Findings by Priority

| Priority | Count | Key Issues |
|----------|-------|------------|
| **CRITICAL** | 3 | Mode mismatch breaks all PE triage, Rich header key wrong, Rich header field names wrong |
| **HIGH** | 2 | Auth timing attack, angr loop race condition |
| **MEDIUM** | 3 | Compiler language inherits Rich header bug, silent exception swallowing, no timeout bounds |
| **LOW** | 1 | Environment variable parsing unguarded |

### Recommended Fix Order

1. **Fix mode normalization** (1.1) — All PE triage is currently non-functional
2. **Fix Rich header keys** (1.2, 1.3, 3.2) — Affects both triage and compiler detection
3. **Fix auth timing** (2.1) — Use `hmac.compare_digest()`
4. **Add tests** for auth.py and compiler_language detection
5. **Fix angr loop race** (3.1) — Add locking or use `_ensure_project_and_cfg()`
