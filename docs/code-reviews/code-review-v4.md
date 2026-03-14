# Code Review v4 — Verified Findings

**Date**: 2026-03-12
**Scope**: Full codebase security, efficiency, stability, memory review
**Method**: 6 parallel review agents + manual verification of every finding
**Status**: ALL 13 ISSUES FIXED — Tests pass (1079/1079), lint clean

## Legend

- **Status**: `FIXED` = resolved | `FP` = false positive | `WONTFIX` = accepted risk

---

## CRITICAL (1)

### C1: `batch_decompile` lock safety gap
- **File**: `arkana/mcp/tools_angr.py:1810-1819`
- **Status**: FIXED
- **Description**: `_batch_lock_held` is assigned at line 1817, AFTER lock acquisition at line 1812. If any exception occurs between lock acquire (1812) and the assignment (1817), the lock is held but `_batch_lock_held` is never set. Since the `try` block at line 1819 hasn't been entered, the `finally` at line 1927 never runs. Lock leaks permanently.
- **Edge case**: Line 1816 `state._decompile_on_demand_waiting = False` could throw if StateProxy is broken.
- **Fix**: Initialized `_batch_lock_held = False` before lock acquisition so the `finally` block always sees it.

---

## HIGH (3)

### H1: Session reaper swallows exceptions silently
- **File**: `arkana/state.py:739,743`
- **Status**: FIXED
- **Description**: Two bare `except Exception: pass` blocks in `_session_reaper_loop()`. Line 739 swallows `close_pe()`/`reset_angr()` failures — if resource cleanup fails (e.g., file descriptor exhaustion), the error is invisible. Line 743 swallows the entire reaper loop iteration errors. Both prevent diagnosing production resource leaks.
- **Fix**: Added `logger.warning("Session reaper cleanup error", exc_info=True)` to both.

### H2: Unbounded `state.notes` and `state.artifacts` lists
- **File**: `arkana/state.py:219-277 (add_note), 327-367 (register_artifact)`
- **Status**: FIXED
- **Description**: Notes and artifacts grow via `.append()` with no size limit. `tool_history` uses `deque(maxlen=MAX_TOOL_HISTORY)` but notes/artifacts don't. In long-running analysis sessions or automated pipelines that add hundreds of notes, memory grows unbounded.
- **Fix**: Added `MAX_NOTES = 10_000` and `MAX_ARTIFACTS = 1_000` caps; raises `RuntimeError` when exceeded.

### H3: String extraction regex can match megabyte-long strings
- **File**: `arkana/parsers/strings.py:23`
- **Status**: FIXED
- **Description**: Regex `b'[ -~]{5,}'` has no upper bound on match length. A binary with a 10MB embedded text resource produces a single 10MB string object. The list comprehension at lines 24-27 materializes ALL matches at once. Used broadly during PE parsing, open_file, and string extraction.
- **Fix**: Added upper bound: `b'[ -~]{5,65536}'` to cap individual match length at 64KB.

---

## MEDIUM (6)

### M1: `diff_binaries` exceptions logged at debug only
- **File**: `arkana/mcp/tools_angr_forensic.py:91-114`
- **Status**: FIXED
- **Description**: Four try/except blocks catch BinDiff extraction errors and log at `debug` level only. User gets empty result categories (0 identical, 0 differing) with no indication the extraction failed. Indistinguishable from "no differences found".
- **Fix**: Changed to `warning` level. Added `warnings` list to result dict with error details.

### M2: `get_cross_reference_map` silent truncation
- **File**: `arkana/mcp/tools_angr.py:1642`
- **Status**: FIXED
- **Description**: `function_addresses[:10]` silently truncates input list. User passing 50 addresses gets results for 10 with no indication of truncation.
- **Fix**: Added `_truncated` notice in response when `len(function_addresses) > 10`.

### M3: `get_function_map` silent truncation of callees/callers
- **File**: `arkana/mcp/tools_angr_disasm.py:734-735, 919-920`
- **Status**: FIXED
- **Description**: Callees silently capped at 15, callers at 10 per function. No truncation indicator in response.
- **Fix**: Added `_callees_truncated`/`_callers_truncated` flags when lists are cut.

### M4: Refinery decompress output unbounded
- **File**: `arkana/mcp/tools_refinery.py:514-526`
- **Status**: FIXED
- **Description**: Input is capped at 10MB, but decompressed output has no size limit. A 10MB gzip bomb can expand to gigabytes, causing OOM before `_check_mcp_response_size` can truncate the response. The full output is materialized as bytes at line 520, then doubled as hex at line 526.
- **Fix**: Added 100MB output cap after decompression with `_output_truncated` flag in response.

### M5: FLOSS background thread has no global timeout
- **File**: `arkana/mcp/tools_pe.py:85-115`
- **Status**: FIXED
- **Description**: The FLOSS deep analysis worker thread has no maximum execution time. If `_parse_floss_analysis()` hangs on a malformed binary (e.g., Vivisect analysis loop), the daemon thread runs until process exit. Stall detection reports it as stalled but never kills it.
- **Fix**: Added elapsed time tracking with 30-minute hard cap (`_FLOSS_THREAD_TIMEOUT`). Logs warning when exceeded. (Note: Python threads can't be killed safely — timeout only logs and breaks out of the worker function.)

### M6: IOC note extraction unbounded per category
- **File**: `arkana/mcp/tools_ioc.py:93-107`
- **Status**: FIXED
- **Description**: When extracting IOCs from notes, regex matches are added to sets without per-category caps. A note containing thousands of IPs/URLs produces unbounded results.
- **Fix**: Added `_MAX_IOCS_PER_CATEGORY = 10_000` cap with early-break per regex loop.

---

## LOW (3)

### L1: `tools_batch.py` bare `except Exception: pass` (6 instances)
- **File**: `arkana/mcp/tools_batch.py:40,74,80,139,246,268`
- **Status**: FIXED
- **Description**: Multiple bare exception handlers with no logging. Silent failures in format detection, ssdeep/TLSH hashing, PE close, and similarity comparison.
- **Fix**: Added `logger.debug()` calls to each exception handler.

### L2: `_phase_caches` keyed by `id(state)` — stale entries possible
- **File**: `arkana/mcp/tools_session.py:24,39`
- **Status**: FIXED
- **Description**: `id(state)` can be reused after GC. Stale cache entry used for wrong session for up to 2 seconds. Impact is minimal (slightly wrong phase string, auto-corrects).
- **Fix**: Added cleanup call in `close_file()` to remove session entry from `_phase_caches`.

### L3: CSRF `_validate_csrf` fail-open code pattern
- **File**: `arkana/dashboard/app.py:367-375`
- **Status**: FIXED
- **Description**: Returns `True` (allow) when `_csrf_secret` is uninitialized (line 368) or when expected token can't be computed (line 375). Not exploitable in practice (`_csrf_secret` is always set before requests arrive, and `_csrf_dashboard_token` is always non-empty), but fail-open is a bad security pattern.
- **Fix**: Changed both to `return False` (fail-closed) with `logger.warning()`.

---

## Rejected / False Positives

| ID | Claim | Verdict | Reason |
|----|-------|---------|--------|
| FP1 | Cache eviction size miscount | FALSE POSITIVE | `continue` at line 364 skips the `total_size -= size` decrement on failure |
| FP2 | BSim `del cfg_b, proj_b` UnboundLocalError | FALSE POSITIVE | Both initialized to `None` at lines 192-193 before `try` |
| FP3 | SSE connection count leak | FALSE POSITIVE | Properly managed via try/finally with `max(0, ...)` guard |
| FP4 | Markdown `_md_inline` ReDoS | FALSE POSITIVE | `[^`]+` and `[^*]+` are negated character classes — linear time |
| FP5 | Callgraph XSS via function names | FALSE POSITIVE | Uses `textContent`/`createTextNode`, not innerHTML |
| FP6 | Request body size validation missing | FALSE POSITIVE | `_parse_json_body()` enforces `_MAX_POST_BODY_SIZE` at lines 506+512 |
| FP7 | Cache meta stale on file deletion | FALSE POSITIVE | `_load_meta()` checks `META_FILE.exists()` at line 100 |
| FP8 | Enrichment CFG reference leak | FALSE POSITIVE | Local vars reference shared read-only angr objects; harmless |
| FP9 | Import project inconsistent state | FALSE POSITIVE | JSON parse error caught before any state mutations |
| FP10 | SSE 2-second token re-validation window | FALSE POSITIVE | Standard SSE behavior; initial auth check is sufficient |
| FP11 | Container parser infinite loop | FALSE POSITIVE | `offset = idx + 1` advances past delimiter; bounded by data length |
| FP12 | Steganography path validation order | FALSE POSITIVE | `check_path_allowed` called BEFORE `os.makedirs` |

---

## Pattern Summary

| Pattern | Confirmed instances | Files affected |
|---------|-------------------|----------------|
| Bare `except Exception: pass` no logging | 10 (2 in state.py + 6 in tools_batch.py) | 2 |
| Unbounded list/dict growth | 2 (notes + artifacts) | 1 |
| Uncapped output after transform | 1 critical (decompress) | 1 |
| Silent list truncation | 3 (xref_map, function_map×2) | 2 |
| Debug-only error logging | 4 (diff_binaries) | 1 |
| Regex match unbounded length | 1 (strings parser) | 1 |
