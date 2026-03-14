# Code Review v5 — Verified Findings

**Date**: 2026-03-12
**Scope**: Full codebase security, efficiency, stability, memory review
**Method**: 6 parallel review agents + manual verification of every finding
**Status**: PENDING FIX — 18 confirmed issues (0 CRITICAL, 4 HIGH, 8 MEDIUM, 6 LOW)

## Legend

- **Status**: `OPEN` = confirmed, needs fix | `FP` = false positive | `WONTFIX` = accepted risk

## V4 Fix Validation

All 13 v4 fixes were validated to confirm they impose no functional limitations:

| Fix | Constraint | Impact Assessment |
|-----|-----------|-------------------|
| H2: MAX_NOTES = 10,000 | Cap on `state.notes` list | All `add_note` callers are MCP tools wrapped by `tool_decorator`, which catches RuntimeError gracefully. 10K notes is far beyond any real session. |
| H3: String regex cap 65,536 chars | `b'[ -~]{5,65536}'` | A single printable ASCII run >64KB is pathological data (embedded resources). Real strings are orders of magnitude shorter. |
| M4: Decompress 100MB cap | Output capped after decompression | `_output_truncated` flag in response. 100MB is generous for any MCP response. |
| M6: IOC 10,000/category | `_MAX_IOCS_PER_CATEGORY` early-break | Extremely unlikely to have >10K IPs or URLs in analysis notes. |
| L3: CSRF fail-closed | `return False` when secret uninitialized | Secret is always set before routes are registered; these paths are unreachable in normal operation. |

---

## HIGH (4)

### H1: `_decompile_on_demand_waiting` not cleared on lock timeout
- **File**: `arkana/mcp/tools_angr.py:393-397, 1816-1820`
- **Status**: OPEN
- **Description**: Both `decompile_function_with_angr` (line 393) and `batch_decompile` (line 1816) set `state._decompile_on_demand_waiting = True` before acquiring `_decompile_lock`. If lock acquisition times out (line 394/1817), the code raises `RuntimeError` but never resets the flag to `False`. The flag remains `True` permanently, which causes the background enrichment sweep to yield on every iteration, effectively pausing enrichment forever for this session.
- **Impact**: Background auto-enrichment stalls permanently after a single decompile lock timeout.
- **Fix**: Reset `state._decompile_on_demand_waiting = False` before raising the RuntimeError on timeout, or wrap the entire sequence in try/finally.

### H2: `find_path_with_custom_input` / `emulate_with_watchpoints` missing `max_steps` validation
- **File**: `arkana/mcp/tools_angr_forensic.py:649, 828`
- **Status**: OPEN
- **Description**: Both tools accept `max_steps` as an integer parameter with defaults (2000 and 1000 respectively) but perform no upper bound validation. A caller can pass `max_steps=999_999_999`, causing angr's symbolic execution to run for effectively unlimited steps, consuming unbounded CPU and memory. Other symbolic execution tools like `find_path_to_address` and `emulate_function_execution` already cap `max_steps` to a sane upper bound.
- **Impact**: Denial of service via memory/CPU exhaustion on the server.
- **Fix**: Add `max_steps = min(max_steps, MAX_SYMBOLIC_STEPS)` validation (e.g., 100,000 cap).

### H3: `analyze_batch` `_parse_single_file` reads files without size limit
- **File**: `arkana/mcp/tools_batch.py:54-61`
- **Status**: OPEN
- **Description**: `_parse_single_file()` calls `os.path.getsize()` at line 54 (stored in `entry["size"]`) but then calls `f.read()` at line 61 without checking the size first. A 10GB file would be fully read into memory. The `analyze_batch` tool processes up to 50 files (MAX_BATCH_FILES), so multiple large files compound the issue.
- **Impact**: OOM on server when batch-analyzing directories containing large files.
- **Fix**: Add a size check after `os.path.getsize()` — reject files above a reasonable cap (e.g., 200MB).

### H4: `shellcode_hex` parameters have no size limit before hex decode
- **File**: `arkana/mcp/tools_qiling.py:266`, `arkana/mcp/tools_new_libs.py:715`
- **Status**: OPEN
- **Description**: Both `emulate_shellcode_with_qiling` and `emulate_shellcode_with_speakeasy` accept `shellcode_hex: Optional[str]` without any length validation. `bytes.fromhex()` is called later to decode the hex string, which doubles the memory (hex string + decoded bytes). A 200MB hex string produces a 100MB byte array plus keeps the original string, consuming 300MB+ per call.
- **Impact**: Memory exhaustion via oversized shellcode parameter.
- **Fix**: Validate `len(shellcode_hex) <= MAX_SHELLCODE_HEX_SIZE` (e.g., 20MB hex = 10MB shellcode) before decoding.

---

## MEDIUM (8)

### M1: `_parse_floss_static_only` unbounded static string list
- **File**: `arkana/parsers/floss.py:229-233`
- **Status**: OPEN
- **Description**: `_parse_floss_static_only()` collects FLOSS static strings into an unbounded list comprehension (line 230-233). The full analysis path (`_parse_floss_analysis`) caps static strings at `_MAX_STATIC_STRINGS = 200_000`, but the static-only path has no such cap. On large binaries with millions of string-like byte sequences, this can consume gigabytes.
- **Impact**: OOM on large binaries during initial FLOSS static-only extraction.
- **Fix**: Apply the same `_MAX_STATIC_STRINGS` cap as the full analysis path.

### M2: `refinery_pipeline` steps list unbounded
- **File**: `arkana/mcp/tools_refinery.py:1247-1249`
- **Status**: OPEN
- **Description**: `refinery_pipeline` checks for empty `steps` at line 1247 but does not cap the list length at line 1249. Each step involves subprocess execution with Binary Refinery units. A caller passing 1000 steps creates 1000 subprocess invocations, with each step's output feeding into the next.
- **Impact**: Resource exhaustion via excessive subprocess spawning.
- **Fix**: Add `_MAX_PIPELINE_STEPS = 50` cap (or similar) with an error message.

### M3: CSV newline escaping in `_build_csv`
- **File**: `arkana/mcp/tools_ioc.py:194-206`
- **Status**: OPEN
- **Description**: `_build_csv()` correctly escapes double quotes (line 202) and CSV formula injection prefixes (lines 203-204), but does not strip or escape newline characters (`\n`, `\r`) in IOC values. A URL IOC containing a newline (e.g., from a malformed string extraction) breaks CSV row boundaries, causing downstream parsers to misalign.
- **Impact**: Malformed CSV output; potential for CSV injection via newline insertion.
- **Fix**: Strip `\n` and `\r` from values before CSV encoding.

### M4: Search helpers don't use `safe_regex_search`
- **File**: `arkana/mcp/_search_helpers.py:102, 177`
- **Status**: OPEN
- **Description**: `search_lines_with_context()` (line 102) and `search_instructions_with_context()` (line 177) call `compiled.search(line)` directly. While the caller validates patterns via `validate_regex_pattern()` (which rejects nested quantifiers), `safe_regex_search()` in `utils.py` provides a timeout-protected wrapper that catches patterns that pass validation but still cause pathological backtracking (e.g., alternation-based ReDoS). The direct `compiled.search()` call can hang indefinitely on crafted input.
- **Impact**: Search operations can hang on pathological regex + input combinations.
- **Fix**: Replace `compiled.search(line)` with `safe_regex_search(compiled, line)` and import from `arkana.utils`.

### M5: `reconstruct_pe_from_dump` hex decoded before size check
- **File**: `arkana/mcp/tools_unpack.py:261-269`
- **Status**: OPEN
- **Description**: Line 261 calls `bytes.fromhex(data_hex.replace(...))` immediately, fully materializing the decoded bytes. The size check `len(data) > 100 * 1024 * 1024` at line 269 happens AFTER the allocation. A 200MB hex string would allocate 100MB of bytes before being rejected.
- **Impact**: Transient OOM before size validation rejects the input.
- **Fix**: Check `len(data_hex) > 200 * 1024 * 1024` (200MB hex = 100MB decoded) before calling `bytes.fromhex()`.

### M6: YARA rule string escaping incomplete
- **File**: `arkana/mcp/tools_pe_forensic.py:105, 123`
- **Status**: OPEN
- **Description**: The YARA rule generator escapes `\\` and `"` in string values (lines 105, 123) but not `\n`, `\t`, or `\x` sequences. YARA interprets these as escape sequences in double-quoted strings. A binary string like `"data\ntest"` would produce a YARA string `"data\ntest"` which YARA treats as `data` + newline + `test`, changing the match semantics. PDB paths with `\t` or `\x` prefixed directory names would similarly be misinterpreted.
- **Impact**: Generated YARA rules match different bytes than intended.
- **Fix**: After `\\` and `"` escaping, also replace literal `\n` → `\\n`, `\t` → `\\t`, `\r` → `\\r`, and ensure `\x` sequences are properly escaped.

### M7: `_decompile_meta` is module-level global, not per-session
- **File**: `arkana/mcp/tools_angr.py:24`
- **Status**: OPEN
- **Description**: `_decompile_meta` is a module-level dict (line 24) keyed by `(target_addr,)` tuple. In HTTP mode with multiple concurrent sessions analyzing different binaries, session A's cached decompilation can be returned to session B if they request the same address. The cache has no session scoping — there is no session ID in the cache key.
- **Impact**: Cross-session data leak in HTTP multi-session mode. User A sees User B's decompiled code.
- **Fix**: Include `state._state_uuid` (or `id(state)`) in the cache key, or make `_decompile_meta` a per-state attribute.

### M8: `get_cross_reference_map` `depth` parameter has no upper bound
- **File**: `arkana/mcp/tools_angr.py:1618, 1685-1703`
- **Status**: OPEN
- **Description**: The `depth` parameter (line 1618, default 1) controls recursive callee traversal via `_collect_callees()` (lines 1685-1703). There is no upper bound validation. A caller passing `depth=100` triggers deep recursive traversal of the entire callgraph. With cycles in the callgraph (common in real binaries), the `visited` set prevents infinite recursion but doesn't prevent visiting every reachable function, which can be thousands.
- **Impact**: CPU exhaustion on dense callgraphs with high depth values.
- **Fix**: Clamp `depth = min(depth, 5)` or similar reasonable upper bound.

---

## LOW (6)

### L1: Functions cache returns shallow copy of mutable inner objects
- **File**: `arkana/dashboard/state_api.py:956`
- **Status**: OPEN
- **Description**: `get_functions_data()` returns `list(cached_data)` which is a shallow copy of the list. The inner dicts (one per function) are shared references. If any downstream code mutates an inner dict (e.g., adding a display field), it corrupts the cache for all subsequent callers. Currently no caller mutates, but the pattern is fragile.
- **Impact**: Latent corruption risk if any caller mutates returned function dicts.
- **Fix**: Either document the contract (callers must not mutate) or use `copy.deepcopy()` (slower but safer).

### L2: Config directory created without restrictive permissions
- **File**: `arkana/user_config.py:33`
- **Status**: OPEN
- **Description**: `CONFIG_DIR.mkdir(parents=True, exist_ok=True)` creates `~/.arkana/` with the process umask (typically 0o755). This directory stores `config.json` (which can contain API keys like `vt_api_key`) and `dashboard_token`. Other users on the system can read these files.
- **Impact**: Information disclosure on multi-user systems.
- **Fix**: Add `mode=0o700` to the `mkdir()` call. Optionally `chmod` the directory if it already exists.

### L3: `qiling_resolve_api_hashes` `hash_values` list unbounded
- **File**: `arkana/mcp/tools_qiling.py:531`
- **Status**: OPEN
- **Description**: `hash_values: List[str]` has no length cap. The tool computes hashes of all known API names for each hash value, so the computation is O(hash_values * known_apis). A list of 100K hash values with 50K known APIs = 5 billion comparisons.
- **Impact**: CPU exhaustion with large hash_values lists.
- **Fix**: Cap `hash_values` to a reasonable limit (e.g., 1000).

### L4: `datetime.utcfromtimestamp` deprecated in Python 3.12+
- **File**: `arkana/mcp/tools_batch.py:190`
- **Status**: OPEN
- **Description**: `datetime.datetime.utcfromtimestamp(t)` is deprecated since Python 3.12 and will be removed in a future version. It creates a naive datetime that can be ambiguous.
- **Impact**: Deprecation warning in Python 3.12+; future breakage.
- **Fix**: Replace with `datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc)`.

### L5: PE object leak on early parse error in `_parse_single_file`
- **File**: `arkana/mcp/tools_batch.py:84-92`
- **Status**: OPEN
- **Description**: If `pefile.PE()` succeeds at line 85 but `parse_data_directories()` raises at line 86-89, the `except` block at line 90 returns without calling `pe.close()`. The `pe` object leaks with its file handles and mmap still open.
- **Impact**: File handle leak when processing malformed PE files in batch mode.
- **Fix**: Add `pe.close()` in the except handler before returning.

### L6: `find_path_to_address` deferred stash not capped
- **File**: `arkana/mcp/tools_angr_forensic.py:~120-180`
- **Status**: OPEN
- **Description**: The symbolic execution `deferred` stash (states that are deprioritized but not discarded) grows unbounded during path exploration. On complex binaries, this can accumulate thousands of deferred states consuming significant memory. `emulate_function_execution` has a deferred cap but `find_path_to_address` does not.
- **Impact**: Gradual memory growth during long-running symbolic execution.
- **Fix**: Add periodic pruning of the `deferred` stash (e.g., cap at 500-1000 states).

---

## Rejected / False Positives

| ID | Claim | Verdict | Reason |
|----|-------|---------|--------|
| FP1 | SSE connection counter TOCTOU race | FALSE POSITIVE | Inner check inside the generator atomically checks AND increments under `_sse_lock` — outer check is just an optimization |
| FP2 | capa_parser double-checked locking unsafe | FALSE POSITIVE | CPython GIL protects `OrderedDict.get()` for atomic reads; the pattern is safe under GIL |
| FP3 | Progress closure captures stale state | FALSE POSITIVE | `current_state` is captured correctly at tool invocation time; closures reference the correct object |
| FP4 | Enrichment ContextVar not inherited by threads | FALSE POSITIVE | Internal enrichment functions use explicit `state` parameter passing, not ContextVar lookup |
| FP5 | `import_project` decompression bomb | FALSE POSITIVE | Already has 257MB archive size cap enforced before extraction |
| FP6 | Phase cache session isolation | FALSE POSITIVE | Already has eviction logic + v4 fix L2 adds `close_file()` cleanup |
| FP7 | CSP missing `connect-src` directive | FALSE POSITIVE | `default-src 'self'` already covers `connect-src` per CSP specification |
| FP8 | Rate limiter O(n log n) sort per request | FALSE POSITIVE | Bounded by 1000-entry cap; `sort()` on <1000 items is <1ms |

---

## Pattern Summary

| Pattern | Confirmed instances | Files affected |
|---------|-------------------|----------------|
| `bytes.fromhex()` without pre-decode size check | 17 unguarded across codebase | ~12 |
| `f.read()` without size limit on external files | 7 unguarded instances | ~5 |
| Unbounded `List` parameters (no length cap) | 17+ unguarded instances | ~10 |
| `_decompile_on_demand_waiting` not cleared on error | 2 (decompile + batch_decompile) | 1 |
| Direct `compiled.search()` instead of `safe_regex_search()` | 2 (both in _search_helpers.py) | 1 |

---

## Systemic Patterns Requiring Attention

### Pattern A: `bytes.fromhex()` pre-validation
17 tool functions accept hex string parameters and call `bytes.fromhex()` without first checking `len(hex_str)`. The hex string is twice the size of the decoded bytes, so a 200MB hex string allocates 100MB of bytes. A consistent pre-validation helper like `_validate_hex_size(hex_str, max_bytes=10*1024*1024)` should be applied across all tools accepting hex input.

### Pattern B: `f.read()` on user-supplied paths
7 instances where tools open user-supplied file paths and call `f.read()` without checking file size first. While `open_file` has size checks, tools that independently read files (batch analysis, diff, reconstruct) bypass these.

### Pattern C: Unbounded list parameters
17+ tools accept `List[str]` parameters without length caps. While MCP request size limits provide a soft bound, explicit validation ensures consistent resource usage and provides clear error messages.
