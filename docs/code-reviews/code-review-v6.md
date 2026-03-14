# Code Review v6 — Verified Findings

**Date**: 2026-03-13
**Scope**: Full codebase security, efficiency, stability, memory review
**Method**: 6 parallel review agents + manual verification of every finding against source code
**Status**: ALL FIXED — 33 confirmed issues (0 CRITICAL, 5 HIGH, 16 MEDIUM, 12 LOW) — all resolved 2026-03-13
**Previous**: Builds on v5 (18 issues). Adds 15 new confirmed issues, re-opens 1 v5 FP, keeps all 17 unfixed v5 issues.

## Legend

- **Status**: `FIXED` = confirmed and resolved | `OPEN` = confirmed, needs fix | `FP` = false positive | `WONTFIX` = accepted risk
- **Source**: `v5` = carried from v5 | `v6` = new in this review
- **Limits**: Whether the fix could impose functionality limitations

---

## HIGH (5)

### H1: `_decompile_on_demand_waiting` not cleared on lock timeout [v5]
- **File**: `arkana/mcp/tools_angr.py:393-397, 1816-1820`
- **Status**: FIXED
- **Limits**: No — only changes error-path behavior
- **Description**: Both `decompile_function_with_angr` (line 393) and `batch_decompile` (line 1816) set `state._decompile_on_demand_waiting = True` before acquiring `_decompile_lock`. If lock acquisition times out, the code raises `RuntimeError` but never resets the flag. The flag remains `True` permanently, causing the background enrichment sweep to yield on every iteration, effectively pausing enrichment forever.
- **Fix**: Reset `state._decompile_on_demand_waiting = False` before raising the RuntimeError on timeout, or wrap in try/finally.

### H2: `find_path_with_custom_input` / `emulate_with_watchpoints` missing `max_steps` validation [v5]
- **File**: `arkana/mcp/tools_angr_forensic.py:649, 828`
- **Status**: FIXED
- **Limits**: No — adds upper bound (100K steps is far beyond useful)
- **Description**: Both tools accept `max_steps` with no upper bound. A caller can pass `max_steps=999_999_999`, causing unbounded CPU and memory usage.
- **Fix**: Add `max_steps = min(max_steps, MAX_SYMBOLIC_STEPS)` (e.g., 100,000 cap).

### H3: `analyze_batch` `_parse_single_file` reads files without size limit [v5]
- **File**: `arkana/mcp/tools_batch.py:54-61`
- **Status**: FIXED
- **Limits**: No — a 200MB file cap is generous for any analysis target
- **Description**: `f.read()` without checking `os.path.getsize()` result first. Up to 50 files in batch mode.
- **Fix**: Reject files above 200MB.

### H4: `shellcode_hex` parameters have no size limit before hex decode [v5]
- **File**: `arkana/mcp/tools_qiling.py:266`, `arkana/mcp/tools_new_libs.py:715`
- **Status**: FIXED
- **Limits**: No — 10MB shellcode is far beyond any real shellcode
- **Description**: `bytes.fromhex()` called on unbounded input. A 200MB hex string allocates 300MB+.
- **Fix**: Validate `len(shellcode_hex) <= 20_000_000` (20MB hex = 10MB shellcode).

### H5: `batch_decompile` holds `threading.Lock` across `await` [v6-NEW]
- **File**: `arkana/mcp/tools_angr.py:1834-1955`
- **Status**: FIXED
- **Limits**: No — restructuring lock scope doesn't change functionality
- **Description**: `state._decompile_lock` is acquired at line 1834 and held until the `finally` block at line 1955. Between those points, the function executes multiple `await` expressions (line 1843: `await ctx.report_progress`, line 1903: `await asyncio.to_thread(_decompile_one)`). Holding a `threading.Lock` across `await` means the async function suspends while holding the lock. If another coroutine in the same event loop tries to acquire the same lock, it blocks the entire event loop thread — deadlock. Contrast with `decompile_function_with_angr` where the lock is acquired/released entirely within `asyncio.to_thread()`.
- **Fix**: Move the lock acquisition into the per-function `_decompile_one` thread worker, or use an `asyncio.Lock` instead. Each function can independently acquire/release the lock within its thread worker.

---

## MEDIUM (16)

### M1: `_parse_floss_static_only` unbounded static string list [v5]
- **File**: `arkana/parsers/floss.py:229-233`
- **Status**: FIXED
- **Limits**: No — `_MAX_STATIC_STRINGS` (200K) is already the cap on the full analysis path
- **Description**: Static-only path has no cap while full analysis path caps at 200K.
- **Fix**: Apply `_MAX_STATIC_STRINGS` cap.

### M2: `refinery_pipeline` steps list unbounded [v5]
- **File**: `arkana/mcp/tools_refinery.py:1247-1249`
- **Status**: FIXED
- **Limits**: No — 50 steps is far beyond any practical pipeline
- **Description**: No cap on number of pipeline steps.
- **Fix**: Add `_MAX_PIPELINE_STEPS = 50` cap.

### M3: CSV newline escaping in `_build_csv` [v5]
- **File**: `arkana/mcp/tools_ioc.py:194-206`
- **Status**: FIXED
- **Limits**: No — stripping newlines from IOC values is always correct
- **Description**: Newlines in IOC values break CSV row boundaries.
- **Fix**: Strip `\n` and `\r` from values.

### M4: Search helpers don't use `safe_regex_search` [v5]
- **File**: `arkana/mcp/_search_helpers.py:102, 177`
- **Status**: FIXED
- **Limits**: No — adds timeout protection without changing results
- **Description**: Direct `compiled.search(line)` can hang on pathological patterns.
- **Fix**: Use `safe_regex_search(compiled, line)`.

### M5: `reconstruct_pe_from_dump` hex decoded before size check [v5]
- **File**: `arkana/mcp/tools_unpack.py:261-269`
- **Status**: FIXED
- **Limits**: No — just moves size check before allocation
- **Description**: Full hex decode happens before size validation.
- **Fix**: Check `len(data_hex)` before `bytes.fromhex()`.

### M6: YARA rule string escaping incomplete [v5]
- **File**: `arkana/mcp/tools_pe_forensic.py:105, 123`
- **Status**: FIXED
- **Limits**: No — proper escaping produces correct YARA rules
- **Description**: `\n`, `\t`, `\x` not escaped in YARA double-quoted strings.
- **Fix**: Escape all YARA special sequences.

### M7: `_decompile_meta` is module-level global, not per-session [v5]
- **File**: `arkana/mcp/tools_angr.py:24`
- **Status**: FIXED
- **Limits**: No — per-session scoping is correct behavior
- **Description**: Cross-session data leak. User A can see User B's decompiled code in HTTP mode.
- **Fix**: Include session ID in cache key or make per-state.

### M8: `get_cross_reference_map` `depth` parameter unbounded [v5]
- **File**: `arkana/mcp/tools_angr.py:1618, 1685-1703`
- **Status**: FIXED
- **Limits**: No — depth=5 cap is generous for any practical use
- **Description**: No upper bound on recursive callee traversal depth.
- **Fix**: Clamp `depth = min(depth, 5)`.

### M9: `find_path_to_address` hardcodes `max_steps=2000` ignoring user control [v6-NEW]
- **File**: `arkana/mcp/tools_angr.py:722`
- **Status**: FIXED
- **Limits**: No — adding a parameter increases flexibility
- **Description**: `find_path_to_address` hardcodes `max_steps = 2000` at line 722. The sibling tool `find_path_with_custom_input` accepts `max_steps` as a parameter (default 2000). Users have no way to increase or decrease the step limit for `find_path_to_address`.
- **Fix**: Add `max_steps: int = 2000` parameter to the function signature with validation `max_steps = min(max(max_steps, 1), 100_000)`.

### M10: `safe_regex_search` thread leak on timeout [v6-NEW]
- **File**: `arkana/utils.py:120-137`
- **Status**: FIXED
- **Limits**: No — improved resource management doesn't affect results
- **Description**: When a regex search times out, `future.cancel()` is called but cannot stop an already-running thread. The thread continues running indefinitely. With `max_workers=4`, pool exhaustion is possible after 4 timeouts. Mitigated by upstream `validate_regex_pattern()` rejecting common ReDoS patterns, but patterns that slip through can permanently consume a thread.
- **Fix**: Consider using `concurrent.futures.ProcessPoolExecutor` instead (processes can be killed), or implement a watchdog that recreates the pool after detecting stuck threads. The monitoring at lines 127-131 already detects the condition but doesn't remediate it.

### M11: `_phase_caches` keyed by singleton proxy `id()` — no session isolation [v6-NEW, re-opened v5 FP6]
- **File**: `arkana/mcp/tools_session.py:25, 40`
- **Status**: FIXED (was re-opened from v5 FP6)
- **Limits**: No — using a real session identifier is correct behavior
- **Description**: v5 rejected this as FP6 citing eviction + cleanup logic. However, the `state` object is a `StateProxy` singleton — `id(state)` always returns the same value regardless of which session is active. All sessions share a single cache entry. The comment "keyed by id(state) for session isolation" is incorrect. While the 2s TTL and simple string output limit practical impact, the code's documented intent (session isolation) does not match its behavior.
- **Fix**: Use `id(get_current_state())` or `state._state_uuid` in the cache key.

### M12: Sigma rule YAML injection via unescaped filename [v6-NEW]
- **File**: `arkana/mcp/tools_threat_intel.py:583, 659`
- **Status**: FIXED
- **Limits**: No — proper escaping produces correct Sigma rules
- **Description**: In `generate_sigma_rule`, the `filename` parameter is properly escaped for the rule title (line 601: `safe_filename`) but NOT escaped in detection items (lines 583, 659). A filename containing a single quote `'` breaks the YAML single-quoted string structure. Other triage strings like `file_paths` ARE properly escaped (lines 662, 729, 785, 790), making this an inconsistency.
- **Fix**: Apply the same `replace("'", "''").replace("\\", "\\\\")` escaping to `filename` in detection items.

### M13: `_score_family` substring match produces false positives on short names [v6-NEW]
- **File**: `arkana/mcp/tools_malware_identify.py:490-495`
- **Status**: FIXED
- **Limits**: Minimal — requiring 4+ char matches or exact-match only for short names is reasonable
- **Description**: `_score_family` uses `name in s_lower` and `s_lower in name` substring matching with no length guard. Family aliases like "rat", "bot", "apt" match arbitrary strings ("operating", "about", "capture"). The `_FAMILY_NAME_WEIGHT` of 0.95 heavily inflates scores on false matches.
- **Fix**: Add minimum length threshold (e.g., 4 chars) for substring matching, or require exact match for names shorter than 4 characters.

### M14: `_collect_all_string_values` reads shared state without locking [v6-NEW]
- **File**: `arkana/mcp/tools_triage.py:71-114`
- **Status**: FIXED
- **Limits**: No — brief lock acquisition doesn't cause contention
- **Description**: Reads `state.pe_data['floss_analysis']` without holding any lock. FLOSS background task writes to this key from a daemon thread. While CPython's GIL prevents crashes, the function can see partially-updated FLOSS data.
- **Fix**: Take a snapshot of needed keys under `state._pe_lock`.

### M15: `_get_cached_flat_strings` builds unbounded cached lists [v6-NEW]
- **File**: `arkana/mcp/tools_strings.py:41-121`
- **Status**: FIXED
- **Limits**: Minimal — 100K string cap is generous; downstream consumers already have limits
- **Description**: Builds and caches a flat list of all strings (FLOSS + basic ASCII). With 5 LRU slots and no cap, up to 5 copies of potentially enormous lists can be cached simultaneously.
- **Fix**: Cap at `_MAX_FLAT_STRINGS = 100_000`.

### M16: `identify_cpp_classes` duplicate dict key `method_count` [v6-NEW]
- **File**: `arkana/mcp/tools_angr_forensic.py:1185-1187`
- **Status**: FIXED
- **Limits**: No — renaming a key is purely a correctness fix
- **Description**: The vtable dict has `"method_count": consecutive_funcs` at line 1185 and `"method_count": len(methods)` at line 1187. The second silently overwrites the first. `consecutive_funcs` (the number of consecutive function pointers detected) is lost.
- **Fix**: Rename line 1185 to `"consecutive_count": consecutive_funcs` or line 1187 to `"total_methods": len(methods)`.

---

## LOW (12)

### L1: Functions cache returns shallow copy of mutable inner objects [v5]
- **File**: `arkana/dashboard/state_api.py:956`
- **Status**: FIXED
- **Limits**: No
- **Description**: `list(cached_data)` is a shallow copy; inner dicts are shared references. No caller currently mutates, but the pattern is fragile.
- **Fix**: Document the read-only contract or use `copy.deepcopy()`.

### L2: Config directory created without restrictive permissions [v5]
- **File**: `arkana/user_config.py:33`
- **Status**: FIXED
- **Limits**: No
- **Description**: `~/.arkana/` created with default umask (typically 0o755). Stores API keys and tokens.
- **Fix**: Add `mode=0o700` to `mkdir()`.

### L3: `qiling_resolve_api_hashes` `hash_values` list unbounded [v5]
- **File**: `arkana/mcp/tools_qiling.py:531`
- **Status**: FIXED
- **Limits**: No — 1000 hashes is far beyond any real use
- **Description**: O(hash_values × known_apis) computation with no cap.
- **Fix**: Cap at 1000.

### L4: `datetime.utcfromtimestamp` deprecated in Python 3.12+ [v5]
- **File**: `arkana/mcp/tools_batch.py:190`
- **Status**: FIXED
- **Limits**: No
- **Description**: Deprecated, will be removed in future Python versions.
- **Fix**: Use `datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc)`.

### L5: PE object leak on early parse error in `_parse_single_file` [v5]
- **File**: `arkana/mcp/tools_batch.py:84-92`
- **Status**: FIXED
- **Limits**: No
- **Description**: `pe.close()` not called if `parse_data_directories()` raises.
- **Fix**: Add `pe.close()` in except handler.

### L6: `find_path_with_custom_input` deferred stash not capped [v5]
- **File**: `arkana/mcp/tools_angr_forensic.py:735-737`
- **Status**: FIXED
- **Limits**: No — 500-state cap matches `find_path_to_address`
- **Description**: Splits to deferred at line 736 but never prunes. `find_path_to_address` already has a 500-state cap.
- **Fix**: Add deferred stash pruning matching `find_path_to_address` pattern.

### L7: Session reaper thread starts unconditionally at import time [v6-NEW]
- **File**: `arkana/state.py:829-830`
- **Status**: FIXED
- **Limits**: No — lazy start doesn't change behavior
- **Description**: `_reaper_thread.start()` at module scope spawns a daemon thread on every import. Unnecessary overhead during tests, CLI help, etc.
- **Fix**: Start lazily on first session creation or via explicit `start()` call from `main.py`.

### L8: `compute_similarity_hashes` reads file without size check [v6-NEW]
- **File**: `arkana/mcp/tools_new_libs.py:510-512`
- **Status**: FIXED
- **Limits**: No — a 500MB cap is generous
- **Description**: `f.read()` without checking file size. Path validation exists but no size guard.
- **Fix**: Add `os.path.getsize()` check before read.

### L9: `_compute_authenticode_hash` doesn't validate `e_lfanew` bounds [v6-NEW]
- **File**: `arkana/mcp/tools_pe_forensic.py:575-605`
- **Status**: FIXED
- **Limits**: No — defense-in-depth improvement
- **Description**: `pe_offset` from `struct.unpack_from('<I', data, 0x3C)` used without bounds check. Protected by outer `try/except Exception` returning `None`, and pefile pre-validates the PE, so practically safe. Adding a bounds check improves diagnostic clarity.
- **Fix**: Add `if pe_offset + 92 > len(data): return None` after reading pe_offset.

### L10: `generate_yara_rule` empty rule name possible [v6-NEW]
- **File**: `arkana/mcp/tools_pe_forensic.py:85`
- **Status**: FIXED
- **Limits**: No
- **Description**: After sanitizing non-alphanumeric chars, `name[0].isdigit()` could raise `IndexError` if name is empty (unlikely in practice due to fallback naming).
- **Fix**: Add `if not name: name = "rule_unknown"` guard.

### L11: `batch_rename` skips name length validation [v6-NEW]
- **File**: `arkana/mcp/tools_rename.py:207-246`
- **Status**: FIXED
- **Limits**: No — applies existing single-rename validation consistently
- **Description**: Single `rename_function`/`rename_variable` tools validate `len(new_name) > 200`, but batch mode validation pass does not check name length.
- **Fix**: Apply same length check in batch validation.

### L12: `refinery_hash` imports reconstructed inside loop [v6-NEW]
- **File**: `arkana/mcp/tools_refinery.py:981-1001`
- **Status**: FIXED
- **Limits**: No — purely an efficiency improvement
- **Description**: Hash unit imports and `_hash_units` dict are rebuilt inside the `for algo in algorithms` loop. Python caches module imports but the lookup overhead is unnecessary.
- **Fix**: Hoist imports and dict above the loop.

---

## Rejected / False Positives

### Carried from v5
| ID | Claim | Verdict | Reason |
|----|-------|---------|--------|
| FP1 | SSE connection counter TOCTOU race | FALSE POSITIVE | Inner check atomically increments under `_sse_lock` |
| FP2 | capa_parser double-checked locking unsafe | FALSE POSITIVE | CPython GIL protects atomic reads |
| FP3 | Progress closure captures stale state | FALSE POSITIVE | Correct capture at invocation time |
| FP4 | Enrichment ContextVar not inherited by threads | FALSE POSITIVE | Explicit parameter passing used |
| FP5 | `import_project` decompression bomb | FALSE POSITIVE | 257MB archive cap exists |
| FP7 | CSP missing `connect-src` directive | FALSE POSITIVE | `default-src 'self'` covers it |
| FP8 | Rate limiter O(n log n) sort per request | FALSE POSITIVE | Bounded by 1000-entry cap |

**Note**: v5 FP6 (`_phase_caches` session isolation) has been re-opened as M11 after deeper analysis confirmed the `StateProxy` singleton issue.

### New in v6
| ID | Claim | Verdict | Reason |
|----|-------|---------|--------|
| FP9 | `_save_enrichment_cache()` shallow copy of `pe_data` | FALSE POSITIVE | Shallow copy is intentional — prevents key injection into `state.pe_data`. No concurrent mutation during serialization. |
| FP10 | Full API key printed to stderr in `main.py:505` | FALSE POSITIVE | Intentional design — auto-generated key must be communicated to operator. Uses stderr (not logger), won't appear in log files. Standard pattern for credential-generating tools. |
| FP11 | `register_binary` DELETE+INSERT not transactional in `_bsim_features.py:516-523` | FALSE POSITIVE | Python sqlite3 module wraps DML in implicit transactions. DELETE and INSERT share the same transaction. If INSERT fails, the `except BaseException` closes the connection, implicitly rolling back both. The caller commits after all operations succeed. |
| FP12 | `map_mitre_attack` cache bypasses `output_path` write | FALSE POSITIVE | The docstring states `output_path` requires `include_navigator_layer=True`. When `include_navigator_layer=True`, the cache is bypassed (line 236 condition). So `output_path` is always reached when properly used. The cache only returns early when `include_navigator_layer=False`, which makes `output_path` meaningless per the API contract. |
| FP13 | RC4 missing preview-based scoring in `brute_force_simple_crypto` | FALSE POSITIVE | RC4 only tries ~12 candidate keys (vs 255 for XOR single-byte). The performance savings from preview-based scoring would be negligible. Total RC4 work is ~12MB maximum. |
| FP14 | `brute_force_simple_crypto` holds full decrypted data for all results | FALSE POSITIVE | Max 10 results × max 1MB = 10MB peak. This is within normal operating memory for an analysis server. The `_raw` field is stripped before response. |
| FP15 | `auto_extract_crypto_keys` excessive CPU from unguarded inner loop | FALSE POSITIVE | The existing `10_000` candidate cap limits total work. Crypto constants rarely appear more than a few times in real binaries. The loop is already bounded. |
| FP16 | `refinery_forensic` `lnk` operation bypasses size limit | FALSE POSITIVE | LNK files are always small. The overall MCP request size limits the input. Adding a dedicated cap for a single format is over-engineering. |

---

## Pattern Summary

| Pattern | Confirmed instances | Files affected |
|---------|-------------------|----------------|
| `bytes.fromhex()` without pre-decode size check | 17 unguarded across codebase | ~12 |
| `f.read()` without size limit on external files | 7 unguarded instances | ~5 |
| Unbounded `List` parameters (no length cap) | 17+ unguarded instances | ~10 |
| `_decompile_on_demand_waiting` not cleared on error | 2 (decompile + batch_decompile) | 1 |
| Direct `compiled.search()` instead of `safe_regex_search()` | 2 (both in _search_helpers.py) | 1 |
| Module-level caches without session scoping | 2 (`_decompile_meta`, `_phase_caches`) | 2 |
| Duplicate/conflicting dict keys | 1 (tools_angr_forensic.py) | 1 |
| Lock held across async boundaries | 1 (batch_decompile) | 1 |

---

## Systemic Patterns Requiring Attention

### Pattern A: `bytes.fromhex()` pre-validation
17 tool functions accept hex string parameters and call `bytes.fromhex()` without first checking `len(hex_str)`. The hex string is twice the size of the decoded bytes, so a 200MB hex string allocates 100MB of bytes. A consistent pre-validation helper like `_validate_hex_size(hex_str, max_bytes=10*1024*1024)` should be applied across all tools accepting hex input.

### Pattern B: `f.read()` on user-supplied paths
7 instances where tools open user-supplied file paths and call `f.read()` without checking file size first. While `open_file` has size checks, tools that independently read files (batch analysis, diff, reconstruct, similarity hashes) bypass these.

### Pattern C: Unbounded list parameters
17+ tools accept `List[str]` parameters without length caps. While MCP request size limits provide a soft bound, explicit validation ensures consistent resource usage and provides clear error messages.

### Pattern D: Module-level caches without session isolation
At least 2 module-level caches (`_decompile_meta` in tools_angr.py, `_phase_caches` in tools_session.py) are shared across sessions. In HTTP multi-session mode, this causes cross-session data leakage or stale results. Session-scoped caches should include `state._state_uuid` or equivalent in cache keys.

### Pattern E: Lock scope in async functions
`batch_decompile` holds a `threading.Lock` across `await` expressions. This pattern should be audited across all async tools that acquire locks — the lock should be held only within synchronous code running in `asyncio.to_thread()`, never across await boundaries.
