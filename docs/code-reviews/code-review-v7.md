# Code Review v7 — Verified Findings

**Date**: 2026-03-13
**Scope**: Full codebase security, efficiency, stability, memory review
**Method**: 6 parallel review agents + 4 parallel validation agents + comprehensive pattern search
**Status**: ALL FIXED — 37 confirmed issues (0 CRITICAL, 4 HIGH, 18 MEDIUM, 15 LOW), all resolved
**Previous**: Builds on v6 (33 issues, all fixed). All v7 findings are NEW issues not covered in v6.

## Legend

- **Status**: `OPEN` = confirmed, needs fix | `FP` = false positive | `WONTFIX` = accepted risk
- **Limits**: Whether the fix could impose functionality limitations

---

## HIGH (4)

### H1: ThreadPoolExecutor `with` block negates timeout in `_parse_pe_to_dict`
- **File**: `arkana/parsers/pe.py:1107-1128`
- **Status**: FIXED
- **Limits**: No — changing to `shutdown(wait=False, cancel_futures=True)` doesn't affect normal operation
- **Description**: When capa or FLOSS tasks time out via `future.result(timeout=...)`, the `with ThreadPoolExecutor() as pool:` context manager calls `pool.shutdown(wait=True)` at `__exit__`, blocking until the timed-out thread actually finishes. The timeout is effectively negated — the function waits indefinitely for the hung thread. The code even acknowledges this: `"the thread may still be running in the background"`.
- **Fix**: After handling all futures, call `pool.shutdown(wait=False, cancel_futures=True)` (Python 3.9+) and `break` out of the `with` block, or restructure to avoid the context manager.

### H2: ThreadPoolExecutor `with` block negates CFG timeout in `angr_background_worker`
- **File**: `arkana/background.py:277-308`
- **Status**: FIXED
- **Limits**: No — same fix pattern as H1
- **Description**: Same pattern as H1. The CFG build runs inside `with ThreadPoolExecutor(max_workers=1) as executor:`. When `future.result(timeout=cfg_timeout)` raises `TimeoutError`, the function returns, but `__exit__` blocks until the CFG thread completes — potentially far longer than `cfg_timeout`.
- **Fix**: Call `executor.shutdown(wait=False, cancel_futures=True)` before returning from the timeout handler.

### H3: `refinery_decompress` checks output size limit AFTER full decompression
- **File**: `arkana/mcp/tools_refinery.py:514-524`
- **Status**: FIXED
- **Limits**: No — streaming decompression with a cap is functionally equivalent
- **Description**: The decompression at line 518 (`data | unit_cls() | bytes`) runs fully in memory before the 100MB limit check at line 523. A 10MB input (within `_MAX_INPUT_SIZE`) with a 1000:1 compression ratio would allocate ~10GB in memory before truncation. This is a decompression bomb vector.
- **Fix**: Use streaming decompression with an incremental output cap. Alternatively, wrap in a subprocess with memory limits, or add a pre-check on expected compression ratio.

### H4: `import_project` reads artifact files from tar without size limit
- **File**: `arkana/mcp/tools_export.py:327-347`
- **Status**: FIXED
- **Limits**: No — adding `MAX_ARTIFACT_FILE_SIZE` check matches export behavior
- **Description**: Artifact files in the import archive are read via `af.read()` (line 346) with no `member.size` check. Binary files have `_MAX_IMPORT_BINARY_SIZE` (line 308), but artifacts have no equivalent limit. A malicious archive could contain artifact entries of arbitrary size, exhausting memory. The existing `MAX_ARTIFACT_FILE_SIZE` constant (100MB) from `constants.py` is not referenced during import.
- **Fix**: Add `if member.size > MAX_ARTIFACT_FILE_SIZE: continue` before reading artifact members. Also add a total artifact size accumulator with a cap.

---

## MEDIUM (18)

### M1: `_hex_to_bytes` has no input size limit
- **File**: `arkana/mcp/_refinery_helpers.py:30-38`
- **Status**: FIXED
- **Limits**: No — a 20MB hex limit (10MB decoded) is generous for any refinery operation
- **Description**: `_hex_to_bytes()` converts arbitrary-length hex strings to bytes with no size limit. Most callers check size AFTER conversion, meaning memory is allocated before validation. 17+ call sites across 7 files lack pre-conversion size checks.
- **Fix**: Add `if len(hex_string) > _MAX_HEX_INPUT_LEN: raise ValueError(...)` at the top of `_hex_to_bytes()`. Set `_MAX_HEX_INPUT_LEN = 20_000_000` (20MB hex = 10MB bytes).

### M2: `angr_hooks` dict accessed without lock protection
- **File**: `arkana/state.py:73`, `arkana/mcp/tools_angr_hooks.py:90,97,123,172`, `arkana/mcp/_angr_helpers.py:33,91`
- **Status**: FIXED
- **Limits**: No — adding lock acquisition doesn't change behavior
- **Description**: `angr_hooks` is a plain dict. `reset_angr()` clears it under `_angr_lock`, but all reads and writes in `tools_angr_hooks.py` and `_angr_helpers.py` (`.items()`, `.__setitem__`, `.pop()`, `.values()`) are completely unprotected. Concurrent hook and CFG rebuild operations could cause `RuntimeError: dictionary changed size during iteration`.
- **Fix**: Protect all `angr_hooks` access with `_angr_lock` in `tools_angr_hooks.py` and `_angr_helpers.py`.

### M3: `_ensure_project_and_cfg` uses stale project reference after hooks rebuild
- **File**: `arkana/mcp/_angr_helpers.py:85-101`
- **Status**: FIXED
- **Limits**: No — refreshing the project reference is correct behavior
- **Description**: After the `_rebuild_project_with_hooks()` call inside the lock block (line 92), the `project` variable used at line 96 (`project.analyses.CFGFast(...)`) still references the old project from line 88 (pre-hooks). The re-read at line 93 refreshes within the lock, but the CFG is built outside the lock (line 96) using the stale reference. If hooks are installed between line 88 and 96, the CFG is built on the wrong project.
- **Fix**: After releasing the lock at line 93, refresh the project: `project, _ = state.get_angr_snapshot()` before building CFG at line 96.

### M4: `get_backward_slice` / `get_forward_slice` unbounded graph traversal
- **File**: `arkana/mcp/tools_angr.py:1172,1225`, `arkana/mcp/tools_angr_forensic.py:1303`
- **Status**: FIXED
- **Limits**: No — a 10K node cap is far beyond useful for a slice display
- **Description**: `nx.ancestors()` and `nx.descendants()` traverse the entire reachable CFG graph (potentially 50K+ nodes) before `[:limit]` slices the output. The traversal itself is unbounded in memory and CPU. Three instances across two files.
- **Fix**: Replace with bounded BFS that stops after visiting `max_nodes` (e.g., 10,000) nodes, instead of computing the full transitive closure and truncating.

### M5: `search_yara_custom` has no timeout on YARA scan
- **File**: `arkana/mcp/tools_strings.py:1409`
- **Status**: FIXED
- **Limits**: No — adding a timeout prevents hangs without affecting normal scans
- **Description**: `compiled.match(filepath)` runs without the `timeout` parameter that `yara-python` supports. A deliberately complex user-supplied YARA rule could scan indefinitely. The 256KB rule size limit helps but does not prevent CPU-intensive rules. Two additional instances in `signatures.py:214` (builtin rules, lower risk) and `tools_pe_forensic.py:220` (generated rules, lower risk).
- **Fix**: Add `timeout=120` to `compiled.match(filepath, timeout=120)` for user-supplied rules. Consider `timeout=300` for builtin rule scans.

### M6: `import_project` bypasses cache eviction via `insert_raw_entry`
- **File**: `arkana/mcp/tools_export.py:356-374`, `arkana/cache.py:547-558`
- **Status**: FIXED
- **Limits**: No — calling eviction after insert is correct behavior
- **Description**: `import_project` writes directly to the cache filesystem and registers metadata via `analysis_cache.insert_raw_entry()`, which does NOT call `_evict_if_needed()`. The normal `put()` method does call eviction. Repeated imports can grow the cache beyond `ARKANA_CACHE_MAX_SIZE_MB`.
- **Fix**: Add `self._evict_if_needed(meta)` call inside `insert_raw_entry()` after updating the metadata, or call it from the import_project caller.

### M7: `get_functions_data()` cache version key invalidated too frequently
- **File**: `arkana/dashboard/state_api.py:948-950`
- **Status**: FIXED
- **Limits**: No — using targeted version components improves cache hit rate
- **Description**: The cache version key includes `len(st.get_tool_history())` which changes on EVERY MCP tool call. This means the 2-second TTL cache is invalidated every time any tool runs (even unrelated tools like `add_note` or `search_hex_pattern`), effectively making the cache useless during active analysis sessions.
- **Fix**: Replace `len(tool_history)` with function-relevant change signals: angr KB function count, renames dict length, and triage status snapshot length.

### M8: `get_strings_data()` has no cache — full rebuild on every pagination request
- **File**: `arkana/dashboard/state_api.py:1633-1786`
- **Status**: FIXED
- **Limits**: No — a short TTL cache is consistent with other data functions
- **Description**: Unlike `get_overview_data()` and `get_functions_data()` which have TTL caches, `get_strings_data()` rebuilds the entire filtered/sorted string list on every request. Each pagination click, sort change, or filter change triggers a full rebuild. For binaries with tens of thousands of strings, this causes noticeable latency.
- **Fix**: Add a short-TTL version-keyed cache (similar to `_functions_cache`), so rapid pagination requests with the same filters reuse the sorted list.

### M9: `export_project` tar.add follows symlinks for both binary and artifacts
- **File**: `arkana/mcp/tools_export.py:151,168`
- **Status**: FIXED
- **Limits**: No — preventing symlink following is correct for security
- **Description**: `tar.add(binary_path, ...)` and `tar.add(art_path, ...)` follow symlinks by default. If the loaded binary or any artifact path is a symlink pointing to a sensitive file (e.g., `/etc/shadow`), its contents would be included in the export archive. The import path correctly rejects symlinks (line 234), but the export path does not check.
- **Fix**: Add `os.path.islink()` checks before `tar.add()`, or use `tar.add(..., follow_symlinks=False)` (Python 3.10+). Alternatively, resolve with `os.path.realpath()` and validate the resolved path.

### M10: `_ToolResultCache` has no global memory bound across all tools
- **File**: `arkana/mcp/_input_helpers.py:43-98`
- **Status**: FIXED
- **Limits**: No — adding a global cap with LRU eviction is defensive, not restrictive
- **Description**: Per-tool LRU limits (5 slots) and TTL (1 hour) are applied, but there is no global memory bound. With 212 tools, the worst case is 1,060 cached entries. If entries contain large results (thousands of items per entry, each holding complex dicts), aggregate memory usage can grow significantly. Stale entries are only evicted on `get()`, not proactively.
- **Fix**: Add a global entry count limit (e.g., 200 total across all tools) with LRU eviction. Alternatively, add periodic sweep of expired entries.

### M11: `cache.py` `put()` creates large transient memory spike during serialization
- **File**: `arkana/cache.py:289-292`
- **Status**: FIXED
- **Limits**: No — streaming serialization produces identical output
- **Description**: `json.dumps(wrapper).encode("utf-8")` creates a full JSON string, `.encode()` creates a bytes copy, then `gzip.compress()` creates a third buffer. For large `pe_data` with 2000 cached function decompilations, this can transiently hold 2-3x the uncompressed JSON size in memory simultaneously.
- **Fix**: Use streaming approach: `gzip.open(tmp, "wt", encoding="utf-8")` with `json.dump(wrapper, f)` to avoid holding the full uncompressed string in memory.

### M12: `_collect_iocs_from_notes` no early exit when all IOC categories are full
- **File**: `arkana/mcp/tools_ioc.py:86-124`
- **Status**: FIXED
- **Limits**: No — early exit is an optimization, not a limitation
- **Description**: The outer note iteration loop continues running all 6 regex patterns against every note even when all IOC categories have reached their 10K cap (`_MAX_IOCS_PER_CATEGORY`). With up to 10K notes, this is wasted computation.
- **Fix**: Add `if all(len(v) >= _MAX_IOCS_PER_CATEGORY for v in iocs.values()): break` at the start of the outer loop.

### M13: `_decompile_on_demand_waiting` boolean flag not per-call, enables race
- **File**: `arkana/mcp/tools_angr.py:1896-1902`, `arkana/state.py:129`
- **Status**: FIXED
- **Limits**: No — using a counter or Event per invocation is more correct
- **Description**: `_decompile_on_demand_waiting` is a single boolean on `AnalyzerState`. If two concurrent decompile calls run, the second call sets it to `True` after the first has already cleared it. The first caller clearing it to `False` also clears the second caller's signal, causing the background enrichment sweep to not yield for the second call.
- **Fix**: Replace with an atomic counter (`_decompile_on_demand_count`) that increments on start and decrements on finish. Background sweep yields when count > 0.

### M14: `get_global_data_refs` rebuilds expensive CFG without caching the result
- **File**: `arkana/mcp/tools_angr.py:1526`
- **Status**: FIXED
- **Limits**: No — caching the CFG improves performance without limiting functionality
- **Description**: When the existing CFG lacks data references, `project.analyses.CFGFast(normalize=True, collect_data_references=True)` is built from scratch on every call. The newly built CFG is not stored in state or cache for reuse. Subsequent calls for different functions rebuild the entire CFG each time.
- **Fix**: Store the data-reference CFG in `state.result_cache` or update `state.angr_cfg` with the enhanced CFG, so subsequent calls reuse it.

### M15: `_run_pipeline_single` has no intermediate size checks between steps
- **File**: `arkana/mcp/tools_refinery.py:1033-1202`
- **Status**: FIXED
- **Limits**: No — checking between steps prevents cascading decompression bombs
- **Description**: Pipeline steps execute sequentially, and decompression steps (`decompress`, `zl`, `bz2`, `lzma`) can produce output far larger than input. The initial input is bounded by `_MAX_INPUT_SIZE`, but after a decompression step, `current` can grow to gigabytes, and subsequent steps operate on it with no size guard.
- **Fix**: Add `if len(current) > _MAX_DECOMPRESS_OUTPUT: raise ValueError(...)` after each decompression-type step.

### M16: `_validate_with_signify` duplicates PE data in memory via BytesIO
- **File**: `arkana/mcp/tools_pe_forensic.py:518-521`
- **Status**: FIXED
- **Limits**: No — reading from disk avoids the copy without functional change
- **Description**: `io.BytesIO(pe.__data__)` creates an in-memory copy of the entire PE binary. Combined with `pe.__data__` already in memory, this doubles peak memory during signature validation. For 50MB+ PEs, this is significant.
- **Fix**: Open the file from disk instead: `with open(state.filepath, 'rb') as f: auth_file = AuthenticodeFile.from_stream(f)`.

### M17: `_compute_authenticode_hash` unknown PE magic falls through to PE32 offsets
- **File**: `arkana/mcp/tools_pe_forensic.py:589-598`
- **Status**: FIXED
- **Limits**: No — returning None for unknown magic is correct
- **Description**: The `else` branch for unknown PE magic values (not `0x10B` PE32 or `0x20B` PE32+) silently uses PE32 offset calculations, producing incorrect hashes for corrupt or non-standard PEs. Also, `sec_dir_offset` is not bounds-checked against `len(data)`.
- **Fix**: Return `None` for unknown magic values. Add bounds check: `if sec_dir_offset + 8 > len(data): return None`.

### M18: `capa_rules_cache` OrderedDict read without lock in fast path
- **File**: `arkana/parsers/capa.py:52-53`
- **Status**: FIXED
- **Limits**: No — adding lock for reads is negligible performance impact
- **Description**: The double-checked locking fast path reads `_capa_rules_cache.get(rules_key)` outside `_capa_rules_lock`. While safe under CPython's GIL, `OrderedDict` is not documented as thread-safe for concurrent reads alongside writes. The code already locks for `move_to_end` (acknowledging the issue) but not for `get`.
- **Fix**: Wrap the fast-path `get()` in `_capa_rules_lock` as well, or switch to a regular `dict` (which has stronger GIL-level guarantees).

---

## LOW (15)

### L1: `renames` dicts have no size limit
- **File**: `arkana/state.py:384-406`
- **Status**: FIXED
- **Limits**: No — a 10K cap matches notes/artifacts pattern
- **Description**: `rename_function`, `rename_variable`, and `add_label` insert into `state.renames` sub-dicts without size checks. Notes have `MAX_NOTES=10K`, artifacts have `MAX_ARTIFACTS=1K`, but renames have no equivalent cap.
- **Fix**: Add `MAX_RENAMES = 10_000` check per sub-dict.

### L2: `triage_status` dict has no size limit
- **File**: `arkana/state.py:538-544`
- **Status**: FIXED
- **Limits**: No — a 100K cap is far beyond any real binary
- **Description**: `set_triage_status` inserts into `self.triage_status` without size check. Programmatic callers could add entries for arbitrary addresses.
- **Fix**: Add `MAX_TRIAGE_STATUS = 100_000` check.

### L3: `install_warning_handler` can attach duplicate handlers
- **File**: `arkana/warning_handler.py:74-78`
- **Status**: FIXED
- **Limits**: No
- **Description**: Creates and attaches a new `LibraryWarningHandler` on every call with no idempotency guard. If called twice, warnings are processed twice (counts inflated). Currently only called once from `main.py:223`.
- **Fix**: Add `if any(isinstance(h, LibraryWarningHandler) for h in logging.getLogger().handlers): return`.

### L4: `cache.py` `put()` orphaned `.tmp` files on crash
- **File**: `arkana/cache.py:303-305`
- **Status**: FIXED
- **Limits**: No
- **Description**: If the process crashes between `tmp.write_bytes(compressed)` and `tmp.replace(entry_path)`, the `.tmp` file is left on disk. No cleanup on startup.
- **Fix**: Add `try/finally` with `tmp.unlink(missing_ok=True)` on error. Add startup sweep for orphaned `.tmp` files.

### L5: `auth.py` UTF-8 decode with `"ignore"` error handling
- **File**: `arkana/auth.py:53`
- **Status**: FIXED
- **Limits**: No
- **Description**: `decode("utf-8", "ignore")` silently strips invalid byte sequences. While practically unexploitable (API keys are ASCII), `"replace"` or `"strict"` would be marginally more defensive.
- **Fix**: Change to `decode("utf-8", "replace")`.

### L6: `ProgressBridge._dispatch` TOCTOU creates unawaited coroutines on loop close
- **File**: `arkana/mcp/_progress_bridge.py:82,92,122-130`
- **Status**: FIXED
- **Limits**: No
- **Description**: The event loop could close between the `is_closed()` check and coroutine creation, producing a `RuntimeWarning: coroutine was never awaited`. The exception handler in `_dispatch` catches the `RuntimeError` but the coroutine object is already created. Extremely narrow window (only during shutdown).
- **Fix**: Create the coroutine lazily inside `_dispatch` by passing a callable + args instead of a pre-created coroutine.

### L7: `_openDetailPanels` in functions.js grows without bound
- **File**: `arkana/dashboard/static/functions.js:5`
- **Status**: FIXED
- **Limits**: No
- **Description**: Stores panel state (including decompiled code) for every function the user opens. Unlike `_analysisCache` which has LRU (50 max), `_openDetailPanels` has no eviction.
- **Fix**: Apply LRU eviction similar to `_analysisCache`.

### L8: FLOSS auto-refresh timer not cleared on page navigation
- **File**: `arkana/dashboard/static/strings.js:328-332`
- **Status**: FIXED
- **Limits**: No
- **Description**: `_flossRefreshTimer` continues fetching `/api/floss-summary` every 5s even after navigating away from the strings page, producing unnecessary network requests.
- **Fix**: Add `visibilitychange` listener to pause, or check `document.hidden` before fetching.

### L9: `_list_files_cache` in state_api.py has no max-entries cap
- **File**: `arkana/dashboard/state_api.py:3188`
- **Status**: FIXED
- **Limits**: No
- **Description**: Has TTL (10s) but no max-entries bound. Unlike other state_api caches which cap at 4 entries. In practice bounded by distinct sample paths (typically 1).
- **Fix**: Add `_MAX_LIST_FILES_CACHE = 4` like other state_api caches.

### L10: `auto_note_function` batch mode blocks event loop without `asyncio.to_thread`
- **File**: `arkana/mcp/tools_notes.py:316,338`
- **Status**: FIXED
- **Limits**: No
- **Description**: `_auto_note_single()` performs angr callgraph lookups synchronously on the event loop. In batch mode (up to 20 functions), this could block briefly. The work is in-memory lookups (not CPU-heavy like decompilation), so practical impact is low.
- **Fix**: Wrap batch loop in `asyncio.to_thread()`.

### L11: `analysis_warnings` list uses `pop(0)` for LRU eviction (O(n))
- **File**: `arkana/state.py:592`
- **Status**: FIXED
- **Limits**: No
- **Description**: `self.analysis_warnings.pop(0)` is O(n) for a list. With `MAX_ANALYSIS_WARNINGS=500` this is minor, but a `deque(maxlen=...)` would be O(1).
- **Fix**: Change to `collections.deque(maxlen=MAX_ANALYSIS_WARNINGS)`.

### L12: `_SKIP` frozenset rebuilt on every `_make_cache_key` call
- **File**: `arkana/mcp/_input_helpers.py:126-134`
- **Status**: FIXED
- **Limits**: No
- **Description**: The `_SKIP` frozenset is defined inside the function body, reconstructed on every call. Moving to module level avoids ~22-element frozenset construction per tool invocation.
- **Fix**: Move `_SKIP` to module level.

### L13: `get_cross_reference_map` `_collect_callees` uses O(n) list membership check
- **File**: `arkana/mcp/tools_angr.py:1737`
- **Status**: FIXED
- **Limits**: No
- **Description**: `if cname not in calls` performs O(n) linear scan on a list. For functions with many callees at depth > 1, this is O(n^2). Also materializes blocks into a list just to count them (line 1775).
- **Fix**: Use a `set` for `calls` tracking. Use `func.graph.number_of_nodes()` instead of `len(list(func.blocks))`.

### L14: `refinery_codec` hex fallback warning not included in MCP response
- **File**: `arkana/mcp/tools_refinery.py:155-161`
- **Status**: FIXED
- **Limits**: No
- **Description**: When hex decode fails, the fallback to raw text is logged via `logger.warning()` but the warning is not included in the MCP response. The calling AI client receives no indication that its hex input was malformed.
- **Fix**: Add a `"warning"` field to the response dict.

### L15: `hashlib.md5()` / `hashlib.sha1()` without `usedforsecurity=False`
- **File**: `arkana/parsers/pe.py:62-63,157-158`
- **Status**: FIXED
- **Limits**: No
- **Description**: MD5 and SHA1 used for identification hashing (not security) fail on FIPS-compliant systems without `usedforsecurity=False` (Python 3.9+). The outer `try/except` catches this but the error message is generic.
- **Fix**: Add `usedforsecurity=False` parameter to all `hashlib.md5()` and `hashlib.sha1()` calls used for identification.

---

## Rejected / False Positives

| ID | Claim | Verdict | Reason |
|----|-------|---------|--------|
| FP1 | `_active_tool_lock` defined but never used for reads | FALSE POSITIVE | Lock IS used for both reads (state_api.py:885-888) and writes (server.py:187,197,249) |
| FP2 | `_reaper_started` race condition in `_start_session_reaper` | FALSE POSITIVE | Only call site (line 757) is inside `_registry_lock`. No race possible. |
| FP3 | `_DOMAIN_RE` has unbounded outer quantifier (ReDoS) | FALSE POSITIVE | Bounded character classes `[a-zA-Z0-9-]{0,61}` + literal dot separators prevent backtracking |
| FP4 | Sigma rule YAML injection via filename | FALSE POSITIVE | Already fixed in v6 (M12). Single-quote escaping is correct for YAML context. |
| FP5 | `_save_enrichment_cache` creates large dict copies | FALSE POSITIVE | The shallow `dict()` copy IS the v6 fix (replaces in-place mutation). O(N) pointers only. |
| FP6 | `_compute_authenticode_hash` CRITICAL security vulnerability | FALSE POSITIVE (severity downgrade) | Entire function is wrapped in `try/except Exception` returning `None`. pefile already validated the PE. Issue is real but MEDIUM, not CRITICAL — produces wrong hash, not a crash or exploit. |
| FP7 | `_run_qiling` arbitrary file read via filepath | FALSE POSITIVE | `filepath` comes from `state.filepath` which was validated during `open_file`. `output_path` is validated via `check_path_allowed()`. Trust boundary is documented. |
| FP8 | `_decompile_meta` module-level global cross-session | FALSE POSITIVE | Already fixed in v6 (M7). Now uses `state._state_uuid` in cache key. |
| FP9 | `batch_decompile` holds `threading.Lock` across `await` | FALSE POSITIVE | Already fixed in v6 (H5). Lock scope was restructured. |
| FP10 | ELF mmap strip detection unreliable | WONTFIX | Correctly documented as heuristic fallback only when pyelftools unavailable. Code annotates results with `"heuristic-based"`. |
| FP11 | `BSim store_binary_features` holds write lock for entire batch | WONTFIX | By design for SQLite (only one writer at a time). Lock does not block reads. Background task only. |
| FP12 | `query_similar_functions` 10K candidate scoring | WONTFIX | Block-count pre-filter eliminates ~80-90% of candidates. The 10K limit is a reasonable bound for the SQL pre-filter. Performance is acceptable for the use case. |
| FP13 | `_parse_floss_static_only` unbounded — v6 M1 | FALSE POSITIVE | Already fixed in v6. `_MAX_STATIC_STRINGS` cap applied. |
| FP14 | Module-level `_api_db_cache` / `_extended_names_cache` unbounded | FALSE POSITIVE | Static data file caches loaded once from bundled JSON files. Not a growth concern. |

---

## Pattern Summary

| Pattern | Confirmed instances | Files affected |
|---------|-------------------|----------------|
| ThreadPoolExecutor `with` block negating timeout | 2 instances | `parsers/pe.py`, `background.py` |
| `bytes.fromhex()` / `_hex_to_bytes` without pre-decode size check | 17+ unguarded call sites | `_refinery_helpers.py`, `tools_deobfuscation.py`, `tools_refinery.py`, `tools_refinery_advanced.py`, `tools_refinery_executable.py`, `tools_angr.py`, `tools_crypto.py`, `tools_payload.py` |
| YARA `match()` without timeout parameter | 3 instances | `signatures.py`, `tools_strings.py`, `tools_pe_forensic.py` |
| Export/import tar symlink following / missing size checks | 3 issues | `tools_export.py` |
| Unbounded `nx.ancestors`/`nx.descendants` graph traversal | 3 instances | `tools_angr.py`, `tools_angr_forensic.py` |
| Dashboard data functions missing cache | 1 instance | `state_api.py` (`get_strings_data`) |
| Dashboard cache invalidated too frequently | 1 instance | `state_api.py` (`get_functions_data`) |
| Decompression without streaming output limit | 2 instances | `tools_refinery.py` (decompress + pipeline) |
| Unbounded state dicts (no size cap) | 2 instances | `state.py` (renames, triage_status) |
| Dict/OrderedDict accessed without lock in multi-threaded context | 2 instances | `state.py` (angr_hooks), `parsers/capa.py` (rules cache) |

---

## Systemic Patterns Requiring Attention

### Pattern A: ThreadPoolExecutor `with` block + timeout = blocking exit
2 instances where `future.result(timeout=N)` is used inside a `with ThreadPoolExecutor() as pool:` block. When the timeout fires, the function handles the error, but the `with` block's `__exit__` calls `pool.shutdown(wait=True)`, which blocks until all submitted threads actually complete. This completely negates the timeout. Fix requires either manual shutdown with `wait=False, cancel_futures=True`, or restructuring to avoid the context manager.

### Pattern B: `bytes.fromhex()` pre-validation (continued from v6)
v6 identified 17 unguarded instances and fixed the most critical ones (`tools_qiling.py`, `tools_new_libs.py`, `tools_unpack.py`). However, 17+ additional call sites remain unguarded, primarily in refinery tools and deobfuscation tools. The centralized fix in `_hex_to_bytes()` would address most of these.

### Pattern C: YARA scan timeout
3 instances of `yara.match()` without the `timeout` parameter. The highest risk is `search_yara_custom` which accepts user-supplied rules. The builtin rule scans in `signatures.py` are lower risk but could still hang on pathological binaries.

### Pattern D: Decompression bomb protection
2 instances where decompression output size is checked only AFTER full decompression into memory. A consistent pattern of streaming decompression with incremental size limits would prevent decompression bomb attacks across all tools.

### Pattern E: Dashboard data function caching
While `get_overview_data()` and `get_functions_data()` have TTL caches, `get_strings_data()` does not. Additionally, `get_functions_data()` has its cache effectively invalidated on every tool call due to the `len(tool_history)` version key. Both should use targeted version keys and TTL caching.
