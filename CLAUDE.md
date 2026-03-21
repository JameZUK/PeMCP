# Arkana Development Guide

## What is Arkana?

Arkana is a Model Context Protocol (MCP) server exposing 256 binary analysis tools to AI clients. It supports PE, ELF, and Mach-O formats with integrations for angr, capa, FLOSS, YARA, Binary Refinery, Qiling, and Speakeasy.

## Project Structure

```
arkana/                  # Main package
├── main.py             # Entry point, arg parsing, server startup
├── state.py            # Thread-safe AnalyzerState + StateProxy (per-session isolation)
├── config.py           # Central re-export hub (constants, imports, state, cache)
├── constants.py        # Pure constants (response limits, timeouts, URLs)
├── imports.py          # Optional library imports with *_AVAILABLE flags
├── cache.py            # Gzip-compressed LRU disk cache (~/.arkana/cache/)
├── auth.py             # Bearer token ASGI middleware
├── integrity.py        # Pre-parse file integrity checks (PE/ELF/Mach-O)
├── utils.py            # ReDoS-safe regex, safe_slice, safe_env_int
├── parsers/            # PE/FLOSS/capa/YARA/strings parsers
├── dashboard/          # Web dashboard (Starlette + htmx + Jinja2)
│   ├── app.py          # ASGI app factory, routes, auth, SSE events
│   ├── state_api.py    # Data extraction layer (reads AnalyzerState for dashboard views)
│   ├── __init__.py     # Package init
│   ├── templates/      # Jinja2 templates (overview, functions, callgraph, sections, strings, timeline, notes)
│   │   └── partials/   # htmx partials (_global_status, _overview_stats, _task_list, _timeline_entry)
│   └── static/         # CSS (CRT theme), JS (htmx, Cytoscape.js, strings.js), logo
└── mcp/                # MCP tool modules (256 tools across 57 files)
    ├── server.py       # FastMCP instance, tool_decorator, response truncation
    ├── _*.py           # Private helpers (angr, input, format, progress, refinery, rename, search)
    └── tools_*.py      # Tool modules grouped by domain
tests/                  # Unit tests (pytest)
tests/integration/      # Integration tests (requires running server)
.claude/skills/         # Claude Code analysis and learning skills
```

## Running Tests

```bash
# Unit tests (no server needed, ~2 seconds)
python -m pytest tests/ -v

# Unit tests with coverage
python -m pytest tests/ -v --cov=arkana --cov-config=.coveragerc

# Integration tests (requires running server)
./run.sh  # Start server in one terminal
python -m pytest tests/integration/mcp_test_client.py -v  # In another
```

Coverage configuration lives in `.coveragerc` (single source of truth). MCP tool modules are excluded from unit test coverage — they are tested via integration tests.

## Lint

```bash
ruff check arkana/ tests/ \
  --select=E9,F63,F7,F82,F841,W291,W292,W293,B006,B007,B018,UP031,UP032,RUF005,RUF010,RUF019,G010
```

## Key Patterns

- **File integrity checks**: `arkana/integrity.py` provides pre-parse validation of binary files using only `struct` (no library deps). `check_file_integrity(data, format, path)` returns a structured assessment (`status`, `confidence`, `issues`, `flags`, `format_details`, `recommendation`). `open_file` runs this automatically and includes `file_integrity` in every response. The standalone `check_file_integrity` MCP tool can run before or after `open_file`. The `force` parameter on `open_file` overrides smart fallback (unknown formats default to raw/shellcode mode instead of crashing in PE mode). `INTEGRITY_FLAGGED_TIMEOUT_FACTOR` (0.5) reduces the PE analysis timeout for files flagged as corrupt/partial. When `open_file` is called on a new file without `close_file()`, it clears all module-level caches (`_decompile_meta`, `_phase_caches`, dashboard caches, `result_cache`, analysis warnings) to prevent cross-file data contamination.
- **Optional deps**: Every library is guarded by `*_AVAILABLE` flags in `imports.py`. Tools return actionable error messages when a dep is missing — never crash.
- **Thread safety**: All shared state uses locks. `StateProxy` + `contextvars` isolates HTTP sessions. Use `ProgressBridge` to report progress from worker threads. Sessions have a `_closing` flag to prevent reactivation during cleanup. angr objects are intentionally shared by reference across sessions (read-only, expensive to copy). `_cached_*` fields on `AnalyzerState` rely on CPython's GIL for atomic reference replacement (never mutated in place after assignment).
- **Session limits**: `MAX_ACTIVE_SESSIONS` (default 100, overridable via `ARKANA_MAX_SESSIONS` env var) caps concurrent HTTP sessions. When the limit is reached, the oldest session (by `last_active`) is evicted with `_closing = True`. `SESSION_TTL_SECONDS` (3600) governs stale session reaping. The session reaper thread auto-restarts if it dies (dead-thread detection via `is_alive()`). Per-session caps: `MAX_NOTES` (10K), `MAX_TOOL_HISTORY` (500), `MAX_ARTIFACTS` (1K), `MAX_RENAMES` (10K), `MAX_COMPLETED_TASKS` (50).
- **`asyncio.to_thread()`**: CPU-intensive tool work runs in threads to avoid blocking the event loop. See `tools_angr.py` and `tools_triage.py` for examples.
- **Response truncation**: `_check_mcp_response_size()` enforces a dual-limit system — soft character limit (8K chars by default, for Claude Code CLI compatibility) plus hard byte limit (64KB backstop). Uses `copy.deepcopy()` to avoid mutating caller data during truncation. Byte-limit backstop includes a final size re-check after preview wrapper creation. The `tool_decorator` includes a safety net that auto-enforces the soft limit even for tools that don't call `_check_mcp_response_size` explicitly. Set `ARKANA_MCP_RESPONSE_LIMIT_CHARS=65536` to restore 64KB-only behavior for non-Claude-Code clients.
- **Pagination**: Two pagination patterns are used:
  1. **Response-level** (`_paginated_response`): Large-output tools like `decompile_function_with_angr` use line-based pagination (`line_offset`/`line_limit`). Results are cached via `_ToolResultCache` so subsequent page requests don't re-execute analysis.
  2. **Field-level** (`_paginate_field`): Tools returning dicts with multiple list fields (e.g., `get_triage_report`, `get_analysis_digest`, `get_session_summary`) use `_paginate_field(items, offset, limit)` to paginate individual fields. Each paginated field gets a sibling `{field}_pagination` dict with `{total, offset, limit, returned, has_more}`. Pagination params are listed in `_SKIP` so they don't affect cache keys. Key tools with field-level pagination: `get_triage_report` (`indicator_offset`/`indicator_limit`), `get_analysis_digest` (5 offset/limit pairs for findings, functions, IOCs, unexplored, notes), `get_session_summary` (`notes_offset`/`notes_limit`/`history_limit`), `get_function_map` (`offset`/`limit`), `suggest_next_action` (`max_suggestions`), `find_anti_debug_comprehensive` (`limit`), `identify_cpp_classes` (`method_limit`), `detect_dga_indicators`/`match_c2_indicators`/`analyze_kernel_driver` (`limit`).
- **Search/grep in decompilation & disassembly**: `decompile_function_with_angr`, `batch_decompile`, and `get_annotated_disassembly` accept optional `search` (regex), `context_lines` (default 2, max 20), and `case_sensitive` (default False) parameters. When `search` is provided, only matching lines/instructions with surrounding context are returned instead of full paginated output. Search is a view/filter on cached results — it does not affect cache keys (handled via `_SKIP` in `_make_cache_key`). `_search_helpers.py` provides `search_lines_with_context()` (for decompiled code) and `search_instructions_with_context()` (for disassembly — searches mnemonic, op_str, call_target, label fields). Both validate patterns via `validate_regex_pattern()` for ReDoS safety. `batch_decompile` with search skips functions with no matches. Constants: `DEFAULT_SEARCH_CONTEXT_LINES` (2), `MAX_SEARCH_CONTEXT_LINES` (20), `MAX_SEARCH_MATCHES` (500).
- **`tool_decorator`**: Wraps every MCP tool — handles session activation, heartbeat, history recording, error enrichment, and sets `_current_tool_var` contextvar for warning attribution.
- **Warning capture**: `arkana/warning_handler.py` installs a `logging.Handler` on the root logger that captures WARNING+ from known library loggers (angr, cle, capa, FLOSS, etc.) into `state.analysis_warnings`. Warnings are deduplicated by `(logger, level, msg[:100])` with count/last_seen tracking. `_current_tool_var` and `_current_task_var` contextvars attribute each warning to the MCP tool or background task that triggered it. `get_analysis_warnings` and `clear_analysis_warnings` MCP tools expose captured warnings. `get_session_summary` and `get_analysis_digest` surface warning counts when > 0. Session-scoped (not persisted to cache). Constant: `MAX_ANALYSIS_WARNINGS` (500).
- **Background task timeout**: All 12 background tools (`find_path_to_address`, `emulate_function_execution`, `analyze_binary_loops`, `get_reaching_definitions`, `get_data_dependencies`, `get_value_set_analysis`, `diff_binaries`, `find_path_with_custom_input`, `emulate_with_watchpoints`, `identify_cpp_classes`, `find_similar_functions`, `build_function_signature_db`) time out automatically via `_run_background_task_wrapper(timeout=N)`. Default `BACKGROUND_TASK_TIMEOUT` is 1800s (30 min), overridable via `ARKANA_BACKGROUND_TASK_TIMEOUT`. BSim tools use `BSIM_BACKGROUND_TIMEOUT` (1800s, overridable via `ARKANA_BSIM_BACKGROUND_TIMEOUT`). Four tools support `on_timeout` callbacks that capture partial results (steps completed, active states, captured events). `_update_progress()` records `last_progress_epoch` on every call, enabling generic stall detection in `check_task_status()`. Tasks include `created_at_epoch` for elapsed time reporting.
- **Data flow analysis**: `find_dangerous_data_flows` in `tools_vuln.py` traces untrusted input sources (recv, fread, ReadFile) to dangerous sinks (strcpy, sprintf, system) using angr reaching-definition analysis with structural fallback. Per-function RDA timeout (`DATA_FLOW_PER_FUNC_TIMEOUT`, 30s) and aggregate timeout (`DATA_FLOW_AGGREGATE_TIMEOUT`, 120s). Reuses `_INPUT_SOURCE_APIS` and `_DANGEROUS_SINK_APIS` from the same module.
- **Obfuscation detection**: `detect_control_flow_flattening` and `detect_opaque_predicates` in `tools_angr_forensic.py`. CFF detection scores functions 0-100 based on dispatcher in-degree, back-edge ratio, state variable detection, and block size uniformity. Opaque predicate detection uses Z3 constraint solving with per-block timeout (`OPAQUE_PREDICATE_SOLVER_TIMEOUT`, 15s). Both tools follow the `find_anti_debug_comprehensive` pattern with `asyncio.to_thread()` and `OBFUSCATION_DETECTION_TIMEOUT` (180s).
- **Emulation debugger**: `tools_debug.py` provides 26 MCP tools for interactive step-through debugging via a persistent Qiling subprocess (`scripts/debug_runner.py`). Unlike fire-and-forget Qiling tools, debug sessions persist across multiple MCP calls using JSONL over stdin/stdout. Key classes: `_DebugSessionManager` (session lifecycle, eviction) and `_DebugSession` (subprocess handle, JSONL IPC). State stored in `state._debug_manager` (lazily created). Session reaper cleans up debug sessions via `cleanup_all()`. Tools: `debug_start`/`debug_stop`/`debug_status` (lifecycle), `debug_step`/`debug_step_over`/`debug_continue`/`debug_run_until` (execution), `debug_set_breakpoint`/`debug_set_watchpoint`/`debug_remove_breakpoint`/`debug_remove_watchpoint`/`debug_list_breakpoints` (breakpoints/watchpoints), `debug_read_state`/`debug_read_memory`/`debug_write_memory`/`debug_write_register` (inspection), `debug_snapshot_save`/`debug_snapshot_restore`/`debug_snapshot_list`/`debug_snapshot_diff` (snapshots), `debug_set_input`/`debug_get_output` (I/O stubs), `debug_get_api_trace`/`debug_clear_api_trace`/`debug_set_trace_filter` (API tracing), `debug_search_memory` (memory search). **I/O stubs** (`stub_io=True` default on `debug_start`): hooks Win32 console APIs (GetStdHandle, WriteConsoleA/W, ReadConsoleA, SetConsoleMode, GetConsoleMode, AllocConsole, FreeConsole) to prevent UC_ERR_READ_UNMAPPED crashes from printf/cout/cin; captures output text and consumes from input queue. **API tracing** (enabled by default): wildcard ENTER/EXIT hooks log all Windows API calls with args and return values; paginated retrieval with optional filter. **Memory search**: searches all mapped regions for string (UTF-8 + UTF-16LE) or hex patterns (with `??` wildcards). Constants: `MAX_DEBUG_SESSIONS` (3), `DEBUG_SESSION_TTL` (1800s), `DEBUG_COMMAND_TIMEOUT` (300s), `MAX_DEBUG_SNAPSHOTS` (10), `MAX_DEBUG_INSTRUCTIONS` (10M), `MAX_DEBUG_MEMORY_READ` (1MB), `MAX_DEBUG_BREAKPOINTS` (100), `MAX_DEBUG_WATCHPOINTS` (50), `MAX_DEBUG_CAPTURED_OUTPUT` (10K), `MAX_DEBUG_PENDING_INPUT` (1K), `MAX_DEBUG_API_TRACE` (10K), `MAX_DEBUG_SEARCH_MATCHES` (100), `DEBUG_SEARCH_CONTEXT_BYTES` (32).
- **BSim function similarity**: `_bsim_features.py` provides architecture-independent function similarity matching inspired by Ghidra's BSim. 6 feature groups (CFG structural, API calls, VEX IR profile, string refs, constants, size metrics) with weighted scoring. SQLite DB at `~/.arkana/bsim/signatures.db` stores indexed function signatures for cross-binary queries. Two-phase query: SQL pre-filter eliminates ~80-90% of candidates, then full scoring on remainder. JSON serialization uses `_safe_json_loads()`/`_safe_json_dumps()` to gracefully handle corrupted DB rows or non-serializable feature objects.
- **Notes system**: `add_note()` categories: `general`, `function`, `tool_result`, `ioc`, `hypothesis`, `conclusion`, `manual`. `hypothesis` is for a condensed one-paragraph verdict; `conclusion` is for a full detailed analysis write-up (supports markdown, rendered on dashboard overview).
- **Artifacts system**: `state.register_artifact()` tracks extracted files (path, hashes, source tool, type detection). Artifacts persist via cache alongside notes/tool_history, and are included in `export_project` / `import_project` archives. Constants: `MAX_ARTIFACT_FILE_SIZE` (100 MB), `MAX_TOTAL_ARTIFACT_EXPORT_SIZE` (50 MB).
- **Rename/annotation layer**: `state.renames` stores function renames (`addr→name`), variable renames (`func_addr→{old→new}`), and address labels (`addr→{name, category}`). All persisted via cache alongside notes. `_rename_helpers.py` provides `apply_function_renames_to_lines()` / `apply_variable_renames_to_lines()` / `get_display_name()` / `normalize_address()` for integrating renames into decompilation and disassembly output. `apply_variable_renames_to_lines()` uses a single-pass combined regex to prevent cascading substitutions (e.g. renaming `v1→counter` then `counter→total` would incorrectly transform `v1` to `total` with sequential replacement). `batch_rename` uses two-pass validate-then-apply for atomicity. 6 tools in `tools_rename.py`.
- **Custom types system**: `state.custom_types` stores user-defined structs and enums. Structs reuse `_parse_fields` from `tools_struct.py` for parsing (with padding bounds 0–10MB, UTF-8/Latin-1 cstring decode). Field names validated against `[a-zA-Z_][a-zA-Z0-9_]*`. Enum values checked against declared byte size with duplicate detection. Cycle detection prevents recursive struct references. Persisted via cache. 5 tools in `tools_types.py`.
- **Decompiler cffi fallback**: `_safe_decompile()` in `_angr_helpers.py` wraps `project.analyses.Decompiler()` with a retry for cffi pickle errors. angr's Clinic pass uses `copy.copy()` on AIL blocks, which falls back to pickle (`__reduce__`) — fails when blocks contain cffi-backed VEX/capstone data (`_CDataBase`). More likely on local/region-scoped CFGs. On pickle error, retries with `cfg=None` (minimal internal CFG path). Returns `(decompiler_result, used_fallback)` tuple. When `used_fallback=True`, a `note` field (`DECOMPILE_FALLBACK_NOTE`) is added to the MCP response warning that pseudocode quality may be reduced. All 4 Decompiler call sites use this helper: `tools_angr.py` (2), `enrichment.py` (1), `state_api.py` (1). The note is persisted in `_decompile_meta` cache so cached results also carry the warning.
- **VB6 support**: `arkana/parsers/vb6.py` provides pure-struct VB6 header parsing (project metadata, forms/modules, Declare Function externals). `tools_vb6.py` exposes `vb6_analyze` MCP tool. `_triage_compiler_language()` detects VB6 via MSVBVM60/50.DLL imports. `_classify_core()` classifies as "VB6 Application". `_category_maps.py` includes 13 MSVBVM APIs (DllFunctionCall=CRITICAL, rtcShell/rtcCreateObject/rtcURLDownload=HIGH, file/registry APIs=MEDIUM).
- **Batch decompile**: `batch_decompile` in `tools_angr.py` decompiles up to 20 functions per call with per-function timeout (60s). Caches per-function results via `_ToolResultCache`. Applies rename helpers to output. Supports `search` param to grep across all functions and return only those with matches.
- **Hex pattern search**: `search_hex_pattern` in `tools_strings.py` searches binary data for hex byte patterns with `??` wildcards. Runs in `asyncio.to_thread()`. Constants: `MAX_HEX_PATTERN_TOKENS` (200), `MAX_HEX_PATTERN_MATCHES` (5000), `MAX_TOOL_LIMIT` (100K, centralized in `constants.py`).
- **Systemic limit clamping**: All ~60 tool functions that accept a `limit` parameter clamp it via `limit = max(1, min(limit, MAX_TOOL_LIMIT))` to prevent unbounded output. `MAX_TOOL_LIMIT` (100,000) is imported from `arkana.constants`.
- **Decompile meta cache**: `_decompile_meta` in `tools_angr.py` is an `OrderedDict` with LRU eviction (cap: `_MAX_DECOMPILE_META` = 2000). Keys are session-scoped tuples `(state._state_uuid, addr_int)`. Access functions call `move_to_end()` on hit; eviction uses `popitem(last=False)`. Cleared by `clear_decompile_meta()` in three contexts: session reaper (reaped sessions), `close_file()`, and `open_file()` (file switch without close). Dashboard functions (`get_decompiled_code`, `trigger_decompile` in `state_api.py`) build cache keys directly using `_get_state()._state_uuid` rather than `_make_decompile_key()`, since dashboard threads run via `asyncio.to_thread()` without the MCP session contextvar set.
- **Incremental enrichment saves**: `_save_enrichment_cache()` is called at 3 points to prevent data loss on server kill: (1) after Phase 2b (IOCs) — saves all fast-phase results (classify, triage, similarity, MITRE, IOCs); (2) periodically during `_decompile_sweep()` every `_SWEEP_SAVE_INTERVAL` (60s); (3) on-demand via `save_decompile_cache_async(state)` — a public function called by MCP `decompile_function_with_angr` and dashboard `trigger_decompile()` after each on-demand decompile. The async save runs in a daemon thread, throttled to `_ASYNC_SAVE_INTERVAL` (30s) per-state via `state._last_decompile_save_time`, with a non-blocking lock to prevent concurrent saves.
- **FLOSS progress polling**: `_load_floss_vivisect_workspace()` splits PE workspace creation from analysis, running `vw.analyze()` in a sub-thread while polling `vw.getFunctions()` every 3s. Progress uses a time-based exponential curve (12-38%) combined with live function-discovery counts. Constants: `VIVISECT_BYTES_PER_SECOND_ESTIMATE` (50KB/s), `VIVISECT_POLL_INTERVAL` (3s). Subsequent FLOSS stages (enrichment, stack/tight/decoded extraction) also report progress via callback. Xref enrichment capped at `MAX_FLOSS_REFS_PER_STRING` (20) to prevent OOM.
- **Web dashboard**: `arkana/dashboard/` provides a real-time web UI on port 8082 (auto-started in both stdio and HTTP modes). Built with Starlette + htmx + Jinja2 with a CRT/WarGames terminal theme. Token auth persisted to `~/.arkana/dashboard_token`. Features: overview with full binary summary (risk, packing, mitigations, findings), function explorer with triage flagging (FLAG/SUS/CLN) and XREF analysis panel, Cytoscape.js call graph with dagre layout and tabbed sidebar, section permissions, expandable analysis timeline (shows request params + result summary), categorised notes viewer, strings explorer with FLOSS detail panel, and SSE real-time updates. Dashboard reads from the active MCP session state via `state_api._get_state()` which checks `_session_registry` for any state with a loaded file. Triage flags set on the dashboard are surfaced to the AI via `get_session_summary()`, `get_analysis_digest()`, and `suggest_next_action()`.
- **Global status bar**: `templates/partials/_global_status.html` renders active tool + running background tasks with progress bars, visible from every page via htmx polling (`hx-get="/dashboard/partials/global-status"` every 3s in `base.html`). Collapses to empty when nothing is running. Data sourced from `get_overview_data()` (`active_tool` + `background_tasks` fields).
- **FLOSS detail panel**: Strings page includes a collapsible FLOSS panel above the stats grid showing analysis status badge, type breakdown (STATIC/STACK/DECODED/TIGHT counts), top decoded and stack strings, and FLOSS metadata. Data from `state_api.get_floss_summary()` via `/api/floss-summary`. Auto-refreshes every 5s while FLOSS analysis is still running.
- **Function analysis API**: `/api/function-analysis` endpoint (`state_api.get_function_analysis_data()`) returns combined xrefs, strings, suspicious APIs, complexity, and enrichment score for a function. Suspicious API detection uses `CATEGORIZED_IMPORTS_DB` from `_category_maps.py` to flag callee names with risk levels (CRITICAL/HIGH/MEDIUM) and categories (process_injection, credential_theft, etc.). Callers/callees are enriched with triage status, complexity, and enrichment score.
- **Functions page XREF panel**: Functions page has a dedicated XREF button alongside DEC. Clicking XREF opens a detail panel with XREFS/STRINGS/CODE tabs (no decompilation required). The XREFS tab shows suspicious APIs with risk badges, callers/callees with triage dots and complexity, all clickable — clicking a caller/callee scrolls to and highlights that function in the table. Panel state survives table reloads (filter/sort changes).
- **Callgraph tabbed sidebar**: Callgraph node sidebar has 4 tabs (INFO/XREFS/STRINGS/CODE). INFO shows basic stats including enrichment score + callers/callees from graph data. XREFS tab shows score alongside triage dots for callers/callees. XREFS/STRINGS/CODE lazy-load from `/api/function-analysis` with per-node caching. Dagre hierarchical layout via `cytoscape-dagre.js` + `dagre.min.js`. Layout detection with automatic fallback to breadthfirst/cose if dagre extension fails. Error handling on `loadGraph` fetch and `initCytoscape` with visible error messages.
- **Callgraph enrichment score**: Callgraph nodes include enrichment score (0–100) from `state._cached_function_scores`. Score drives visual border thickness via `mapData(score, 0, 100, 2, 5)` — higher-score nodes have thicker borders. Legend includes a "BORDER THICKNESS = SCORE" note. Score is also surfaced in `get_callgraph_data()` node data and `get_function_analysis_data()` response (top-level + per-caller/callee).
- **Overview function links**: Overview page items (capa capabilities, YARA matches, FLOSS decoded/stack strings, high-value strings, network IOCs, recent notes) display clickable `→ func_name` links that navigate to the containing function on the Functions page via `?highlight=0xADDR`. Enrichment is performed by `_apply_overview_enrichment()` in `state_api.py` using `_build_function_lookup()` (binary search over angr KB functions) and `_find_containing_function()`. YARA matches are only linked when the match VA falls in an executable PE section (`_is_executable_va()`). For .NET binaries without angr functions, FLOSS static string file offsets are converted to VAs via `_file_offset_to_va()` as a fallback. All three caches — `_overview_enrichment_cache` (10s TTL, sha256-versioned), `_func_lookup_cache` (5s TTL, filepath-validated), and `_overview_cache` (2s TTL, filepath-validated) — prevent cross-file pollution. All five dashboard caches are also explicitly cleared by `_cleanup_session_caches()` on file switch and session reaping.
- **Cross-page deep linking**: Functions page handles `?highlight=0xADDR` query parameter — scrolls to and flashes the target function row using existing `navigateToFunction()`. Used by overview, notes, strings, imports, callgraph, and timeline pages. Callgraph page handles `?focus=0xADDR` to center on a node.
- **Notes function links**: Notes page and overview recent notes display clickable address links when the address resolves to a known function. `get_notes_data()` enriches notes with `func_addr`/`func_name`.
- **Imports clickable exports**: Imports page export addresses link to the Functions page via `?highlight=`.

## Input Validation & Safety Guards

- **Emulation limits**: Qiling tools validate `max_instructions` (0–10M) via `_validate_max_instructions()` to prevent CPU/memory exhaustion.
- **Debug session limits**: Max 3 concurrent debug sessions (`MAX_DEBUG_SESSIONS`), 1MB max memory read (`MAX_DEBUG_MEMORY_READ`), 1MB max watchpoint region (`MAX_DEBUG_WATCHPOINT_SIZE`), 100 max breakpoints (`MAX_DEBUG_BREAKPOINTS`), 50 max watchpoints (`MAX_DEBUG_WATCHPOINTS`), 10 max snapshots (`MAX_DEBUG_SNAPSHOTS`). Debug addresses validated to ≤40 chars. Oldest session evicted when limit reached. I/O stubs: 10K max captured output entries (`MAX_DEBUG_CAPTURED_OUTPUT`), 1K max pending input entries (`MAX_DEBUG_PENDING_INPUT`). API trace: 10K max trace entries (`MAX_DEBUG_API_TRACE`). Memory search: 100 max matches (`MAX_DEBUG_SEARCH_MATCHES`), regions >64MB skipped, hex patterns max 200 bytes.
- **Auth header handling**: `BearerAuthMiddleware` lowercases ASGI header keys defensively before matching.
- **Error message sanitization**: Crypto tool errors truncate user input to 50 chars to prevent information disclosure.
- **Address validation**: Dashboard endpoints reject address parameters longer than 40 characters.
- **Content-Length parsing**: POST endpoints wrap `int(content_length)` in try/except for malformed values.
- **Delay-load imports**: PE parser bounds delay-load thunk iteration at 10,000 to prevent infinite loops on malformed binaries.
- **ThreadPool cap**: PE parser limits `ThreadPoolExecutor` workers to `min(cpu_count, 8)`.
- **IOC regex**: Domain TLD matching tightened to `{2,16}` characters.
- **Cache eviction**: CAPA and YARA rule caches use LRU (OrderedDict) instead of FIFO.
- **ELF symbol parsing**: Per-symbol error handling continues iteration on individual failures.
- **CSP**: Dashboard Content-Security-Policy restricts `img-src` to `'self'` only (no `data:` URIs).
- **Dashboard XSS prevention**: All dynamic values in dashboard JS (functions.js, strings.js, callgraph.js) are escaped via `escapeHtml()` before innerHTML insertion — including addresses, names, numeric counts, scores, and complexity values.
- **Path validation**: `_get_filepath()` in `_format_helpers.py` always validates paths via `state.check_path_allowed()`, even when falling back to `state.filepath`.
- **Recursion depth guard**: `_make_hashable()` in `_input_helpers.py` enforces a max depth of 20 to prevent stack overflow on cyclic data structures.
- **Cache size bounds**: `ARKANA_CACHE_MAX_SIZE_MB` env var is clamped to 1–50000 MB to prevent misconfiguration.
- **Search regex safety**: `search` parameters on decompile/disassembly tools validate patterns via `validate_regex_pattern()` — rejects patterns >1000 chars, nested quantifiers (ReDoS), and invalid syntax. Context lines clamped to `[0, 20]`, matches capped at 500.
- **File size limit**: `DEFAULT_MAX_FILE_SIZE_MB` (256) in `constants.py`, overridable via `ARKANA_MAX_FILE_SIZE_MB` env var (parsed safely via `_safe_env_int()`).
- **Decompression bomb protection**: `refinery_decompress` uses streaming chunk iteration with a running byte count, aborting when cumulative output exceeds `_MAX_DECOMPRESS_OUTPUT` (100 MB). Prevents zip-bomb style attacks via crafted compressed data.
- **Hex input validation**: All `bytes.fromhex()` call sites validate input length before decoding. `_hex_to_bytes()` in `_refinery_helpers.py` provides friendly error messages for invalid hex. `patch_binary_memory` caps hex input at 2 MB.
- **Refinery pipeline loop limits**: Pipeline iteration loops break when item count reaches the configured `limit`, preventing unbounded output accumulation.
- **IOC filtering**: `_is_non_routable_ip()` uses Python's `ipaddress` module to correctly filter CGNAT (100.64.0.0/10), multicast, and other non-routable ranges (replaces simple prefix matching).
- **Cache atomic writes**: `cache.put()` and `update_session_data()` use `tempfile.NamedTemporaryFile()` + `os.replace()` for atomic writes, preventing `.tmp` file collisions and partial writes on crash. Orphaned `.tmp` files are cleaned up at startup.
- **Resource entry cap**: PE resource directory traversal is bounded at `_MAX_RESOURCE_ENTRIES` (1000) to prevent OOM on malformed binaries.
- **Result cache defensive copy**: `_ToolResultCache.set()` stores `list(items)` (shallow copy) to prevent callers from accidentally mutating cached data.

## Dashboard

The web dashboard starts automatically on port 8082. Access URL is logged at startup with a token query parameter.

```bash
# Access dashboard (token is printed at startup)
http://127.0.0.1:8082/dashboard/?token=<TOKEN>
```

Pages: Overview (binary summary, risk, mitigations, findings with function pivot links, recent notes), Functions (sortable, triage buttons, enrichment score column, XREF analysis panel with clickable navigation, inline notes, code search, symbol tree view, `?highlight=` deep linking), Call Graph (Cytoscape.js with dagre layout, tabbed sidebar: INFO/XREFS/STRINGS/CODE, score-based border thickness, `?focus=` deep linking), Sections (permission flags, entropy heatmap), Imports (DLL/export tables, clickable export addresses), Hex View (infinite-scroll hex dump, auto-loads chunks on scroll, jump-to-offset), Strings (FLOSS detail panel, type/category filtering, sifter scores, function column with links), CAPA (capability matches grouped by namespace, function links), MITRE (ATT&CK technique matrix with IOC panel), Types (custom struct/enum editor), Diff (binary diff via angr BinDiff with file browser and manual path input), Timeline (expandable tool calls, clickable note addresses), Notes (category filtering, clickable address links).

A global status bar between the nav and content area shows the active tool and running background tasks with progress bars from any page. It auto-refreshes every 3s via htmx and collapses when idle.

Dashboard triage flags are persisted to the analysis cache and restored when the same file is reopened. Flagged/suspicious functions are prioritised in `suggest_next_action()`.

**CSP compliance**: Dashboard uses `script-src 'self'` CSP. All event handlers use `addEventListener` or event delegation — no inline `onclick` attributes. Dynamic HTML uses `data-*` attributes for actions with delegated listeners.

- **`fetchJSON()` helper**: All dashboard JS files use the shared `fetchJSON(url, options)` helper from `dashboard.js` which checks `r.ok` before parsing JSON and throws on HTTP errors. This replaces raw `fetch().then(r => r.json())` calls throughout.
- **`asyncio.to_thread()` everywhere**: All dashboard API endpoints and htmx partials run data functions via `asyncio.to_thread()` to avoid blocking the event loop. Partials include `try/except` with empty-HTML fallbacks.
- **`Cache-Control: no-store`**: Security middleware adds `Cache-Control: no-store` to all non-static responses to prevent browser caching of sensitive API data. Static files use `Cache-Control: public, max-age=3600`.
- **Diff path validation**: `get_diff_data()` validates `file_path_b` via `os.path.realpath()` + `os.path.isfile()` + samples directory containment check.
- **Callgraph edge bound**: `get_callgraph_data()` caps edges at 5,000 to prevent oversized payloads.
- **Search query bound**: `search_decompiled_code()` caps query length at 500 characters.
- **Hex View**: Infinite scroll loads 4096-byte chunks, keeps max 64KB in DOM, trims rows from opposite end. `/api/hex` endpoint with offset/length params.
- **Binary Diff**: `/api/diff` runs angr BinDiff in `asyncio.to_thread()`. `/api/list-files` lists samples directory for the file browser. Uses `getattr()` with fallback for BinDiff attribute names across angr versions.
- **Full-Text Code Search**: `/api/search-code` searches `_decompile_meta` cache with line-level context. Functions page SEARCH button and code search results panel with highlighted matches.
- **Symbol Tree**: Functions page TABLE/TREE toggle. Groups functions into 6 categories (flagged, suspicious, decompiled, renamed, other, library/PLT). Event delegation via `data-tree-action` attributes.
- **Responsive nav**: Navigation uses JS-based overflow detection. Links that fit are shown inline; overflow links are moved into a "MORE (N)" dropdown positioned after the visible links. `_initNavOverflow()` in `dashboard.js` measures each link's position, moves overflow items into `#nav-more-dropdown`, and re-distributes on window resize. Two-pass measurement accounts for the MORE button taking space.
- **Functions scroll preservation**: `reloadFunctions()` in `functions.js` saves and restores both table container `scrollTop` and `window.scrollY` around `innerHTML` replacement, preventing scroll jumps during SSE-triggered enrichment reloads.

## Docker

```bash
./run.sh --stdio          # stdio mode (for Claude Code)
./run.sh                  # HTTP mode (port 8082)
./run.sh --samples ~/dir  # Mount samples directory
```

The Docker image uses 4 venvs to isolate incompatible unicorn versions (angr needs v2, Speakeasy/Unipacker/Qiling need v1). .NET deobfuscation tools are invoked via `asyncio.create_subprocess_exec()` — no Python venv needed. de4dot-cex runs via `mono` (.NET Framework), NETReactorSlayer is a self-contained linux-x64 binary, ilspycmd is a `dotnet` global tool.

## Known Tool Limitations

These are inherent limitations from underlying frameworks or architecture, not bugs:

- **`get_data_dependencies`**: Returns raw angr internals (`SimEngineRDVEX`, `LocalVariableTag`). Prefer `get_reaching_definitions` or `propagate_constants` for readable output.
- **`get_backward_slice` / `get_forward_slice`**: Returns CFG reachability, not true data-flow slices. The `variable` parameter selects the start point but slicing follows control flow.
- **`extract_function_constants`**: Includes code addresses (call/branch targets) alongside data constants. Filter by checking section ranges.
- **Qiling emulation**: Requires manual rootfs setup with real Windows DLLs. `qiling_setup_check()` verifies. See `docs/QILING_ROOTFS.md`.
- **Debug sessions**: Emulation fidelity limited by Qiling/Unicorn — anti-emulation techniques, threading, and complex Windows APIs may not work. Memory watchpoints have performance overhead (global hook per type). Snapshots consume memory proportional to mapped regions. `ql.save()`/`ql.restore()` may not fully restore complex states (file handles, network sockets). API breakpoints cannot be cleanly removed in Qiling.
- **`auto_unpack_pe`**: FSG-packed binaries may fail with Unipacker. Use `qiling_dump_unpacked_binary()` as fallback.
- **`get_virustotal_report_for_loaded_file`**: Requires API key via `set_api_key(service="virustotal", key="...")`.
- **`analyze_batch`**: 8KB MCP response soft limit can truncate data for large file sets. Use smaller lists (5-10 files).
- **`search_decompiled_code`**: Searches C pseudocode, not assembly. Use `get_annotated_disassembly(search=...)` for assembly-level search.
- **`refinery_carve` / `refinery_extract_iocs`**: May produce false positives on raw binary data. Validate extracted IOCs.
- **`scan_for_indirect_jumps`**: Filters constant-target exits and `Ijk_Ret` (returns). Classifies results as `indirect_call` or `indirect_jump`.
- **`get_function_variables`**: Automatically filters VEX IR temporaries (`ir_N`, `tmp_N`); reports their count separately.
- **`get_calling_conventions`**: May return no results for simprocedures/thunks. Includes diagnostic note when this occurs.
- **`dotnet_analyze`**: CLR type/method flags displayed as compact pipe-separated format (e.g. `Public | Class | AutoLayout`).
- **DFS symbolic execution**: angr's `DFS()` exploration technique triggers cffi pickle errors (`cannot pickle '_cffi_backend._CDataBase'`). `solve_constraints_for_path` uses BFS by default. `find_path_to_address` has `use_dfs` parameter (default True — set to False if pickle errors occur). `explore_symbolic_states` has `strategy` parameter.
- **`reconstruct_pe_from_dump`**: LIEF Builder API varies between versions. Tool auto-detects constructor signature (`Builder(pe, config_t)` vs `Builder(pe)`).
- **`get_value_set_analysis`**: VFG analysis has known angr compatibility issues. May return limited value-set data. Prefer `get_reaching_definitions` or `propagate_constants`.
- **`detect_compression_headers`**: May produce false positives on code sections where instruction bytes match compression magic bytes.
- **`save_patched_binary`**: `bytes_patched` count includes all differences between angr's in-memory loader state and the original file (loader alignment, padding), not just user-initiated patches.
- **`refinery_executable` entropy_map**: Returns raw iemap output (visual entropy representation), not numeric entropy values. Use `get_entropy_analysis` for numeric data.
- **`go_analyze`**: pygore (last release Oct 2021) cannot parse modern Go binaries. Falls back to `_go_string_scan()` which detects Go via 13 runtime markers and version strings (detection threshold: 2+ markers OR version string). When fallback triggers, returns marker list and Go version but no package/type metadata — use `elf_analyze()` for full symbol info.

## CI

GitHub Actions runs on every push/PR (plus manual `workflow_dispatch`): unit tests (Python 3.10-3.12), ruff lint, and smoke tests. Coverage floor is 65% with branch coverage enabled. Dependabot is configured for weekly pip dependency updates.
