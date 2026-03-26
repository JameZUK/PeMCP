# Arkana Development Guide

## What is Arkana?

Arkana is a Model Context Protocol (MCP) server exposing 281 binary analysis tools to AI clients. It supports PE, ELF, and Mach-O formats with integrations for angr, capa, FLOSS, YARA, Binary Refinery, Qiling, Speakeasy, oletools, and GoReSym.

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
├── resource_monitor.py  # Process-level RSS/CPU monitoring (psutil daemon thread)
    └── mcp/                # MCP tool modules (281 tools across 61 files)
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

- **File integrity checks**: `arkana/integrity.py` validates binaries pre-parse using only `struct`. `open_file` runs this automatically. The `force` parameter overrides smart fallback. `open_file`/`close_file` **block when background tasks are active** — they return an error with `active_tasks` and `hint` suggesting `abort_background_task()` or `force_switch=True`. When `open_file` is called on a new file without `close_file()`, it clears all module-level caches to prevent cross-file data contamination. `open_file` PE analysis uses soft/overtime timeouts (task ID `"pe-analysis"`): `PE_ANALYSIS_SOFT_TIMEOUT` (300s) → `TASK_OVERTIME` with stall detection → `PE_ANALYSIS_MAX_RUNTIME` (3600s) ceiling. Set `ARKANA_PE_ANALYSIS_SOFT_TIMEOUT=0` for old hard-timeout behavior.
- **Optional deps**: Every library is guarded by `*_AVAILABLE` flags in `imports.py`. Tools return actionable error messages when a dep is missing — never crash.
- **Thread safety**: All shared state uses locks. `StateProxy` + `contextvars` isolates HTTP sessions. `_cached_*` fields on `AnalyzerState` rely on CPython's GIL for atomic reference replacement (never mutated in place after assignment).
- **Session limits**: `MAX_ACTIVE_SESSIONS` (default 100, env: `ARKANA_MAX_SESSIONS`). Per-session caps: `MAX_NOTES` (10K), `MAX_TOOL_HISTORY` (500), `MAX_ARTIFACTS` (1K), `MAX_RENAMES` (10K), `MAX_COMPLETED_TASKS` (50).
- **Response truncation**: Dual-limit — soft char limit (8K default) plus hard byte limit (64KB). `tool_decorator` auto-enforces even for tools that don't call `_check_mcp_response_size`. Set `ARKANA_MCP_RESPONSE_LIMIT_CHARS=65536` for non-Claude-Code clients.
- **Pagination**: Two patterns: (1) **Response-level** (`_paginated_response`) for large-output tools using `line_offset`/`line_limit`, cached via `_ToolResultCache`. (2) **Field-level** (`_paginate_field`) for dict tools with multiple list fields, adding `{field}_pagination` metadata. Pagination params listed in `_SKIP` so they don't affect cache keys.
- **Search/grep in decompilation**: `decompile_function_with_angr`, `batch_decompile`, `get_annotated_disassembly` accept `search` (regex), `context_lines`, `case_sensitive`. Search is a view/filter on cached results. `_search_helpers.py` validates via `validate_regex_pattern()` for ReDoS safety.
- **`tool_decorator`**: Wraps every MCP tool — handles session activation, heartbeat, history recording, error enrichment, and sets `_current_tool_var` contextvar for warning attribution.
- **Warning capture**: `arkana/warning_handler.py` captures WARNING+ from library loggers into `state.analysis_warnings`, deduplicated, attributed via `_current_tool_var`/`_current_task_var`. Session-scoped (not persisted to cache).
- **Resource monitor**: `arkana/resource_monitor.py` — psutil daemon thread. Alerts injected into `_collect_background_alerts()`. Returns `None` when psutil unavailable.
- **Null-region detection**: `_is_null_region_artifact()` filters null-byte regions (angr interprets as `add [rax], al`) from `get_function_map` and enrichment. `release_angr_memory` drops angr project/CFG, calls `gc.collect()` + `malloc_trim(0)`, preserves PE data/notes/session.
- **Background task timeout**: 14 background tools use progress-adaptive timeouts via `_run_background_task_wrapper`. Soft timeout → `TASK_OVERTIME` → stall-kill/ceiling. `_background_alerts` injected into every tool response. `cancel_all_background_tasks()` called by `open_file`/`close_file`. Generation guard prevents stale threads from writing results after file switches. Set soft timeout to 0 for old single hard-timeout behavior.
- **Emulation debugger**: 29 tools in `tools_debug.py`, persistent Qiling subprocess (`scripts/debug_runner.py`), JSONL IPC. Three stub layers: CRT (~47 APIs), I/O (console), API trace hooks. All use `hook_address()` per IAT entry. `debug_stub_api` supports `set_last_error` for anti-emulation bypass.
- **Emulation inspect sessions**: 7 tools in `tools_emulate_inspect.py` for post-emulation memory inspection. Keep subprocess alive after `run()` for memory search/read without re-emulation.
- **BSim function similarity**: `_bsim_features.py` — architecture-independent matching. SQLite DB at `~/.arkana/bsim/signatures.db`. Two-phase query: SQL pre-filter then full scoring.
- **Notes system**: Categories: `general`, `function`, `tool_result`, `ioc`, `hypothesis`, `conclusion`, `manual`. Hypothesis notes support `confidence`, `hypothesis_status`, `evidence` list, `superseded_by`. `update_hypothesis` MCP tool manages lifecycle.
- **Sandbox report ingestion**: `tools_sandbox.py` — 3 tools parsing CAPE/Cuckoo/ANY.RUN/Hybrid Analysis/Joe Sandbox JSON into unified schema on `state._sandbox_report`. Cleared on file switch.
- **CTI report generator**: `generate_cti_report` aggregates all cached analysis into markdown or JSON. Optional `output_path` saves to file.
- **Ghidra/IDA export**: `export_ghidra_script`/`export_ida_script` generate Python scripts from renames, types, notes, triage status.
- **VBA/XLM macro analysis**: `tools_macro.py` — 3 tools. Requires `oletools`. Works on Office docs directly without `open_file`.
- **VM protection detection**: `detect_vm_protection` characterizes VMProtect/Themida/etc via 6 heuristics. Does NOT require angr.
- **Decompilation digest**: `batch_decompile(digest=True)` — ~17x token compression via structured behavioral summaries. `_build_function_digest()` extracts API calls, strings, 12 behavioral patterns, complexity metrics.
- **Rename/annotation layer**: `apply_variable_renames_to_lines()` uses single-pass combined regex to prevent cascading substitutions. `batch_rename` uses two-pass validate-then-apply for atomicity.
- **Custom types**: Structs reuse `_parse_fields`. Cycle detection prevents recursive references. Persisted via cache.
- **Decompiler cffi fallback**: `_safe_decompile()` retries with `cfg=None` on pickle errors. Returns `(result, used_fallback)` tuple. All 4 Decompiler call sites use this helper.
- **Extended enrichment pipeline**: After IOC collection, runs 5 additional phases (family ID, API hash scan, C2 indicators, DGA detection, crypto constants). All cached and persisted via `_save_enrichment_cache()`.
- **Incremental enrichment saves**: Saves at 3 points: after Phase 2g, every 60s during decompile sweep, and async after on-demand decompiles (throttled 30s).
- **Decompile meta cache**: `_decompile_meta` — `OrderedDict` with LRU eviction (cap 2000). Dashboard functions build keys using `_get_state()._state_uuid` directly (not `_make_decompile_key()`) since dashboard threads lack MCP session contextvar.

## Input Validation & Safety Guards

- **Emulation limits**: Qiling validates `max_instructions` (0–10M). Inspect sessions: max 3, 30-min TTL, 300s run timeout, 1MB max read, 100 max search matches.
- **Debug session limits**: Max 3 sessions, 1MB max read, 100 max breakpoints, 50 max watchpoints, 10 max snapshots, 10K max trace entries. User stubs: 200 max, validated names.
- **Security**: Auth lowercases ASGI headers. Error messages truncate input to 50 chars. Dashboard validates address length (≤40), escapes all dynamic values (`escapeHtml()`). Path validation via `state.check_path_allowed()`.
- **Resource bounds**: Delay-load imports capped at 10K. ThreadPool capped at `min(cpu_count, 8)`. PE resources capped at 1K. IOC TLD regex `{2,16}`. Cache size clamped 1–50000 MB. File size limit 256MB (env: `ARKANA_MAX_FILE_SIZE_MB`).
- **Safety**: Decompression bomb protection (100MB limit). Hex input validated before `fromhex()`. Refinery pipeline loops break at `limit`. Cache uses atomic writes (`tempfile` + `os.replace()`). Search regex validated for ReDoS. `_make_hashable()` enforces depth 20. `_ToolResultCache.set()` stores shallow copies.
- **Systemic limit clamping**: All ~60 tools accepting `limit` clamp via `max(1, min(limit, MAX_TOOL_LIMIT))` where `MAX_TOOL_LIMIT` = 100K.

## Dashboard

Port 8082, auto-starts. Access URL logged at startup with token query parameter.

Pages: Overview, Functions (sortable, triage, XREF panel, code search, symbol tree), Call Graph (Cytoscape.js, dagre), Sections (entropy heatmap), Imports, Hex View (infinite scroll), Strings (FLOSS detail, sifter scores), CAPA, MITRE, Types (struct/enum editor), Diff (BinDiff), Timeline, Notes.

Global status bar shows active tool + background tasks, 3s htmx refresh, collapses when idle. Triage flags persisted to cache.

**CSP**: `script-src 'self'`, no inline scripts. Event delegation with `data-*` attributes. `fetchJSON()` shared helper. `Cache-Control: no-store` on non-static responses. Dedicated thread pool (`_dash_to_thread()`, 4 threads, env: `ARKANA_DASHBOARD_THREADS`). Diff path validation includes samples directory containment. Callgraph capped at 5K edges. Code search capped at 500 chars. Responsive nav overflow. Functions scroll preservation on enrichment reloads.

## Docker

```bash
./run.sh --stdio          # stdio mode (for Claude Code)
./run.sh                  # HTTP mode (port 8082)
./run.sh --samples ~/dir  # Mount samples directory
```

4 venvs isolate incompatible unicorn versions (angr v2, Speakeasy/Unipacker/Qiling v1). .NET tools via subprocess (de4dot-cex/mono, NETReactorSlayer, ilspycmd/dotnet).

## Known Tool Limitations

These are inherent limitations from underlying frameworks, not bugs:

- **`get_data_dependencies`**: Returns raw angr internals. Prefer `get_reaching_definitions` or `propagate_constants`.
- **`get_backward_slice`/`get_forward_slice`**: CFG reachability, not true data-flow slices.
- **`extract_function_constants`**: Includes code addresses alongside data constants.
- **Qiling emulation**: Requires manual rootfs setup. `qiling_setup_check()` verifies.
- **Debug sessions**: Fidelity limited by Qiling/Unicorn. **Register writes don't redirect execution** — use code patching instead. **Unresolved MSVCRT imports** need IAT patching. **Threading unsupported** — stub and redirect. **Timeout pauses, not kills** — session preserved for inspection. `DEBUG_COMMAND_TIMEOUT` (300s, env: `ARKANA_DEBUG_COMMAND_TIMEOUT`).
- **`auto_unpack_pe`**: FSG may fail. Use `qiling_dump_unpacked_binary()` as fallback.
- **`qiling_dump_unpacked_binary`**: `smart_unpack` hooks VirtualAlloc to track allocations, scans for PE headers. Falls back to largest-region heuristic.
- **`get_virustotal_report_for_loaded_file`**: Requires API key via `set_api_key(service="virustotal", key="...")`.
- **`analyze_batch`**: 8KB soft limit can truncate. Use 5-10 files max.
- **`search_decompiled_code`**: Searches pseudocode, not assembly. Use `get_annotated_disassembly(search=...)` for assembly.
- **DFS symbolic execution**: angr DFS triggers cffi pickle errors. `solve_constraints_for_path` uses BFS by default. `find_path_to_address` has `use_dfs` param.
- **`reconstruct_pe_from_dump`**: LIEF Builder API varies between versions. Auto-detects signature.
- **`get_value_set_analysis`**: Known angr compatibility issues. Prefer `get_reaching_definitions`.
- **`detect_compression_headers`**: May false-positive on code sections.
- **`save_patched_binary`**: `bytes_patched` includes loader differences, not just user patches.
- **`go_analyze`**: GoReSym→pygore→string_scan fallback. GoReSym needs PATH or `~/.arkana/tools/`.
- **`detect_null_regions`**: May flag legitimate null-initialized data sections.
- **`release_angr_memory`**: After release, angr tools rebuild from disk.
- **Speakeasy allocation tracking**: `emulate_pe_with_windows_apis(track_allocations=True)` for VirtualAlloc/Protect anomaly detection.

## CI

GitHub Actions runs on every push/PR: unit tests (Python 3.10-3.12), ruff lint, smoke tests. Coverage floor 65% with branch coverage. Dependabot weekly pip updates.
