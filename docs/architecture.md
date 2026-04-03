# Architecture & Design

Technical documentation for Arkana's internal structure, design principles, and data handling.

---

## Package Structure

```
arkana.py                        # Entry point (thin wrapper)
arkana/
├── __init__.py                 # Package metadata
├── __main__.py                 # python -m arkana support
├── state.py                    # Thread-safe AnalyzerState
├── config.py                   # Imports, availability flags, constants
├── cache.py                    # Disk-based analysis cache (gzip/LRU)
├── user_config.py              # Persistent API key storage (~/.arkana/)
├── utils.py                    # Utility functions
├── hashing.py                  # ssdeep implementation
├── mock.py                     # MockPE for non-PE/shellcode mode
├── background.py               # Background task management
├── enrichment.py               # Auto-enrichment background coordinator
├── integrity.py                # Pre-parse file integrity checks (PE/ELF/Mach-O)
├── resources.py                # PEiD/capa/YARA rule downloads
├── parsers/
│   ├── pe.py                   # PE structure parsing
│   ├── capa.py                 # Capa integration
│   ├── floss.py                # FLOSS integration (with Vivisect progress polling)
│   ├── signatures.py           # PEiD/YARA scanning
│   ├── strings.py              # String utilities
│   ├── go_pclntab.py           # Go pclntab parser (Go 1.2-1.26+, pure-Python)
│   └── go_types.py             # Go type descriptor parser (struct/interface/itab)
├── dashboard/                  # Web dashboard (Starlette + htmx + Jinja2)
│   ├── app.py                  # ASGI app factory, routes, auth, SSE events
│   ├── state_api.py            # Data extraction layer (reads AnalyzerState for views)
│   ├── templates/              # Jinja2 templates (overview, functions, callgraph, etc.)
│   │   └── partials/           # htmx partials (_global_status, _overview_stats, etc.)
│   └── static/                 # CSS (CRT theme), JS (htmx, Cytoscape.js, dagre)
├── cli/
│   └── printers.py             # CLI output formatting
└── mcp/
    ├── __init__.py
    ├── server.py                 - MCP server setup, response truncation & validation helpers
    ├── _angr_helpers.py          - Shared angr utilities (project/CFG init, address resolution)
    ├── _format_helpers.py        - Shared binary format helpers
    ├── _refinery_helpers.py      - Shared Binary Refinery utilities (hex conversion, safety limits)
    ├── _progress_bridge.py       - Thread-safe MCP progress bridge for background tools
    ├── _bsim_features.py          - BSim function similarity feature extraction & matching
    ├── _category_maps.py         - Category mappings for tool organisation
    ├── _input_helpers.py         - Hex/int parameter parsing, LRU result cache, pagination utilities
    ├── _search_helpers.py        - Regex search-with-context for decompiled code and disassembly
    ├── _rename_helpers.py        - Function/variable rename application for decompilation output
    ├── tools_pe.py               - File management, PE data retrieval & integrity (8 tools)
    ├── tools_pe_extended.py      - Extended PE analysis (14 tools)
    ├── tools_strings.py          - String analysis, capa, fuzzy search & custom YARA (13 tools)
    ├── tools_angr.py             - Core angr tools (18 tools, incl. symbolic execution)
    ├── tools_angr_disasm.py      - Angr disassembly & function recovery (6 tools)
    ├── tools_angr_dataflow.py    - Angr data flow analysis (5 tools)
    ├── tools_angr_hooks.py       - Angr function hooking (3 tools)
    ├── tools_angr_forensic.py    - Angr forensic & advanced analysis (10 tools)
    ├── tools_new_libs.py         - LIEF/Capstone/Keystone/Speakeasy (13 tools)
    ├── tools_qiling.py           - Qiling cross-platform emulation (8 tools)
    ├── tools_debug.py            - Interactive emulation debugger (29 tools)
    ├── tools_dotnet.py           - .NET analysis (dnfile/dncil, 2 tools)
    ├── tools_go.py               - Go binary analysis (pygore, 1 tool)
    ├── tools_rust.py             - Rust binary analysis (2 tools)
    ├── tools_elf.py              - ELF analysis (pyelftools, 2 tools)
    ├── tools_macho.py            - Mach-O analysis (LIEF, 1 tool)
    ├── tools_format_detect.py    - Auto binary format detection (1 tool)
    ├── tools_virustotal.py       - VirusTotal API integration (1 tool)
    ├── tools_deobfuscation.py    - Hex dump & deobfuscation tools (5 tools)
    ├── tools_triage.py           - Comprehensive triage report (1 tool)
    ├── tools_cache.py            - Analysis cache management (3 tools)
    ├── tools_config.py           - Configuration & utility tools (5 tools)
    ├── tools_classification.py   - Binary purpose classification (1 tool)
    ├── tools_samples.py          - Sample directory listing & discovery (1 tool)
    ├── tools_notes.py            - Persistent notes management (5 tools)
    ├── tools_history.py          - Tool invocation history (2 tools)
    ├── tools_session.py          - Session summary, analysis digest & discoverability (6 tools)
    ├── tools_export.py           - Project export/import (2 tools)
    ├── tools_crypto.py           - Cryptographic algorithm identification & key extraction (3 tools)
    ├── tools_payload.py          - Steganography, container parsing & config extraction (3 tools)
    ├── tools_ioc.py              - Structured IOC export (JSON/CSV/STIX) (1 tool)
    ├── tools_unpack.py           - Multi-method unpacking & OEP detection (3 tools)
    ├── tools_diff.py             - Binary payload comparison (1 tool)
    ├── tools_rename.py             - Function/variable renames & address labels (6 tools)
    ├── tools_types.py              - Custom struct/enum type definitions (5 tools)
    ├── tools_struct.py             - Binary struct parsing (1 tool)
    ├── tools_bsim.py              - BSim function similarity matching (9 tools)
    ├── tools_malware_id.py         - Malware family identification (3 tools)
    ├── tools_detection.py          - Detection engineering: YARA/Sigma rule generation (2 tools)
    ├── tools_forensic_pe.py        - PE forensics & detection engineering (7 tools)
    ├── tools_workflow.py         - Report generation & sample naming (2 tools)
    ├── tools_refinery.py         - Binary Refinery core transforms (11 tools)
    ├── tools_refinery_advanced.py  - Refinery advanced transforms (8 tools)
    ├── tools_refinery_dotnet.py  - Refinery .NET analysis (1 dispatched tool)
    ├── tools_refinery_executable.py  - Refinery executable operations (1 dispatched tool)
    ├── tools_refinery_extract.py  - Refinery archive/document extraction (1 dispatched tool)
    ├── tools_refinery_forensic.py  - Refinery forensic parsing (1 dispatched tool)
    ├── tools_context.py          - Context aggregation (1 tool)
    ├── tools_dashboard_exposed.py - Dashboard-exposed analysis (3 tools)
    ├── tools_frida.py            - Frida script generation (4 tools)
    ├── tools_vuln.py             - Vulnerability pattern detection (2 tools)
    ├── tools_dotnet_deobfuscate.py - .NET deobfuscation & decompilation (3 tools)
    ├── tools_batch.py            - Batch analysis operations
    ├── tools_learning.py         - Learner progress tracking (4 tools)
    ├── tools_malware_detect.py   - DGA/C2/kernel driver detection (3 tools)
    ├── tools_malware_id.py       - Malware family identification (3 tools)
    ├── tools_pe_forensic.py      - PE forensics (7 tools)
    ├── tools_pe_structure.py     - PE structure parsing
    ├── tools_threat_intel.py     - Threat intelligence & attribution (5 tools)
    ├── tools_warnings.py         - Analysis warning management (2 tools)
    ├── tools_coverage.py         - Code coverage import (2 tools)
    ├── tools_trace_analysis.py   - Trace analysis & MBA detection (2 tools)
    ├── _anti_vm_hooks.py         - Anti-VM bypass hook installation for Qiling emulation
    └── _go_abi.py                - Go ABI detection and call instruction annotation
```

---

## Design Principles

- **Modular Package**  - Clean `arkana/` package structure with 65 MCP modules and separated concerns (parsers, MCP tools, CLI, configuration).
- **Docker-First Design**  - No interactive prompts. Dependencies are managed via Docker, making it container and CI/CD ready.
- **Single-File Analysis Context**  - The server holds one file in memory via `AnalyzerState`. All tools operate on this shared context. Use `open_file` and `close_file` to switch between files. Calling `open_file` on a new file without `close_file` is safe — all module-level caches (`_decompile_meta`, `_phase_caches`, dashboard caches, `result_cache`, analysis warnings) are cleared automatically to prevent cross-file data contamination.
- **Thread-Safe State**  - Centralised `AnalyzerState` class with locking for concurrent access.
- **Background Tasks**  - Long-running operations (symbolic execution, Angr CFG) run asynchronously with progress-adaptive timeouts (soft timeout → OVERTIME → stall-kill/ceiling). Background alerts are passively injected into tool responses. `abort_background_task()` provides explicit cancellation.
- **Disk-Based Caching**  - Analysis results are cached in `~/.arkana/cache/` as gzip-compressed JSON, keyed by SHA256. Re-opening a previously analysed file loads from cache in under 10 ms. LRU eviction keeps cache size bounded.
- **Lazy Loading**  - Heavy analysis (Angr CFG) runs in the background. The server is usable immediately.
- **Pagination**  - Tools that return lists support `limit` and `offset` parameters with LRU result caching, preventing response truncation and giving AI clients control over data volume per call (default limit 20 for most tools).
- **Smart Truncation**  - MCP responses use a dual-limit system: a soft character limit (8K by default, tuned for Claude Code CLI) plus a hard 64KB byte-limit backstop per the MCP protocol specification. The `tool_decorator` includes a safety net that auto-enforces the soft limit even for tools that don't call `_check_mcp_response_size()` explicitly. Set `ARKANA_MCP_RESPONSE_LIMIT_CHARS=65536` to restore 64KB-only behaviour for non-Claude-Code clients.
- **Graceful Degradation**  - All 20+ optional libraries are detected at startup. Tools that require unavailable libraries return clear error messages instead of crashing.
- **Auto-Enrichment**  - After `open_file`, a background coordinator (`arkana/enrichment.py`) automatically runs classification, triage, similarity hashing, MITRE mapping, IOC collection, FLIRT library identification, a decompilation sweep, and auto-noting. Each phase checks a cancellation event and yields to on-demand decompile requests. Disable with `ARKANA_AUTO_ENRICHMENT=0`; control sweep depth with `ARKANA_ENRICHMENT_MAX_DECOMPILE=N`. The decompile sweep skips functions with more than `MAX_ENRICHMENT_BLOCKS` (300) basic blocks to prevent long uninterruptible decompiler calls. Enrichment results are saved incrementally — after the fast phases (classify through IOCs) and periodically during the decompile sweep (every 60s) — so that a server crash loses at most ~60 seconds of work instead of everything. On-demand decompiles (MCP tool + dashboard) also trigger async cache saves (throttled to 30s intervals per-state, non-blocking).
- **Decompile Lock**  - A `ResettableLock` in `state.py` prevents concurrent angr decompilation (which isn't thread-safe). On file switch, `cancel_all_background_tasks()` calls `force_reset()` to release the lock even if a thread is stuck in angr's uninterruptible C Decompiler call. Uses thread-ID-to-generation mapping so stale threads' `release()` becomes a no-op. MCP clients are notified via a transient `decompile_lock_reset` alert in `_background_alerts`.
- **Partial CFG Acceptance**  - When angr's CFG build stalls, times out, crashes, or accumulates too many errors after discovering functions, `_accept_partial_cfg()` stores a `_PartialCFG` wrapper backed by the live `project.kb.functions`. Tools see it as a normal CFG — `get_function_map()`, `decompile_function_with_angr()`, and call graph tools all work on the discovered functions. Four acceptance triggers: stall-kill (≥100 funcs), max-runtime exceeded, high error rate with stalled progress, and exception with enough functions in the KB. Quality metadata is stored in `state._cfg_quality` and surfaced via a persistent `cfg_partial` alert.
- **Tool Decorator**  - Every MCP tool is wrapped by `tool_decorator` in `server.py`, which handles session activation, heartbeat updates, tool history recording, error enrichment, and response size enforcement.
- **Rename/Annotation Layer**  - Users can rename functions and variables, and add address labels. Renames persist via cache alongside notes and are automatically applied in decompilation and disassembly output. Variable renames use a single-pass combined regex to prevent cascading substitutions. `batch_rename` supports bulk operations with two-pass validate-then-apply atomicity.
- **Custom Types**  - User-defined structs and enums for parsing binary data. Field types reuse `parse_binary_struct` types. Persisted via cache with validation guards (field name regex, enum byte-size checks, duplicate detection, cycle detection for recursive structs).
- **Artifacts**  - Tools that extract files (unpacking, payload carving, config extraction) register them via `state.register_artifact()` with path, hashes, source tool, and type detection. Artifacts persist via cache and are included in project export/import archives.

---

## Tool Registration

Tool registration is managed by `arkana/tool_registry.py`. All tools are registered at startup via `register_all_tools()`. Module groups (CORE, COMMON_ANALYSIS, ANGR, PE, ELF, etc.) organise tool modules by domain. Refinery tools are conditionally registered based on `REFINERY_AVAILABLE`.

### Brief Descriptions

`--brief-descriptions` (or `ARKANA_BRIEF_DESCRIPTIONS=1`) extracts the `---compact:` shorthand line from each tool's docstring, replacing the full description in the MCP tool listing. This reduces the listing size by ~90% (~23 KB vs ~280 KB). Parameter schemas are still conveyed via the MCP `inputSchema` field.

Every `@tool_decorator` function must include a `---compact:` line in its docstring. Grammar:

```
---compact: <action> [| <details>] [| needs: <prereqs>]
```

- **`<action>`**: Telegraphic description, no articles, max ~60 chars
- **`<details>`**: Key modes, outputs, differentiators (pipe-separated)
- **`needs:`**: Prerequisites — `file`, `angr`, `angr+CFG`, `PE`, `ELF`, `qiling`, `refinery`, `debug session`, etc.

Compliance enforced by `tests/test_compact_descriptions.py`. Useful when `ENABLE_TOOL_SEARCH` is disabled.

---

## BSim Function Similarity

### What BSim Does Well

1. **Binary-level family detection**: "Is this sample related to anything I've analyzed before?" Use `triage_binary_similarity` after opening a new file. If the DB contains previously analyzed samples from the same campaign, they'll show up with shared function counts and overlap ratios.

2. **Tracking analysis across variants**: When you rename functions in sample A (e.g., `decrypt_config`, `c2_beacon`), those names are automatically synced to the BSim DB. When sample B from the same family arrives, `transfer_annotations` can apply your renames to matching functions — saving hours of re-analysis.

3. **Growing knowledge base**: Every binary you open is automatically indexed via auto-enrichment (`ARKANA_BSIM_AUTO_INDEX=1`). The more you analyze, the better BSim gets at recognizing related code.

### What BSim Does NOT Do

- **Identify specific library functions by name** in dynamically-linked binaries. Windows malware calls DLL functions via the IAT — the DLL code is not in the binary. Matching against ntdll.dll/msvcrt.dll signatures produces structural coincidences, not functional identification. Use FLIRT signatures (`identify_library_functions`) for that.

- **Replace YARA or capa**. BSim answers "have I seen this code before?" not "does this file contain these bytes?" (YARA) or "what can this code do?" (capa).

### Recommended Workflow

1. **Open file** → auto-enrichment indexes into BSim DB automatically
2. **Run `triage_binary_similarity`** → check if related to known samples
3. **Analyze and rename functions** → names sync to BSim DB automatically
4. **When a variant arrives** → triage detects it, then `transfer_annotations(sha256, preview=True)` shows what renames can be carried over
5. **Use `seed_signature_db`** for statically-linked libraries (e.g., Go binaries embedding crypto) — this IS effective for identifying compiled-in code

### Limitations

- Function-level matching uses structural + behavioral features (8 groups: CFG, API calls, VEX IR, strings, constants, size, block hashes, call context), not exact byte patterns. Annotation transfer requires similarity ≥ 0.85, confidence ≥ 3, and ≥ 2 shared real API calls.
- Works best comparing binaries from the same compiler and similar optimization levels.
- Very small functions (< 3 basic blocks) are excluded from matching.
- angr pseudo-APIs (`UnresolvableCallTarget`, etc.) are filtered from all comparisons.

---

## Pagination & Result Limits

Most tools that return lists of results support **pagination** via `limit` and `offset` parameters. This prevents response truncation and gives AI clients control over how much data they receive per call.

### How Pagination Works

Every paginated tool response includes a `_pagination` metadata block:

```json
{
  "results": [ ... ],
  "count": 20,
  "_pagination": {
    "total": 150,
    "offset": 0,
    "limit": 20,
    "returned": 20,
    "has_more": true
  }
}
```

To fetch the next page, call the same tool with `offset=20` (or whatever `offset + limit` is). Continue until `has_more` is `false`.

### Default Limits

The default `limit` varies by tool to balance context efficiency with completeness:

| Default `limit` | Tools |
|---|---|
| **20** | Most tools  - `get_pe_data`, `get_floss_analysis_info`, `get_capa_analysis_info`, `get_function_xrefs`, `get_backward_slice`, `get_forward_slice`, `get_function_complexity_list`, `extract_function_constants`, `get_global_data_refs`, `scan_for_indirect_jumps`, `get_reaching_definitions`, `get_data_dependencies`, `get_control_dependencies`, `identify_library_functions`, `diff_binaries`, `detect_self_modifying_code`, `find_code_caves`, `identify_cpp_classes`, `identify_crypto_algorithm`, `auto_extract_crypto_keys`, all Refinery tools, all multi-format analysis tools (`dotnet_analyze`, `elf_analyze`, `macho_analyze`, `go_analyze`), `get_notes`, `get_tool_history`, `get_triage_report`, and more |
| **30** | `get_function_map` (function ranking), `disassemble_at_address` (instructions) |
| **50** | `get_call_graph` (call graph edges), `analyze_entropy_by_offset`, `qiling_trace_execution` |
| **80** | `get_value_set_analysis`, `propagate_constants`, `get_function_variables` |
| **300** | `get_annotated_disassembly` (rich disassembly blocks) |
| **10** | `brute_force_simple_crypto`, `extract_steganography`, `find_oep_heuristic` |

The hard upper bound on `limit` is **100,000** (enforced in `get_pe_data` and string tools) to prevent excessive memory allocation.

### Search Within Results

Three tools support an optional `search` parameter for regex grep within their output: `decompile_function_with_angr`, `batch_decompile`, and `get_annotated_disassembly`. When `search` is provided, only matching lines/instructions with surrounding context are returned instead of full paginated output. The `context_lines` parameter (default 2, max 20) controls how many lines of context surround each match, and `case_sensitive` (default False) controls case sensitivity. Search is a view/filter on cached results — it does not affect cache keys, so the same cached decompilation serves both paginated browsing and search queries. `batch_decompile` with `search` excludes functions that have no matches.

### Field-Level Pagination

Tools that return dicts with multiple list fields use `_paginate_field()` for inline pagination. Each paginated field gets a sibling `{field}_pagination` dict:

```json
{
  "suspicious_imports": [ ... ],
  "suspicious_imports_pagination": {
    "total": 85,
    "offset": 0,
    "limit": 50,
    "returned": 50,
    "has_more": true
  }
}
```

Key tools with field-level pagination:

| Tool | Pagination Parameters |
|---|---|
| `get_triage_report` | `indicator_offset` (default 0), `indicator_limit` (default 50) — applies to all list fields |
| `get_analysis_digest` | `findings_offset/limit`, `functions_offset/limit`, `ioc_offset/limit`, `unexplored_offset/limit`, `notes_offset/limit` |
| `get_session_summary` | `notes_offset/limit` (default 0/50), `history_limit` (default 30) |
| `get_analysis_timeline` | `offset` (default -1 = most recent), `limit` (default 50) |
| `get_function_map` | `offset` (default 0), `limit` (default 30) |
| `suggest_next_action` | `max_suggestions` (default 5) |
| `find_anti_debug_comprehensive` | `limit` (default 60) |
| `identify_cpp_classes` | `method_limit` (default 20) |
| `detect_dga_indicators` | `limit` (default 20) |
| `match_c2_indicators` | `limit` (default 20) |
| `analyze_kernel_driver` | `limit` (default 30) |

All field-level pagination parameters are included in the `_SKIP` set so they don't affect cache keys.

### Result Caching (LRU)

Paginated results are cached in an **LRU cache** (5 slots per tool) so that paging through results doesn't re-compute the full dataset on each call. The cache is keyed by tool name and non-pagination parameters  - changing `offset`, `limit`, `search`, `context_lines`, or `case_sensitive` hits the same cache entry. The internal maximum cached items per result set is **5,000**.

### Session & State Limits

| Setting | Value | Description |
|---|---|---|
| `MAX_ACTIVE_SESSIONS` | 100 | Maximum concurrent HTTP sessions (overridable via `ARKANA_MAX_SESSIONS`). Oldest session evicted when limit reached. |
| `MAX_COMPLETED_TASKS` | 50 | Maximum completed/failed background tasks retained per session |
| `MAX_TOOL_HISTORY` | 500 | Maximum tool invocation history entries retained per session |
| `MAX_NOTES` | 10,000 | Maximum notes per session |
| `MAX_ARTIFACTS` | 1,000 | Maximum artifacts per session |
| `MAX_RENAMES` | 10,000 | Maximum renames per session |
| `SESSION_TTL_SECONDS` | 3600 | Session lifetime before cleanup (1 hour) |
| `MAX_MCP_RESPONSE_SIZE_KB` | 64 | MCP response size limit per the protocol specification |
| `ARKANA_MAX_CONCURRENT_ANALYSES` | 3 | Concurrent heavy analysis semaphore (configurable via environment variable) |
| `MAX_ANALYSIS_WARNINGS` | 500 | Maximum unique library warnings captured per session (deduplicated) |
| `_MAX_DECOMPILE_META` | 2,000 | Maximum cached decompilation results (LRU eviction via OrderedDict, session-scoped keys) |
| `MAX_TOOL_LIMIT` | 100,000 | Hard upper bound for `limit` parameters across all ~60 tool functions |
| `ANGR_CFG_SOFT_TIMEOUT` | 900 | Soft timeout (15 min) for CFG build before entering OVERTIME. Set to 0 to disable. |
| `BACKGROUND_TASK_SOFT_TIMEOUT` | 300 | Soft timeout (5 min) for generic background tasks before entering OVERTIME. |
| `OVERTIME_CHECK_INTERVAL` | 60 | Progress check frequency during OVERTIME (seconds) |
| `OVERTIME_STALL_KILL` | 300 | Kill task after this many seconds of zero progress during OVERTIME |
| `OVERTIME_MAX_RUNTIME` | 21,600 | Absolute ceiling (6 hours) — safety net for pathological slow-progress cases |
| `MAX_DEBUG_SESSIONS` | 3 | Maximum concurrent interactive debug sessions (overridable via `ARKANA_MAX_DEBUG_SESSIONS`). Oldest evicted when limit reached. |
| `DEBUG_SESSION_TTL` | 1,800 | Debug session idle timeout in seconds (overridable via `ARKANA_DEBUG_SESSION_TTL`) |
| `DEBUG_COMMAND_TIMEOUT` | 300 | Per-command timeout for debug execution commands (overridable via `ARKANA_DEBUG_COMMAND_TIMEOUT`). On timeout, the session is paused (not killed) — memory and state are preserved for inspection and execution can be resumed |
| `DEBUG_RUNNER_TIMEOUT_BUFFER` | 15 | Extra seconds added to the client-side safety-net timeout beyond the runner-side deadline |
| `MAX_DEBUG_SNAPSHOTS` | 10 | Maximum saved snapshots per debug session (overridable via `ARKANA_MAX_DEBUG_SNAPSHOTS`) |
| `MAX_DEBUG_INSTRUCTIONS` | 10,000,000 | Maximum instructions per continue/run_until operation |
| `MAX_DEBUG_BREAKPOINTS` | 100 | Maximum breakpoints per debug session |
| `MAX_DEBUG_WATCHPOINTS` | 50 | Maximum watchpoints per debug session |
