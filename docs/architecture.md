# Architecture & Design

Technical documentation for PeMCP's internal structure, design principles, and data handling.

---

## Package Structure

```
PeMCP.py                        # Entry point (thin wrapper)
pemcp/
├── __init__.py                 # Package metadata
├── __main__.py                 # python -m pemcp support
├── state.py                    # Thread-safe AnalyzerState
├── config.py                   # Imports, availability flags, constants
├── cache.py                    # Disk-based analysis cache (gzip/LRU)
├── user_config.py              # Persistent API key storage (~/.pemcp/)
├── utils.py                    # Utility functions
├── hashing.py                  # ssdeep implementation
├── mock.py                     # MockPE for non-PE/shellcode mode
├── background.py               # Background task management
├── resources.py                # PEiD/capa/YARA rule downloads
├── parsers/
│   ├── pe.py                   # PE structure parsing
│   ├── capa.py                 # Capa integration
│   ├── floss.py                # FLOSS integration
│   ├── signatures.py           # PEiD/YARA scanning
│   └── strings.py              # String utilities
├── cli/
│   └── printers.py             # CLI output formatting
└── mcp/
    ├── __init__.py
    ├── server.py                — MCP server setup, response truncation & validation helpers
    ├── _angr_helpers.py         — Shared angr utilities (project/CFG init, address resolution)
    ├── _format_helpers.py       — Shared binary format helpers
    ├── _refinery_helpers.py     — Shared Binary Refinery utilities (hex conversion, safety limits)
    ├── _progress_bridge.py      — Thread-safe MCP progress bridge for background tools
    ├── _category_maps.py        — Category mappings for tool organisation
    ├── _input_helpers.py        — Hex/int parameter parsing, LRU result cache, pagination utilities
    ├── tools_pe.py              — File management & PE data retrieval (7 tools)
    ├── tools_pe_extended.py     — Extended PE analysis (14 tools)
    ├── tools_strings.py         — String analysis, capa, fuzzy search & custom YARA (13 tools)
    ├── tools_angr.py            — Core angr tools (16 tools)
    ├── tools_angr_disasm.py     — Angr disassembly & function recovery (6 tools)
    ├── tools_angr_dataflow.py   — Angr data flow analysis (5 tools)
    ├── tools_angr_hooks.py      — Angr function hooking (3 tools)
    ├── tools_angr_forensic.py   — Angr forensic & advanced analysis (10 tools)
    ├── tools_new_libs.py        — LIEF/Capstone/Keystone/Speakeasy (13 tools)
    ├── tools_qiling.py          — Qiling cross-platform emulation (8 tools)
    ├── tools_dotnet.py          — .NET analysis (dnfile/dncil, 2 tools)
    ├── tools_go.py              — Go binary analysis (pygore, 1 tool)
    ├── tools_rust.py            — Rust binary analysis (2 tools)
    ├── tools_elf.py             — ELF analysis (pyelftools, 2 tools)
    ├── tools_macho.py           — Mach-O analysis (LIEF, 1 tool)
    ├── tools_format_detect.py   — Auto binary format detection (1 tool)
    ├── tools_virustotal.py      — VirusTotal API integration (1 tool)
    ├── tools_deobfuscation.py   — Hex dump & deobfuscation tools (5 tools)
    ├── tools_triage.py          — Comprehensive triage report (1 tool)
    ├── tools_cache.py           — Analysis cache management (3 tools)
    ├── tools_config.py          — Configuration & utility tools (4 tools)
    ├── tools_classification.py  — Binary purpose classification (1 tool)
    ├── tools_samples.py         — Sample directory listing & discovery (1 tool)
    ├── tools_notes.py           — Persistent notes management (5 tools)
    ├── tools_history.py         — Tool invocation history (2 tools)
    ├── tools_session.py         — Session summary, analysis digest & discoverability (6 tools)
    ├── tools_export.py          — Project export/import (2 tools)
    ├── tools_crypto.py          — Cryptographic algorithm identification & key extraction (3 tools)
    ├── tools_payload.py         — Steganography, container parsing & config extraction (3 tools)
    ├── tools_ioc.py             — Structured IOC export (JSON/CSV/STIX) (1 tool)
    ├── tools_unpack.py          — Multi-method unpacking & OEP detection (3 tools)
    ├── tools_diff.py            — Binary payload comparison (1 tool)
    ├── tools_workflow.py        — Report generation & sample naming (2 tools)
    ├── tools_refinery.py        — Binary Refinery core transforms (11 tools)
    ├── tools_refinery_advanced.py — Refinery advanced transforms (8 tools)
    ├── tools_refinery_dotnet.py — Refinery .NET analysis (1 dispatched tool)
    ├── tools_refinery_executable.py — Refinery executable operations (1 dispatched tool)
    ├── tools_refinery_extract.py — Refinery archive/document extraction (1 dispatched tool)
    └── tools_refinery_forensic.py — Refinery forensic parsing (1 dispatched tool)
```

---

## Design Principles

- **Modular Package** — Clean `pemcp/` package structure with 39 tool modules and separated concerns (parsers, MCP tools, CLI, configuration).
- **Docker-First Design** — No interactive prompts. Dependencies are managed via Docker, making it container and CI/CD ready.
- **Single-File Analysis Context** — The server holds one file in memory via `AnalyzerState`. All tools operate on this shared context. Use `open_file` and `close_file` to switch between files.
- **Thread-Safe State** — Centralised `AnalyzerState` class with locking for concurrent access.
- **Background Tasks** — Long-running operations (symbolic execution, Angr CFG) run asynchronously with heartbeat monitoring.
- **Disk-Based Caching** — Analysis results are cached in `~/.pemcp/cache/` as gzip-compressed JSON, keyed by SHA256. Re-opening a previously analysed file loads from cache in under 10 ms. LRU eviction keeps cache size bounded.
- **Lazy Loading** — Heavy analysis (Angr CFG) runs in the background. The server is usable immediately.
- **Pagination** — Tools that return lists support `limit` and `offset` parameters with LRU result caching, preventing response truncation and giving AI clients control over data volume per call (default limit 20 for most tools).
- **Smart Truncation** — MCP responses exceeding 64KB are intelligently truncated (lists shortened, strings clipped) whilst preserving structure.
- **Graceful Degradation** — All 20+ optional libraries are detected at startup. Tools that require unavailable libraries return clear error messages instead of crashing.

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
| **20** | Most tools — `get_pe_data`, `get_floss_analysis_info`, `get_capa_analysis_info`, `get_function_xrefs`, `get_backward_slice`, `get_forward_slice`, `get_function_complexity_list`, `extract_function_constants`, `get_global_data_refs`, `scan_for_indirect_jumps`, `get_reaching_definitions`, `get_data_dependencies`, `get_control_dependencies`, `identify_library_functions`, `diff_binaries`, `detect_self_modifying_code`, `find_code_caves`, `identify_cpp_classes`, `identify_crypto_algorithm`, `auto_extract_crypto_keys`, all Refinery tools, all multi-format analysis tools (`dotnet_analyze`, `elf_analyze`, `macho_analyze`, `go_analyze`), `get_notes`, `get_tool_history`, `get_triage_report`, and more |
| **30** | `get_function_map` (function ranking), `disassemble_at_address` (instructions) |
| **50** | `get_call_graph` (call graph edges), `analyze_entropy_by_offset`, `qiling_trace_execution` |
| **80** | `get_value_set_analysis`, `propagate_constants`, `get_function_variables` |
| **300** | `get_annotated_disassembly` (rich disassembly blocks) |
| **10** | `brute_force_simple_crypto`, `extract_steganography`, `bruteforce_xor_key`, `find_oep_heuristic` |

The hard upper bound on `limit` is **100,000** (enforced in `get_pe_data` and string tools) to prevent excessive memory allocation.

### Result Caching (LRU)

Paginated results are cached in an **LRU cache** (5 slots per tool) so that paging through results doesn't re-compute the full dataset on each call. The cache is keyed by tool name and non-pagination parameters — changing `offset` or `limit` hits the same cache entry. The internal maximum cached items per result set is **5,000**.

### Session & State Limits

| Setting | Value | Description |
|---|---|---|
| `MAX_COMPLETED_TASKS` | 50 | Maximum completed/failed background tasks retained per session |
| `MAX_TOOL_HISTORY` | 500 | Maximum tool invocation history entries retained per session |
| `SESSION_TTL_SECONDS` | 3600 | Session lifetime before cleanup (1 hour) |
| `MAX_MCP_RESPONSE_SIZE_KB` | 64 | MCP response size limit per the protocol specification |
| `PEMCP_MAX_CONCURRENT_ANALYSES` | 3 | Concurrent heavy analysis semaphore (configurable via environment variable) |
