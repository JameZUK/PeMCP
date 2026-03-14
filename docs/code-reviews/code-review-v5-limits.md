# Code Review v5 — Hardcoded Limits Audit

**Date**: 2026-03-12
**Scope**: All hardcoded limits, caps, truncation, and silent data loss across codebase
**Method**: 4 parallel inventory agents + 2 manual verification agents
**Goal**: Identify limits that could cause the AI or user to receive incomplete analysis data without knowing it

## Legend

- **SILENT**: Truncation happens with NO indication in the response — the AI/user cannot tell data was lost
- **REPORTED**: The response includes a count, flag, or message indicating truncation occurred
- **PARTIAL**: Some hint exists (e.g., a total count elsewhere) but no explicit truncation indicator

---

## Severity Classification

- **HIGH**: The AI receives incomplete data for a core analysis task and has no way to know. Could lead to wrong conclusions.
- **MEDIUM**: Data is silently dropped but the impact is limited (secondary data, rare path, or alternative tool available).
- **LOW**: The limit is reasonable, the data is redundant, or truncation is properly reported.

---

## HIGH — Silent limits that could mislead the AI (6)

### LIM-H1: `get_analysis_digest` silently drops findings, notes, IOCs, and functions
- **File**: `arkana/mcp/tools_session.py:330,340,348,387,396`
- **Truncation**: SILENT
- **Limits**:
  - `key_findings[:15]` — only 15 key tool findings shown
  - `func_notes[:30]` — only 30 function summaries shown
  - IOCs `[:10]` per category (IPs, URLs, domains, registry keys)
  - `unexplored[:10]` — only 10 unexplored high-priority functions listed
  - `general_notes[:10]` — only 10 analyst notes shown
- **Impact**: `get_analysis_digest()` is the AI's primary "refresh your understanding" tool. In a long session with 40+ findings, 50+ notes, and dozens of IOCs, the AI would see a partial picture and believe it's complete. No `_truncated` flags, no total counts alongside sliced lists.
- **Fix**: Add `_truncated` flag and total count for each sliced list. Example: `"key_findings_total": len(all_findings), "key_findings_truncated": len(all_findings) > 15`.

### LIM-H2: `get_session_summary` silently truncates notes and tool history
- **File**: `arkana/mcp/tools_session.py:140,147,157`
- **Truncation**: SILENT
- **Limits**:
  - `notes[:50]` — only 50 notes returned (total count IS present as `"count"` but list itself is silently cut)
  - `current_history[-30:]` — only last 30 tool calls (total `tools_run_count` IS present)
  - `prev[-30:]` — only last 30 previous session tool calls
- **Impact**: The total counts exist as separate fields, but the AI must do arithmetic to notice that `len(notes) < count`. No `_truncated` flag on the lists themselves.
- **Fix**: Add `"notes_truncated": len(all_notes) > 50` and `"history_truncated": len(all_history) > 30` flags.

### LIM-H3: Triage `indicator_limit=20` silently caps suspicious imports, anomalies, IOCs
- **File**: `arkana/mcp/tools_triage.py:469,580-583,615,720,725,823`
- **Truncation**: PARTIAL (summary counts hint at totals, but lists are silently sliced)
- **Limits** (all default `indicator_limit=20`):
  - `suspicious_imports[:20]` — summary has severity counts, but list is cut
  - `ip_addresses[:20]`, `urls[:20]`, `domains[:20]`, `registry_keys[:20]`
  - `header_anomalies[:20]`
  - `ordinal_only_imports[:20]`, `non_standard_dlls[:20]`
  - `yara_matches[:20]`
- **Impact**: A heavily-instrumented binary (e.g., RAT with 50+ suspicious imports, or a binary matching 30 YARA rules) loses data. The `suspicious_import_summary` counts are computed from the full list but the `suspicious_imports` list is cut with no `"_truncated"` flag. The AI must compare `len(list)` against the sum of severity counts to notice.
- **Fix**: Add `"_total_found": len(all_items)` alongside each sliced list. Or add a top-level `"truncation_info"` dict listing which fields were capped.

### LIM-H4: `_decompile_meta` cache eviction silently drops decompiled functions
- **File**: `arkana/mcp/tools_angr.py:24-26`
- **Truncation**: SILENT
- **Limits**: `_MAX_DECOMPILE_META = 500` — FIFO eviction when cache exceeds 500 entries
- **Impact**: In a long analysis session where the AI decompiles 600+ functions, the first 100+ decompiled functions are evicted from cache. When the AI (or `batch_decompile` search) later references a cached result, it gets a cache miss and must re-decompile. This isn't data loss per se, but it causes unexpected re-analysis and can confuse tools like `batch_decompile(search=...)` that rely on cached results.
- **Additional issue**: This cache is module-level (not per-session), so in HTTP multi-session mode, sessions compete for the same 500 slots (see v5 M7).
- **Fix**: Increase cap to 2000 or make per-session. Add `"_cache_eviction_note"` when a previously-cached function is re-decompiled.

### LIM-H5: FLOSS enrichment cap silently drops cross-references for strings beyond 500
- **File**: `arkana/parsers/floss.py:401-403`, `arkana/constants.py:118`
- **Truncation**: SILENT (logged to server, never surfaced to AI)
- **Limit**: `MAX_FLOSS_ENRICHMENT_STRINGS = 500`
- **Impact**: When a binary has thousands of static strings, only the first 500 get cross-reference enrichment (`references` field populated). The remaining strings exist in search results but lack function-linking context. The AI would see some strings with `references: [0x401000, ...]` and others without, with no explanation. This specifically affects the overview function-linking feature and dashboard string→function navigation.
- **Fix**: Surface the cap in `get_floss_analysis_info()` response: `"xref_enrichment": {"strings_enriched": 500, "total_static": 5000, "capped": true}`.

### LIM-H6: `MCP_SOFT_RESPONSE_LIMIT_CHARS = 8000` truncates most tool outputs
- **File**: `arkana/mcp/server.py:22`, `arkana/constants.py:52`
- **Truncation**: REPORTED (`_truncation_warning` key + `ctx.warning()`)
- **Limit**: 8,000 character soft limit (configurable via `ARKANA_MCP_RESPONSE_LIMIT_CHARS`)
- **Impact**: While truncation IS reported, the 8K default is extremely aggressive. Tools like `get_triage_report`, `get_full_analysis_results`, `batch_decompile`, and `get_cross_reference_map` routinely produce 20-50K character responses. The truncation system slices lists and adds "...[TRUNCATED]" to strings, but the AI may lose critical detail in the middle of structured data. The AI is told to paginate, but some tools don't support pagination.
- **Why HIGH**: This is the single most impactful limit in the system. Every tool response is subject to it. While reported, the AI often loses significant analysis context.
- **Mitigation**: Set `ARKANA_MCP_RESPONSE_LIMIT_CHARS=65536` for non-Claude-Code clients. Ensure all high-output tools support pagination or `limit` parameters.

---

## MEDIUM — Silent limits with limited impact (12)

### LIM-M1: C++ class methods capped at 20 (no total count in one path)
- **File**: `arkana/mcp/tools_angr_forensic.py:1076,1180`
- **Truncation**: SILENT (path 1), PARTIAL (path 2 has `method_count`)
- **Impact**: Large vtables with 50+ methods silently truncated. The heuristic path (path 2) does report `method_count` as an integer, but the angr-native path (path 1) has no count at all.
- **Fix**: Add `"method_count": len(cls.methods)` to both paths.

### LIM-M2: Anti-debug limits — functions[:30], strings[:30], instructions[:20], techniques[:60]
- **File**: `arkana/mcp/tools_angr_forensic.py:1776-1780`
- **Truncation**: PARTIAL (`total_techniques_found` reports full count for techniques, but not for the other 3 lists)
- **Impact**: Binaries with heavy anti-analysis (>30 functions with anti-debug) lose detail.
- **Fix**: Add total counts for each sliced list.

### LIM-M3: PEiD detections capped at 3 in `open_file` response
- **File**: `arkana/mcp/tools_pe.py:168`
- **Truncation**: SILENT
- **Impact**: Initial file open shows max 3 packer signatures. The full triage shows up to 8. The AI might not realize there are more packers detected until running triage.
- **Fix**: Add `"total_peid_detections": len(packer_names)` alongside the sliced list.

### LIM-M4: Triage pefile warnings capped at 10
- **File**: `arkana/mcp/tools_triage.py:844`
- **Truncation**: SILENT
- **Impact**: Heavily malformed binaries can produce 50+ pefile warnings. Only 10 become header anomalies. The warnings are often repetitive but occasionally contain unique structural issues.
- **Fix**: Add `"total_pefile_warnings": len(pefile_warnings)` to the anomalies section.

### LIM-M5: Calling convention recovery caps at 500 functions (fallback path)
- **File**: `arkana/mcp/tools_angr_disasm.py:152`
- **Truncation**: SILENT
- **Impact**: When angr's batch CC analysis fails and the fallback path triggers, only the first 500 functions get CC analysis. Rare but affects large binaries.
- **Fix**: Add `"_fallback_function_cap": 500, "_total_functions": len(all_funcs)` when fallback is used.

### LIM-M6: Batch analysis exports capped at 50 per file
- **File**: `arkana/mcp/tools_batch.py:132`
- **Truncation**: SILENT
- **Impact**: DLLs with hundreds of exports lose data in batch comparison mode. Does not affect single-file analysis.
- **Fix**: Add `"exports_total": len(exports)` when `len(exports) > 50`.

### LIM-M7: Enrichment sweep caps at 100 functions decompiled
- **File**: `arkana/enrichment.py:344`, `arkana/constants.py:113`
- **Truncation**: PARTIAL (task status records count, but no explicit "N skipped" in any tool response)
- **Configurable**: Yes (`ARKANA_ENRICHMENT_MAX_DECOMPILE`)
- **Impact**: Binaries with 500+ functions only get 100 pre-decompiled. The AI can still decompile on demand, but `get_analysis_digest` and `suggest_next_action` may not surface un-decompiled functions effectively. The `check_task_status('auto-enrichment')` shows `decompile_sweep(100)` but the AI must compare against total function count.
- **Fix**: Include `"enrichment_decompile_cap": {"decompiled": 100, "total_scorable": 450, "capped": true}` in `get_session_summary` or `get_analysis_digest`.

### LIM-M8: Function map default limit=15 (reported but very low default)
- **File**: `arkana/mcp/tools_angr_disasm.py:766`
- **Truncation**: REPORTED (`total_functions` vs `returned`)
- **Impact**: The AI sees 15 out of potentially hundreds of functions by default. While `total_functions` is reported, the default is very conservative. An AI analyzing a binary for the first time gets a very narrow view.
- **Note**: The AI can increase `limit`, so this is a "too conservative default" issue rather than a data loss issue.

### LIM-M9: Symbolic execution events capped at 500
- **File**: `arkana/mcp/tools_angr_forensic.py:975,1000,1011`
- **Truncation**: REPORTED (`total_events` included)
- **Impact**: Long symbolic execution traces lose later events. The earliest 500 events are kept, which may miss the most interesting behavior (end-of-execution).
- **Note**: Well-reported but the choice to keep earliest events (not most recent or most interesting) could be improved.

### LIM-M10: YARA scan match instances capped at 20
- **File**: `arkana/mcp/tools_pe_forensic.py:226,232`
- **Truncation**: SILENT (double truncation: per-string and overall)
- **Impact**: When scanning with `scan_after_generate=True`, only 20 match instances shown. Adequate for confirming a rule works, but insufficient for exhaustive match enumeration.
- **Fix**: Add `"total_match_instances": total_count` to the scan result.

### LIM-M11: Product IDs capped at 10 in Rich header analysis
- **File**: `arkana/mcp/tools_triage.py:412`
- **Truncation**: SILENT
- **Impact**: Rich header product IDs beyond 10 are hidden. Matters for build-environment attribution analysis of complex binaries compiled with many tools.
- **Fix**: Add `"total_unique_product_ids": len(product_ids)`.

### LIM-M12: Callgraph edge cap at 5000 (dashboard)
- **File**: `arkana/dashboard/state_api.py`
- **Truncation**: SILENT (affects dashboard visualization, not MCP tools)
- **Impact**: Large binaries with dense callgraphs lose edges in the dashboard visualization. The MCP `get_call_graph` tool has its own separate limits.

---

## LOW — Well-handled or inconsequential limits (14)

### LIM-L1: Decompile line pagination (default 80 lines)
- **File**: `tools_angr.py:283`
- **REPORTED**: Full `_pagination` block with `total`, `has_more`, `next_step`. Gold standard.

### LIM-L2: Batch decompile cap of 20 functions
- **File**: `tools_angr.py:1800-1801`
- **REPORTED**: Raises `ValueError` with clear message. AI must split requests.

### LIM-L3: Callees 15 / Callers 10 with truncation flags
- **File**: `tools_angr_disasm.py:732-739`
- **REPORTED**: `_callees_truncated`/`_callers_truncated` flags with full counts.

### LIM-L4: Call graph compact mode top 10 hubs
- **File**: `tools_angr_forensic.py:1321`
- **REPORTED**: `total_functions`/`total_call_edges` counts. Compact mode by design.

### LIM-L5: Triage compact mode top 8 findings
- **File**: `tools_triage.py:1932`
- **REPORTED**: Explicit `"note": "Use get_triage_report(compact=False) for full details."`

### LIM-L6: Integrity issues in warning message capped at 3
- **File**: `tools_pe.py:353`
- **REPORTED**: Only the warning text is truncated; full integrity data is in the response payload.

### LIM-L7: Go/Rust language indicators capped at 5
- **File**: `tools_triage.py:1433,1446`
- **Impact**: NONE. Language detection is binary — 5 indicators is more than sufficient.

### LIM-L8: Critical imports in auto-notes capped at 3
- **File**: `tools_triage.py:1613`
- **Impact**: Low. Full count in summary note. Complete list available in triage report.

### LIM-L9: String regex cap at 65536 chars (v4 fix H3)
- **File**: `parsers/strings.py:23`
- **Impact**: NONE. Single printable ASCII runs >64KB are pathological/embedded resources.

### LIM-L10: IOC per-category cap at 10,000 (v4 fix M6)
- **File**: `tools_ioc.py:83`
- **Impact**: NONE. No real analysis session generates 10K IPs/URLs.

### LIM-L11: Notes cap at 10,000 (v4 fix H2)
- **File**: `state.py`
- **Impact**: NONE. Well beyond any practical session.

### LIM-L12: Tool history deque maxlen=500
- **File**: `state.py`
- **Impact**: LOW. 500 tool calls is a very long session. Oldest entries evicted.

### LIM-L13: MAX_TOOL_LIMIT = 100,000
- **File**: `constants.py:143`
- **Impact**: NONE. Generic ceiling for `limit` parameters.

### LIM-L14: Hex display truncation at 4096 bytes with marker
- **File**: `_refinery_helpers.py:44`
- **Impact**: LOW. Hex preview truncated with `...[truncated, N bytes total]` marker. Full data saved to artifact.

---

## Systemic Patterns

### Pattern 1: Silent list slicing `[:N]` without truncation indicators
The most pervasive pattern. Found in **40+ locations** across the codebase. Lists are sliced with `[:N]` and the result is placed directly in the response dict with no total count or truncation flag. The AI has no way to know data was dropped.

**Affected tools** (non-exhaustive):
- `get_analysis_digest` (5 sliced lists)
- `get_session_summary` (3 sliced lists)
- `get_triage_report` (10+ sliced lists via `indicator_limit`)
- `find_anti_debug_comprehensive` (4 sliced lists)
- `identify_cpp_classes` (method lists)
- `analyze_batch` (shared imports, high entropy, similarity pairs)

### Pattern 2: Inconsistent truncation reporting
Some tools follow best practices (pagination blocks, `_truncated` flags) while others silently slice. There is no standard convention for reporting truncation.

**Well-designed examples** to follow:
- `decompile_function_with_angr`: `_pagination` block with `total`, `has_more`, `next_step`
- `get_function_map`: `total_functions` vs `returned`
- `get_cross_reference_map`: `_truncated` notice (v4 fix M2)
- Callees/callers: `_callees_truncated`/`_callers_truncated` with counts

### Pattern 3: Low defaults that bias the AI toward partial views
Several tools default to `limit=15` or `limit=20`, giving the AI a narrow initial view. While these are adjustable parameters, the AI may not know to increase them unless it notices the gap between returned count and total count.

### Pattern 4: Session tools are the worst offenders
`tools_session.py` is the most problematic file because it's the AI's "meta" layer — the tools it uses to understand the overall analysis state. Silent truncation here means the AI's global understanding is incomplete.

---

## Recommended Fix Priority

### Priority 1 — Add truncation indicators to session/digest tools
Files: `tools_session.py`
Effort: Small (add `_truncated`/`_total` fields)
Impact: Highest — directly affects AI's global analysis understanding

### Priority 2 — Add truncation indicators to triage tool
File: `tools_triage.py`
Effort: Medium (10+ sliced lists need `_total` fields)
Impact: High — triage is the AI's primary binary assessment

### Priority 3 — Add truncation indicators to anti-debug and C++ class tools
Files: `tools_angr_forensic.py`
Effort: Small
Impact: Medium — affects specialized analysis tasks

### Priority 4 — Surface FLOSS enrichment cap in tool responses
Files: `parsers/floss.py`, `tools_pe.py` or `tools_strings.py`
Effort: Small
Impact: Medium — affects string→function linking accuracy

### Priority 5 — Consider raising conservative defaults
- `get_function_map` limit: 15 → 30
- `indicator_limit` default: 20 → 50
- `_MAX_DECOMPILE_META`: 500 → 2000
These changes increase response sizes but reduce the chance of the AI missing data.

---

## Full Inventory: All Constants by File

### arkana/constants.py (38 constants)

| Constant | Value | Configurable |
|----------|-------|--------------|
| `MAX_MCP_RESPONSE_SIZE_KB` | 64 | No |
| `MAX_MCP_RESPONSE_SIZE_BYTES` | 65,536 | No |
| `MCP_SOFT_RESPONSE_LIMIT_CHARS` | 8,000 | `ARKANA_MCP_RESPONSE_LIMIT_CHARS` |
| `ANGR_ANALYSIS_TIMEOUT` | 300s | `ARKANA_ANGR_ANALYSIS_TIMEOUT` |
| `ANGR_SHORT_TIMEOUT` | 120s | No |
| `ANGR_CFG_TIMEOUT` | 1,800s | `ARKANA_ANGR_CFG_TIMEOUT` |
| `BACKGROUND_TASK_TIMEOUT` | 1,800s | `ARKANA_BACKGROUND_TASK_TIMEOUT` |
| `CAPA_ANALYSIS_TIMEOUT` | 300s | `ARKANA_CAPA_ANALYSIS_TIMEOUT` |
| `FLOSS_ANALYSIS_TIMEOUT` | 300s | `ARKANA_FLOSS_ANALYSIS_TIMEOUT` |
| `BSIM_BACKGROUND_TIMEOUT` | 1,800s | `ARKANA_BSIM_BACKGROUND_TIMEOUT` |
| `ENRICHMENT_TIMEOUT` | 1,800s | `ARKANA_ENRICHMENT_TIMEOUT` |
| `ENRICHMENT_MAX_DECOMPILE` | 100 | `ARKANA_ENRICHMENT_MAX_DECOMPILE` |
| `HTTP_DOWNLOAD_TIMEOUT` | 60s | No |
| `HTTP_API_TIMEOUT` | 20s | No |
| `HTTP_QUICK_TIMEOUT` | 15s | No |
| `MAX_ARTIFACT_FILE_SIZE` | 100 MB | No |
| `MAX_TOTAL_ARTIFACT_EXPORT_SIZE` | 50 MB | No |
| `MAX_BATCH_RENAMES` | 50 | No |
| `MAX_STRUCT_FIELDS` | 100 | No |
| `MAX_ENUM_VALUES` | 500 | No |
| `MAX_BATCH_DECOMPILE` | 20 | No |
| `BATCH_DECOMPILE_PER_FUNCTION_TIMEOUT` | 60s | No |
| `MAX_HEX_PATTERN_TOKENS` | 200 | No |
| `MAX_HEX_PATTERN_MATCHES` | 5,000 | No |
| `DEFAULT_SEARCH_CONTEXT_LINES` | 2 | No |
| `MAX_SEARCH_CONTEXT_LINES` | 20 | No |
| `MAX_SEARCH_MATCHES` | 500 | No |
| `MAX_FLOSS_ENRICHMENT_STRINGS` | 500 | No |
| `MAX_FLOSS_REFS_PER_STRING` | 20 | No |
| `VIVISECT_BYTES_PER_SECOND_ESTIMATE` | 50,000 | No |
| `VIVISECT_POLL_INTERVAL` | 3s | No |
| `INTEGRITY_*` | Various | No |
| `MAX_LIST_SAMPLES_LIMIT` | 500 | No |
| `MAX_TOOL_LIMIT` | 100,000 | No |

### arkana/state.py

| Constant | Value |
|----------|-------|
| `MAX_COMPLETED_TASKS` | 50 |
| `MAX_TOOL_HISTORY` | 500 |
| `MAX_NOTES` | 10,000 |
| `MAX_ARTIFACTS` | 1,000 |
| `SESSION_TTL_SECONDS` | 3,600 |
| Decompile notification deque | 200 |

### arkana/parsers/

| Constant | Value | File |
|----------|-------|------|
| `_MAX_STATIC_STRINGS` | 200,000 | floss.py |
| `_MAX_DYNAMIC_STRINGS` | 50,000 | floss.py |
| `_MAX_MATCHES_PER_TERM` | 10,000 | strings.py |
| `_MAX_RELOC_ENTRIES` | 50,000 | pe.py |
| `_MAX_EXCEPTION_ENTRIES` | 10,000 | pe.py |
| `_max_delay_thunks` | 10,000 | pe.py |
| `_MAX_CAPA_CACHE` | 8 | capa.py |

### arkana/mcp/ (selected)

| Constant | Value | File |
|----------|-------|------|
| `_MAX_DECOMPILE_META` | 500 | tools_angr.py |
| `_MAX_TRIAGE_STRINGS` | 100,000 | tools_triage.py |
| `_MAX_INPUT_SIZE_SMALL` | 10 MB | _refinery_helpers.py |
| `_MAX_INPUT_SIZE_LARGE` | 50 MB | _refinery_helpers.py |
| `_MAX_OUTPUT_ITEMS` | 500 | _refinery_helpers.py |
| `_MAX_FILE_READ_SIZE` | 500 MB | _refinery_helpers.py |
| `_MAX_SCHEMA_FIELDS` | 200 | tools_struct.py |
| `_MAX_DATA_SIZE` | 10 MB | tools_struct.py |
| `_MAX_INITIAL_CANDIDATES` | 10,000 | tools_deobfuscation.py |
| `_MAX_INSTRUCTIONS_LIMIT` | 10,000,000 | tools_qiling.py |
| `_MAX_TIMEOUT_SECONDS` | 600s | tools_qiling.py |
| `_MAX_IOCS_PER_CATEGORY` | 10,000 | tools_ioc.py |
| `MAX_BATCH_FILES` | 50 | tools_batch.py |
| BSim SQL LIMIT | 10,000 | _bsim_features.py |
| Rust `scan_limit` | 2 MB | tools_rust.py |
