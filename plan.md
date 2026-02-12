# Fix Plan: All Open Issues from PeMCP Review (Fourth Iteration)

## Status Reassessment

After re-reading the code, several issues from the third-iteration review have already been
fixed in the codebase but were not reflected in the review document:

| Issue | Status | Evidence |
|-------|--------|----------|
| H1 (Unguarded sub-parsers) | **Already Fixed** | `_safe_parse()` at `pe.py:42-49`, used at lines 914-936 |
| H2 (Angr state race condition) | **Already Fixed** | `_angr_lock` in `state.py:112-123`, `set_angr_results`/`get_angr_snapshot` |
| M1 (Truncation unbound var) | **Already Fixed** | `data_size_bytes = 0` at `server.py:110` |
| M2 (Cache meta inconsistency) | **Already Fixed** | `_remove_entry_and_meta()` at `cache.py:269-274` |
| M3 (Silent PE fallback) | **Already Fixed** | `ctx.warning()` at `tools_pe.py:156-158`, `logger.warning()` at `main.py:259` |
| M5 (No rate limiting) | **Already Fixed** | `_analysis_semaphore` at `tools_pe.py:25` |
| L2 (ISO string sort) | **Already Fixed** | `created_at_epoch` at `state.py:107` |
| L4 (Speakeasy filesystem-only check) | **Already Fixed** | Subprocess import check at `config.py:350-356` |

## Genuinely Open Issues to Fix (14 items)

### Phase 1: High-Priority Security & Correctness (3 fixes)

**Fix 1: H4 — Deprecated `datetime.utcfromtimestamp` / `utcnow` in triage**
- File: `pemcp/mcp/tools_triage.py` lines 153, 155
- Change `datetime.datetime.utcfromtimestamp(int(raw_ts))` → `datetime.datetime.fromtimestamp(int(raw_ts), tz=datetime.timezone.utc)`
- Change `datetime.datetime.utcnow()` → `datetime.datetime.now(datetime.timezone.utc)`

**Fix 2: H5 — Missing path sandbox checks on 3 tools**
- File: `pemcp/mcp/tools_new_libs.py`
- Add `state.check_path_allowed(target)` in:
  - `parse_binary_with_lief` after line 88 (when `file_path` is explicitly provided)
  - `compute_similarity_hashes` after line 445 (when `file_path` is explicitly provided)
  - `compare_file_similarity` for `file_path_b` parameter

**Fix 3: H6 — Operator precedence bug in capa status checks**
- File: `pemcp/mcp/tools_strings.py` lines 284, 439
- Add explicit parentheses around the `and` clause

### Phase 2: Medium-Priority Code Quality (6 fixes)

**Fix 4: M6 — Remove dead code in `_triage_high_value_strings`**
- File: `pemcp/mcp/tools_triage.py` lines 1186-1193
- Delete the no-op loop that iterates once and breaks

**Fix 5: M7 — Extract duplicated entropy calculation to utility**
- File: `pemcp/utils.py` (add `shannon_entropy(data: bytes) -> float`)
- Update: `pemcp/mcp/tools_pe_extended.py` (2 locations)
- Update: `pemcp/mcp/tools_angr_forensic.py` (1 location)

**Fix 6: M8 — Use `collections.deque` for BFS in `get_call_graph`**
- File: `pemcp/mcp/tools_angr_forensic.py` lines 1005-1008
- Replace `list` + `pop(0)` with `deque` + `popleft()`

**Fix 7: M9 — Relax `scan_for_embedded_files` to support non-PE binaries**
- File: `pemcp/mcp/tools_new_libs.py` line 787
- Replace `_check_pe_loaded()` with a check for `state.filepath` being set

**Fix 8: M10 — Fix inaccurate step counting in `emulate_with_watchpoints`**
- File: `pemcp/mcp/tools_angr_forensic.py` lines 801-805
- Track actual steps by checking `simgr.active` count or step history length

**Fix 9: M11 — Add timeout wrappers on angr forensic tools**
- File: `pemcp/mcp/tools_angr_forensic.py`
- Wrap `asyncio.to_thread()` with `asyncio.wait_for(..., timeout=300)` for:
  - `detect_self_modifying_code` (line 201)
  - `find_code_caves` (line 307)
  - `detect_packing` (line 435)
  - `get_call_graph` (line 1069)

### Phase 3: Performance (1 fix)

**Fix 10: H3 — Eliminate double file read in `open_file`**
- File: `pemcp/mcp/tools_pe.py`
- Pass `_raw_file_data` (already read for hashing) to `pefile.PE(data=_raw_file_data)` instead of re-reading from disk

### Phase 4: Low-Priority Improvements (4 fixes)

**Fix 11: L6 — Move inline imports to top of files**
- Files: `tools_pe_extended.py`, `tools_angr_forensic.py`, `tools_triage.py`
- Move `import datetime`, `import re`, `import binascii`, `import math`, `import struct` to module-level

**Fix 12: L8 — Improve `_safe_slice` edge case handling**
- File: `pemcp/mcp/tools_new_libs.py` lines 54-68
- Add catch-all for `set`, `frozenset`, and other iterables

**Fix 13: L1/L9 — Reformat dense code in parsers and tool modules**
- Files: `pemcp/parsers/pe.py`, `pemcp/mcp/tools_strings.py`
- Break semicolon-separated statements into individual lines

**Fix 14: L5 — Reformat dense summary dict**
- File: `pemcp/mcp/tools_pe.py` lines 649-700
- Break dense inline expressions into multi-line format

### Final: Update REVIEW.md

Mark all fixed issues as resolved and update the status table.

## Execution Order

1. Fix 1 (H4) — one file, 2-line change
2. Fix 2 (H5) — one file, 3 added lines (security fix)
3. Fix 3 (H6) — one file, 2-line change
4. Fix 4 (M6) — one file, delete 8 lines
5. Fix 5 (M7) — add utility, update 3 files
6. Fix 6 (M8) — one file, 3-line change
7. Fix 7 (M9) — one file, 2-line change
8. Fix 8 (M10) — one file, small logic change
9. Fix 9 (M11) — one file, wrap 4 calls
10. Fix 10 (H3) — one file, pass data instead of path
11. Fix 11 (L6) — 3 files, move imports
12. Fix 12 (L8) — one file, add catch-all
13. Fix 13 (L1/L9) — 2 files, reformat
14. Fix 14 (L5) — one file, reformat
15. Update REVIEW.md

## Files Modified Summary

| File | Fixes Applied |
|------|--------------|
| `pemcp/mcp/tools_triage.py` | H4, M6 |
| `pemcp/mcp/tools_new_libs.py` | H5, M9, L8 |
| `pemcp/mcp/tools_strings.py` | H6, L9 |
| `pemcp/utils.py` | M7 |
| `pemcp/mcp/tools_pe_extended.py` | M7, L6 |
| `pemcp/mcp/tools_angr_forensic.py` | M8, M10, M11, L6 |
| `pemcp/mcp/tools_pe.py` | H3, L5 |
| `pemcp/parsers/pe.py` | L1 |
| `reports/REVIEW.md` | Status update |

**Total: 9 source files + 1 review doc, 14 issues**
