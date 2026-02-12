# Implementation Plan: Fix All Review Issues

## Overview

This plan addresses all 13 issues from the third review iteration (3 high, 5 medium, 5 low priority). Changes are grouped by file to minimize context switching.

---

## Step 1: `parsers/pe.py` — Guard sub-parsers + reformat dense code [H1, L1]

**H1: Wrap each sub-parser in `_parse_pe_to_dict` with individual try/except**

In `_parse_pe_to_dict` (lines 593-617), wrap each parser call so a failure in one doesn't kill the entire analysis. Introduce a small helper:

```python
def _safe_parse(key, func, *args, **kwargs):
    """Call func and return its result, or an error dict on failure."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.warning(f"Parser '{key}' failed: {e}")
        return {"error": f"{key} parsing failed: {type(e).__name__}: {e}"}
```

Then replace the block of 18 sequential calls:
```python
# Before:
pe_info_dict['sections'] = _parse_sections(pe)
pe_info_dict['imports'] = _parse_imports(pe)
# ...

# After:
nt_headers_info, magic_type_str = _parse_nt_headers(pe)  # keep this one separate (needed by later parsers)
pe_info_dict['nt_headers'] = nt_headers_info
pe_info_dict['dos_header'] = _safe_parse('dos_header', _parse_dos_header, pe)
pe_info_dict['data_directories'] = _safe_parse('data_directories', _parse_data_directories, pe)
pe_info_dict['sections'] = _safe_parse('sections', _parse_sections, pe)
# ... etc for all remaining sub-parsers
```

Special handling: `_parse_nt_headers` returns a tuple `(info, magic_type_str)` which later parsers depend on. Guard it but default `magic_type_str` to `"Unknown"` on failure.

**L1: Reformat dense functions in the same file**

While editing `parsers/pe.py`, reformat the dense semicolon-separated lines in:
- `_parse_imports` (lines 138-151)
- `_parse_exports` (lines 153-163)
- `_parse_resources_summary` (lines 165-186)
- `_parse_version_info` (lines 188-218)
- `_parse_debug_info` (lines 220-231)
- `_parse_rich_header` (lines 366-372)
- `_parse_delay_load_imports` (lines 374-420)
- `_parse_tls_info` (lines 422-441)
- `_parse_load_config` (lines 443-452)
- `_parse_com_descriptor` (lines 454-465)
- `_parse_coff_symbols` (lines 514-532)

Break multiple-statement-per-line patterns into proper multi-line Python. No logic changes — pure reformatting for readability.

**Files changed:** `pemcp/parsers/pe.py`

---

## Step 2: `background.py` + `state.py` — Fix angr race condition + task sort [H2, L2]

**H2: Add a threading lock for angr state writes**

Add an `_angr_lock` to `AnalyzerState` in `state.py`:
```python
self._angr_lock = threading.Lock()
```

Add accessor methods:
```python
def set_angr_results(self, project, cfg, loop_cache, loop_cache_config):
    """Atomically set all angr analysis results."""
    with self._angr_lock:
        self.angr_project = project
        self.angr_cfg = cfg
        self.angr_loop_cache = loop_cache
        self.angr_loop_cache_config = loop_cache_config

def get_angr_snapshot(self):
    """Return a consistent snapshot of (project, cfg)."""
    with self._angr_lock:
        return self.angr_project, self.angr_cfg
```

Update `background.py:angr_background_worker` to use `set_angr_results()` instead of setting fields individually.

Update `_angr_helpers.py:_ensure_project_and_cfg` to use `get_angr_snapshot()` so it reads both fields atomically.

**L2: Use numeric epoch timestamp for task eviction sort**

In `state.py:_evict_old_tasks`, add a `created_at_epoch` field when creating tasks (already done in `set_task`), and sort by it:
```python
finished.sort(key=lambda item: item[1].get("created_at_epoch", 0))
```

Update `background.py:start_angr_background` and `_run_background_task_wrapper` to include `created_at_epoch: time.time()` alongside the ISO string.

**Files changed:** `pemcp/state.py`, `pemcp/background.py`, `pemcp/mcp/_angr_helpers.py`

---

## Step 3: `tools_pe.py` — Eliminate double file read + reformat summary [H3, L5]

**H3: Pass already-read data to `pefile.PE(data=...)` instead of re-reading**

In `open_file` (line 289-292), change:
```python
# Before:
def _load_pe():
    return pefile.PE(abs_path, fast_load=False)

# After:
def _load_pe():
    return pefile.PE(data=_raw_file_data, fast_load=False)
```

This reuses the bytes already read at line 174-176 for hashing. Halves peak memory usage for PE mode.

**L5: Reformat dense summary dict in `get_analyzed_file_summary`**

Break the dense single-line dict entries at lines 626-646 into readable multi-line format. No logic changes.

**Files changed:** `pemcp/mcp/tools_pe.py`

---

## Step 4: `server.py` — Fix truncation fallback unbound variable [M1]

In `_check_mcp_response_size`, initialize `data_size_bytes` before the try block:
```python
data_size_bytes = 0  # Safe default for error fallback
try:
    serialized_data = json.dumps(data_to_return, ensure_ascii=False)
    data_size_bytes = len(serialized_data.encode('utf-8'))
    ...
```

This ensures the variable is always bound when the except handler references it.

**Files changed:** `pemcp/mcp/server.py`

---

## Step 5: `cache.py` — Fix meta inconsistency after entry removal [M2]

In the `get()` method, after calling `_remove_entry()`, also update and save the meta index:

```python
# At line 137 (version mismatch):
self._remove_entry(sha256)
meta = self._load_meta()
meta.pop(sha256, None)
self._save_meta(meta)
return None

# At line 161 (corrupt entry):
self._remove_entry(sha256)
meta = self._load_meta()
meta.pop(sha256, None)
self._save_meta(meta)
return None
```

To avoid code duplication, extract a `_remove_entry_and_meta` helper that does both operations.

**Files changed:** `pemcp/cache.py`

---

## Step 6: `main.py` + `tools_pe.py` — Log warning on unknown format fallback [M3]

In both auto-detection locations, add a warning log when falling back to PE for unknown formats:

`main.py` (line 254-255):
```python
else:
    effective_mode = 'pe'
    logger.warning(f"Unrecognized file format (magic: {magic.hex()}). Falling back to PE mode. "
                   "Use --mode to specify the format explicitly.")
```

`tools_pe.py` (line 152-153):
```python
else:
    mode = "pe"
    await ctx.warning(f"Unrecognized file format (magic: {magic.hex()}). Falling back to PE mode. "
                      "Use mode='shellcode', 'elf', or 'macho' to specify explicitly.")
```

**Files changed:** `pemcp/main.py`, `pemcp/mcp/tools_pe.py`

---

## Step 7: `config.py` — Move `basicConfig` out of module scope [M4]

Remove `logging.basicConfig(...)` from `config.py` line 89. Instead:

1. In `config.py`, only create the logger:
   ```python
   logger = logging.getLogger("PeMCP")
   ```
   Remove the `logging.basicConfig()` call and all the info/warning log statements that fire during import (lines 288-300). Replace with a function:
   ```python
   def log_library_availability():
       """Log availability of optional libraries. Called once from main()."""
       if MCP_SDK_AVAILABLE: logger.info("MCP SDK found.")
       # ... all the other availability logs
   ```

2. In `main.py:main()`, add `logging.basicConfig(...)` before the first log call, and call `config.log_library_availability()` after configuring the log level.

**Files changed:** `pemcp/config.py`, `pemcp/main.py`

---

## Step 8: `tools_pe.py` — Add concurrent analysis semaphore [M5]

Add a module-level `asyncio.Semaphore` to limit concurrent `open_file` analyses:

```python
# At module level in tools_pe.py:
_analysis_semaphore = asyncio.Semaphore(int(os.environ.get("PEMCP_MAX_CONCURRENT_ANALYSES", "3")))
```

In the `open_file` function, wrap the analysis block:
```python
async with _analysis_semaphore:
    # ... existing analysis logic
```

This prevents more than 3 (configurable) simultaneous file analyses. Additional requests will queue automatically via the semaphore.

**Files changed:** `pemcp/mcp/tools_pe.py`

---

## Step 9: `Dockerfile` — Tighten permissions [L3]

Change line 113:
```dockerfile
# Before:
RUN mkdir -p /app/home/.pemcp/cache && chmod -R 777 /app/home

# After:
RUN mkdir -p /app/home/.pemcp/cache && chmod -R 755 /app/home
```

Since `run.sh` passes `--user "$(id -u):$(id -g)"` and the volume is mounted, the host UID already owns the files. `755` is sufficient.

**Files changed:** `Dockerfile`

---

## Step 10: `config.py` — Functional speakeasy availability check [L4]

Replace the filesystem-only check with a quick subprocess import test:

```python
_SPEAKEASY_VENV_PYTHON = Path("/app/speakeasy-venv/bin/python")
_SPEAKEASY_RUNNER = DATA_DIR / "scripts" / "speakeasy_runner.py"
if _SPEAKEASY_VENV_PYTHON.is_file() and _SPEAKEASY_RUNNER.is_file():
    try:
        import subprocess
        result = subprocess.run(
            [str(_SPEAKEASY_VENV_PYTHON), "-c", "import speakeasy"],
            capture_output=True, timeout=10,
        )
        SPEAKEASY_AVAILABLE = result.returncode == 0
        if not SPEAKEASY_AVAILABLE:
            SPEAKEASY_IMPORT_ERROR = f"speakeasy import failed in venv: {result.stderr.decode()[:200]}"
    except Exception as e:
        SPEAKEASY_IMPORT_ERROR = f"Speakeasy venv check failed: {e}"
else:
    SPEAKEASY_IMPORT_ERROR = f"Speakeasy venv not found (expected {_SPEAKEASY_VENV_PYTHON})"
```

**Files changed:** `pemcp/config.py`

---

## Execution Order

The steps are ordered to minimize merge conflicts (deepest/most isolated changes first):

1. **Step 1** — `parsers/pe.py` (H1 + L1) — largest change, isolated file
2. **Step 2** — `state.py` + `background.py` + `_angr_helpers.py` (H2 + L2)
3. **Step 3** — `tools_pe.py` (H3 + L5)
4. **Step 4** — `server.py` (M1) — one-line fix
5. **Step 5** — `cache.py` (M2) — small fix
6. **Step 6** — `main.py` + `tools_pe.py` (M3) — log warning additions
7. **Step 7** — `config.py` + `main.py` (M4) — logging refactor
8. **Step 8** — `tools_pe.py` (M5) — semaphore addition
9. **Step 9** — `Dockerfile` (L3) — one-line fix
10. **Step 10** — `config.py` (L4) — speakeasy check

---

## Files Modified Summary

| File | Issues Fixed |
|------|-------------|
| `pemcp/parsers/pe.py` | H1, L1 |
| `pemcp/state.py` | H2, L2 |
| `pemcp/background.py` | H2, L2 |
| `pemcp/mcp/_angr_helpers.py` | H2 |
| `pemcp/mcp/tools_pe.py` | H3, M3, M5, L5 |
| `pemcp/mcp/server.py` | M1 |
| `pemcp/cache.py` | M2 |
| `pemcp/main.py` | M3, M4 |
| `pemcp/config.py` | M4, L4 |
| `Dockerfile` | L3 |

**Total: 10 files, 13 issues**
