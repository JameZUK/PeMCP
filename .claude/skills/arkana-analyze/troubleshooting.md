# Troubleshooting Guide

When tools fail or return unexpected output, use these strategies before retrying
blindly.

## Refinery Pipeline Failures

- **Bisect**: Remove steps from the end of the pipeline until output is correct,
  then add steps back one at a time to isolate the failing operation.
- **Preview input**: Use `get_hex_dump(offset, length=64)` or `refinery_pretty_print`
  to inspect the raw data before transforming — wrong input is the most common cause.
- **Discover operations**: Call `refinery_list_units(category)` to confirm operation
  names and available parameters before constructing pipelines. Do not guess at
  operation names — they must match exactly.
- **Check hex encoding**: Ensure `data_hex` is valid hex (even length, 0-9a-f only).
  Use `file_offset`+`length` instead of `data_hex` when possible.

## Decompilation/Disassembly Failures

- "Angr background analysis is still in progress" → `check_task_status('startup-angr')`
  and wait; use `get_angr_partial_functions()` to see what's available now.
- "No function at address" → The address may be mid-function or data. Try
  `disassemble_at_address` to see what's there, or check `get_function_map()`.
- cffi fallback note in response → Decompiler quality reduced. Cross-check critical
  logic against `get_annotated_disassembly()`.

## Emulation Failures

- CRT init crash → Check `debug_get_api_trace()` for the last API call. Stub the
  failing API with `debug_stub_api()`. Common: `_initterm_e`, `GetSystemTimeAsFileTime`.
- No output captured → Verify `stub_io=True` was set in `debug_start`. Check
  `debug_get_output()` — output may be buffered.
- "Rootfs not found" → Run `qiling_setup_check()` to verify setup.

## General Issues

- Truncated responses → Check for `has_more: true` in pagination fields. Use
  `offset`/`limit` parameters to page through results.
- "No file loaded" → Call `open_file()` first. Use `list_samples()` to find files.
- "Background tasks active" on `open_file`/`close_file` → Use
  `abort_background_task(task_id)` or pass `force_switch=True`.

## Null-Byte Regions and Fake Functions

**Symptom**: `get_function_map` shows thousands of tiny functions (1-3 blocks each) with no meaningful names, all in a contiguous address range. Memory usage explodes during enrichment.

**Cause**: Large null-byte regions (BSS sections, shellcode staging areas, resource padding) where angr interprets `0x00 0x00` as `add [rax], al` instructions, creating thousands of fake functions.

**Solution**:
1. These functions are auto-filtered from `get_function_map` and the enrichment decompile sweep
2. Run `detect_null_regions()` to see where null regions are and their classification
3. If angr already consumed excessive memory, use `release_angr_memory()` to free it
4. The `decompile_function_with_angr` tool warns if you try to decompile a null-artifact function

**Prevention**: The filtering is automatic — no action needed for most analyses. For very large shellcode blobs (>1MB), consider using `emulate_shellcode_with_qiling()` instead of angr for initial analysis.
