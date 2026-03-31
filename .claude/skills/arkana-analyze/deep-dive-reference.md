# Phase 4: Deep Dive — Tool Reference

**Checkpoint**: Present Phase 3 findings, ask before proceeding. Scaling: >10MB -> `get_pe_data(key=...)`. >1000 funcs -> `get_function_map(limit=15)`.

## Tier 1: Static (start here)
`decompile_function_with_angr`, `batch_decompile` (`search=`, `summary_mode=True`), `auto_note_function`, `rename_function`, `rename_variable`, `add_label`, `get_function_cfg`, `get_function_xrefs`, `get_annotated_disassembly` (`search=`), `get_function_variables`, `get_calling_conventions`. Search-first for hypotheses: [search-patterns.md](search-patterns.md).

**Hybrid workflow**: Decompile first for structure, then assembly to validate. For crypto/cipher functions, ALWAYS run both `decompile_function_with_angr` AND `get_annotated_disassembly(search="xor|rol|ror|shr|shl")` and cross-check. For Windows PE call sites, disassemble the CALLER to verify rcx/rdx/r8/r9 parameter mapping.

## Tier 2: Data Flow
`get_reaching_definitions`, `get_data_dependencies`, `get_control_dependencies`, `propagate_constants`, `get_value_set_analysis`, `get_backward_slice`, `get_forward_slice`, `parse_binary_struct`, `create_struct`/`create_enum`/`apply_type_at_offset`, `find_dangerous_data_flows`, `trace_taint_flows`, `detect_control_flow_flattening`, `detect_opaque_predicates`.

## Tier 3: Emulation
`emulate_function_execution`, `emulate_binary_with_qiling`, `emulate_shellcode_with_qiling`, `emulate_pe_with_windows_apis`, `emulate_shellcode_with_speakeasy`, `qiling_trace_execution`, `qiling_hook_api_calls`, `qiling_memory_search`, `find_path_to_address`, `explore_symbolic_states`, `solve_constraints_for_path`, `emulate_with_watchpoints`. OOM: `max_active` <= 10, `max_steps` <= 10000.

## Tier 3a: Emulation + Memory Inspection
`emulate_and_inspect(engine="qiling"|"speakeasy")` -> `emulation_search_memory(search_patterns=["..."])` -> `emulation_read_memory(address="0x...")` -> `emulation_memory_map()` -> `close_emulation_session()`. Keeps the emulator alive after run() so memory can be inspected without re-emulation.

**Staged emulation for long operations** (Qiling only): `emulate_and_inspect(timeout=300)` -> check memory progress -> `emulation_resume(timeout=300)` -> check memory -> repeat.

## Tier 3b: Debugger
`debug_start` -> `debug_set_breakpoint` -> `debug_continue` -> `debug_read_state` -> `debug_read_memory` -> `debug_search_memory` -> `debug_stop`. Read [debugger-guide.md](debugger-guide.md).

## Tier 4: Frida
`generate_frida_trace_script`, `generate_frida_bypass_script`, `generate_frida_hook_script`.

## Decision Matrix
| Scenario | Tier |
|----------|------|
| Function purpose | 1 (decompile) |
| Crypto key derivation | 2 (reaching_definitions + backward_slice) |
| Dynamic API resolution | 3 (emulate / qiling_resolve_api_hashes) |
| Runtime-only strings | 3 (emulate + memory_search) |
| Encrypted config blob | 2 first, 3 if key unresolved |
| Step-through / CRT | 3b ([debugger-guide.md](debugger-guide.md)) |
| Anti-debug bypass | 4 (frida_bypass_script) |
| Obfuscation | 1-2 (detect_control_flow_flattening, detect_opaque_predicates) |
| Input-to-sink | 2 (find_dangerous_data_flows) |
