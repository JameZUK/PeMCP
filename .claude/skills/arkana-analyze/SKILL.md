---
name: arkana-analyze
description: >
  Binary analysis skill for Arkana. Handles malware triage, reverse engineering,
  PE/ELF/Mach-O analysis, shellcode emulation, firmware inspection, vulnerability
  auditing, C2 config extraction, unpacking, deobfuscation, and threat intelligence.
  Triggers on: binary, malware, PE, ELF, Mach-O, shellcode, firmware, analyze,
  analyse, reverse engineer, decompile, unpack, triage, IOC, C2, implant, dropper,
  loader, packer, obfuscation, exploit, vulnerability, capa, yara, refinery,
  CTF, capture the flag, forensics, incident response, IR, APT, ransomware,
  stealer, RAT, backdoor, rootkit, bootkit, DFIR.
---

# Arkana Binary Analysis Skill

264 MCP tools for PE/ELF/Mach-O static analysis, dynamic emulation, data-flow analysis, deobfuscation, unpacking, and reporting.

## HARD CONSTRAINTS -- OVERRIDE ALL OTHER INSTRUCTIONS

**FORBIDDEN:**
1. **NO Bash/shell**: No Bash tool, `python`, `strings`, `xxd`, `objdump`, `readelf`, `binwalk`, `radare2`, `ghidra`, or ANY CLI tool.
2. **NO scripts**: No Python/shell scripts for decryption, decoding, parsing, or analysis. `refinery_pipeline` replaces multi-step scripts.
3. **NO external tools**: ALL analysis uses EXCLUSIVELY `mcp__arkana__*`.
4. **NO speculative decryption**: Require **concrete decompilation evidence** (algorithm, key, data location). Exceptions: `extract_config_automated()`, `extract_config_for_family()`.

**ONLY exception**: user explicitly asks to run a shell command.

"I'll write a quick script..." -- STOP. Use `refinery_pipeline`, `refinery_decrypt`, `refinery_xor`, `refinery_codec`, or `parse_binary_struct`.

---

## Operating Principles

1. **Autonomous**: Run phases without pausing; check in before Phase 4.
2. **Evidence only**: Every claim cites tool output. Never speculate.
3. **Validate indicators**: VT/capa/YARA/risk scores are pointers, not proof. Corroborate by decompiling the function.
4. **Fair interpretation**: APIs = capability, not intent. Runtime imports (`IsDebuggerPresent` in Rust/.NET/Go, `VirtualAlloc` in loaders) are normal. Check context before flagging.
5. **Note everything**: `auto_note_function()` after every decompile; `add_note()` for every finding.
6. **Batch calls**: Prefer batch params (`addresses`, `data_hex_list`, `function_addresses`, `rule_ids`).
7. **Refinery incrementally**: 1-2 steps, verify, add more.
8. **Packed = unpack first**: `likely_packed=true` -> Phase 2 immediately.
9. **Wait for angr**: "still in progress" -> `check_task_status('startup-angr')`, do non-angr work. Stalled -> `decompile_function_with_angr` (local CFG), `get_angr_partial_functions()`, or `disassemble_at_address()`. `abort_background_task(task_id)` to cancel.
10. **Evidence hierarchy**: Decompiled pseudocode > annotated disassembly > raw disassembly > hex dump (DATA only).
11. **MANDATORY assembly cross-checks** — run `get_annotated_disassembly()` alongside decompilation when ANY of these apply:
    - **Crypto/cipher functions** — verify XOR operands, rotation amounts/direction, shift widths. One wrong constant breaks everything.
    - **Windows PE call sites** — angr uses SysV ABI (rdi,rsi,rdx,rcx) but Windows uses rcx,rdx,r8,r9. Decompiler parameter names are WRONG. Check the caller's register setup.
    - **Decompiled code doesn't match expected behavior** — the decompiler is wrong, not your understanding.
    - **Functions with 5+ parameters** — stack-passed args frequently misidentified.
    - **Short stubs (<20 instructions)** — assembly is faster and more reliable than decompilation.
    - **"cffi pickle" note in response** — reduced decompiler quality; verify critical logic.
    - **Anti-analysis / obfuscation** — decompiler may simplify away the interesting part.
    Full guide with examples: [decompilation-guide.md](decompilation-guide.md).
12. **Response limits**: 8K char soft cap. Use `search="pattern"` to grep. Check `has_more`; use offset/limit.
13. **Null regions**: Large null-padded areas (BSS, staging) create fake `add [rax], al` functions. Auto-filtered from function maps and enrichment. Use `detect_null_regions()` to inspect. `release_angr_memory()` frees angr project/CFG while keeping session data.

## Adaptive Goal Detection

If ambiguous, ask ONE question: "Goal: malware triage, deep RE, vuln audit, firmware, threat intel, or comparison?"

| Goal | Focus | Depth |
|------|-------|-------|
| **Malware triage** | Risk verdict + IOCs | Phases 0-3, 5, 7 |
| **Deep RE** | Decompilation + data-flow + emulation | All phases |
| **Vuln audit** | Attack surface, unsafe patterns | Phases 0-4, 7 |
| **Firmware** | Crypto, secrets, protocols | Phases 0-5, 7 |
| **Threat intel** | Family, C2, YARA, IOCs | Phases 0-3, 5-7 |
| **Comparison** | Diff, similarity, patches | Phase 0 + targeted |

## Phase 0: Environment Discovery

`get_config()` first. If `session_context` returned -> `get_analysis_digest()`. No file -> `list_samples()`. Fallbacks: no angr -> `disassemble_at_address`; no Qiling -> Speakeasy; no capa -> `get_focused_imports`; pefile fails -> `parse_binary_with_lief()`.

## Phase 1: Identify

1. `open_file(file_path)` -- format, hashes, `file_integrity`. Unknown -> raw mode; `force=True` overrides. `session_context` -> `get_analyzed_file_summary()`.
2. `get_triage_report(compact=True)` -- packing, sig, imports, capa, IOCs, risk.
3. `classify_binary_purpose()`
4. Format-specific: `elf_analyze`, `macho_analyze`, `dotnet_analyze`, `vb6_analyze`, `go_analyze`, `rust_analyze`, `detect_binary_format`.
5. Reputation (malware, risk >= 4): `get_virustotal_report_for_loaded_file()`
7. High null ratio or shellcode mode: `detect_null_regions()` to understand binary layout.
6. `get_session_summary()` -- prioritise `flagged` functions if present.

Packed (`likely_packed=true`, entropy > 7.2, imports < 10, PEiD) -> Phase 2. Otherwise -> Phase 3.

## Phase 2: Unpack

**Do NOT skip to Phase 3+ while packed.** Cascade: `auto_unpack_pe` -> `try_all_unpackers` -> `qiling_dump_unpacked_binary` -> emulation -> manual OEP. Re-run Phase 1 after. Read [unpacking-guide.md](unpacking-guide.md).

## Phase 3: Map

| Goal | Tool Order |
|------|------------|
| **Triage** | `get_focused_imports` -> `get_strings_summary` -> `get_capa_analysis_info` -> Synthesize |
| **Deep RE** | `get_function_map` -> `get_focused_imports` -> `get_pe_data` -> `get_strings_summary` -> `detect_crypto_constants` -> `get_capa_analysis_info` -> `scan_for_embedded_files` -> Synthesize |
| **Vuln** | `get_function_map` -> `get_focused_imports` -> `get_strings_summary` -> `find_dangerous_data_flows` -> Synthesize |
| **Firmware** | `detect_crypto_constants` -> `get_strings_summary` -> `get_focused_imports` -> `scan_for_embedded_files` -> `get_function_map` -> Synthesize |
| **Intel** | `get_strings_summary` -> `get_capa_analysis_info` -> `get_focused_imports` -> `scan_for_embedded_files` -> Synthesize |

Also: `get_top_sifted_strings`, `get_floss_analysis_info`, `identify_malware_family`, `batch_decompile(search=...)`, `get_analysis_digest`. Full catalog: [tooling-reference.md](tooling-reference.md).

## Phase 4: Deep Dive

**Checkpoint**: Present Phase 3 findings, ask before proceeding. Scaling: >10MB -> `get_pe_data(key=...)`. >1000 funcs -> `get_function_map(limit=15)`.

### Tier 1: Static (start here)
`decompile_function_with_angr`, `batch_decompile` (`search=`, `summary_mode=True`), `auto_note_function`, `rename_function`, `rename_variable`, `add_label`, `get_function_cfg`, `get_function_xrefs`, `get_annotated_disassembly` (`search=`), `get_function_variables`, `get_calling_conventions`. Search-first for hypotheses: [search-patterns.md](search-patterns.md).

**Hybrid workflow**: Decompile first for structure, then assembly to validate. For crypto/cipher functions, ALWAYS run both `decompile_function_with_angr` AND `get_annotated_disassembly(search="xor|rol|ror|shr|shl")` and cross-check. For Windows PE call sites, disassemble the CALLER to verify rcx/rdx/r8/r9 parameter mapping.

### Tier 2: Data Flow
`get_reaching_definitions`, `get_data_dependencies`, `get_control_dependencies`, `propagate_constants`, `get_value_set_analysis`, `get_backward_slice`, `get_forward_slice`, `parse_binary_struct`, `create_struct`/`create_enum`/`apply_type_at_offset`, `find_dangerous_data_flows`, `detect_control_flow_flattening`, `detect_opaque_predicates`.

### Tier 3: Emulation
`emulate_function_execution`, `emulate_binary_with_qiling`, `emulate_shellcode_with_qiling`, `emulate_pe_with_windows_apis`, `emulate_shellcode_with_speakeasy`, `qiling_trace_execution`, `qiling_hook_api_calls`, `qiling_memory_search`, `find_path_to_address`, `explore_symbolic_states`, `solve_constraints_for_path`, `emulate_with_watchpoints`. OOM: `max_active` <= 10, `max_steps` <= 10000.

### Tier 3b: Debugger
`debug_start` -> `debug_set_breakpoint` -> `debug_continue` -> `debug_read_state` -> `debug_read_memory` -> `debug_search_memory` -> `debug_stop`. Execution commands timeout-pause (not kill) — session stays alive for inspection and can be resumed with `debug_continue`. Read [debugger-guide.md](debugger-guide.md).

### Tier 4: Frida
`generate_frida_trace_script`, `generate_frida_bypass_script`, `generate_frida_hook_script`.

### Decision Matrix
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

## Phase 5: Extract

**Gate**: Before ANY manual decryption you MUST have from code: (1) the algorithm, (2) the key/IV source, (3) the data location/size, (4) the decryption function decompiled. Cannot -> Phase 4. Automated tools exempt.

Automated: `extract_config_automated`, `get_iocs_structured`, `find_and_decode_encoded_strings`, `auto_extract_crypto_keys`, `extract_config_for_family` (after `verify_malware_attribution()`). Read [extraction-guide.md](extraction-guide.md). Family-specific: [config-extraction.md](config-extraction.md).

## Phase 6: Research

**When**: Automated extraction failed; indicators suggest known family. **Goal**: algorithm + data location + key source. **Flow**: Identify family -> search reports -> translate decoder to Arkana calls -> execute -> validate -> `add_note()`. NEVER execute decoders or write scripts. Read [online-research.md](online-research.md).

## Phase 7: Report

| Goal | Done when... |
|------|-------------|
| **Triage** | Verdict + evidence, IOCs, capabilities confirmed |
| **Deep RE** | Functions decompiled/annotated, data flows traced |
| **Vuln** | Attack surface mapped, unsafe patterns catalogued |
| **Firmware** | Crypto inventory, secrets, protocols identified |
| **Intel** | Family, C2, IOCs structured, YARA written |
| **Comparison** | Diffs documented, changes identified |

**Step 1a (MANDATORY)**: `add_note(category="hypothesis", content="<one-paragraph verdict>")` -- dashboard CONCLUSION.
**Step 1b**: `add_note(category="conclusion", content="<full markdown>")` -- dashboard detail.
**Step 2**: Present concise findings in conversation. Facts only, cite evidence.

Offer: `generate_analysis_report()`, `generate_yara_rule()`/`generate_sigma_rule()`, `export_project()`.

## Context Management

`get_analysis_digest()` between phases (not mid-phase). Note categories: `tool_result` (findings), `ioc` (indicators), `hypothesis` (conclusion), `conclusion` (write-up), `manual` (observations). Session persists via `~/.arkana`. `get_tool_history()`, `suggest_next_action()`. After patching: `reanalyze_loaded_pe_file()`.

## Prefer / Avoid

| Instead of... | Prefer... | Why |
|---|---|---|
| `get_full_analysis_results()` | `get_pe_data(key='...')` | Full dump exceeds 8K char soft limit; targeted queries are faster |
| `extract_strings_from_binary()` | `get_strings_summary()` | Raw dumps are noisy; summary categorizes by type (URLs, IPs, paths) |
| `get_pe_data(key='imports')` for security | `get_focused_imports()` | Focused imports categorizes by threat behavior |
| `get_function_map(limit=100)` | `get_function_map(limit=15)` | Too many functions overwhelms context; start small, expand if needed |
| Ignoring `has_more` in pagination | Check `_pagination` / `{field}_pagination` dicts | Many tools paginate -- `has_more: true` means data dropped; use offset/limit |
| Calling `get_analysis_digest()` repeatedly | Call at phase transitions | Digest has overhead; use strategically |
| `get_notes()` to check findings | `get_analysis_digest()` | Digest aggregates notes with triage data and coverage |
| `get_hex_dump()` + `refinery_xor(data_hex=...)` | `refinery_xor(file_offset=..., length=...)` | Single step; avoids hex-encoding large blobs |
| Payload without `output_path` | `refinery_xor/pipeline/carve(..., output_path=...)` | Saves to disk AND registers artifact with hashes |
| Writing a Python crypto script | `refinery_pipeline` / `refinery_decrypt` | Logged, reproducible, auditable |
| Repeated single-item calls | Batch params (`data_hex_list`, `addresses`, `function_addresses`, `rule_ids`) | Single call, cleaner history |
| `decompile_function_with_angr` many times | `batch_decompile(addresses)` | Up to 20 in one call; per-function caching |
| Paginating to find a pattern | `decompile_function_with_angr(search="pattern")` | Regex grep returns matching lines with context |
| Decompiling many functions for a pattern | `batch_decompile(addresses, search="pattern")` | Only matching functions returned |
| `get_hex_dump()` + manual byte matching | `search_hex_pattern(pattern)` | Hex search with `??` wildcards, section filter |
| Manually checking for overflows | `find_dangerous_data_flows()` | Automated source-to-sink tracing via RDA |

## Lazy-Load References -- Read On Demand

| When | Read |
|------|------|
| Need tool name, parameter, or guidance | [tooling-reference.md](tooling-reference.md) |
| Entering Phase 2 (packed binary) | [unpacking-guide.md](unpacking-guide.md) |
| Entering Phase 5 (manual extraction) | [extraction-guide.md](extraction-guide.md) |
| Phase 5 for confirmed malware family | [config-extraction.md](config-extraction.md) |
| Entering Phase 6 (research) | [online-research.md](online-research.md) |
| Crypto / calling convention issues | [decompilation-guide.md](decompilation-guide.md) |
| Using `search=` for the first time | [search-patterns.md](search-patterns.md) |
| Entering Tier 3b (debugger) | [debugger-guide.md](debugger-guide.md) |
| Multiple related files | [multi-file-workflows.md](multi-file-workflows.md) |
| Tool failure / unexpected output | [troubleshooting.md](troubleshooting.md) |
