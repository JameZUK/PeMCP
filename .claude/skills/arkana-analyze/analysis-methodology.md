# Analysis Methodology — Detailed Reference

This file contains the full operational detail referenced by compact entries in
SKILL.md. Read this for the reasoning and specific examples behind each principle.

## Speculative Decryption — Forbidden Examples

"Concrete evidence" means you decompiled the function that performs the operation
and can cite: the specific algorithm (e.g., "sub_401830 calls CryptDecrypt with
CALG_RC4"), the key source (e.g., "16-byte key loaded from .rdata+0x5000"), and
the data location (e.g., "reads 54KB from RCDATA/202").

Specifically forbidden without decompilation evidence:
- Guessing XOR keys or trying `brute_force_simple_crypto` (this tool produces
  false positives — a coincidental "MZ" match does NOT mean you found the right
  key; it means 2 bytes out of thousands happened to align)
- Trying random decompression algorithms on high-entropy data
- Chaining speculative `refinery_pipeline` operations hoping something works
- Trying multiple RC4/AES/XOR key combinations from different resources
- Deriving keys from known-plaintext XOR and assuming they repeat

The ONLY exceptions:
- `extract_config_automated()` and `extract_config_for_family()`, which use
  validated family-specific logic internally
- `brute_force_simple_crypto()` AFTER decompilation reveals the algorithm is
  simple XOR but the key can't be traced statically — and even then, validate
  results thoroughly (a valid PE needs more than just "MZ at offset 0"; check
  e_lfanew, section count, import table)

## Fair Interpretation — API Examples

Many flagged APIs are imported by language runtimes, not by the developer's code:
- `IsDebuggerPresent` in Rust stdlib (panic handler), Delphi VCL, .NET CLR, Go runtime
- `QueryPerformanceCounter` in any binary that measures time (async runtimes, HTTP
  clients, GUI frameworks)
- `VirtualProtect` in any loader (section permissions)
- `VirtualAlloc` in JIT compilers (.NET, Java) and large-buffer allocators
- `CreateProcessW` in any tool that launches subprocesses

These are normal imports — not anti-analysis techniques. An API is only
"anti-analysis" when user-written code checks its result and alters execution
flow defensively.

**Packer/loader mechanics**: Minimal imports, dynamic API resolution, PEB access,
reflective loading, NtTerminateProcess hooking — these are **functional
requirements** of any loader or packer, not anti-analysis techniques. A reflective
loader has few imports because it doesn't need more. It resolves APIs at runtime
because that's how loading works. Label these as "loader mechanics" or "packer
behavior", not "anti-analysis".

**Commercial protectors**: EMERITA, Themida, VMProtect, ASProtect, Enigma Protector,
and similar products are legitimate commercial software protection tools. Their
techniques (code signing, packing, import minimisation, runtime loading) are product
features, not indicators of malicious intent. Identify the protector and note it.

**YARA false positives**: Rules matching byte patterns (not strings) can fire on
compiled code coincidentally. Always check the matched offset — is it in user code
or in a known library? Crypto-detection rules commonly match legitimate TLS
implementations (ChaCha20, AES). Behavioral rules can match compiler-generated
instruction sequences. Verify before reporting.

**Framing language**: Say "the binary imports X" (fact), not "the binary uses
anti-analysis technique X" (interpretation) unless you have confirmed deliberate
defensive use. Say "the loader resolves APIs dynamically" (mechanism), not "the
binary hides its imports" (intent).

## Packed Binaries — Why Unpack First

The packing stub is designed to defeat static analysis — angr's CFG builder will
stall or produce useless results on obfuscated/encrypted code. The resources,
strings, and encrypted blobs inside a packed binary are there to be processed by
the UNPACKED code. You cannot understand the decryption without first understanding
the code that performs it, and you cannot understand that code until the binary is
unpacked.

If ALL unpacking and emulation methods fail: Report what IS known (packer ID,
entropy, import count, any VT results, any strings or IOCs extracted from the
packed binary) and clearly state that deeper analysis was blocked by packing. Do
not guess at the payload's nature.

## Phase 0 — Container Path Layout

| Path | Mode | Purpose |
|------|------|---------|
| `/samples` | ro | Sample input directory |
| `/output` | rw | Export/report output |
| `/app/home/.arkana` | rw | Persistent cache, notes, session data |
| `/app/qiling-rootfs` | rw | Qiling emulation rootfs |

## LIEF as pefile Fallback

If PE analysis via pefile fails (timeout, crash, or corrupt headers flagged by
`file_integrity`), use `parse_binary_with_lief()` as a fallback parser. LIEF can
extract sections, imports, exports, headers, and Authenticode signatures from PE
files that pefile cannot handle — including malformed, partially corrupt, or
unusually structured binaries. It also supports ELF and Mach-O natively. Use when:
- `open_file` times out or raises an error on a PE file
- `file_integrity.status` is `"corrupt"` or `"partial"` and pefile-based tools return errors
- You need cross-format structural comparison (LIEF normalises PE/ELF/Mach-O)

## Phase 2 — Anti-Pattern Warning

**ACTUALLY CALL THE UNPACKING TOOLS**: Do not just think about which unpacking
tool to use — call it. The most common failure mode is recognizing the binary
is packed, identifying the right tool in your reasoning, but then trying
something else instead (hex dumps, refinery operations, manual stub analysis).
The method cascade below exists for a reason: call `auto_unpack_pe()` first,
then `try_all_unpackers()`, then `qiling_dump_unpacked_binary()`. Only attempt
manual stub analysis (Method 5) after all three automated methods have been
tried and have returned explicit failure results.

## Phase 2 — Full Method Cascade

1. **`auto_unpack_pe()`** — handles UPX, ASPack, PECompact, Themida, and more.
   Best for known packers identified by PEiD.

2. **`try_all_unpackers()`** — orchestrates multiple unpacking methods automatically.
   Tries known unpackers, then heuristic approaches.

3. **`qiling_dump_unpacked_binary()`** — emulates until OEP is reached, dumps from
   memory. Works for custom/unknown packers. Requires Qiling rootfs.

4. **Emulation-based analysis** (if unpacking fails but you still need behaviour):
   - `emulate_binary_with_qiling()` — run the packed binary and observe API calls,
     file/registry/network activity, and memory writes
   - `emulate_pe_with_windows_apis()` — Speakeasy emulation with Windows API simulation
   - `qiling_memory_search()` — search memory after emulation for decrypted strings,
     URLs, config data, or unpacked PE images
   - `qiling_hook_api_calls()` — hook specific APIs (e.g., VirtualAlloc, connect,
     InternetOpenUrl) to capture runtime behaviour

5. **Manual OEP recovery** (last resort):
   - `find_oep_heuristic()` to locate the original entry point
   - `emulate_with_watchpoints()` with breakpoints near OEP candidates
   - `qiling_memory_search()` to find the unpacked image in memory
   - `reconstruct_pe_from_dump()` to rebuild a valid PE from the dump

Multi-layer packing: If the unpacked result is still packed, repeat Phase 2.
Track layer count and note each packer identified.

## Background Tasks — Detailed Behaviour

- After the soft timeout, tasks enter `overtime` status (still running).
- If the task is making progress, it keeps running (no ceiling except 6h safety net).
- If stalled for 5 minutes with zero progress, it is automatically killed.
- Background alerts appear in every tool response (`_background_alerts`).
- Use `check_task_status(task_id)` for detailed progress including
  `recommendation`, `discovery_rate_per_min`, `stall_seconds`.
- Use `abort_background_task(task_id)` to explicitly stop any task.
- `open_file()` and `close_file()` **block** when background tasks are active —
  abort tasks first or pass `force_switch=True` to override.
- `decompile_function_with_angr()` works WITHOUT a full CFG (builds local CFG).

When waiting for angr:
1. `check_task_status('startup-angr')` — shows `functions_discovered_so_far`
   and `stall_detection`
2. Do one round of non-angr work (strings, resources, imports) while waiting
3. Check status again, then retry
4. If stalled (`is_stalled=true`), don't wait — use `decompile_function_with_angr`
   (builds a local CFG automatically), `get_angr_partial_functions()`, or
   `disassemble_at_address()` immediately.

## Symbolic Execution — OOM Prevention

angr clones full state objects at every branch. On complex binaries (hash functions,
CRT-heavy MinGW/MSVC code, crypto loops), state counts explode and can OOM-kill
the Docker container. Mitigations:
- Keep `max_active` ≤ 10 (default 50 is dangerous for complex targets)
- Keep `max_steps` ≤ 10000 (not 50000+)
- Use `start_address` to skip CRT initialization when possible
- Prefer concrete emulation (Qiling/Speakeasy/debugger) for hash-heavy code —
  symbolic execution cannot efficiently invert hash functions
- If targeting a comparison (memcmp, strcmp), start AFTER the value generation
  so the expected value is concrete and the constraint is trivial

## Decompiler Calling Convention — Register Mapping

angr's decompiler uses **System V AMD64** calling convention by default. For
**Windows PE binaries and shellcode**, this means parameter names in pseudocode
do NOT match the actual Windows x64 convention:

| Pseudocode param | SysV register | Windows x64 actual |
|------------------|---------------|-------------------|
| `a0` | rdi | NOT a parameter |
| `a1` | rsi | NOT a parameter |
| `ptr` / `a2` | rdx | param 2 |
| `a3` | rcx | param 1 |

Windows x64: `rcx`=param1, `rdx`=param2, `r8`=param3, `r9`=param4.

When decompiled code doesn't produce expected results — especially for crypto/cipher
functions — **check the assembly at the call site** to see which registers actually
carry which arguments.

## Pagination — Tool-Specific Parameters

Key paginated tools and their offset/limit params:
- `get_triage_report`: `indicator_offset` / `indicator_limit`
- `get_analysis_digest`: 5 pairs for findings, functions, IOCs, unexplored, notes
- `get_session_summary`: `notes_offset` / `notes_limit` / `history_limit`
- `get_function_map`: `offset` / `limit`
- `suggest_next_action`: `max_suggestions`
- `find_anti_debug_comprehensive`: `limit`
- `identify_cpp_classes`: `method_limit`
- `detect_dga_indicators` / `match_c2_indicators` / `analyze_kernel_driver`: `limit`

## Phase 7 — Summary Requirements

The summary must:
- **State only what was observed**, backed by specific tool output (tool name, key
  values, addresses). No speculation, no assumptions, no "likely" or "probably".
- **Cite evidence plainly**: e.g., "Triage risk score: 8/10 (CRITICAL). Imports
  VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread. Decompilation of
  sub_401200 confirms these are called in sequence to write and execute code in a
  remote process (explorer.exe PID obtained via CreateToolhelp32Snapshot loop)."
- **Show your workings for derived artefacts**: When reporting extracted configs,
  decrypted payloads, or decoded strings, include a brief extraction chain — where
  the data was found, what algorithm/key was used, and how the key was obtained.
- **Separate facts from unknowns**: if something could not be determined (e.g.,
  packed binary blocked deeper analysis), say so explicitly rather than guessing.
- **Be brief**: aim for a short, scannable summary — not a wall of text.

After the summary, offer follow-up options:
1. **Detailed report**: `get_analysis_digest()` → `generate_analysis_report()`,
   optionally `auto_name_sample()` for a descriptive filename.
2. **Detection signatures**: `generate_yara_rule(scan_after_generate=True)`,
   `generate_sigma_rule(rule_type='all')`, `map_mitre_attack(include_navigator_layer=True)`.
3. **Session export**: `export_project()` — saves all notes, history, findings,
   and extracted artifacts as a portable archive (importable via `import_project()`).

Goal-adapted detail when full report is requested:
- **Malware triage**: Verdict + evidence + IOC table + validated capabilities. Apply
  fair interpretation rules — do not cite runtime imports or packer mechanics as evidence.
- **Deep RE**: Findings by function/module, call graphs, data flows, algorithms.
- **Vulnerability audit**: Attack surface, unsafe functions, hardening assessment.
- **Firmware**: Crypto inventory, credentials, protocols, debug interfaces.
- **Threat intel**: Verified attribution (cite specific evidence — hash seed, constants,
  config structure), C2 infra, YARA/Sigma, MITRE, IOC export.
- **Comparison**: Function-level diffs, similarity scores, behavioral changes.

## Context Management — Full Detail

1. **At phase transitions**: Call `get_analysis_digest()` between phases (e.g.,
   Phase 3→4, Phase 4→5), after any unexpected finding that changes the analysis
   direction, and before generating the final summary. Do NOT call it on a fixed
   cadence within a phase.

2. **Note categories** (directly feed dashboard):
   - `tool_result` → dashboard KEY FINDINGS
   - `ioc` → indicators
   - `hypothesis` → dashboard CONCLUSION section + overview AI assessment card
   - `conclusion` → detailed markdown write-up on dashboard overview
   - `manual` → analyst observations

3. **Session persistence**: Notes, history, artifacts, renames, custom types, and cache
   persist across container restarts via `~/.arkana`. When reopening a previously
   analyzed file, session context is automatically restored.

4. **Tool history**: `get_tool_history()` to review what's been run.
   `get_progress_overview()` for coverage gaps.

5. **Guided next steps**: `suggest_next_action()` recommends tools based on current
   analysis state. `list_tools_by_phase()` shows available tools per workflow phase.

6. **After patching**: `reanalyze_loaded_pe_file()` to refresh.
   `remove_cached_analysis(sha256)` to evict stale cache entries.

## Decision Matrix — Full Reference

| Scenario | Recommended Tier |
|----------|-----------------|
| Understanding function purpose | Tier 1 (decompile) |
| Tracing crypto key derivation | Tier 2 (reaching_definitions + backward_slice) |
| Resolving dynamic API calls | Tier 3 (emulate or qiling_resolve_api_hashes) |
| Decrypting runtime-only strings | Tier 3 (emulate + memory_search) |
| Understanding control flow obfuscation | Tier 2 (control_dependencies + propagate_constants) |
| Extracting config from encrypted blob | Tier 2 first, Tier 3 if key not resolved |
| Analyzing anti-debug checks | Tier 1 (decompile + xrefs), Tier 3 if complex |
| Bypassing anti-debug for live analysis | Tier 4 (generate_frida_bypass_script) |
| Broad runtime API tracing | Tier 4 (generate_frida_trace_script) |
| Hooking specific APIs at runtime | Tier 4 (generate_frida_hook_script) |
| Detecting control flow flattening | Tier 1 (detect_control_flow_flattening) |
| Identifying opaque predicates | Tier 2 (detect_opaque_predicates) |
| Tracing untrusted input to dangerous sinks | Tier 2 (find_dangerous_data_flows) |
| Identifying C++ vtable dispatch | Tier 1 (identify_cpp_classes + scan_for_indirect_jumps) |
| Step-through debugging scenarios | Tier 3b — see [debugger-guide.md](debugger-guide.md) |

## Refinery Pipelines — Incremental Build Strategy

When using `refinery_pipeline` with more than 2 steps, build and verify stage-by-stage:
start with the first 1-2 steps and inspect the output, verify it matches expectations,
then add the next step. Never construct a pipeline with 5+ steps in a single attempt —
each intermediate check catches wrong assumptions about the data format.

If a pipeline produces wrong output, bisect it by removing steps from the end until
output is correct, then add steps back one at a time to find the failing operation.
