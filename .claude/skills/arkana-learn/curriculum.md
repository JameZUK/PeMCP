# Arkana Learning Curriculum

Structured modules for teaching reverse engineering using Arkana tools.
Each module defines prerequisites, learning objectives, key concepts, relevant
tools, and suggested exercises. The SKILL.md references this document when
deciding what to teach — either following the sequence or pulling in modules
contextually during guided analysis.

## How Modules Are Used

- **Structured lesson mode**: The user requests a topic → deliver the matching
  module as a focused lesson with explanations and demonstrations.
- **Guided analysis mode**: During hands-on analysis, pull in relevant modules
  when the binary naturally presents a teaching moment (e.g., packed binary
  triggers the Packing & Unpacking module).
- **Progress tracking**: After covering a module's key concepts, update the
  learner's mastery via `update_concept_mastery()`.

---

## Tier 1: Foundation

For users new to reverse engineering. Assumes general programming knowledge but
no binary analysis experience. Focus on building mental models and vocabulary.

### Module 1.1: Binary Basics

**Prerequisites**: None
**Concepts**: `binary_formats`, `compilation_pipeline`, `file_identification`

**Learning objectives**:
- Understand what a compiled binary is and how source code becomes machine code
- Distinguish between PE (Windows), ELF (Linux), and Mach-O (macOS) formats
- Identify a binary's format from magic bytes and file headers
- Understand the difference between static and dynamic linking

**Key Arkana tools**:
- `open_file()` — load a binary and see initial detection results
- `detect_binary_format()` — identify format from magic bytes
- `classify_binary_purpose()` — determine binary type (GUI, CLI, DLL, driver)

**Suggested exercises**:
1. Load a simple PE binary and examine the initial detection output
2. Compare the `open_file()` output for a PE vs an ELF binary
3. Identify a binary's purpose from classification output alone

**Teaching notes**:
- Use the "shipping container" analogy: a binary is a container with a manifest
  (headers), cargo (code/data sections), and a delivery label (entry point)
- Explain that reverse engineering is reading the container without the original
  shipping documents (source code)

---

### Module 1.2: PE Structure Deep Dive

**Prerequisites**: `binary_formats`
**Concepts**: `pe_headers`, `pe_sections`, `entry_point`, `pe_resources`

**Learning objectives**:
- Read and interpret DOS header, PE signature, COFF header, and Optional header
- Understand sections (.text, .data, .rdata, .rsrc, .reloc) and their purposes
- Identify the entry point and understand what happens when a PE loads
- Extract and examine embedded resources

**Key Arkana tools**:
- `get_pe_data(key='headers')` — raw header data
- `get_pe_data(key='sections')` — section table with sizes, entropy, permissions
- `get_pe_metadata()` — compilation timestamp, subsystem, characteristics
- `get_section_permissions()` — read/write/execute permissions per section
- `extract_resources()` — enumerate and extract embedded resources
- `extract_manifest()` — application manifest (privileges, dependencies)

**Suggested exercises**:
1. Examine the section table — which section contains code? Which has data?
2. Check section permissions — is any section both writable AND executable? (red flag)
3. Compare section entropy values — what does high entropy suggest?
4. Extract and examine resources — do any contain embedded executables?

**Teaching notes**:
- Draw the PE structure as a layered diagram: DOS stub → PE header → sections
- Explain virtual vs raw addresses early — this trips up many beginners
- Section entropy is a natural bridge to Module 2.3 (Packing)

---

### Module 1.3: String Analysis

**Prerequisites**: `binary_formats`
**Concepts**: `string_extraction`, `string_types`, `operational_strings`, `encoded_strings`

**Learning objectives**:
- Understand why strings are valuable intelligence in reverse engineering
- Distinguish ASCII, wide (UTF-16), and encoded/obfuscated strings
- Identify operationally significant strings (URLs, IPs, file paths, registry
  keys, mutex names, error messages, API names)
- Recognise when strings are deliberately hidden or encoded

**Key Arkana tools**:
- `get_strings_summary()` — categorised string intelligence
- `search_for_specific_strings(patterns=[...])` — targeted string search
- `get_top_sifted_strings()` — ML-ranked strings by relevance
- `get_floss_analysis_info()` — FLOSS decoded strings (stack, tight, decoded)
- `extract_wide_strings()` — UTF-16/wide string extraction

**Suggested exercises**:
1. Run `get_strings_summary()` on a binary — what categories appear?
2. Search for network indicators: URLs, IP addresses, domain names
3. Compare `get_strings_summary()` with `get_floss_analysis_info()` — what
   does FLOSS find that simple extraction misses?
4. Look for strings that hint at the binary's purpose (error messages, usage text)

**Teaching notes**:
- Strings are often the fastest way to understand what a binary does
- "A URL in a binary is like finding an address book in someone's pocket"
- Warn about false positives — not every string is meaningful
- Encoded strings (base64, XOR) are a natural bridge to deobfuscation

---

### Module 1.4: Import & Export Analysis

**Prerequisites**: `binary_formats`, `pe_headers`
**Concepts**: `import_address_table`, `dynamic_linking`, `suspicious_imports`,
  `dll_sideloading`

**Learning objectives**:
- Understand what imports and exports are (the binary's "shopping list" of OS functions)
- Read an import table and identify which DLLs and functions are used
- Recognise suspicious import combinations that suggest specific behaviours
  (process injection, file manipulation, network communication, persistence)
- Understand how export tables work and why they matter for DLLs

**Key Arkana tools**:
- `get_focused_imports()` — security-relevant imports categorised by threat behaviour
- `get_pe_data(key='imports')` — full unfiltered import table
- `get_pe_data(key='exports')` — export table for DLLs
- `get_import_hash_analysis()` — imphash for similarity matching

**Suggested exercises**:
1. Run `get_focused_imports()` — what behavioural categories appear?
2. Look for the "process injection trinity": VirtualAllocEx + WriteProcessMemory
   + CreateRemoteThread
3. Compare the import count between a normal binary and a packed one
4. Check a DLL's export table — do the exports look legitimate or suspicious?

**Teaching notes**:
- Imports tell you what the binary CAN do, not necessarily what it DOES do
- "Imports are like ingredients in a recipe — seeing flour, eggs, and sugar
  suggests baking, but you still need to read the recipe (decompile) to know
  what's being made"
- Low import count (<10) often signals packing — the real imports are hidden

---

### Module 1.5: Introduction to Assembly

**Prerequisites**: `binary_formats`, `pe_sections`
**Concepts**: `x86_registers`, `common_instructions`, `stack_frames`,
  `calling_conventions`, `reading_disassembly`

**Learning objectives**:
- Know the general-purpose x86/x64 registers and their conventional roles
- Read common instructions: mov, push, pop, call, ret, jmp, cmp, test, lea
- Understand the stack frame: prologue, locals, epilogue
- Identify function calls and their arguments in disassembly
- Read Arkana's annotated disassembly output

**Key Arkana tools**:
- `disassemble_at_address(address, num_instructions)` — raw disassembly
- `get_annotated_disassembly(address)` — disassembly with variable names and xrefs
- `disassemble_raw_bytes(hex_bytes)` — disassemble arbitrary bytes

**Suggested exercises**:
1. Disassemble a function prologue — identify the stack frame setup
2. Find a function call in disassembly — trace the arguments being passed
3. Compare `disassemble_at_address()` with `get_annotated_disassembly()` —
   how do annotations help?
4. Identify a loop in disassembly (cmp + jmp pattern)

**Teaching notes**:
- Start with just 10 instructions — mov, push, pop, call, ret, jmp, jz/jnz,
  cmp, test, lea — this covers ~80% of what beginners encounter
- Use register analogies: EAX = "calculator display", ESP = "bookmark in a
  stack of papers", EIP = "your finger following the recipe"
- Don't try to teach all calling conventions at once — start with cdecl

---

## Tier 2: Intermediate

For users who understand basic binary structure and can read simple disassembly.
Focus on analytical techniques and tool proficiency.

### Module 2.1: Control Flow Analysis

**Prerequisites**: `x86_registers`, `common_instructions`, `reading_disassembly`
**Concepts**: `basic_blocks`, `control_flow_graphs`, `branches`, `loops`,
  `switch_tables`, `indirect_jumps`

**Learning objectives**:
- Understand basic blocks and how they form a control flow graph (CFG)
- Read Arkana's CFG output and trace execution paths
- Identify conditional branches and their conditions
- Recognise loop patterns and switch/case dispatch tables
- Understand indirect jumps and why they complicate analysis

**Key Arkana tools**:
- `get_function_cfg(address)` — control flow graph for a function
- `get_function_map(limit=N)` — ranked function list for targeting analysis
- `scan_for_indirect_jumps()` — find indirect jump sites
- `get_function_complexity_list()` — cyclomatic complexity ranking

**Suggested exercises**:
1. Get the CFG for a function — identify the entry block and exit blocks
2. Trace both paths of a conditional branch — what determines which path executes?
3. Find a loop in the CFG — identify the loop header, body, and exit condition
4. Compare two functions by complexity — what makes one more complex?

---

### Module 2.2: Decompilation

**Prerequisites**: `control_flow_graphs`, `calling_conventions`, `stack_frames`
**Concepts**: `decompiler_output`, `type_recovery`, `variable_naming`,
  `decompiler_artefacts`, `pseudocode_reading`

**Learning objectives**:
- Understand what a decompiler does (lifting machine code to pseudocode)
- Read C-like pseudocode output and map it to behaviour
- Recognise decompiler artefacts vs actual program logic
- Compare decompiled output with disassembly to verify understanding
- Use function cross-references to trace call chains

**Key Arkana tools**:
- `decompile_function_with_angr(address)` — C-like pseudocode
- `auto_note_function(address)` — record function purpose
- `get_function_xrefs(address)` — callers and callees
- `get_function_variables(address)` — stack and register variables
- `get_calling_conventions(address)` — parameter recovery

**Suggested exercises**:
1. Decompile a function and describe its purpose in plain English
2. Compare the decompiled output with the disassembly — find where the
   decompiler simplified or may have lost information
3. Follow the cross-references: who calls this function? What does it call?
4. Identify the function's parameters from calling convention recovery

---

### Module 2.3: Packing & Unpacking

**Prerequisites**: `pe_sections`, `entry_point`, `import_address_table`
**Concepts**: `packing_purpose`, `packer_identification`, `entropy_analysis`,
  `unpacking_methods`, `oep_concept`

**Learning objectives**:
- Understand why binaries are packed (size reduction, anti-analysis)
- Identify packed binaries using entropy, import count, section names, and PEiD
- Use Arkana's automated unpacking cascade
- Understand the concept of the Original Entry Point (OEP)
- Know when to use each unpacking method

**Key Arkana tools**:
- `detect_packing()` — packing detection with PEiD signatures
- `analyze_entropy_by_offset()` — entropy distribution across the binary
- `auto_unpack_pe()` — automated unpacking for known packers
- `try_all_unpackers()` — orchestrated multi-method attempt
- `qiling_dump_unpacked_binary()` — emulation-based memory dump

**Suggested exercises**:
1. Compare entropy of a packed vs unpacked binary — what's the difference?
2. Check the import table of a packed binary — why are there so few imports?
3. Attempt to unpack a UPX-packed binary — examine the unpacked result
4. After unpacking, re-run string analysis — what new strings appear?

**Reference**: [unpacking-guide.md](../arkana-analyze/unpacking-guide.md)

---

### Module 2.4: Crypto Pattern Recognition

**Prerequisites**: `decompiler_output`, `string_extraction`
**Concepts**: `crypto_constants`, `xor_encryption`, `rc4_pattern`, `aes_pattern`,
  `key_identification`, `iv_identification`

**Learning objectives**:
- Recognise common cryptographic constants in binary data (S-boxes, round constants)
- Identify XOR encryption loops in decompiled code
- Recognise RC4 (KSA + PRGA pattern) and AES (SubBytes table, Rijndael)
- Find encryption keys and IVs in binary data
- Understand the difference between crypto for legitimate use vs obfuscation

**Key Arkana tools**:
- `identify_crypto_algorithm()` — detect crypto constants and signatures
- `detect_crypto_constants()` — scan for known constant patterns
- `auto_extract_crypto_keys()` — extract embedded keys
- `decompile_function_with_angr(address)` — read the crypto implementation

**Suggested exercises**:
1. Run `identify_crypto_algorithm()` — what algorithms are detected?
2. Decompile a function flagged as crypto — can you identify the algorithm?
3. Find where the encryption key is stored — is it hardcoded or derived?
4. XOR challenge: given encrypted data and a key, use `refinery_xor()` to decrypt

---

### Module 2.5: Capability Mapping

**Prerequisites**: `suspicious_imports`, `string_extraction`
**Concepts**: `capa_rules`, `attack_techniques`, `capability_validation`,
  `behavioural_indicators`, `false_positives`

**Learning objectives**:
- Understand what capa rules detect and how ATT&CK technique mapping works
- Interpret capability matches — what they mean and what they DON'T mean
- Validate capability claims by examining the underlying code
- Distinguish between confirmed capabilities and false positive matches
- Build a behavioural profile of a binary from multiple data sources

**Key Arkana tools**:
- `get_capa_analysis_info()` — ATT&CK technique mappings
- `get_capa_rule_match_details(rule_name)` — deep dive into specific rules
- `get_extended_capabilities()` — extended capability detection
- `get_focused_imports()` — corroborate with import analysis

**Suggested exercises**:
1. Run capa and identify the top ATT&CK techniques matched
2. Pick a capability match — decompile the matched function to verify it
3. Find a false positive: a capability match that doesn't represent actual
   malicious behaviour. Why did the rule match?
4. Build a behavioural summary: combine imports, strings, and capa results

---

## Tier 3: Advanced

For users comfortable with decompilation and static analysis. Focus on data flow,
dynamic analysis, and anti-analysis techniques.

### Module 3.1: Data Flow Analysis

**Prerequisites**: `decompiler_output`, `control_flow_graphs`
**Concepts**: `reaching_definitions`, `def_use_chains`, `control_dependencies`,
  `constant_propagation`, `backward_slice`, `forward_slice`,
  `value_set_analysis`

**Learning objectives**:
- Understand reaching definitions: "where does this variable's value come from?"
- Trace data dependencies through function code
- Use backward slicing to trace a value's origin
- Use forward slicing to trace how a value propagates
- Apply constant propagation to resolve computed values
- Know when data flow analysis is more useful than reading decompiled code

**Key Arkana tools**:
- `get_reaching_definitions(address)` — variable value sources
- `get_data_dependencies(address)` — def-use chains
- `get_control_dependencies(address)` — which conditions control which blocks
- `propagate_constants(address)` — resolve constant expressions
- `get_backward_slice(address, variable)` — trace data origin
- `get_forward_slice(address, variable)` — trace data propagation
- `get_value_set_analysis(address)` — pointer target tracking

**Suggested exercises**:
1. Pick a function parameter — use backward slicing to find where the caller
   passes this value from
2. Find a crypto key load — use reaching definitions to trace where the key
   bytes originate
3. Use constant propagation on an obfuscated function — does it simplify?
4. Compare reading decompiled code vs using data flow tools — when is each
   approach more effective?

---

### Module 3.2: Emulation & Dynamic Analysis

**Prerequisites**: `decompiler_output`, `import_address_table`
**Concepts**: `emulation_vs_execution`, `api_hooking`, `memory_inspection`,
  `symbolic_execution`, `watchpoints`, `qiling_vs_speakeasy`

**Learning objectives**:
- Understand the difference between emulation and real execution
- Choose between Qiling, Speakeasy, and angr emulation based on the task
- Hook API calls to observe runtime behaviour
- Search emulation memory for decrypted data
- Use watchpoints to monitor specific memory regions
- Understand symbolic execution basics (finding inputs that reach a target)

**Key Arkana tools**:
- `emulate_binary_with_qiling()` — full binary emulation
- `emulate_pe_with_windows_apis()` — Speakeasy PE emulation
- `emulate_shellcode_with_qiling()` — shellcode emulation
- `qiling_hook_api_calls(hooks=[...])` — API call hooking
- `qiling_memory_search(pattern)` — post-emulation memory search
- `qiling_trace_execution()` — detailed API tracing
- `emulate_with_watchpoints()` — memory/register watchpoints
- `find_path_to_address(target)` — symbolic execution path finding
- `explore_symbolic_states(find, avoid)` — BFS/DFS symbolic exploration
  (**OOM risk**: keep `max_active` ≤ 10 and `max_steps` ≤ 10000 for complex binaries)
- `solve_constraints_for_path(target, start_address)` — solve for concrete input
- `emulate_function_execution(address, args)` — single function emulation

**Suggested exercises**:
1. Emulate a binary with Qiling — what API calls does it make?
2. Hook VirtualAlloc and WriteProcessMemory — what data is written?
3. After emulation, search memory for URLs or IP addresses
4. Use symbolic execution to find an input that reaches a specific code path
5. Observe what happens when you use `max_active=50` vs `max_active=10` on a
   binary with complex hashing — monitor container memory usage

---

### Module 3.3: Anti-Analysis Techniques

**Prerequisites**: `decompiler_output`, `emulation_vs_execution`, `api_hooking`
**Concepts**: `anti_debug`, `anti_vm`, `timing_checks`, `tls_callbacks`,
  `obfuscation_techniques`, `control_flow_flattening`, `string_encryption`

**Learning objectives**:
- Identify common anti-debug techniques (IsDebuggerPresent, NtQueryInformationProcess,
  timing checks, exception-based, TLS callbacks)
- Recognise anti-VM checks (CPUID, registry checks, hardware fingerprinting,
  MAC address checks, process name checks)
- Understand control flow obfuscation (flattening, opaque predicates, junk code)
- Identify string encryption and runtime-only decryption patterns
- Know strategies for bypassing each technique during analysis

**Key Arkana tools**:
- `find_anti_debug_comprehensive()` — detect anti-debug techniques
- `detect_self_modifying_code()` — find code that modifies itself at runtime
- `get_function_cfg(address)` — visualise obfuscated control flow
- `propagate_constants(address)` — see through opaque predicates
- `find_and_decode_encoded_strings()` — recover encoded strings

**Suggested exercises**:
1. Run `find_anti_debug_comprehensive()` — what techniques are detected?
2. Decompile an anti-debug function — how does it check for a debugger?
3. Find a timing check — what API does it use? How large is the threshold?
4. Identify an obfuscated function — what makes it hard to read?

---

### Module 3.4: Malware Configuration Extraction

**Prerequisites**: `crypto_constants`, `key_identification`, `emulation_vs_execution`
**Concepts**: `c2_config_patterns`, `config_storage`, `encryption_layers`,
  `extraction_methodology`, `validation`

**Learning objectives**:
- Understand common C2 config storage patterns (XOR blobs, .NET fields, PE
  resources, config structs, runtime-only, steganography)
- Follow the extraction methodology: locate → identify algorithm → find key →
  decrypt → validate
- Use automated extraction tools and fall back to manual methods
- Document the full extraction chain for reproducibility
- Validate extracted configs (plausible domains, correct struct size, etc.)

**Key Arkana tools**:
- `extract_config_automated()` — auto-detect and extract C2 configs
- `get_iocs_structured()` — aggregate all IOCs
- `refinery_xor()`, `refinery_decrypt()`, `refinery_auto_decrypt()` — manual decryption
- `refinery_pipeline()` — chain multiple decryption/decoding steps
- `decompile_function_with_angr(address)` — read the decryption routine
- `get_backward_slice(address, variable)` — trace key origin
- `extract_config_for_family(family)` — KB-driven extraction for confirmed families
- `parse_binary_struct(schema, data_hex)` — parse decrypted config structs
- `scan_for_api_hashes()` — detect API hash resolution (evidence for family ID)

**Suggested exercises**:
1. Try automated extraction first — does it find a config?
2. If automated fails: identify the encryption function via capa/imports
3. Decompile the encryption function — what algorithm is used?
4. Trace the key: where is it stored? How is it loaded?
5. Manually decrypt using refinery tools and validate the result

**Reference**: [config-extraction.md](../arkana-analyze/config-extraction.md)

---

## Tier 4: Expert

For experienced analysts looking to master advanced techniques. Focus on
complex unpacking, protocol analysis, YARA authoring, and campaign analysis.

### Module 4.1: Advanced Unpacking

**Prerequisites**: `unpacking_methods`, `oep_concept`, `emulation_vs_execution`
**Concepts**: `manual_oep_recovery`, `multi_layer_packing`, `process_hollowing`,
  `dotnet_obfuscators`, `pe_reconstruction`, `emulation_based_dumping`

**Learning objectives**:
- Recover the Original Entry Point manually using heuristic and emulation methods
- Handle multi-layer packing (packer within a packer)
- Understand process hollowing and how to analyse hollowed payloads
- Deal with .NET-specific obfuscators (ConfuserEx, .NET Reactor, Babel)
- Reconstruct a valid PE from a memory dump

**Key Arkana tools**:
- `find_oep_heuristic()` — heuristic OEP detection
- `emulate_with_watchpoints()` — breakpoint near OEP candidates
- `qiling_dump_unpacked_binary()` — emulation-based memory dump
- `reconstruct_pe_from_dump()` — rebuild PE from memory dump
- `qiling_memory_search()` — find unpacked image in memory
- `refinery_dotnet()` — .NET deobfuscation operations

**Suggested exercises**:
1. Given a custom-packed binary where auto_unpack fails, find the OEP manually
2. Emulate to the OEP, dump memory, and reconstruct the PE
3. Handle a multi-layer packed binary — track each layer
4. Analyse a .NET binary protected with ConfuserEx

**Reference**: [unpacking-guide.md](../arkana-analyze/unpacking-guide.md)

---

### Module 4.2: Protocol Reverse Engineering

**Prerequisites**: `decompiler_output`, `reaching_definitions`, `emulation_vs_execution`
**Concepts**: `network_protocols`, `serialization_formats`, `command_dispatch`,
  `session_management`, `custom_encodings`

**Learning objectives**:
- Identify network communication functions and trace the data flow
- Reconstruct custom protocol message formats from code
- Identify command dispatch tables (command ID → handler function)
- Understand session establishment and authentication mechanisms
- Document protocol specifications from reverse engineering findings

**Key Arkana tools**:
- `get_focused_imports()` — identify networking APIs (WSAStartup, connect, send, recv)
- `get_cross_reference_map()` — trace call chains from network functions
- `decompile_function_with_angr(address)` — read protocol handlers
- `get_data_dependencies(address)` — trace data through protocol processing
- `get_function_variables(address)` — identify buffer structures

**Suggested exercises**:
1. Find the network initialisation code — trace the connection setup
2. Identify the main recv/dispatch loop — what commands does it handle?
3. Decompile a command handler — what does this command do?
4. Document the protocol: message format, command IDs, encoding

---

### Module 4.3: YARA Rule Authoring

**Prerequisites**: `string_extraction`, `crypto_constants`, `pe_structure`
**Concepts**: `yara_syntax`, `byte_patterns`, `string_selection`,
  `condition_logic`, `false_positive_avoidance`, `rule_testing`

**Learning objectives**:
- Write effective YARA rules from analysis findings
- Choose good byte patterns (unique, stable across versions, not compiler-generated)
- Use string types (text, hex, regex) appropriately
- Write conditions that balance detection vs false positive rate
- Test rules against the sample and known-good files

**Key Arkana tools**:
- `search_yara_custom(rule)` — test a YARA rule against the loaded binary
- `get_hex_dump(offset, length)` — examine raw bytes for pattern selection
- `compute_similarity_hashes()` — generate hashes for clustering/matching
- `get_strings_summary()` — find unique strings for rule conditions

**Suggested exercises**:
1. Write a YARA rule using strings found during analysis
2. Add byte pattern conditions from unique code sequences
3. Test the rule — does it match the sample? Does it avoid false positives?
4. Refine the rule: make it resilient to minor binary changes

---

### Module 4.4: Campaign Analysis

**Prerequisites**: All Tier 3 modules
**Concepts**: `binary_diffing`, `similarity_hashing`, `variant_evolution`,
  `infrastructure_tracking`, `multi_sample_workflows`, `attribution`

**Learning objectives**:
- Compare related samples to identify changes between versions
- Use similarity hashing (ssdeep, TLSH, imphash) for sample clustering
- Track infrastructure changes across campaign samples
- Manage multi-file analysis workflows efficiently
- Build a campaign timeline from binary metadata and extracted configs

**Key Arkana tools**:
- `diff_binaries()` — structural comparison between binaries
- `compute_similarity_hashes()` — ssdeep/TLSH/imphash generation
- `compare_file_similarity()` — similarity scoring
- `get_pe_metadata()` — compilation timestamps, linker versions
- `export_project()` / `import_project()` — session management

**Suggested exercises**:
1. Compare two variants — what functions changed? What stayed the same?
2. Generate similarity hashes for a sample set — which cluster together?
3. Extract C2 configs from multiple samples — map the infrastructure evolution
4. Build a campaign report: timeline, samples, infrastructure, TTPs

---

## Concept Index

Quick reference mapping concept IDs to modules for progress tracking.

| Concept ID | Module | Tier |
|---|---|---|
| `binary_formats` | 1.1 | Foundation |
| `compilation_pipeline` | 1.1 | Foundation |
| `file_identification` | 1.1 | Foundation |
| `pe_headers` | 1.2 | Foundation |
| `pe_sections` | 1.2 | Foundation |
| `entry_point` | 1.2 | Foundation |
| `pe_resources` | 1.2 | Foundation |
| `string_extraction` | 1.3 | Foundation |
| `string_types` | 1.3 | Foundation |
| `operational_strings` | 1.3 | Foundation |
| `encoded_strings` | 1.3 | Foundation |
| `import_address_table` | 1.4 | Foundation |
| `dynamic_linking` | 1.4 | Foundation |
| `suspicious_imports` | 1.4 | Foundation |
| `dll_sideloading` | 1.4 | Foundation |
| `x86_registers` | 1.5 | Foundation |
| `common_instructions` | 1.5 | Foundation |
| `stack_frames` | 1.5 | Foundation |
| `calling_conventions` | 1.5 | Foundation |
| `reading_disassembly` | 1.5 | Foundation |
| `basic_blocks` | 2.1 | Intermediate |
| `control_flow_graphs` | 2.1 | Intermediate |
| `branches` | 2.1 | Intermediate |
| `loops` | 2.1 | Intermediate |
| `switch_tables` | 2.1 | Intermediate |
| `indirect_jumps` | 2.1 | Intermediate |
| `decompiler_output` | 2.2 | Intermediate |
| `type_recovery` | 2.2 | Intermediate |
| `variable_naming` | 2.2 | Intermediate |
| `decompiler_artefacts` | 2.2 | Intermediate |
| `pseudocode_reading` | 2.2 | Intermediate |
| `packing_purpose` | 2.3 | Intermediate |
| `packer_identification` | 2.3 | Intermediate |
| `entropy_analysis` | 2.3 | Intermediate |
| `unpacking_methods` | 2.3 | Intermediate |
| `oep_concept` | 2.3 | Intermediate |
| `crypto_constants` | 2.4 | Intermediate |
| `xor_encryption` | 2.4 | Intermediate |
| `rc4_pattern` | 2.4 | Intermediate |
| `aes_pattern` | 2.4 | Intermediate |
| `key_identification` | 2.4 | Intermediate |
| `iv_identification` | 2.4 | Intermediate |
| `capa_rules` | 2.5 | Intermediate |
| `attack_techniques` | 2.5 | Intermediate |
| `capability_validation` | 2.5 | Intermediate |
| `behavioural_indicators` | 2.5 | Intermediate |
| `false_positives` | 2.5 | Intermediate |
| `reaching_definitions` | 3.1 | Advanced |
| `def_use_chains` | 3.1 | Advanced |
| `control_dependencies` | 3.1 | Advanced |
| `constant_propagation` | 3.1 | Advanced |
| `backward_slice` | 3.1 | Advanced |
| `forward_slice` | 3.1 | Advanced |
| `value_set_analysis` | 3.1 | Advanced |
| `emulation_vs_execution` | 3.2 | Advanced |
| `api_hooking` | 3.2 | Advanced |
| `memory_inspection` | 3.2 | Advanced |
| `symbolic_execution` | 3.2 | Advanced |
| `watchpoints` | 3.2 | Advanced |
| `qiling_vs_speakeasy` | 3.2 | Advanced |
| `anti_debug` | 3.3 | Advanced |
| `anti_vm` | 3.3 | Advanced |
| `timing_checks` | 3.3 | Advanced |
| `tls_callbacks` | 3.3 | Advanced |
| `obfuscation_techniques` | 3.3 | Advanced |
| `control_flow_flattening` | 3.3 | Advanced |
| `string_encryption` | 3.3 | Advanced |
| `c2_config_patterns` | 3.4 | Advanced |
| `config_storage` | 3.4 | Advanced |
| `encryption_layers` | 3.4 | Advanced |
| `extraction_methodology` | 3.4 | Advanced |
| `validation` | 3.4 | Advanced |
| `manual_oep_recovery` | 4.1 | Expert |
| `multi_layer_packing` | 4.1 | Expert |
| `process_hollowing` | 4.1 | Expert |
| `dotnet_obfuscators` | 4.1 | Expert |
| `pe_reconstruction` | 4.1 | Expert |
| `emulation_based_dumping` | 4.1 | Expert |
| `network_protocols` | 4.2 | Expert |
| `serialization_formats` | 4.2 | Expert |
| `command_dispatch` | 4.2 | Expert |
| `session_management` | 4.2 | Expert |
| `custom_encodings` | 4.2 | Expert |
| `yara_syntax` | 4.3 | Expert |
| `byte_patterns` | 4.3 | Expert |
| `string_selection` | 4.3 | Expert |
| `condition_logic` | 4.3 | Expert |
| `false_positive_avoidance` | 4.3 | Expert |
| `rule_testing` | 4.3 | Expert |
| `binary_diffing` | 4.4 | Expert |
| `similarity_hashing` | 4.4 | Expert |
| `variant_evolution` | 4.4 | Expert |
| `infrastructure_tracking` | 4.4 | Expert |
| `multi_sample_workflows` | 4.4 | Expert |
| `attribution` | 4.4 | Expert |
