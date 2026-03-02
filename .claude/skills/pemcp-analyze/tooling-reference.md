# PeMCP Tool Reference

Complete catalog of all 178 MCP tools organized by use case.
Source files: `pemcp/mcp/tools_*.py`

---

## Tool Selection: Prefer / Avoid

| Instead of... | Prefer... | Why |
|---|---|---|
| `get_full_analysis_results()` | `get_pe_data(key='...')` | Full dump can exceed 64KB limit; targeted queries are faster |
| `extract_strings_from_binary()` | `get_strings_summary()` | Raw dumps are noisy; summary categorizes by type (URLs, IPs, paths) |
| `get_pe_data(key='imports')` for security | `get_focused_imports()` | Focused imports categorizes by threat behavior |
| `get_function_map(limit=100)` | `get_function_map(limit=20-30)` | Too many functions overwhelms context; start small, expand if needed |
| Calling `get_analysis_digest()` repeatedly | Call at phase transitions | Digest has overhead; use it strategically |
| `get_notes()` to check findings | `get_analysis_digest()` | Digest aggregates notes with triage data and coverage |
| `get_hex_dump()` + `refinery_xor(data_hex=...)` | `refinery_xor(file_offset=..., length=...)` | Single step; avoids hex-encoding large blobs |
| Extracting payload without `output_path` | `refinery_xor/pipeline/carve(..., output_path=...)` | Saves to disk AND registers as artifact with hashes and type detection |
| Writing a Python crypto script (RC4, XOR, AES) | `refinery_pipeline` / `refinery_decrypt` | Internal tools are logged, reproducible, auditable |
| Repeated single-item tool calls (e.g., 50× `get_string_at_va`) | Batch parameters (`data_hex_list`, `virtual_addresses`, `function_addresses`, `rule_ids`) | Single call, cleaner history, per-item error isolation |

---

## Loading & Sample Management

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `open_file` | Loading any binary for analysis | `file_path` |
| `close_file` | Done with current file, loading another | — |
| `reanalyze_loaded_pe_file` | Need fresh analysis after patching | — |
| `list_samples` | Browsing available samples in /samples | — |
| `detect_binary_format` | File type unknown, need magic byte detection | — |

## Environment & Configuration

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_config` | **First call** — discover libraries, paths, container mode | — |
| `get_current_datetime` | Need timestamp for notes or reports | — |
| `check_task_status` | Checking background task completion | `task_id` |
| `set_api_key` | Configuring VT or other API keys | `service`, `key` |

## Triage & Risk Assessment

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_triage_report` | **Second call** — comprehensive automated triage | `compact=True` (default) |
| `classify_binary_purpose` | Determine binary type (GUI, DLL, driver, service) | — |
| `get_virustotal_report_for_loaded_file` | Check community reputation | — |
| `get_analyzed_file_summary` | Quick summary without full triage | — |
| `get_capa_analysis_info` | CAPA capability analysis overview | — |
| `get_capa_rule_match_details` | Detailed match info for a specific capa rule | `rule_name` |
| `get_extended_capabilities` | Extended capability detection beyond capa | — |

## PE Structure

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_pe_data` | Specific PE field needed | `key`: imports, exports, sections, tls_info, digital_signature, yara_matches, header, debug, resources, relocations, rich_header |
| `get_focused_imports` | Security-relevant imports only | `category` (optional filter) |
| `get_full_analysis_results` | Complete PE analysis dump | — |
| `get_section_permissions` | Check section R/W/X flags | — |
| `get_pe_metadata` | Extended metadata (timestamps, linker, compiler) | — |
| `get_load_config_details` | Load config directory (SEH, CFG, guard) | — |
| `extract_resources` | Extract PE resource data | `resource_type` (optional) |
| `extract_manifest` | Extract embedded manifest XML | — |
| `get_import_hash_analysis` | Imphash, section hash analysis | — |
| `parse_binary_with_lief` | Cross-format PE/ELF/Mach-O parsing via LIEF | — |
| `modify_pe_section` | Modify section content for patching | `section_name`, `data` |

## Multi-Format Analysis

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `elf_analyze` | Analyzing ELF binaries | — |
| `elf_dwarf_info` | Extracting DWARF debug symbols from ELF | — |
| `macho_analyze` | Analyzing Mach-O binaries | — |
| `dotnet_analyze` | .NET assembly analysis (dnfile + dotnetfile fallback) | — |
| `dotnet_disassemble_method` | Disassemble specific .NET CIL method | `method_name` |
| `go_analyze` | Go binary analysis (packages, version) | — |
| `rust_analyze` | Rust binary metadata | — |
| `rust_demangle_symbols` | Demangle Rust symbol names | — |

## String Analysis

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_strings_summary` | Categorized string overview (URLs, IPs, paths) | — |
| `extract_strings_from_binary` | Raw string extraction | `min_length`, `encoding` |
| `extract_wide_strings` | Unicode/wide string extraction | — |
| `search_for_specific_strings` | Search for known string patterns | `patterns` |
| `fuzzy_search_strings` | Approximate string matching | `query`, `threshold` |
| `get_top_sifted_strings` | ML-ranked strings by relevance (StringSifter) | `limit` |
| `get_strings_for_function` | Strings referenced by a specific function | `address` |
| `get_string_usage_context` | Disassembly context around a string reference | `string_value` |
| `get_string_at_va` | Read string at specific virtual address | `address` |
| `get_floss_analysis_info` | FLOSS decoded/stacked strings | — |
| `search_floss_strings` | Regex search against FLOSS results | `pattern` |
| `search_yara_custom` | Custom YARA rule scanning | `rule` |
| `detect_format_strings` | Find printf-style format strings (vuln audit) | — |

## Decompilation & Disassembly

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `decompile_function_with_angr` | Get C-like pseudocode for a function | `address` |
| `get_annotated_disassembly` | Disassembly with variable names and xrefs | `address` |
| `disassemble_at_address` | Raw disassembly at arbitrary address | `address`, `count` |
| `disassemble_raw_bytes` | Disassemble arbitrary byte sequences | `bytes`, `arch` |
| `get_function_map` | List functions ranked by interestingness | `limit` (default 20) |
| `get_function_complexity_list` | Functions sorted by cyclomatic complexity | — |
| `get_function_cfg` | Control flow graph for a function | `address` |
| `get_function_xrefs` | Cross-references (callers + callees) | `address` |
| `get_cross_reference_map` | Batch cross-reference lookup | `function_addresses` |
| `get_function_variables` | Stack and register variables | `address` |
| `get_calling_conventions` | Recovered calling conventions and params | `address` |
| `identify_library_functions` | Identify standard library functions | — |
| `extract_function_constants` | Constant values used in a function | `address` |
| `get_global_data_refs` | Global data references across binary | — |
| `scan_for_indirect_jumps` | Find jump tables, vtables, indirect calls | — |
| `identify_cpp_classes` | C++ class structure identification | — |
| `get_call_graph` | Inter-procedural call graph from a function | `address` |

## Data Flow Analysis

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_reaching_definitions` | Track where variable values come from | `address` |
| `get_data_dependencies` | Def-use chains within a function | `address` |
| `get_control_dependencies` | Which conditions control which blocks | `address` |
| `propagate_constants` | Resolve constant values through computation | `address` |
| `get_value_set_analysis` | Pointer target tracking | `address` |
| `get_backward_slice` | Trace data origin backward from a point | `address`, `variable` |
| `get_forward_slice` | Trace data propagation forward | `address`, `variable` |
| `get_dominators` | Dominator tree for CFG analysis | `address` |
| `analyze_binary_loops` | Loop detection and analysis | — |

## Emulation

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `emulate_function_execution` | Execute a single function with concrete args | `address`, `args` |
| `emulate_binary_with_qiling` | Full binary emulation with API tracking | `timeout`, `rootfs` |
| `emulate_shellcode_with_qiling` | Shellcode emulation (x86/x64/ARM/MIPS) | `shellcode`, `arch` |
| `qiling_trace_execution` | Detailed API call tracing during emulation | — |
| `qiling_hook_api_calls` | Hook specific APIs in Qiling emulation | `api_names` |
| `qiling_dump_unpacked_binary` | Dump unpacked binary from emulation memory | — |
| `qiling_resolve_api_hashes` | Resolve API hash constants to names | — |
| `qiling_memory_search` | Search emulation memory for patterns/strings | `pattern` |
| `qiling_setup_check` | Verify Qiling rootfs setup | — |
| `emulate_pe_with_windows_apis` | PE emulation with Windows API sim (Speakeasy) | — |
| `emulate_shellcode_with_speakeasy` | Shellcode with Speakeasy | `shellcode`, `arch` |
| `emulate_with_watchpoints` | Emulation with memory/register breakpoints | `address`, `watchpoints` |
| `find_path_to_address` | Symbolic execution to find reaching inputs | `target_address` |
| `find_path_with_custom_input` | Path finding with custom constraints | `target`, `constraints` |

## Cryptography

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `identify_crypto_algorithm` | Detect crypto constants and algorithm signatures | — |
| `auto_extract_crypto_keys` | Automatically extract embedded crypto keys | — |
| `brute_force_simple_crypto` | Brute-force simple ciphers (XOR, Caesar, SUB) | `data`, `method` |
| `detect_crypto_constants` | Scan for known crypto S-boxes and constants | — |

## Deobfuscation

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `find_and_decode_encoded_strings` | Decode Base64/hex/XOR obfuscated strings | — |
| `deobfuscate_base64` | Decode hex-encoded Base64 data | `data` |
| `deobfuscate_xor_single_byte` | Single-byte XOR decryption | `data`, `key` |
| `deobfuscate_xor_multi_byte` | Multi-byte XOR decryption | `data`, `key` |
| `brute_force_simple_crypto` | Brute-force XOR/RC4/ADD/SUB/ROL/ROR with known-plaintext support | `data_hex`, `known_plaintext` |
| `is_mostly_printable_ascii` | Check if data is mostly printable | `data` |
| `get_hex_dump` | Hex dump of a binary region | `offset`, `length` |

## Binary Refinery — Encoding & Decoding

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_codec` | Encode/decode (base64, hex, url, utf8, etc.) | `data`, `operation`, `codec` |
| `refinery_xor` | XOR with known key; can read slices from loaded file and save output | `data_hex` or `file_offset`+`length`, `key_hex`, `output_path` |
| `refinery_auto_decrypt` | Auto-detect and decrypt XOR/SUB patterns | `data` |
| `refinery_decompress` | Decompress gzip/bzip2/lz4/zlib/lzma | `data`, `algorithm` |
| `refinery_hash` | Compute MD5/SHA1/SHA256/ssdeep/imphash | `data`, `algorithm` |
| `refinery_string_operations` | String manipulation (trim, split, case) | `data`, `operation` |
| `refinery_pretty_print` | Pretty-print JSON/XML/hex/structures | `data`, `format` |

## Binary Refinery — Encryption

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_decrypt` | AES/RC4/DES/ChaCha20/Blowfish decryption | `data`, `algorithm`, `key`, `iv` |
| `refinery_key_derive` | Key derivation (PBKDF2, scrypt, etc.) | `password`, `algorithm` |

## Binary Refinery — Carving & Extraction

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_carve` | Carve embedded files from binary data; save carved items to disk | `data`, `pattern`, `output_path` |
| `refinery_extract` | Extract from archives/containers | `data`, `format` |
| `refinery_regex_extract` | Extract data matching regex patterns | `data`, `pattern` |
| `refinery_regex_replace` | Find and replace with regex | `data`, `pattern`, `replacement` |
| `refinery_extract_iocs` | Extract IOCs via refinery patterns | `data` |
| `refinery_extract_domains` | Extract domain names from data | `data` |

## Binary Refinery — .NET

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_dotnet` | .NET resource extraction, deobfuscation | `data`, `operation` |

## Binary Refinery — Executable & Forensic

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_executable` | Executable analysis operations via refinery | `data`, `operation` |
| `refinery_forensic` | Forensic analysis via refinery | `data`, `operation` |
| `refinery_pe_operations` | PE repair, overlay extraction, rebuilding | `data`, `operation` |

## Binary Refinery — Script Deobfuscation

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_deobfuscate_script` | Deobfuscate batch/PowerShell/VBS scripts | `data`, `script_type` |
| `refinery_decompile` | Decompile code/scripts via refinery | `data` |

## Binary Refinery — Utilities

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_pipeline` | Chain multiple refinery operations (encoding, compression, crypto, slicing, bitwise, padding); supports batch mode (`data_hex_list` up to 100 items) and file offset input | `data_hex` or `file_offset`+`length`, `steps`, `output_path`, `data_hex_list` (batch) |
| `refinery_list_units` | List all available refinery units | `category` (optional) |

## Payload & Config Extraction

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `extract_config_automated` | Auto-extract C2 configurations | — |
| `extract_steganography` | Detect data hidden after image EOF | — |
| `parse_custom_container` | Parse custom malware container formats | `format_hint` |
| `scan_for_embedded_files` | Detect nested PE/ZIP/PDF/scripts | — |
| `detect_compression_headers` | Find compression/archive headers in data | — |
| `extract_config_for_family` | KB-driven config extraction for a confirmed malware family | `family`, `section_hint` (optional), `offset_hint` (optional) |
| `parse_binary_struct` | Parse binary data according to a typed field schema (ints, strings, IPs) | `schema`, `data_hex` or `file_offset`+`length` |

## Unpacking

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `auto_unpack_pe` | Known packers (UPX, ASPack, Themida, etc.) | — |
| `try_all_unpackers` | Orchestrate multiple unpacking methods | — |
| `find_oep_heuristic` | Find original entry point heuristically | — |
| `reconstruct_pe_from_dump` | Rebuild PE from memory dump | `dump_data`, `oep` |
| `detect_packing` | Detect packing/compression indicators | — |

## IOC Extraction

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_iocs_structured` | Aggregate IOCs into STIX/OpenIOC/JSON | `format` |
| `refinery_extract_iocs` | IOC extraction via refinery patterns | `data` |
| `refinery_extract_domains` | Domain extraction from data | `data` |
| `scan_for_api_hashes` | Scan for API hash constants used by shellcode/malware (ror13, djb2, crc32, fnv1a); supports `family_hint` for KB-driven config | `hash_algorithm`, `seed`, `family_hint`, `include_extended_db` |

## Binary Modification & Patching

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `patch_binary_memory` | Patch binary memory/sections | `address`, `data` |
| `patch_with_assembly` | Patch with assembled instructions | `address`, `instructions` |
| `assemble_instruction` | Assemble instructions to bytes | `instructions`, `arch` |
| `modify_pe_section` | Modify PE section content | `section_name`, `data` |
| `save_patched_binary` | Save patched binary to disk | `output_path` |

## Comparison & Diffing

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `diff_binaries` | Compare two binaries (matching/differing functions) | `file_path_2` |
| `diff_payloads` | Byte-by-byte comparison of two payloads | `payload_1`, `payload_2` |
| `compute_similarity_hashes` | ssdeep/TLSH/imphash similarity hashes | — |
| `compare_file_similarity` | Compare two files for similarity scores | `file_path_2` |

## Anti-Analysis Detection

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `find_anti_debug_comprehensive` | Comprehensive anti-debug technique detection | — |
| `detect_self_modifying_code` | Detect self-modifying code patterns | — |
| `find_code_caves` | Find executable gaps in code sections | — |

## Hooking (Emulation Control)

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `hook_function` | Hook a function for emulation/symbolic execution | `address`, `handler` |
| `list_hooks` | List all active function hooks | — |
| `unhook_function` | Remove a function hook | `address` |
| `list_angr_analyses` | List all available angr analysis types | — |

## Session, Notes & History

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `add_note` | Record a finding or observation | `content`, `category` |
| `get_notes` | Retrieve all notes for current file | — |
| `update_note` | Edit an existing note | `note_id`, `content` |
| `delete_note` | Remove a note | `note_id` |
| `auto_note_function` | Auto-generate behavioral summary for function | `address` |
| `get_tool_history` | Review tools run during session | — |
| `clear_tool_history` | Clear tool history | — |
| `get_analysis_timeline` | Timeline of analysis activities | — |
| `get_session_summary` | Comprehensive session summary | — |

## Analysis Progress & Guidance

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_analysis_digest` | Aggregated findings summary (call at phase transitions) | — |
| `get_progress_overview` | Analysis coverage and gaps | — |
| `suggest_next_action` | AI-suggested next analysis steps | — |
| `list_tools_by_phase` | Tools organized by workflow phase | — |

## Reporting & Export

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `generate_analysis_report` | Generate comprehensive formatted report | `format` |
| `auto_name_sample` | Generate descriptive filename from findings | — |
| `export_project` | Export portable project archive (includes artifacts up to 50 MB) | `output_path` |
| `import_project` | Import a project archive (restores artifacts to ~/.pemcp/imported/artifacts/) | `project_path` |

## Cache Management

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_cache_stats` | Check disk cache usage statistics | — |
| `clear_analysis_cache` | Clear entire analysis cache | — |
| `remove_cached_analysis` | Remove specific cached analysis | `sha256` |

## Malware Family Identification

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `identify_malware_family` | After decompiling API hash routines, finding config encryption, or identifying distinctive constants — matches evidence against 123-family knowledge base | `hash_algorithm`, `hash_seed`, `hash_constants`, `config_encryption`, `config_pattern`, `compiler`, `command_count`, `network_headers`, `network_uris`, `constants`, `dll_names`, `matched_strings`, `matched_hex_patterns` |
| `list_malware_signatures` | To browse known malware families and their fingerprints before analysis, or review a specific family's full indicator profile | `family` (optional — omit for summary of all families) |
| `verify_malware_attribution` | After `identify_malware_family()` returns a candidate — confirms attribution with per-evidence pass/fail verdicts. Catches misattribution between similar families | `family` (required), plus same evidence params as `identify_malware_family` |

## Entropy Analysis

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `analyze_entropy_by_offset` | Entropy visualization by file offset | `window_size` |
