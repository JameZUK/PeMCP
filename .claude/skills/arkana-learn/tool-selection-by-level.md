# Guided Analysis — Tool Selection by Level

## Foundation learner — use these tools, explain everything
| Step | Tool | What to teach |
|------|------|---------------|
| Load | `open_file()` | Binary format detection, file hashes |
| Triage | `get_triage_report(compact=True)` | Risk assessment, what indicators mean |
| Classify | `classify_binary_purpose()` | Binary types (GUI, CLI, DLL, driver) |
| Strings | `get_strings_summary()` | String categories, operational significance |
| Imports | `get_focused_imports()` | Import table, suspicious combinations |
| Structure | `get_section_permissions()` | Sections, permissions, entropy |

## Intermediate learner — add decompilation and deeper analysis
| Step | Tool | What to teach |
|------|------|---------------|
| Functions | `get_function_map(limit=15)` | Function ranking, targeting analysis |
| CFG | `get_function_cfg(address)` | Control flow, basic blocks |
| Decompile | `decompile_function_with_angr(address)` | Reading pseudocode (paginated — use `line_offset`; use `search="pattern"` to grep) |
| Capabilities | `get_capa_analysis_info()` | ATT&CK mapping, validation |
| Packing | `detect_packing()` | Packing detection, unpacking cascade |
| Crypto | `identify_crypto_algorithm()` | Crypto pattern recognition |

## Advanced learner — add data flow and emulation
| Step | Tool | What to teach |
|------|------|---------------|
| Data flow | `get_reaching_definitions(addr)` | Variable origin tracing |
| Slicing | `get_backward_slice(addr, var)` | Key/data origin analysis |
| Emulation | `emulate_binary_with_qiling()` | Dynamic behaviour |
| Hooks | `qiling_hook_api_calls(hooks)` | Runtime monitoring |
| Anti-debug | `find_anti_debug_comprehensive()` | Evasion techniques |

## Expert learner — peer-level discussion, minimal hand-holding
| Step | Tool | What to teach |
|------|------|---------------|
| All tools as needed | — | Focus on methodology, edge cases, trade-offs |
| Manual unpacking | `find_oep_heuristic()` + emulation | OEP recovery |
| C2 extraction | extraction cascade | Full evidence chain |
| YARA | `search_yara_custom()` | Rule authoring from findings |
