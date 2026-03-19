# Future Improvements

Proposed enhancements and feature ideas for Arkana. Items are grouped by domain and prioritised within each section. Each proposal includes a value assessment to help determine whether the added complexity justifies the benefit over manual analysis.

**Current state:** 229 MCP tools across 56 files, supporting PE/ELF/Mach-O with angr, capa, FLOSS, YARA, Binary Refinery, Qiling, and Speakeasy integrations.

**Evaluation criteria for each proposal:**
- **Value** — Does this enable analysis that's currently impossible, or just faster?
- **Uniqueness** — Do competing tools (Ghidra MCP, BinNinja MCP, IDA MCP) already offer this?
- **Complexity** — New dependencies, Docker image size, maintenance burden?
- **Frequency** — How often would a typical analyst use this?

---

## Table of Contents

1. [Context Aggregation for AI Clients](#1-context-aggregation-for-ai-clients)
2. [Symbolic Execution Extensions](#2-symbolic-execution-extensions)
3. [Taint Analysis](#3-taint-analysis)
4. [Vulnerability Pattern Detection](#4-vulnerability-pattern-detection)
5. [Frida Script Generation](#5-frida-script-generation)
6. [Control Flow Deobfuscation](#6-control-flow-deobfuscation)
7. [.NET Deobfuscation & Decompilation](#7-net-deobfuscation--decompilation)
8. [Expose Dashboard-Only Functions as MCP Tools](#8-expose-dashboard-only-functions-as-mcp-tools)
9. [YARA-X Backend](#9-yara-x-backend)
10. [Analysis Coverage Reporting](#10-analysis-coverage-reporting)
11. [Memory Forensics (Volatility 3)](#11-memory-forensics-volatility-3)
12. [Cross-Binary Annotation Transfer](#12-cross-binary-annotation-transfer)
13. [Struct Layout Recovery](#13-struct-layout-recovery)
14. [Multi-Binary Campaign Analysis](#14-multi-binary-campaign-analysis)
15. [Patching Primitives](#15-patching-primitives)
16. [Expose Unused angr Analyses](#16-expose-unused-angr-analyses)
17. [Qiling Snapshots & Interactive Debugging](#17-qiling-snapshots--interactive-debugging)
18. [FLIRT Signature Matching](#18-flirt-signature-matching)

---

## 1. Context Aggregation for AI Clients ✅ IMPLEMENTED

**Status**: Implemented in `arkana/mcp/tools_context.py` (1 tool: `get_analysis_context_for_function`)
**Priority**: High
**Complexity**: Low (uses only existing code)
**New dependencies**: None
**New tools**: ~~1~~ 1 (`get_analysis_context_for_function`)

### Problem

Analysing a single function currently requires 5-10 separate MCP tool calls: decompile, get xrefs, get strings, check suspicious APIs, read notes, check triage status, get complexity, check BSim matches. Each round-trip costs latency and context window tokens.

### Proposal

A single `get_analysis_context_for_function(address)` tool that returns a combined response:

```
{
  "decompilation": "...",          // from decompile cache or on-demand
  "xrefs": { "callers": [...], "callees": [...] },
  "strings": [...],
  "suspicious_apis": [...],        // with risk levels
  "notes": [...],
  "triage_status": "FLAG|SUS|CLN|null",
  "complexity": { "cyclomatic": N, "basic_blocks": N },
  "enrichment_score": N,
  "bsim_matches": [...]            // if signature DB exists
}
```

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | No — same data, fewer calls |
| **Speed improvement** | High — 1 call vs 5-10 |
| **Uniqueness** | Moderate — Ghidra MCP has a similar aggregate function |
| **Complexity cost** | Minimal — thin wrapper over existing functions |
| **Frequency of use** | Very high — every function investigation |
| **Alternative** | AI calls each tool separately (works, just slower) |

### Implementation

- New function in `tools_angr.py` or a new `tools_context.py`
- Calls existing internal functions: `_decompile_cached()`, `state.get_function_xrefs()`, `get_strings_for_function()`, etc.
- Respects existing response truncation and pagination
- Dashboard's `get_function_analysis_data()` in `state_api.py` already does something similar — could share logic

---

## 2. Symbolic Execution Extensions ✅ IMPLEMENTED

**Status**: Implemented in `arkana/mcp/tools_angr.py` (2 tools: `solve_constraints_for_path`, `explore_symbolic_states`)
**Priority**: High
**Complexity**: Medium
**New dependencies**: None (angr already available)
**New tools**: ~~2-3~~ 2

### Problem

Arkana exposes `find_path_to_address` and `find_path_with_custom_input`, but these are high-level wrappers. Analysts need finer control: what concrete inputs satisfy branch constraints? What constraints exist along a specific path? What states does the exploration produce?

### Proposal

**Tool A: `solve_constraints_for_path`**
- Given start address + target address, find concrete input values satisfying all branch constraints
- Return solved input bytes/values in a structured format
- Primary use case: CTF challenges, vulnerability research ("what input reaches this dangerous `system()` call?")

**Tool B: `explore_symbolic_states`**
- Expose angr's exploration strategies (DFS, BFS, directed) with configurable find/avoid address sets
- Return satisfying states with their constraints and solved values
- Include timeout, state explosion limits, and step counting

**Tool C: `get_path_constraints`** (optional)
- For a given execution path, extract and display all branch constraints in human-readable form
- Useful for understanding why certain paths are taken

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Yes — automated constraint solving is impossible manually |
| **Uniqueness** | High — no competing MCP server exposes symbolic execution |
| **Complexity cost** | Medium — angr's API is well-understood but state explosion needs careful management |
| **Frequency of use** | Medium — CTFs, vuln research, understanding specific code paths |
| **Alternative** | Write custom angr scripts (high skill barrier) |

### Risks

- State explosion can cause OOM or hang — needs aggressive timeouts and state limits
- angr's symbolic execution doesn't work well on all binaries (large, obfuscated, or self-modifying code)
- Results can be hard to interpret without RE experience

### Implementation

- New tools in `tools_angr.py` or `tools_angr_symbolic.py`
- Background task pattern (like existing `find_path_to_address`)
- State count limits, memory caps, and timeouts mandatory
- Return `SimState.solver.eval()` results as hex/int/bytes

---

## 3. Taint Analysis ⚡ PARTIALLY IMPLEMENTED

**Status**: Partially implemented via `find_dangerous_data_flows` in `arkana/mcp/tools_vuln.py` (1 tool). Full angr RDA-based taint tracking (Tools B and C) remains unimplemented.
**Priority**: High
**Complexity**: Medium-High
**New dependencies**: None (built on angr's RDA)
**New tools**: ~~2-3~~ 1 implemented, 2 remaining

### Problem

Arkana has `get_reaching_definitions` and `get_data_dependencies` but these return raw dataflow results. Analysts need higher-level questions answered: "Does user input reach a dangerous function?" "Where does the return value of `recv()` end up?"

### Proposal

**Tool A: `find_dangerous_data_flows`** ✅ IMPLEMENTED
- Traces data flow from known input sources (recv, read, scanf, argv, etc.) to dangerous sinks (system, strcpy, sprintf, memcpy, WinExec, etc.) across decompiled functions
- Returns ranked source-sink pairs with propagation paths and confidence scores
- Pattern-based approach using decompiled code (not full angr RDA)

**Tool B: `find_tainted_sinks`**
- Automatic mode: identify common source-sink pairs without manual source specification
- Use angr's RDA + known API signatures from `_category_maps.py`
- Return ranked list of potential vulnerabilities with source→sink paths

**Tool C: `get_def_use_chains`** (optional)
- Present reaching definition data as actionable use-def and def-use chains
- Structured, navigable format rather than raw RD analysis output

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Partially — possible manually by reading decompiled code, but automated taint tracking catches paths humans miss |
| **Uniqueness** | High — no competing MCP server offers taint analysis |
| **Complexity cost** | Medium-High — angr's RDA can be slow/incomplete on complex binaries |
| **Frequency of use** | Medium — vulnerability hunting, understanding data flow in malware |
| **Alternative** | Manually trace data flow through decompiled code (error-prone, slow) |

### Risks

- angr's RDA may not complete on large or complex functions
- False positives: not all paths are actually reachable at runtime
- Taint tracking through memory (heap, global variables) is inherently imprecise
- Performance: may need to be a background task with timeout

### Implementation

- `find_dangerous_data_flows` provides pattern-based source-to-sink tracing via decompiled code
- Full RDA-based taint tracking (Tools B and C) would build on existing `get_reaching_definitions` infrastructure in `tools_angr_dataflow.py`
- Known source/sink API lists already partially exist in `_category_maps.py` (CATEGORIZED_IMPORTS_DB)
- Background task pattern with progress reporting
- Cache results per function (taint sources don't change for a given binary)

---

## 4. Vulnerability Pattern Detection ✅ IMPLEMENTED

**Status**: Implemented in `arkana/mcp/tools_vuln.py` (2 tools: `scan_for_vulnerability_patterns`, `assess_function_attack_surface`)
**Priority**: Medium-High
**Complexity**: Medium
**New dependencies**: None
**New tools**: ~~2-3~~ 2

### Problem

Arkana identifies suspicious APIs via triage and `get_focused_imports`, but doesn't check whether those APIs are actually used dangerously. `CreateRemoteThread` flagged as "suspicious" is very different from `CreateRemoteThread` called with a user-controlled buffer address.

### Proposal

**Tool A: `scan_for_vulnerability_patterns`**
- Check decompiled functions for common vulnerability patterns:
  - Buffer overflow: unbounded copies (`strcpy`, `sprintf`, `gets` with no size check)
  - Format string: user-controlled format argument to `printf`/`sprintf`
  - Integer overflow: unchecked arithmetic before allocation size
  - Command injection: concatenated strings passed to `system`/`WinExec`/`ShellExecute`
- Use decompiler output + pattern matching (not full taint analysis)

**Tool B: `assess_function_attack_surface`**
- For a given function: does it process external input? Call dangerous APIs? How complex is the data flow?
- Return a risk score with explanation
- Lighter-weight than full taint analysis

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Partially — a skilled analyst spots these patterns manually in decompiled code |
| **Uniqueness** | High — no competing MCP server offers vulnerability-focused analysis |
| **Complexity cost** | Medium — pattern matching on decompiler output, not full formal analysis |
| **Frequency of use** | Medium — vuln research, audit, understanding exploit potential of malware |
| **Alternative** | Read decompiled code and manually identify dangerous patterns |

### Risks

- False positives from pattern matching (e.g., `strcpy` with a known-bounded source)
- angr's decompiler output isn't always accurate — false patterns possible
- Risk of overconfidence in automated findings (analyst still needs to verify)

### Implementation

- New `tools_vuln.py` module
- Operates on cached decompilation output (text pattern matching + AST analysis if available)
- Leverage existing `CATEGORIZED_IMPORTS_DB` for dangerous API identification
- Return structured findings with confidence levels and evidence snippets

---

## 5. Frida Script Generation ✅ IMPLEMENTED

**Status**: Implemented in `arkana/mcp/tools_frida.py` (3 tools: `generate_frida_hook_script`, `generate_frida_bypass_script`, `generate_frida_trace_script`)
**Priority**: Medium-High
**Complexity**: Low
**New dependencies**: None (generates JS code, doesn't run Frida)
**New tools**: ~~2-3~~ 3

### Problem

Analysts frequently need to transition from static analysis to dynamic instrumentation. Writing Frida scripts manually requires knowledge of the Frida JS API and the binary's internals. Arkana already knows the binary's suspicious APIs, anti-debug techniques, and function signatures.

### Proposal

**Tool A: `generate_frida_hook_script`**
- Given a function address or API name, generate a Frida JS hook script
- Log arguments (with known API signatures for readable output), return values, and call stacks
- Pre-populate with type-aware argument formatting for common APIs

**Tool B: `generate_frida_bypass_script`**
- For detected anti-debug/anti-analysis techniques (from `find_anti_debug_comprehensive`), generate bypass hooks
- E.g., hook `IsDebuggerPresent` to return 0, `NtQueryInformationProcess` to hide debugger, timing checks to return consistent values

**Tool C: `generate_frida_trace_script`** (optional)
- Generate comprehensive tracing script for all suspicious APIs identified by triage
- Group hooks by category (crypto, network, process, registry, file)

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | No — analyst could write these scripts manually |
| **Speed improvement** | High — generating correct Frida hooks manually takes 10-30 minutes per function |
| **Uniqueness** | High — no competing MCP server generates instrumentation scripts |
| **Complexity cost** | Low — pure template-based code generation |
| **Frequency of use** | Medium — every time an analyst needs to move from static to dynamic |
| **Alternative** | Write Frida scripts manually or use generic templates |

### Risks

- Generated scripts may not work on all targets (architecture, runtime version)
- API signatures may be incomplete — scripts might log raw hex instead of parsed arguments
- Risk of generating scripts that crash the target process

### Implementation

- New `tools_frida.py` module (or section in `tools_new_libs.py`)
- Template library of Frida JS snippets per API category
- Use `get_focused_imports` and `find_anti_debug_comprehensive` results as input
- No Frida dependency — generates standalone `.js` files registered as artifacts

---

## 6. Control Flow Deobfuscation ⚡ PARTIALLY IMPLEMENTED

**Status**: Detection implemented (Tools A and C) in `arkana/mcp/tools_vuln.py` (2 tools: `detect_control_flow_flattening`, `detect_opaque_predicates`). Deobfuscation (Tool B) remains unimplemented.
**Priority**: Medium
**Complexity**: High
**New dependencies**: None
**New tools**: ~~2-3~~ 2 implemented, 1 remaining (research-grade)

### Problem

Control flow flattening (CFF) is the dominant commercial obfuscation technique (OLLVM, Themida, VMProtect, Code Virtualizer). CFF-obfuscated functions have artificially complex CFGs that defeat decompilers — the decompiled output is an unreadable state machine.

### Proposal

**Tool A: `detect_control_flow_flattening`** ✅ IMPLEMENTED
- Analyse a function's CFG for CFF hallmarks:
  - Single-entry dispatcher block with high in-degree
  - State variable (usually a local integer) driving a switch/if-else chain
  - All real basic blocks route back to the dispatcher
- Return confidence score, dispatcher address, state variable identification

**Tool B: `deobfuscate_control_flow`** (advanced)
- Attempt to recover original control flow using angr's symbolic execution
- Determine state variable transitions by symbolically executing each case
- Return the simplified CFG with recovered edges
- Register a patched binary as an artifact (optional)

**Tool C: `detect_opaque_predicates`** ✅ IMPLEMENTED
- Identify always-true/always-false conditional branches using angr's constraint solver
- Flag branches with only one feasible path
- Useful for cleaning up dead-code insertions from obfuscators

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Yes for detection; deobfuscation enables analysis of otherwise unreadable code |
| **Uniqueness** | Very high — no MCP server offers this |
| **Complexity cost** | Detection: medium. Deobfuscation: very high (research-grade problem) |
| **Frequency of use** | Low-Medium — only when analysing obfuscated malware |
| **Alternative** | Manual analysis of CFF is extremely tedious; specialised tools like D-810 (IDA plugin) exist but aren't MCP-accessible |

### Risks

- CFF deobfuscation is an active research problem — no solution works on all obfuscators
- Symbolic execution may not scale to large functions
- False positives in detection (some legitimate code has dispatcher patterns)
- Tool B is a multi-week research project, not a straightforward implementation

### Recommendation

~~Implement Tool A (detection) first as a standalone feature.~~ Tools A and C are implemented. Tool B (deobfuscation) should be deferred until there's demonstrated demand and a proven algorithm for the target obfuscators.

### References

- [Control-Flow Deobfuscation using Trace-Informed Synthesis (ACM POPL)](https://dl.acm.org/doi/10.1145/3689789)
- [DEBRA: Real-World Benchmark for Deobfuscation (SURE 2025)](https://dl.acm.org/doi/10.1145/3733822.3764674)
- [Peephole Deobfuscation (CERT Polska 2025)](https://cert.pl/en/posts/2025/04/peephole-deobfuscation/)

---

## 7. .NET Deobfuscation & Decompilation ✅ IMPLEMENTED

**Status**: Implemented in `arkana/mcp/tools_dotnet_deobfuscate.py` (3 tools: `detect_dotnet_obfuscation`, `dotnet_deobfuscate`, `dotnet_decompile`)
**Priority**: High
**Complexity**: Medium-High
**Docker image impact**: +80-400MB (.NET runtime required)
**New tools**: ~~1-2~~ 3

### Integrate de4dot + NETReactorSlayer

Add a unified `dotnet_deobfuscate` MCP tool that automatically detects and removes .NET obfuscation, covering the vast majority of protectors seen in real-world malware.

**Tools to integrate:**

| Tool | Purpose | License |
|------|---------|---------|
| [de4dot](https://github.com/de4dot/de4dot) (active fork) | Generic .NET deobfuscator — handles ~20 obfuscators (ConfuserEx, Dotfuscator, SmartAssembly, Agile.NET, Babel, CryptoObfuscator, etc.) | GPLv3 |
| [NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) | Dedicated .NET Reactor deobfuscator — better coverage than de4dot for this specific protector | GPLv3 |

**Why these two:**
- de4dot remains the industry standard despite being archived upstream — active forks (de4dot-cex, de4dotEx) cover modern protectors like ConfuserEx2.
- NETReactorSlayer is complementary, not a replacement — .NET Reactor is common in malware and de4dot handles it poorly.
- No better alternatives exist. Other tools (AsmResolver, dnlib, dnpatch) are libraries for building tools, not standalone deobfuscators.

**Proposed architecture:**
- Both are C# CLI tools requiring .NET runtime — no Python venv needed, but needs `dotnet-runtime` in the Docker image.
- Follow the existing subprocess runner pattern (like Speakeasy/Qiling/Unipacker): thin Python runner script invokes `dotnet de4dot.dll` or `dotnet NETReactorSlayer.CLI.dll`, parses stdout, returns JSON.
- Single MCP tool `dotnet_deobfuscate(method="auto"|"de4dot"|"reactor_slayer")` mirrors the `try_all_unpackers` orchestration pattern — try de4dot first, fall back to NETReactorSlayer.
- Output file registered via `state.register_artifact()`, can be immediately re-analysed with `open_file()` + `dotnet_analyze` + `refinery_dotnet`.
- Availability check in `imports.py` via `_check_de4dot_available()`.

**Implementation steps:**
1. Dockerfile: add `dotnet-runtime-8.0` (or trimmed), download de4dot + NETReactorSlayer release binaries to `/app/de4dot/` and `/app/netreactorslayer/`.
2. Runner script: `scripts/de4dot_runner.py` — accepts JSON command on stdin, invokes CLI, returns JSON result on stdout.
3. MCP tool: `dotnet_deobfuscate` in `tools_dotnet.py` — orchestrates both tools, registers output artifact.
4. Config: add paths and availability flags to `config.py` / `imports.py`.
5. Tests: unit test for runner JSON protocol, integration test with a known obfuscated .NET sample.

**Optional follow-up:** Add `ilspycmd` (ILSpy CLI) as a separate `dotnet_decompile` tool for full C# source recovery beyond CIL disassembly. Pairs well with deobfuscation — deobfuscate first, then decompile to readable C#.

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Yes — obfuscated .NET binaries are currently opaque to Arkana's CIL tools |
| **Uniqueness** | High — no competing MCP server integrates .NET deobfuscation |
| **Complexity cost** | Medium-High — .NET runtime in Docker, subprocess management |
| **Frequency of use** | High — .NET malware (AsyncRAT, Agent Tesla, RedLine, etc.) is extremely common |
| **Alternative** | Run de4dot manually outside Arkana, then re-open the cleaned binary |

### References

- [.NET Deobfuscator list](https://github.com/NotPrab/.NET-Deobfuscator)
- [.NET Deobfuscation techniques (cyber.wtf)](https://cyber.wtf/2025/04/07/dotnet-deobfuscation/)
- [ILSpy/ILSpyCmd](https://github.com/icsharpcode/ILSpy)

---

## 8. Expose Dashboard-Only Functions as MCP Tools ✅ IMPLEMENTED

**Status**: Implemented in `arkana/mcp/tools_dashboard_exposed.py` (3 tools: `search_decompiled_code`, `get_entropy_analysis`, `generate_report`)
**Priority**: Medium-High
**Complexity**: Low
**New dependencies**: None
**New tools**: 3

### Problem

Several useful analysis functions exist in `dashboard/state_api.py` but are only accessible via the web dashboard. AI clients using MCP can't access them.

### Proposal

**Tool A: `search_decompiled_code`**
- Full-text regex search across all cached decompilations
- Returns matching functions with line context (like grep)
- Dashboard already has this via `/api/search-code`; needs MCP wrapper

**Tool B: `get_entropy_analysis`**
- Per-section entropy values + offset-based entropy breakdown
- Useful for detecting packed/encrypted sections programmatically
- Dashboard heatmap data (`get_entropy_data()`), not currently exposed

**Tool C: `generate_report`** (expose existing `generate_report_text()`)
- Generate the markdown analysis report currently only available via dashboard modal
- AI client could use this as a starting point and refine it

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | No — same data available via dashboard |
| **Speed improvement** | High for AI clients that don't use the dashboard |
| **Uniqueness** | N/A — internal feature |
| **Complexity cost** | Very low — thin MCP wrappers over existing functions |
| **Frequency of use** | search_decompiled_code: high. entropy: medium. report: medium |
| **Alternative** | Use the web dashboard manually |

### Implementation

- Each tool is a ~30-line MCP function calling the existing `state_api` function
- `search_decompiled_code` needs pagination (line_offset/line_limit)
- `generate_report` should return the markdown text directly (not a file)

---

## 9. YARA-X Backend

**Priority**: Medium
**Complexity**: Low-Medium
**New dependencies**: `yara-x` PyPI package
**Docker image impact**: +5-10MB
**New tools**: 1-2

### Problem

YARA-X (the Rust rewrite) reached 1.0 stable in June 2025. It's faster, has better error reporting, and is where all new YARA module development happens. VirusTotal has deprecated legacy YARA. Arkana currently uses only legacy python-yara.

### Proposal

**Tool A: `scan_with_yara_x`**
- Optional YARA-X backend alongside existing YARA support
- Python bindings available (`yara-x` on PyPI)
- Use when available, fall back to legacy YARA otherwise

**Tool B: `validate_yara_rules`** (optional)
- Use YARA-X's improved linter/validator for rules generated by `generate_yara_rule`
- Better error messages than legacy YARA

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | No — same scanning capability, better performance |
| **Speed improvement** | Moderate — YARA-X is faster on large rule sets |
| **Uniqueness** | Moderate — forward-looking, but current YARA works fine |
| **Complexity cost** | Low — API is similar to legacy YARA |
| **Frequency of use** | Every file analysis (YARA runs during triage) |
| **Alternative** | Continue using legacy YARA (works, maintained for now) |

### Risks

- Adding another dependency increases maintenance burden
- YARA-X Python bindings may have different edge-case behaviour
- Legacy YARA rules may not be 100% compatible

### Recommendation

Low urgency. Worth adding when legacy YARA becomes unmaintained, or when a YARA-X-specific feature is needed. Not a priority while legacy YARA still works.

### References

- [YARA-X 1.0.0 Stable Release (VirusTotal)](https://blog.virustotal.com/2025/06/yara-x-100-stable-release-and-its.html)
- [YARA-X GitHub](https://github.com/VirusTotal/yara-x)

---

## 10. Analysis Coverage Reporting ⚡ PARTIALLY IMPLEMENTED

**Status**: Partially implemented via the `coverage_detail` field added to `get_analysis_digest`. Per-category breakdowns (decompiled, annotated, triaged functions) are now included in the digest response. A standalone `get_analysis_coverage_report` tool and `find_interesting_unanalyzed_regions` remain unimplemented.
**Priority**: Medium
**Complexity**: Low-Medium
**New dependencies**: None
**New tools**: ~~2~~ 0 new tools (enhanced existing tool instead)

### Problem

Neither the AI nor the human analyst has a clear picture of what has and hasn't been examined. How many functions are decompiled? How much of the binary's code is covered by angr's CFG? Are there large unanalysed regions?

### Proposal

**Tool A: `get_analysis_coverage_report`** (partially covered by `get_analysis_digest` `coverage_detail`)
- Report analysis completeness:
  - Functions: identified / decompiled / annotated (renamed/noted) / triaged (FLAG/SUS/CLN) — ✅ now in `coverage_detail`
  - Code: bytes covered by CFG vs total executable sections
  - Strings: analysed (FLOSS) vs raw extraction only
  - Enrichment: which auto-enrichment phases completed
- Include list of unanalysed regions sorted by size

**Tool B: `find_interesting_unanalyzed_regions`**
- Combine entropy analysis, string presence, and instruction boundary detection
- Rank unanalysed binary regions by likely interestingness
- Help the analyst decide where to look next

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | No — but prevents missing important code regions |
| **Uniqueness** | Moderate — Ghidra MCP has "completeness scoring" |
| **Complexity cost** | Low — aggregates existing analysis state |
| **Frequency of use** | Medium — useful for thoroughness checks |
| **Alternative** | `suggest_next_action` partially covers this; `get_analysis_digest` now includes `coverage_detail` |

### Recommendation

~~Tool A overlaps significantly with `get_analysis_digest` + `get_progress_overview`. Consider enhancing those tools rather than adding a new one, unless the granularity of coverage data justifies a separate tool.~~ The `coverage_detail` enhancement to `get_analysis_digest` covers the core use case of Tool A. A standalone tool may still be warranted for byte-level CFG coverage and Tool B (unanalysed region ranking).

---

## 11. Memory Forensics (Volatility 3)

**Priority**: Medium
**Complexity**: High
**New dependencies**: volatility3 (~50MB + symbol tables)
**Docker image impact**: +100-500MB (symbol tables are large)
**New tools**: 3-4

### Problem

Memory forensics is a natural extension of binary analysis. Analysts investigating incidents often have both malware samples and memory dumps. Currently they need separate tools for each.

### Proposal

**Tool A: `analyze_memory_dump`**
- Open a memory dump (raw, ELF core, crashdump) and run basic analysis: process list, loaded modules, network connections
- Use Volatility 3's Python API

**Tool B: `extract_process_from_memory`**
- Extract a specific process's PE image from a memory dump
- Register as artifact for immediate analysis with Arkana's existing PE tools

**Tool C: `detect_injection_in_memory`**
- Run Volatility 3's malfind-equivalent: detect injected code, process hollowing, reflective DLL injection
- Cross-reference with loaded binary's characteristics

**Tool D: `scan_memory_for_iocs`**
- Search memory dump for IOCs extracted from the current binary analysis

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Yes — memory forensics is currently impossible in Arkana |
| **Uniqueness** | Very high — no competing MCP server integrates Volatility |
| **Complexity cost** | High — large dependency, symbol table management, different analysis paradigm |
| **Frequency of use** | Low-Medium — only for incident response with memory dumps |
| **Alternative** | Use Volatility 3 standalone + Arkana for extracted files |

### Risks

- Volatility 3 symbol tables are large and require internet download or pre-packaging
- Memory dump analysis is CPU/memory intensive
- Different analysis paradigm from binary file analysis — may confuse the UX
- Maintenance burden of keeping Volatility 3 + symbols up to date

### Recommendation

This is a significant scope expansion. The strongest use case is Tool B (extract process → analyse with existing tools), which bridges the two worlds. Consider implementing that single tool first rather than full Volatility integration.

### References

- [Volatility 3 GitHub](https://github.com/volatilityfoundation/volatility3)
- [Using Volatility 3 to Combat Modern Malware (RVAsec)](https://rvasec.com/rvasec-14-video-andrew-case-using-volatility-3-to-combat-modern-malware/)

---

## 12. Cross-Binary Annotation Transfer

**Priority**: Medium
**Complexity**: Medium
**New dependencies**: None (uses existing BSim + diff)
**New tools**: 1

### Problem

When analysing a new version of a previously analysed binary (e.g., updated malware variant), all function renames, notes, and type annotations must be recreated from scratch.

### Proposal

**Tool: `transfer_annotations`**
- Given a previously analysed binary (via project export or cache), match functions using BSim similarity
- Transfer renames, notes, address labels, and triage flags from the old analysis
- Report match quality per function (exact match, high confidence, low confidence, no match)

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | No — saves time on repeat analysis |
| **Uniqueness** | Moderate — Ghidra MCP has "cross-binary documentation transfer" |
| **Complexity cost** | Medium — needs reliable function matching (BSim exists) and merge logic |
| **Frequency of use** | Low-Medium — malware campaigns, firmware updates |
| **Alternative** | Re-analyse from scratch; manually re-apply renames |

### Risks

- BSim matching may produce false positives — wrong renames transferred
- Merge conflicts when functions have diverged
- Need careful UX: analyst must review transferred annotations

### Implementation

- Use existing `diff_binaries` + `query_signature_db` for matching
- Import/export project archives already exist — leverage that format
- Add confidence thresholds: auto-apply high-confidence matches, flag low-confidence for review

---

## 13. Struct Layout Recovery

**Priority**: Medium
**Complexity**: High
**New dependencies**: None
**New tools**: 1-2

### Problem

When decompiled code accesses memory through a pointer at multiple offsets (e.g., `*(ptr + 0x10)`, `*(ptr + 0x18)`, `*(ptr + 0x20)`), the analyst must manually infer the struct layout. angr has type inference capabilities that could automate this.

### Proposal

**Tool A: `recover_struct_layout`**
- Given a pointer address/variable, analyse all access patterns to infer struct fields
- Return field offsets, sizes, and inferred types (int, pointer, string pointer, etc.)
- Optionally create a custom struct definition via `create_struct`

**Tool B: `infer_function_types`** (optional)
- Analyse parameter and return value usage to infer C types
- Use angr's calling convention analysis + type propagation

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Partially — improves decompilation readability significantly |
| **Uniqueness** | Moderate — Ghidra, IDA, Binary Ninja all have this (Arkana doesn't) |
| **Complexity cost** | High — angr's type inference is less mature than competitors |
| **Frequency of use** | Medium — useful for complex data-oriented code |
| **Alternative** | Manually create struct definitions based on reading decompiled code |

### Risks

- angr's type inference accuracy is lower than Ghidra/BinNinja (2.67% vs ~15% on benchmarks)
- Results may be misleading if inference is wrong
- Significant implementation effort for uncertain quality

### Recommendation

Defer unless angr's type inference significantly improves. The existing `create_struct` + `apply_type_at_offset` tools let analysts manually define types when needed. An AI client can often infer types from decompiled code and create the struct via those existing tools.

### References

- [Benchmarking Binary Type Inference (SURE 2025)](https://sure-workshop.org/accepted-papers/2025/sure25-8.pdf)

---

## 14. Multi-Binary Campaign Analysis

**Priority**: Medium
**Complexity**: Medium
**New dependencies**: None
**New tools**: 2

### Problem

Malware analysts rarely work with single samples in isolation. Campaign analysis requires comparing multiple samples to find shared code, strings, and IOCs. Currently this requires analysing each file separately and manually correlating findings.

### Proposal

**Tool A: `compare_binaries_overview`**
- Given 2+ loaded/cached binaries, compare: shared strings, shared imports, shared constants, BSim function matches, YARA rule overlap, IOC overlap
- Return a similarity matrix and shared artifact list

**Tool B: `generate_family_yara_rule`**
- Given multiple samples from the same family, generate YARA rules targeting their shared unique characteristics
- Filter out common library code and compiler artifacts
- Return a rule that matches the family but not benign software

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Partially — possible manually but extremely tedious across many samples |
| **Uniqueness** | High — no MCP server offers multi-binary campaign tools |
| **Complexity cost** | Medium — needs multi-session state or cached analysis access |
| **Frequency of use** | Low-Medium — threat intel teams, campaign tracking |
| **Alternative** | Analyse individually + manually compare; use VT/sandbox for clustering |

### Risks

- Multi-binary analysis needs a way to reference multiple files (currently single-file sessions)
- Memory/storage requirements scale with sample count
- YARA rule generation quality is hard to validate automatically

### Implementation

- Tool A could work with the existing samples directory + cache
- Open file A, cache its analysis, open file B, compare against cache
- Tool B would use `generate_yara_rule` as a building block

---

## 15. Patching Primitives

**Priority**: Low-Medium
**Complexity**: Low
**New dependencies**: None
**New tools**: 2-3

### Problem

Arkana has `patch_binary_memory` (raw hex) and `patch_with_assembly` (keystone assembler), but common patching operations require manually crafting the right bytes. Binary Ninja's MCP server has 7 patching tools; Arkana has 2 low-level ones.

### Proposal

**Tool A: `nop_instruction_range`**
- NOP out instructions at a given address range
- Auto-detect architecture and instruction size
- Common use: disabling anti-debug checks, license verification, integrity checks

**Tool B: `patch_conditional_branch`**
- Flip a conditional branch (JZ→JNZ, JE→JNE) or force it (JZ→JMP, JZ→NOP)
- The most common binary patching operation

**Tool C: `create_patch_checkpoint`** / `revert_patch_checkpoint`** (optional)
- Save/restore binary state for undo/redo of patches
- Currently patches are permanent unless you re-open the original file

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | No — same operations possible with `patch_with_assembly` |
| **Speed improvement** | Moderate — saves looking up NOP encoding and branch opcodes |
| **Uniqueness** | Low — BinNinja MCP has these |
| **Complexity cost** | Low — simple wrappers |
| **Frequency of use** | Low — patching is uncommon in malware analysis (more common in cracking/CTF) |
| **Alternative** | Use existing `patch_with_assembly("nop")` or `patch_binary_memory` |

### Recommendation

Low priority. The existing tools are sufficient with slightly more effort. Consider implementing only if patching becomes a frequent workflow.

---

## 16. Expose Unused angr Analyses

**Priority**: Medium
**Complexity**: Medium
**New dependencies**: None
**New tools**: 2-3

### Problem

angr provides several analysis passes that Arkana doesn't expose. Some of these could provide useful insights.

### Available but unused angr analyses

| Analysis | What it does | Potential value |
|----------|-------------|-----------------|
| **DDG** (Data Dependency Graph) | More precise data dependency tracking than VFG | Foundation for taint analysis (see §3) |
| **StaticStride** | Detect memory access stride patterns | Identify loop structures, array traversals, crypto operations |
| **PointsToAnalysis** | Pointer aliasing analysis | Understand indirect calls, vtable dispatch |
| **InliningAnalyzer** | Detect inlined functions | Recover original code structure from optimised binaries |
| **RegionIdentifier** | Identify related code regions | Group related functionality |

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Mostly incremental improvements to existing analysis |
| **Uniqueness** | Low — these are standard program analysis techniques |
| **Complexity cost** | Medium — each analysis needs timeout management, result formatting, background task wrapper |
| **Frequency of use** | Low — most analysts don't need raw program analysis passes |
| **Alternative** | Existing tools (reaching definitions, data dependencies) cover most use cases |

### Recommendation

Only implement if a higher-level tool (like taint analysis) needs them as building blocks. Exposing raw angr analyses as MCP tools provides little value to analysts who aren't program analysis experts.

---

## 17. Qiling Snapshots & Interactive Debugging

**Priority**: Low-Medium
**Complexity**: Medium
**New dependencies**: None (Qiling supports this natively)
**New tools**: 2-3

### Problem

Qiling supports save/restore of emulation state (snapshots), but Arkana doesn't expose this. Analysts can't explore "what-if" branches during emulation without re-running from the start.

### Proposal

**Tool A: `qiling_save_snapshot`**
- Save current emulation state (registers, memory, file descriptors) to a named checkpoint
- Return snapshot ID and metadata (current PC, instruction count, API calls so far)

**Tool B: `qiling_restore_snapshot`**
- Restore a previously saved snapshot and continue emulation from that point
- Enables branching exploration: save before a conditional, explore both paths

**Tool C: `qiling_set_breakpoint`** (optional)
- Set a breakpoint at an address; emulation pauses and returns state when hit
- Interactive debugging without a full debugger

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Partially — branching exploration is new; breakpoints are a convenience |
| **Uniqueness** | Moderate — no other MCP server offers emulation snapshots |
| **Complexity cost** | Medium — Qiling snapshot API exists but needs state management |
| **Frequency of use** | Low — emulation is already a niche workflow |
| **Alternative** | Re-run emulation from start with different hooks/parameters |

### Risks

- Snapshot serialisation may fail for complex states (open files, network sockets)
- Memory overhead of storing multiple snapshots
- Interactive debugging model doesn't fit well with MCP's request-response pattern

### Recommendation

Low priority. The existing `emulate_binary_with_qiling` + hooks covers most use cases. Snapshots add complexity for a narrow workflow improvement.

---

## 18. FLIRT Signature Matching via python-flirt

**Priority**: Low-Medium
**Complexity**: Low
**New dependencies**: `python-flirt` PyPI package
**New tools**: 1

### Problem

Arkana uses angr's built-in FLIRT for library function identification, but the community maintains a large database of FLIRT signatures (FLIRTDB) that angr doesn't include. The `python-flirt` library provides direct access to IDA-format `.sig` files.

### Proposal

**Tool: `match_flirt_signatures`**
- Load `.sig` files from a configurable directory
- Match against the loaded binary
- Return identified functions with names and confidence
- Complement (not replace) angr's built-in FLIRT

### Value assessment

| Dimension | Assessment |
|-----------|-----------|
| **Enables new analysis?** | Incremental — more library functions identified on stripped binaries |
| **Uniqueness** | Low — Binary Ninja has WARP, IDA has FLIRT natively |
| **Complexity cost** | Low — small library, simple API |
| **Frequency of use** | Low — angr's FLIRT already covers common cases |
| **Alternative** | angr's built-in FLIRT (`identify_library_functions`) works for most binaries |

### Recommendation

Low priority unless analysts frequently encounter stripped binaries where angr's FLIRT fails but IDA-format signatures exist. The marginal improvement doesn't justify maintaining a separate signature database.

### References

- [python-flirt on PyPI](https://pypi.org/project/python-flirt/)
- [FLIRTDB Community Signatures](https://github.com/Maktm/FLIRTDB)

---

## Priority Summary

### Recommended for implementation (high value relative to complexity)

| # | Proposal | Complexity | Unique? | Frequency |
|---|----------|-----------|---------|-----------|
| 1 | ~~Context aggregation~~ ✅ | Low | Moderate | Very high |
| 8 | ~~Expose dashboard functions~~ ✅ | Low | N/A | High |
| 5 | ~~Frida script generation~~ ✅ | Low | High | Medium |
| 7 | ~~.NET deobfuscation~~ ✅ | Medium-High | High | High |
| 2 | ~~Symbolic execution extensions~~ ✅ | Medium | Very high | Medium |

### Worth discussing (moderate value, some complexity)

| # | Proposal | Complexity | Unique? | Frequency |
|---|----------|-----------|---------|-----------|
| 3 | ~~Taint analysis~~ ⚡ (partial: `find_dangerous_data_flows`) | Medium-High | High | Medium |
| 4 | ~~Vulnerability patterns~~ ✅ | Medium | High | Medium |
| 6 | ~~CFF detection~~ ⚡ (partial: detection implemented, deobfuscation deferred) | Medium | Very high | Low-Medium |
| 10 | ~~Coverage reporting~~ ⚡ (partial: `coverage_detail` in digest) | Low-Medium | Moderate | Medium |
| 14 | Multi-binary campaign | Medium | High | Low-Medium |

### Likely not worth the complexity

| # | Proposal | Why defer |
|---|----------|-----------|
| 9 | YARA-X | Legacy YARA still works; migration isn't urgent |
| 11 | Volatility 3 | Massive scope expansion for low-frequency use case |
| 13 | Struct recovery | angr's type inference is weak; manual types work |
| 15 | Patching primitives | Existing tools sufficient with minor extra effort |
| 16 | Raw angr analyses | Low value without higher-level tools using them |
| 17 | Qiling snapshots | Narrow use case, complex state management |
| 18 | python-flirt | Marginal improvement over angr's built-in FLIRT |
| 12 | Annotation transfer | Needs reliable matching; niche workflow |
