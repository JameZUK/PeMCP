# Angr Capability Gap Analysis for PeMCP

## Current State

PeMCP exposes **14 angr-powered tools** via MCP, covering decompilation, CFG extraction, symbolic execution, emulation, loop analysis, cross-references, slicing, dominators, complexity ranking, constant extraction, data references, indirect jump detection, and in-memory patching.

This review identifies angr capabilities that would be **high-value for AI-driven binary analysis** but are not yet implemented.

---

## Priority 1 — High Impact, Directly Actionable

### 1. Reaching Definitions Analysis (RDA)

**What it is:** `project.analyses.ReachingDefinitionsAnalysis` computes which variable definitions (register writes, memory stores) reach each program point. It builds def-use and use-def chains.

**Why it matters for AI analysis:** This is the single most impactful missing analysis. It enables:
- **Taint tracking** — trace where user input flows (e.g., does `recv()` data reach `memcpy()` size?)
- **Vulnerability hunting** — identify unvalidated data reaching dangerous sinks
- **Data flow understanding** — "what values can register X hold at this point?"
- **Dead code detection** — definitions that are never used

**Suggested tool:** `get_reaching_definitions(function_address, target_address=None)` — returns def-use chains for a function, optionally filtered to show what reaches a specific instruction.

**angr API:**
```python
rd = project.analyses.ReachingDefinitionsAnalysis(func, observe_all=True)
# rd.observed_results contains definitions at each program point
# rd.all_definitions contains all Definition objects
```

---

### 2. Calling Convention Recovery

**What it is:** `project.analyses.CallingConventionAnalysis` and `project.analyses.CompleteCallingConventionsAnalysis` determine function signatures — calling convention (cdecl, stdcall, fastcall, thiscall), parameter count/types, and return type.

**Why it matters for AI analysis:** When an AI decompiles and analyzes functions, understanding "this function takes 3 arguments via registers and returns a pointer" is fundamental context. Without it, the AI has to guess from decompiler output.

**Suggested tool:** `get_function_calling_conventions(function_address=None, recover_all=False)` — returns calling convention, parameter locations, and return value info for one or all functions.

**angr API:**
```python
project.analyses.CompleteCallingConventionsAnalysis(recover_variables=True)
func.calling_convention  # SimCC object
func.prototype           # SimTypeFunction with arg/return types
```

---

### 3. Variable Recovery

**What it is:** `project.analyses.VariableRecoveryFast` (or the slower `VariableRecovery`) identifies local variables, function parameters, their stack offsets, register assignments, and access patterns.

**Why it matters for AI analysis:** Transforms raw register/stack offset references into named variables. Dramatically improves the AI's ability to reason about what a function does. Also feeds into calling convention analysis and decompilation quality.

**Suggested tool:** `get_function_variables(function_address)` — returns list of recovered variables with their locations (stack offset, register), sizes, and access points.

**angr API:**
```python
vr = project.analyses.VariableRecoveryFast(func)
# func.variable_manager contains recovered variables
for var in func.variable_manager.local_variables:
    print(var.name, var.size, var.category)
```

---

### 4. Data Dependency Graph (DDG)

**What it is:** `project.analyses.DDG` builds a graph showing data dependencies between instructions — which instruction's output feeds into which instruction's input.

**Why it matters for AI analysis:** The existing backward/forward slice tools operate on *control flow* (what blocks can reach/be reached). DDG operates on *data flow* (what instruction produces the value consumed by another). This distinction is critical:
- Control flow slice: "what code paths lead here"
- Data dependency: "what computed this specific value"

An AI analyzing a crypto routine needs DDG to trace how a key value is derived from its inputs.

**Suggested tool:** `get_data_dependencies(instruction_address, direction="backward", limit=100)` — returns the chain of instructions that produce/consume values at the target.

**angr API:**
```python
ddg = project.analyses.DDG(func)
# ddg.graph is a NetworkX DiGraph of data dependencies
```

---

### 5. Disassemble Address Range

**What it is:** Lift and disassemble arbitrary bytes at any address, not tied to a known function boundary.

**Why it matters for AI analysis:** The current tools require a known function address. But AI analysts frequently need to:
- Inspect shellcode or code fragments not recognized as functions
- Examine bytes at an arbitrary offset (e.g., inside data sections that contain hidden code)
- View raw instructions around a crash address or suspicious offset

**Suggested tool:** `disassemble_at_address(address, num_instructions=20)` — returns disassembly listing with instruction bytes, mnemonic, operands.

**angr API:**
```python
block = project.factory.block(addr, num_inst=20)
for insn in block.capstone.insns:
    print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
```

---

### 6. Function Hooking for Emulation

**What it is:** `project.hook(addr, SimProcedure)` or `project.hook_symbol(name, SimProcedure)` replaces function implementations during symbolic execution or emulation.

**Why it matters for AI analysis:** The current `emulate_function_execution` and `find_path_to_address` tools run against raw binary code. When the binary calls `malloc`, `printf`, `GetProcAddress`, etc., execution either crashes or diverges wildly. Hooking lets the AI:
- Skip or stub out problematic library calls
- Replace crypto functions with identity functions to simplify analysis
- NOP out anti-debugging checks
- Provide concrete return values for external calls

**Suggested tools:**
- `hook_function(address_or_name, return_value_hex=None, nop=False)` — hook a function to return a specific value or do nothing
- `list_hooked_functions()` — show current hooks
- `unhook_function(address_or_name)` — remove a hook

**angr API:**
```python
# Return a constant
class ReturnValue(angr.SimProcedure):
    def run(self):
        return self.state.solver.BVV(value, project.arch.bits)
project.hook_symbol('malloc', ReturnValue())
# Or hook by address
project.hook(0x401000, ReturnValue())
```

---

## Priority 2 — Significant Value for Specialized Analysis

### 7. Symbolic Input Configuration

**What it is:** Configuring what is symbolic beyond just stdin — registers, memory regions, file contents, environment variables.

**Why it matters for AI analysis:** `find_path_to_address` currently only supports stdin as symbolic input. Many binaries read from files, network sockets, command-line args, or Windows API calls. An AI should be able to say "make the buffer at 0x404000 symbolic" or "make argc/argv symbolic."

**Suggested tool:** `find_path_with_symbolic_input(target_address, symbolic_memory=[], symbolic_registers=[], symbolic_files=[], ...)` — extended symbolic execution with configurable symbolic sources.

---

### 8. BinDiff (Binary Comparison)

**What it is:** `project.analyses.BinDiff` compares two binaries and identifies matching, added, removed, and modified functions.

**Why it matters for AI analysis:** Essential for:
- **Patch diffing** — comparing a patched binary to its unpatched version to understand what was fixed
- **Malware variant analysis** — comparing two malware samples to find shared/divergent code
- **Update analysis** — understanding what changed between software versions

**Suggested tool:** `diff_binaries(file_path_a, file_path_b, limit=50)` — returns matched function pairs with similarity scores, plus unmatched functions from each binary.

**angr API:**
```python
proj_a = angr.Project(path_a, auto_load_libs=False)
proj_b = angr.Project(path_b, auto_load_libs=False)
diff = proj_a.analyses.BinDiff(proj_b)
# diff.identical, diff.differing, diff.unmatched_from_a, diff.unmatched_from_b
```

---

### 9. Constant Propagation

**What it is:** `project.analyses.PropagatorAnalysis` propagates known constant values through a function, simplifying expressions and resolving indirect references.

**Why it matters for AI analysis:** Malware commonly obfuscates constants (API hashes, XOR keys, C2 addresses) by computing them through arithmetic chains. Constant propagation resolves `mov eax, 5; add eax, 3` into `eax = 8`, making the AI's job dramatically easier. Also resolves indirect call targets when the target is computable.

**Suggested tool:** `propagate_constants(function_address)` — returns simplified expressions at key program points, resolved indirect targets, and de-obfuscated constant values.

---

### 10. FLIRT Signature Matching

**What it is:** `project.analyses.FlirtAnalysis` matches functions against IDA-style FLIRT signatures to identify known library code (statically linked CRT, OpenSSL, zlib, etc.).

**Why it matters for AI analysis:** A typical statically-linked binary has hundreds of library functions mixed with application code. Without FLIRT, the AI wastes time analyzing `__security_check_cookie` or `_memcpy`. FLIRT identification lets the AI focus on application-specific code.

**Suggested tool:** `identify_library_functions(signature_dir=None, limit=100)` — returns list of functions matched to known library signatures.

**angr API:**
```python
project.analyses.FlirtAnalysis(sig_path)
# Functions in project.kb.functions now have updated names
```

---

### 11. Control Dependence Graph (CDG)

**What it is:** `project.analyses.CDG` shows which basic blocks' execution depends on which conditional branches.

**Why it matters for AI analysis:** Complements the existing dominator analysis. While dominators show "what must execute before X," CDG shows "what conditional decision controls whether X runs." For an AI analyzing an anti-analysis check like `if (IsDebuggerPresent()) exit()`, CDG directly reveals which branch governs the exit path.

**Suggested tool:** `get_control_dependencies(target_address)` — returns the conditional branches that control whether the target executes.

---

### 12. Self-Modifying Code Detection

**What it is:** `project.analyses.SelfModifyingCodeAnalysis` identifies code that writes to its own executable memory regions.

**Why it matters for AI analysis:** Common in packers, crypters, and sophisticated malware. Detecting self-modifying code early tells the AI that static analysis alone is insufficient and emulation or dynamic approaches are needed for those regions.

**Suggested tool:** `detect_self_modifying_code()` — returns list of instructions/regions that modify executable memory.

---

### 13. Code Cave Detection

**What it is:** `project.analyses.CodeCaveAnalysis` finds unused/padding regions within executable sections.

**Why it matters for AI analysis:** Useful for:
- **Injection detection** — malware often injects code into code caves
- **Patching** — identifying safe locations to insert instrumentation
- **Anomaly detection** — code caves with non-zero content may indicate tampering

**Suggested tool:** `find_code_caves(min_size=16)` — returns list of unused regions in executable sections with their sizes and contents.

---

## Priority 3 — Advanced / Niche but Valuable

### 14. Full Program Call Graph Export

**What it is:** Export the complete inter-procedural call graph (not just per-function callers/callees).

**Why it matters:** The existing `get_function_xrefs` shows one function's neighbors. A full call graph export lets the AI reason about program structure holistically — finding entry points to critical subsystems, identifying isolated components, computing call depth, etc.

**Suggested tool:** `get_call_graph(limit=500, root_address=None)` — returns the full or rooted call graph as nodes+edges.

---

### 15. SimInspect Breakpoints for Emulation

**What it is:** `state.inspect.b('mem_write', ...)` sets conditional breakpoints during symbolic execution or emulation that trigger on memory reads/writes, register access, syscalls, etc.

**Why it matters:** During emulation, an AI may want to know "when does this function write to address 0x404000?" or "what value is read from the registry key?" without analyzing every instruction. SimInspect breakpoints provide targeted monitoring.

**Suggested tool:** `emulate_with_watchpoints(function_address, watchpoints=[{"type": "mem_write", "address": "0x404000"}], ...)` — emulate with monitoring, returning triggered events.

---

### 16. Structured Disassembly with Annotations

**What it is:** `project.analyses.Disassembly` produces disassembly annotated with variable names, cross-references, and comments — similar to what IDA/Ghidra shows.

**Why it matters:** The current decompiler produces C pseudocode, but sometimes the AI needs assembly-level detail *with context*. Raw Capstone disassembly loses cross-reference and variable annotations.

**Suggested tool:** `get_annotated_disassembly(function_address)` — returns assembly with variable names, xref annotations, and string references inline.

---

### 17. VFG / Value-Set Analysis

**What it is:** `project.analyses.VFG` performs abstract interpretation to compute possible value sets for registers and memory at each program point.

**Why it matters:** Answers questions like "what range of values can this pointer hold?" or "is this array index always in bounds?" Enables the AI to reason about pointer aliasing and buffer bounds without full symbolic execution.

**Note:** VFG is computationally expensive and may not be practical for large binaries. Consider exposing it as a per-function analysis with background task support.

---

### 18. Packing/Obfuscation Detection

**What it is:** `project.analyses.PackingDetector` uses heuristics to determine if a binary is packed or obfuscated.

**Why it matters:** Already partially covered by PEiD signatures, but angr's `PackingDetector` uses different heuristics (entropy analysis, section characteristics, import table anomalies). Having both provides higher confidence.

**Suggested tool:** Could be integrated into the existing triage report rather than a standalone tool.

---

### 19. Binary Reassembly / Patch-to-Disk

**What it is:** `project.analyses.Reassembler` can produce a modified binary file from in-memory patches.

**Why it matters:** The current `patch_binary_memory` only modifies the in-memory representation. For an AI workflow that involves "patch out the anti-debug check and save the clean binary," writing to disk is essential.

**Suggested tool:** `save_patched_binary(output_path)` — writes the current in-memory state to a new PE file.

---

### 20. Class Identification (C++)

**What it is:** `project.analyses.ClassIdentifier` identifies C++ class hierarchies from vtable analysis.

**Why it matters:** For C++ binaries, understanding class structures and virtual method dispatch is critical. Without it, the AI sees raw vtable pointer dereferences instead of method calls.

**Suggested tool:** `identify_classes(limit=50)` — returns discovered classes with vtable addresses, virtual methods, and inheritance relationships.

---

## Summary Table

| # | Capability | Priority | Complexity | Standalone Tool? |
|---|-----------|----------|-----------|-----------------|
| 1 | Reaching Definitions (RDA) | P1 | Medium | Yes |
| 2 | Calling Convention Recovery | P1 | Low | Yes |
| 3 | Variable Recovery | P1 | Low | Yes |
| 4 | Data Dependency Graph | P1 | Medium | Yes |
| 5 | Disassemble Address Range | P1 | Low | Yes |
| 6 | Function Hooking | P1 | Medium | Yes (3 tools) |
| 7 | Symbolic Input Config | P2 | High | Yes |
| 8 | BinDiff | P2 | Medium | Yes |
| 9 | Constant Propagation | P2 | Low-Med | Yes |
| 10 | FLIRT Signatures | P2 | Low | Yes |
| 11 | Control Dependence Graph | P2 | Low | Yes |
| 12 | Self-Modifying Code Detection | P2 | Low | Yes |
| 13 | Code Cave Detection | P2 | Low | Yes |
| 14 | Full Call Graph Export | P3 | Low | Yes |
| 15 | SimInspect Watchpoints | P3 | High | Yes |
| 16 | Annotated Disassembly | P3 | Medium | Yes |
| 17 | VFG / Value-Set Analysis | P3 | High | Yes |
| 18 | Packing Detection | P3 | Low | Integrate into triage |
| 19 | Patch-to-Disk | P3 | Medium | Yes |
| 20 | Class Identification | P3 | Medium | Yes |

---

## Recommended Implementation Order

**Phase 1 — Immediate wins (low complexity, high impact):**
1. Disassemble Address Range (#5)
2. Calling Convention Recovery (#2)
3. Variable Recovery (#3)
4. FLIRT Signature Matching (#10)

**Phase 2 — Core data flow (medium complexity, highest analytical value):**
5. Reaching Definitions Analysis (#1)
6. Data Dependency Graph (#4)
7. Function Hooking (#6)
8. Control Dependence Graph (#11)

**Phase 3 — Specialized capabilities:**
9. Constant Propagation (#9)
10. BinDiff (#8)
11. Self-Modifying Code & Code Cave Detection (#12, #13)
12. Full Call Graph Export (#14)

**Phase 4 — Advanced features:**
13. Symbolic Input Configuration (#7)
14. SimInspect Watchpoints (#15)
15. Annotated Disassembly (#16)
16. Remaining items (#17-#20)
