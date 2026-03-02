# Decompilation

Reference material for Module 2.2. Builds on Foundation knowledge of control flow
graphs, calling conventions, and stack frames. This concept teaches learners to read
decompiler output critically and cross-reference it with disassembly.

---

## Core Concepts

### What Decompilers Do

A decompiler reverses the compilation process: it takes machine code and produces
human-readable pseudocode (usually C-like). The pipeline has several stages:

1. **Lifting**: Machine instructions are translated into an intermediate
   representation (IR) — a simplified, architecture-independent instruction set.
   angr uses VEX IR for this step.

2. **Control flow recovery**: The IR is organised into a CFG. Loops, conditionals,
   and switch statements are identified from the graph structure.

3. **Data flow analysis**: The decompiler tracks how values flow through registers
   and memory to determine which registers and stack slots are "the same variable."

4. **Type recovery**: Based on how values are used (pointer arithmetic, comparisons,
   function arguments), the decompiler infers types — `int`, `char*`, `HANDLE`, etc.

5. **Structuring**: The CFG is converted into structured control flow — if/else,
   while, for, switch — matching the patterns a human programmer would write.

6. **Output generation**: Variable names are assigned (usually `v0`, `v1` or `arg_0`,
   `var_4`), and the structured pseudocode is emitted.

### Reading Pseudocode

Decompiled output looks like C but is not compilable C. Key things to watch for:

**Variable types**: The decompiler guesses types from usage. `int64_t v3` means it
saw a 64-bit value. `char *v7` means it saw a value used as a memory address where
single bytes are read. These guesses can be wrong.

**Pointer arithmetic**: `*(DWORD *)(v3 + 16)` means "read a 4-byte value at offset
16 from the address in v3." This is likely a struct field access:
`my_struct->field_at_offset_16`.

**Casts**: `(unsigned int)v5 >> 3` — the cast changes the shift behavior (logical
vs arithmetic). Decompilers insert casts to preserve the exact semantics of the
machine code, even when the original source did not have them.

**Function calls**: `sub_401200(v3, 0, 256)` — the decompiler has identified a call
to function at 0x401200 with three arguments. Without symbols, functions are named
by address. Use `get_function_xrefs()` and context clues (imported API calls inside
the function) to understand what it does.

### Decompiler Artefacts

Decompiler output contains artefacts — things that look like code but are products
of the decompilation process, not the original program:

**Incorrect types**: The decompiler may call something `int` when it is actually a
`HANDLE` or a pointer. Type recovery is heuristic; it does not always get it right.

**Merged or split variables**: Two conceptually different variables that happen to
use the same register may be merged into one. Conversely, one variable that moves
between registers may be split into two. Watch for variables that seem to change
purpose mid-function.

**Missed optimisations**: Compiler optimisations (strength reduction, loop
unrolling, CMOV instead of branches) produce machine code patterns that the
decompiler may not fully reconstruct. The output may look more complex than the
original source.

**Phantom branches**: Some decompilers insert branches that do not correspond to
real conditional logic — they are artefacts of the structuring algorithm trying to
impose if/else structure on goto-based control flow.

**Incorrect argument counts**: If the calling convention is misidentified, the
decompiler may show too many or too few arguments. Compare with
`get_calling_conventions()` output.

### Comparing Decompiled Output with Disassembly

The decompiler is a tool, not an oracle. Verification against disassembly is
essential when:

- A function's behavior seems wrong or contradictory
- The decompiler shows dead code or unreachable paths
- You suspect a type error is changing the meaning of an operation
- Security-sensitive logic (crypto, auth checks) needs precise understanding

Use `get_annotated_disassembly(address)` alongside `decompile_function_with_angr(address)`
to cross-reference. The disassembly is ground truth; the decompilation is an
interpretation.

### Using Cross-References (Xrefs)

Cross-references answer two critical questions:
- **Who calls this function?** (callers / incoming xrefs)
- **What does this function call?** (callees / outgoing xrefs)

Tracing call chains is how you build a mental model of program behavior. Starting
from a known API call (e.g., `CreateFileA`), trace backward through callers to
understand who triggers the file operation and why. Starting from `main()` or the
entry point, trace forward through callees to see the execution flow.

---

## Key Arkana Tools

| Tool | Purpose |
|------|---------|
| `decompile_function_with_angr(address)` | Produce C-like pseudocode for a function (paginated — 80 lines/page, use `line_offset` for more) |
| `auto_note_function(address)` | Record a behavioral summary after decompiling — always call this |
| `get_function_xrefs(address)` | Find callers and callees of a function |
| `get_function_variables(address)` | List stack and register variables with types and offsets |
| `get_calling_conventions(address)` | Recover parameter count, types, and calling convention |

---

## Teaching Moments During Guided Analysis

**When a learner decompiles their first function**: Walk through the output line by
line. Identify the function signature, local variables, control flow structures,
and return value. Point out where the decompiler assigned generic names (`v0`, `a1`)
and discuss what the variables might actually represent based on usage.

**When decompiled output looks wrong**: This is a teaching moment about decompiler
limitations. Compare with `get_annotated_disassembly()`. Show where the decompiler
lost information or made an incorrect type assumption. Emphasise that the
disassembly is always authoritative.

**When the learner needs to understand a call chain**: Use `get_function_xrefs()` to
trace callers and callees. Build a call graph on paper or mentally. This is often
more valuable than deeply understanding any single function.

**After every decompilation**: Model the habit of calling `auto_note_function()`.
Explain that notes persist across the session and feed into the final analysis
digest. This teaches disciplined analysis documentation.

---

## Socratic Questions

- "Does this decompiled output look correct to you, or might the decompiler have
  gotten something wrong?"
  *Expected direction*: Look for suspicious type assignments, variables that change
  purpose, or control flow that seems unnecessarily complex. Compare with
  disassembly to verify.

- "Why do you think the decompiler named this variable v3?"
  *Expected direction*: Decompilers assign generic names sequentially. The number
  has no semantic meaning — it is just the third variable the decompiler encountered.
  Without debug symbols, there is no way to recover original variable names.

- "This function calls three other sub_ functions. How would you figure out what
  they do without decompiling all of them?"
  *Expected direction*: Check xrefs to see if they call known APIs. Look at their
  arguments — are they passing strings, handles, buffers? The context of how a
  function is called often reveals its purpose.

- "The decompiler shows `if (v2 != 0)` — what was the original assembly?"
  *Expected direction*: Likely `test eax, eax` / `jz` or `cmp eax, 0` / `je`. The
  decompiler reconstructed the condition from the flag-setting instruction and the
  conditional jump.

---

## Common Mistakes

**Blindly trusting decompiler output**: The most common and most dangerous mistake.
Decompiled code is an approximation. Types can be wrong, variables can be merged,
and control flow can be restructured. Always verify critical logic against the
disassembly.

**Ignoring compiler optimisations**: Compilers transform code in ways that make
decompilation imperfect. Inlined functions disappear. Loop unrolling creates
repetitive code that looks hand-written. Tail call optimisation turns calls into
jumps, confusing the decompiler about function boundaries.

**Not checking xrefs**: Understanding a function in isolation is often insufficient.
A function that allocates memory and copies data looks innocent until you see that
its caller passes user-controlled input and its callee calls `CreateRemoteThread`.
Always trace the call chain.

**Ignoring return values**: Decompiled output may show a function returning a value
that the caller ignores. This is often meaningful — it may indicate error handling
that was intentionally omitted (or a decompiler artefact). Check whether the caller
actually uses the return value by examining the disassembly.

**Spending too long on one function**: It is easy to get lost in a single complex
function. Step back and use `get_function_map()` to see the bigger picture. Often,
understanding the program's overall structure is more valuable than perfecting your
understanding of one routine.
