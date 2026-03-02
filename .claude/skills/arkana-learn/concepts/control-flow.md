# Control Flow Analysis

Reference material for Module 2.1. Builds on Foundation knowledge of x86 registers,
common instructions, and reading disassembly. This concept teaches learners to see
program structure rather than individual instructions.

---

## Core Concepts

### Basic Blocks

A basic block is the fundamental unit of control flow analysis: a straight-line
sequence of instructions with exactly one entry point (the first instruction) and
exactly one exit point (the last instruction). No jumps into the middle, no jumps
out from the middle.

A basic block ends when one of these occurs:
- A branch instruction (conditional or unconditional jump)
- A call to a function that does not return (e.g., `ExitProcess`, `abort`)
- The instruction before a jump target (because the target starts a new block)

**Why this matters**: Basic blocks let us reason about code in chunks rather than
instruction-by-instruction. If execution reaches any instruction in a block, every
instruction in that block will execute.

### Control Flow Graphs (CFGs)

A CFG connects basic blocks with directed edges showing how execution can flow
between them. Each edge represents a possible transfer of control: a taken branch,
a fall-through, or a function call/return.

CFGs reveal structure that linear disassembly hides. A flat listing of instructions
makes loops, nested conditionals, and error handling look like spaghetti. A CFG
shows the actual decision tree: "if this condition is true, go here; otherwise, go
there." This is why decompilers and analysts both rely on CFGs to recover the
original program logic.

### Conditional Branches

Conditional branches are the if/else of machine code. The typical pattern:

```
cmp eax, 5       ; compare eax with 5 (sets CPU flags)
jz  0x401020     ; jump to 0x401020 if they are equal (ZF=1)
; fall-through   ; otherwise continue here
```

Common conditional jump instructions and their meanings:
- `jz` / `je` — jump if zero / equal (ZF=1)
- `jnz` / `jne` — jump if not zero / not equal (ZF=0)
- `jl` / `jb` — jump if less (signed) / below (unsigned)
- `jg` / `ja` — jump if greater (signed) / above (unsigned)

The `test` instruction is an AND that discards the result but sets flags. `test eax, eax`
is the standard way to check "is eax zero?" — it sets ZF=1 if eax is 0.

### Unconditional Jumps

`jmp` transfers control without any condition. It appears in:
- The end of an if-block jumping over the else-block
- Loop back-edges returning to the loop header
- Tail calls (jumping to another function instead of calling it)
- Switch/case fall-through prevention

### Loop Patterns

Loops in compiled code follow a few recognizable patterns:

**Pre-test (while loop)**: The condition check is at the top. The back-edge goes from
the bottom of the loop body to the condition block.
```
loop_header:  cmp ecx, 0    ; condition check first
              jz  loop_exit
              ; ... loop body ...
              jmp loop_header
loop_exit:
```

**Post-test (do-while loop)**: The condition check is at the bottom. The body always
executes at least once.
```
loop_body:    ; ... loop body ...
              dec ecx
              jnz loop_body  ; check at the end
```

**Counted loop (for loop)**: Uses a counter register, often with an increment and a
comparison against a bound.
```
              xor ecx, ecx       ; i = 0
loop_header:  cmp ecx, 10        ; i < 10
              jge loop_exit
              ; ... loop body ...
              inc ecx             ; i++
              jmp loop_header
```

### Switch/Case Dispatch (Jump Tables)

When a switch statement has many cases with sequential values, compilers generate a
jump table: an array of addresses indexed by the switch variable.

```
cmp eax, 7           ; check if value is within table bounds
ja  default_case     ; if above max, go to default
jmp [jump_table + eax*4]  ; index into address table
```

The jump table itself is an array of pointers in the `.rdata` section. Each entry is
the address of a case handler.

### Indirect Jumps

An indirect jump (`jmp eax`, `jmp [eax+ecx*4]`, `call [eax]`) transfers control to
an address computed at runtime. These are harder to analyse because the target is not
visible in the instruction itself. Sources include:
- Jump tables (switch/case) — benign and common
- Virtual function dispatch (vtables) — C++ polymorphism
- Function pointer calls — callbacks, event handlers
- Obfuscation — deliberately hiding control flow targets

Indirect jumps make static CFG construction incomplete, because the analyser cannot
always determine all possible targets.

---

## Key Arkana Tools

| Tool | Purpose |
|------|---------|
| `get_function_cfg(address)` | Retrieve the CFG for a function — shows blocks, edges, and conditions |
| `get_function_map(limit=N)` | List functions ranked by interestingness — pick targets for CFG analysis |
| `scan_for_indirect_jumps()` | Find all indirect jump/call sites across the binary |
| `get_function_complexity_list()` | Rank functions by cyclomatic complexity |

---

## Teaching Moments During Guided Analysis

**When a learner encounters a function with high complexity**: Explain that cyclomatic
complexity counts independent paths through the CFG. A complexity of 1 means straight-line
code. A complexity of 20+ means many branches — likely a parser, dispatcher, or
validation routine. Use `get_function_cfg()` to visualise why.

**When a learner sees a loop in decompiled output**: Ask them to find it in the CFG.
Identify the loop header (the block with two incoming edges — one from outside, one
from the back-edge), the loop body, and the exit condition.

**When an indirect jump appears**: Discuss whether it is a jump table (benign compiler
output) or something more suspicious. Use `scan_for_indirect_jumps()` to see all
such sites and categorise them.

---

## Socratic Questions

- "What does a high cyclomatic complexity suggest about this function?"
  *Expected direction*: More decision points, harder to understand, possibly a
  command dispatcher or parser. Worth decompiling for deeper understanding.

- "Can you spot the loop in this CFG?"
  *Expected direction*: Look for a back-edge — an edge going from a lower block back
  to a higher block. The target of the back-edge is the loop header.

- "This function has 3 exit blocks. What might each one represent?"
  *Expected direction*: Success return, error return, and edge-case return. Each exit
  may return a different value.

- "Why does the CFG have an edge to a block that does not seem reachable from normal flow?"
  *Expected direction*: It may be an exception handler, a compiler-inserted check
  (stack canary failure), or dead code.

---

## Common Mistakes

**Confusing basic block boundaries**: Learners often think a basic block ends at every
instruction, or that a `call` instruction ends a block. A `call` to a normal function
does NOT end a basic block — execution continues at the next instruction after the call
returns. Only calls to no-return functions (like `exit()`) end a block.

**Missing exception handlers as control flow paths**: Exception handlers (SEH on Windows,
`.eh_frame` on Linux) create implicit control flow edges that do not appear as explicit
jump instructions. A function may have a CFG path to a handler block that is only taken
when an exception occurs. Ignoring these means missing error recovery logic and potential
anti-analysis tricks.

**Assuming linear execution order**: Just because block B appears after block A in the
disassembly listing does not mean A always executes before B. The CFG edges, not the
address ordering, determine execution flow.

**Confusing cyclomatic complexity with difficulty**: A high-complexity function is not
necessarily "harder" — it may just have many simple cases in a switch statement. A
low-complexity function with pointer arithmetic and bitwise operations can be far
harder to understand.
