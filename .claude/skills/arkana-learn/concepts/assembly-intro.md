# Concept Reference: Introduction to Assembly

Foundation tier reference for Module 1.5. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

Assembly language is the human-readable representation of machine code — the raw
instructions that a CPU executes. When you disassemble a binary, you convert the
machine code bytes back into assembly mnemonics. Reading assembly is the
fundamental skill of reverse engineering: everything else (decompilation, data
flow analysis, emulation) is built on top of understanding what the instructions
do.

The goal for beginners is NOT to memorise every instruction. It is to recognise
the 10 most common instructions and the patterns they form (function prologues,
loops, conditionals, function calls). These patterns cover roughly 80% of what
a beginner encounters.

## x86/x64 Register Overview

### General-Purpose Registers with Role Analogies

| Register | 64-bit | Analogy | Conventional Role |
|----------|--------|---------|-------------------|
| EAX | RAX | Calculator display | Accumulator — arithmetic results, function return values |
| EBX | RBX | Notebook | Base — general storage, preserved across calls |
| ECX | RCX | Lap counter | Counter — loop counters, string operations |
| EDX | RDX | Scratch paper | Data — I/O operations, multiplication overflow |
| ESI | RSI | "Reading from" bookmark | Source index — source pointer in copy operations |
| EDI | RDI | "Writing to" bookmark | Destination index — destination pointer in copy operations |
| ESP | RSP | Bookmark in a stack of papers | Stack pointer — always points to top of the stack |
| EBP | RBP | Table of contents | Base/frame pointer — marks the start of the current stack frame |
| EIP | RIP | Finger following a recipe | Instruction pointer — address of the next instruction to execute |

Key teaching points:
- EAX almost always holds the return value of a function (this is a convention,
  not a hardware requirement)
- ESP changes constantly as values are pushed and popped
- EIP is never written to directly — it changes via jmp, call, ret, and branches
- 64-bit registers (RAX, RBX, etc.) are the extended versions; the lower 32 bits
  are the E-prefixed names (EAX is the lower 32 bits of RAX)
- x64 calling convention passes first 4 args in RCX, RDX, R8, R9 (Windows) or
  RDI, RSI, RDX, RCX, R8, R9 (Linux)

### The EFLAGS Register

Do not teach all flags — focus on these two:
- **ZF (Zero Flag)** — set to 1 when a comparison or arithmetic result is zero
- **CF (Carry Flag)** — set to 1 when an unsigned operation overflows

These are what `cmp` and `test` set, and what `jz`/`jnz`/`ja`/`jb` read.

## The 10 Essential Instructions

### Data Movement

```asm
mov  eax, 5          ; EAX = 5 (copy value into register)
mov  eax, [ebx]      ; EAX = value at memory address in EBX
mov  [ebx], eax      ; Store EAX value at memory address in EBX
push eax             ; Put EAX on top of stack, ESP decreases by 4
pop  ebx             ; Take top of stack into EBX, ESP increases by 4
lea  eax, [ebx+8]    ; EAX = EBX + 8 (address calculation, no memory access)
```

Teaching `lea` vs `mov`: "LEA calculates an address but does not read from it.
`mov eax, [ebx+8]` reads the value at address EBX+8. `lea eax, [ebx+8]` just
computes EBX+8 and stores the result. LEA is often used as a fast way to do
addition and multiplication."

### Control Flow

```asm
call 0x401000        ; Push return address, jump to 0x401000 (function call)
ret                  ; Pop return address from stack, jump there (function return)
jmp  0x401050        ; Unconditional jump (goto)
```

### Comparison and Testing

```asm
cmp  eax, 10         ; Compute EAX - 10, set flags (result discarded)
test eax, eax        ; Compute EAX AND EAX, set flags (tests if EAX is zero)
```

After `cmp` or `test`, a conditional jump reads the flags:
```asm
jz   target          ; Jump if Zero Flag set (je is a synonym)
jnz  target          ; Jump if Zero Flag not set (jne is a synonym)
ja   target          ; Jump if above (unsigned greater than)
jb   target          ; Jump if below (unsigned less than)
jg   target          ; Jump if greater (signed greater than)
jl   target          ; Jump if less (signed less than)
```

### No Operation

```asm
nop                  ; Do nothing (used for alignment, padding, or patching)
```

## Stack Frame Anatomy

The stack frame is the function's private workspace. Teach the pattern, not every
variation.

### Function Prologue (setting up)

```asm
push ebp             ; Save the caller's frame pointer
mov  ebp, esp        ; Set up our own frame pointer
sub  esp, 0x20       ; Reserve 32 bytes for local variables
```

Analogy: "You walk up to a shared desk (the stack). First you save where the
previous person left their bookmark (push ebp). Then you put your own bookmark
down (mov ebp, esp). Then you spread out your papers, claiming space for your
work (sub esp, N)."

### Accessing Local Variables and Parameters

```asm
mov  eax, [ebp+8]    ; First parameter (above saved EBP and return address)
mov  eax, [ebp+0xC]  ; Second parameter
mov  eax, [ebp-4]    ; First local variable
mov  eax, [ebp-8]    ; Second local variable
```

Stack layout (32-bit cdecl):
```
[ebp+0xC]  → Second argument
[ebp+8]    → First argument
[ebp+4]    → Return address (saved by CALL)
[ebp]      → Saved EBP (saved by PUSH EBP)
[ebp-4]    → First local variable
[ebp-8]    → Second local variable
```

### Function Epilogue (cleaning up)

```asm
mov  esp, ebp        ; Discard local variables (or: leave)
pop  ebp             ; Restore caller's frame pointer (or: leave)
ret                  ; Return to caller
```

The `leave` instruction is shorthand for `mov esp, ebp` followed by `pop ebp`.

## Calling Conventions Simplified

Start with cdecl only. Mention stdcall briefly. Save fastcall/thiscall/x64 for
when the learner encounters them.

### cdecl (C Declaration) — the default

- Arguments pushed right-to-left onto the stack
- Return value in EAX
- Caller cleans up the stack (adds to ESP after the call)

```asm
; Calling printf("Hello %d", 42)
push 42              ; Second argument (pushed first: right-to-left)
push offset aHelloD  ; First argument (format string)
call _printf
add  esp, 8          ; Caller cleans up 2 arguments x 4 bytes = 8
```

### stdcall (Windows API standard)

Same as cdecl but the callee cleans the stack (via `ret N`):
```asm
push 0               ; uType (MB_OK)
push offset aTitle   ; lpCaption
push offset aText    ; lpText
push 0               ; hWnd
call _MessageBoxA    ; MessageBoxA cleans up via: ret 16
; No add esp here — MessageBoxA already did it
```

## Reading Arkana Disassembly Output

Arkana's `disassemble_at_address` returns output like:
```
0x00401000:  push   ebp
0x00401001:  mov    ebp, esp
0x00401003:  sub    esp, 0x20
0x00401006:  mov    eax, dword ptr [ebp + 8]
0x00401009:  test   eax, eax
0x0040100b:  jz     0x401020
```

Arkana's `get_annotated_disassembly` adds context:
```
0x00401000:  push   ebp                    ; function prologue
0x00401001:  mov    ebp, esp
0x00401003:  sub    esp, 0x20              ; 32 bytes of locals
0x00401006:  mov    eax, dword ptr [ebp + 8]  ; arg_0 (first parameter)
0x00401009:  test   eax, eax              ; check if arg_0 is NULL
0x0040100b:  jz     0x401020              ; jump to error handling if NULL
```

Teach the learner to read annotated disassembly first — it bridges the gap
between raw instructions and understanding. Once comfortable, graduate to raw
disassembly.

## Key Arkana Tools

- **`disassemble_at_address(address, num_instructions)`** — Raw disassembly at
  a specific address. Use to examine specific code regions, verify decompiler
  output, or explore functions instruction by instruction.
- **`get_annotated_disassembly(address)`** — Disassembly enriched with variable
  names, cross-references, and comments. The best tool for beginners because
  annotations provide context that raw disassembly lacks.
- **`disassemble_raw_bytes(hex_bytes)`** — Disassemble arbitrary bytes without
  needing a loaded binary. Useful for teaching: give the learner hex bytes and
  ask them to predict what the disassembly will look like.

## Socratic Questions

- "What happens to ESP when you PUSH a value?"
  (Expected insight: ESP decreases by 4 (or 8 on x64) — the stack grows
  downward toward lower addresses)
- "Why does the function save EBP first thing?"
  (Expected insight: EBP holds the caller's frame pointer. If we overwrite it
  without saving, the caller cannot find its own local variables when we return)
- "This function ends with 'ret 8'. What does the 8 mean?"
  (Expected insight: the function pops the return address AND removes 8 bytes
  of arguments from the stack — this is stdcall convention)
- "You see 'test eax, eax' followed by 'jz'. What is this checking?"
  (Expected insight: TEST performs AND — EAX AND EAX is zero only if EAX is
  zero. So this is checking if EAX is NULL/zero, then jumping if it is)
- "What is the difference between 'mov eax, [ebx]' and 'lea eax, [ebx]'?"
  (Expected insight: MOV reads the value from the memory address in EBX and
  stores it in EAX. LEA just copies the address itself — it does not access
  memory)
- "If you see 'call eax' instead of 'call 0x401000', what does that suggest?"
  (Expected insight: an indirect call — the target address is computed at
  runtime, often from a function pointer, vtable, or resolved API address)

## Common Misconceptions

### "I need to memorise all instructions"

x86 has hundreds of instructions, but the 10 covered here appear in the vast
majority of code. Beginners should focus on recognising patterns (prologue,
epilogue, loop, conditional, call) rather than memorising the instruction set.
Look up unfamiliar instructions as you encounter them — do not try to learn them
all upfront.

### "Assembly is unreadable"

Assembly is verbose, not unreadable. Each instruction does exactly one small
thing. The challenge is volume, not complexity. With practice, patterns emerge:
function boundaries, loops (cmp + jmp backward), conditionals (cmp + jmp
forward), and string operations (rep movs) become recognisable at a glance.
Annotated disassembly and decompilation make the learning curve gentler.

### "Every instruction matters equally"

In practice, most instructions are boilerplate: stack management, register
shuffling, alignment padding. The instructions that matter are the ones that
interact with the outside world (CALL to APIs), make decisions (CMP + Jcc),
and manipulate data in meaningful ways. Teach the learner to skim boilerplate
and focus on these key instructions.

### "Assembly maps 1:1 to source code lines"

A single line of C can compile to dozens of instructions (especially struct
access, array indexing, or floating-point operations). Conversely, compiler
optimisations can eliminate entire source code blocks. There is no predictable
line-by-line correspondence. This is why decompilers exist — they reconstruct
approximate high-level code from the instruction patterns.

### "Registers are like variables"

Registers are shared, temporary storage locations that are constantly reused.
Unlike variables, a register does not "belong" to a value — EAX might hold a
function's return value on one line and an unrelated calculation three
instructions later. This is why data flow analysis matters: tracking which
value is in which register at which point requires following the instruction
sequence, not just reading register names.

## When to Teach This

- **After PE structure and strings**: The learner should understand what binary
  sections contain code (.text) before diving into reading that code.
- **When decompilation is introduced**: Understanding assembly provides the
  foundation for understanding what a decompiler does and why its output
  sometimes differs from the actual behaviour.
- **When disassembly appears on screen**: Any time `disassemble_at_address` or
  `get_annotated_disassembly` output is shown, use it to reinforce instruction
  recognition and pattern identification.
- **Gradually, not all at once**: Introduce instructions as they appear in real
  analysis. Start with the prologue pattern, then add conditionals and calls as
  they come up naturally. Do not deliver all 10 instructions as a lecture.
