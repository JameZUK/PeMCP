# Decompilation Best Practices & Pitfalls

This guide covers how to effectively use Arkana's decompilation tools, validate
output accuracy, and avoid common pitfalls — especially around calling conventions,
parameter recovery, and decompiler limitations.

---

## Golden Rule: Validate Decompiled Code Against Assembly

**When decompiled pseudocode doesn't match expected behavior, CHECK THE ASSEMBLY.**

The angr decompiler produces C-like pseudocode from VEX IR, which involves
significant heuristic reconstruction. It is often correct, but it can silently
produce misleading output — particularly for:

- **Calling conventions** (wrong parameter mapping)
- **Crypto/cipher functions** (wrong rotation direction, operator precedence)
- **Optimised code** (merged operations, strength reduction)
- **Obfuscated code** (opaque predicates, dead code)
- **cffi fallback decompilation** (reduced CFG quality)

### When to Cross-Validate

**ALWAYS** cross-check decompiled code against `get_annotated_disassembly()` when:

1. **Crypto or cipher functions** — parameter order determines key vs plaintext vs
   output. A single swap produces garbage output that wastes hours of analysis.

2. **The decompiled code doesn't produce expected results** — if you implement
   what the decompiler shows and get wrong output, the decompiler may be wrong,
   not your implementation.

3. **Shellcode or position-independent code** — angr may apply the wrong calling
   convention (see below).

4. **Functions with many parameters (5+)** — parameter recovery degrades with
   count; stack-passed parameters are frequently misidentified.

5. **cffi fallback warning** — if the response includes a `note` about "cffi
   pickle incompatibility", cross-references and type propagation are limited.

6. **Indirect calls or virtual dispatch** — decompiler may not resolve the target.

7. **SIMD/intrinsics** — VEX IR may not faithfully represent SSE/AVX operations.

### How to Cross-Validate

```
1. decompile_function_with_angr(address)     → read pseudocode, note parameters
2. get_annotated_disassembly(address)         → read actual instructions
3. Compare: do register assignments at call sites match the decompiler's
   parameter names? Are rotations/shifts in the correct direction?
4. If the function is called from another function, also disassemble the
   CALLER to see what values are loaded into argument registers.
```

**Critical**: When validating a function's parameters, look at the **call site**
(the caller), not just the function body. The caller's register setup shows
the actual argument mapping.

---

## Calling Convention Pitfalls

### The Problem

angr's decompiler defaults to **System V AMD64 ABI** for x86-64 code:
- Parameters: `rdi, rsi, rdx, rcx, r8, r9`
- Named in pseudocode as: `a0, a1, a2, a3, a4, a5`

But **Windows x64** uses a different convention:
- Parameters: `rcx, rdx, r8, r9` (then stack)
- Shadow space: 32 bytes reserved on stack

**This means angr's pseudocode parameter names are WRONG for Windows binaries.**

### Real-World Example (ValleyRAT ARX Cipher)

The decompiler showed:
```c
void sub_25255(int64_t a0, int64_t a1, void *ptr, int64_t a3, int64_t a4, ...)
```

The call site assembly was:
```asm
lea rcx, [rdi + 4]       ; rcx = pointer to key (Windows param 1)
lea rdx, [rdi + 0x14]    ; rdx = pointer to counter (Windows param 2)
lea r8,  [rdi + 0x23C]   ; r8  = encrypted data (Windows param 3)
mov r9d, [rdi]            ; r9  = size (Windows param 4)
call 0x25255
```

The decompiler mapped these as:
| Pseudocode | Register (SysV) | Register (Windows) | Actual meaning |
|------------|----------------|-------------------|----------------|
| `a0` | rdi | — | Not a parameter |
| `a1` | rsi | — | Not a parameter |
| `ptr` | rdx | rdx (param 2) | Counter/nonce |
| `a3` | rcx | rcx (param 1) | **Key** |
| `a4` | r8 | r8 (param 3) | Encrypted data |
| `a5` | r9 | r9 (param 4) | Size |

Trusting the decompiler's parameter order would swap key and counter,
producing wrong decryption output.

### How to Handle This

1. **For Windows PE binaries**: Always check `get_annotated_disassembly()` at
   call sites to verify parameter assignment via `rcx, rdx, r8, r9`.

2. **For shellcode**: The calling convention is whatever the author chose —
   usually Windows x64 on Windows shellcode, but could be custom. Always
   verify at the call site.

3. **For ELF binaries**: angr's default (SysV) is usually correct on Linux.

4. **For Mach-O binaries**: Uses SysV on x86-64, Apple's variant on ARM64.

5. **Use `get_calling_conventions(address)`** to see what angr recovered —
   but treat it as a hint, not ground truth. Verify critical functions.

### Quick Reference: x64 Calling Conventions

| Convention | Param 1 | Param 2 | Param 3 | Param 4 | Param 5+ |
|------------|---------|---------|---------|---------|----------|
| **Windows x64** | rcx | rdx | r8 | r9 | stack |
| **System V (Linux)** | rdi | rsi | rdx | rcx | r8, r9, stack |

| Convention | Return | Caller-saved | Callee-saved |
|------------|--------|-------------|-------------|
| **Windows x64** | rax | rcx,rdx,r8-r11 | rbx,rbp,rdi,rsi,r12-r15 |
| **System V** | rax | rcx,rdx,rdi,rsi,r8-r11 | rbx,rbp,r12-r15 |

---

## Common Decompiler Inaccuracies

### 1. Rotation Operations

The decompiler may show rotations as shifts:
```c
// Decompiler output (potentially wrong):
result = (x << 5) | (x >> 27);
// This IS a ROL32(x, 5) — correct, but verify the shift amounts
```

**Pitfall**: If the decompiler gets shift amounts wrong (e.g., shows 5 instead
of 8), the entire cipher is broken. Verify against the actual `rol`/`ror`
instructions in disassembly.

### 2. Signedness Confusion

```c
// Decompiler may show:
if ((int64_t)x < 0)     // signed comparison
// When the actual instruction is:
jb target               // unsigned comparison (below, not less-than)
```

This matters for bounds checks, loop conditions, and crypto operations.

### 3. Stack Variable Merging

The decompiler may merge distinct stack variables that happen to occupy the
same stack slot at different times (due to stack frame reuse). This makes
it look like one variable is being used for two unrelated purposes.

**Fix**: Check `get_function_variables(address)` and cross-reference with
disassembly to see actual stack layout.

### 4. Missed Function Arguments

When angr can't determine the calling convention or the function uses varargs,
it may show fewer parameters than actually exist. The "missing" parameters
are still passed but invisible in pseudocode.

**Fix**: Look at the call site in disassembly to count actual register/stack
arguments being set up.

### 5. Loop Reconstruction

Complex loops (especially with multiple exit conditions or `break`/`continue`
equivalents) may be decompiled as nested `if/goto` instead of clean loops.
This is correct but harder to read.

**Fix**: Read the CFG (`get_function_cfg(address)`) to understand the actual
loop structure.

### 6. Optimised Crypto Constants

Compilers may pre-compute crypto constants or inline lookup tables. The
decompiler faithfully shows the pre-computed values but they're unrecognisable:
```c
x = x * 0x01010101;  // Compiler-optimised byte broadcast
```

**Fix**: Use `detect_crypto_constants()` to identify known algorithm constants,
then map back to the decompiled functions.

---

## Workflow: Decompiling a Crypto Function

Crypto functions are the highest-risk case for decompiler errors. Use this
workflow:

```
1. decompile_function_with_angr(crypto_addr)
   → Read the pseudocode, identify the algorithm structure

2. get_annotated_disassembly(crypto_addr)
   → Verify: rotation amounts, shift directions, XOR operands,
     loop bounds, comparison operators

3. Disassemble the CALL SITE (the function that calls the crypto function)
   → Verify: which registers carry key, plaintext, output, size
   → Map registers to the correct calling convention (Windows vs SysV)

4. get_calling_conventions(crypto_addr)
   → Compare angr's parameter recovery with what you see at the call site

5. If implementing the cipher externally:
   → Test with known input/output first
   → If output is wrong, re-check parameter order and rotation directions
```

---

## Workflow: Decompiling Shellcode

Shellcode has additional challenges:

1. **No PE headers** → angr has no metadata about calling convention, imports,
   or sections. Everything is heuristic-recovered.

2. **Self-modifying code** → decompiler sees the initial bytes, not the
   runtime-modified code. Use `emulate_shellcode_with_speakeasy()` or
   `emulate_shellcode_with_qiling()` to capture runtime behavior.

3. **API resolution by hash** → the decompiler shows `call [rbx+0x48]` instead
   of `call VirtualAlloc`. Use `scan_for_api_hashes()` to identify the APIs,
   then `rename_function()` / `add_label()` for readability.

4. **Position-independent code** → relative addressing via `call $+5; pop reg`
   pattern. The decompiler usually handles this correctly but may assign wrong
   base addresses to data references.

**Recommended workflow**:
```
1. open_file(shellcode_path, mode="shellcode")
2. get_function_complexity_list() → find the main functions by block count
3. disassemble_at_address(entry) → understand the entry stub
4. decompile_function_with_angr(main_func) → get pseudocode
5. get_annotated_disassembly(main_func) → validate critical sections
6. scan_for_api_hashes() → identify resolved APIs
7. rename_function() → apply meaningful names for readability
8. emulate_shellcode_with_speakeasy() → capture API calls dynamically
```

---

## When to Use Disassembly Instead of Decompilation

| Situation | Use decompile | Use disassembly |
|-----------|:---:|:---:|
| Understanding overall function logic | Yes | Fallback |
| Verifying crypto parameters | Verify with | Yes |
| Short stubs (< 20 instructions) | Overkill | Yes |
| Heavily obfuscated code | May fail | Yes |
| Calling convention verification | No | Yes |
| Understanding loop structure | Yes | Supplement |
| API hash resolution | No | Yes |
| Anti-debug trick identification | Verify with | Yes |
| Data structure layout | Helpful | Supplement |

---

## Tool Quick Reference

| Tool | Best for |
|------|----------|
| `decompile_function_with_angr` | Primary pseudocode (gold standard) |
| `batch_decompile` | Decompile up to 20 functions at once |
| `get_annotated_disassembly` | Assembly with variable names and xrefs |
| `disassemble_at_address` | Quick look at raw instructions |
| `disassemble_raw_bytes` | Disassemble arbitrary byte sequences |
| `get_calling_conventions` | Parameter recovery (treat as hint) |
| `get_function_variables` | Stack/register variable layout |
| `get_function_cfg` | Control flow graph structure |
| `search_decompiled_code` | Search across all cached decompilations |
| `rename_function` / `rename_variable` | Improve readability after analysis |
| `auto_note_function` | Record findings after decompilation |
