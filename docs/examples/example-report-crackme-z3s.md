# Analysis Report: CrackMeZ3S — CTF Crackme (Interactive Debugger Showcase)

**Prompt:** `/arkana-analyse find a difficult crackme that will need to extensively use arkana but will need to use the debugger to solve`

**Sample:** CrackMeZ3S.exe by PELock (PE32 x86, 101,376 bytes) — [source code & solution](https://github.com/PELock/CrackMeZ3S-CTF-CrackMe-Tutorial) | [author's write-up](https://www.pelock.com/articles/how-to-write-a-crackme-for-a-ctf-competition)

**Flag:** `PELock v2.0`

---

## Why This Example

This analysis demonstrates Arkana's **interactive debugger** in a real-world
CTF scenario. The crackme encrypts key verification data at compile time and
only decrypts it at runtime — static analysis alone cannot extract the expected
values. The debugger was used to execute decryption routines in isolation and
read the plaintext results directly from emulated memory.

Along the way, several Qiling/Unicorn limitations were encountered and
overcome, establishing reusable patterns for future debug sessions.

---

## Executive Summary

| Property | Value |
|----------|-------|
| Risk Score | 64 / 100 (CRITICAL — anti-debug APIs) |
| Format | PE32 x86, MSVC compiled |
| Classification | CTF crackme, 6-key multi-threaded verification |
| Anti-Analysis | 26 techniques across 13 functions |
| Tools Used | 151 invocations across 6 debug sessions |

CrackMeZ3S requires six independent conditions to be satisfied simultaneously.
Each condition is verified by a separate thread, coordinated by an orchestrator
that encrypts function pointers via `EncodePointer` and validates the assembled
flag against an MD5 hash. The binary includes 4 timing anti-debug checks, 18
Polish-language red-herring error messages, and random data corruption on
detection.

---

## Architecture

```
Orchestrator (sub_402240)
├── EncodePointer × 6 function pointers (offset -100)
├── CreateEventW × 6 manual-reset events
├── CreateThread → launches chain of 6 verification threads
├── WaitForMultipleObjects on all 6 events
├── 4× QueryPerformanceCounter timing checks (>5s = random corruption)
├── Collector (sub_401180) assembles flag chars into g_4084f8
├── sprintf: "#flag4poprawna %s \n123458s3cr3t _+=-=-="
├── MD5 check against 4ED28DA4AAE4F2D58BF52EB0FE09F40B
├── Success: decrypts victory message via custom 16-bit cipher
└── Failure: displays one of 18 Polish red-herring tips
```

---

## The 6 Keys

### Key 0 — Console Password (sub_401e80) — *Debugger Required*

The function prompts "Podaj tajne haslo:" (Enter secret password), then
decrypts a 33-byte hardcoded blob via a position-dependent cipher with 40+
arithmetic operations per byte (ROL, XOR, NOT, ADD, SUB with varying constants
and index-dependent transforms). The decrypted blob is the expected MD5 hash of
the password.

**Static analysis** identified the encrypted blob (extracted from MOV
immediates) and the cipher structure, but the algorithm was too complex for
manual computation (1,300+ operations for 33 bytes).

**Debugger extraction**:
1. Patched 22 unresolved MSVCRT IAT entries to a `xor eax,eax; ret` code-cave
   stub at 0x403600 to bypass CRT initialisation crashes
2. Ran through CRT init to the orchestrator at 0x402240
3. Patched the orchestrator at 0x402253 with `JMP 0x401F04` (E9 AC FC FF FF) to
   redirect execution into the blob initialisation code
4. Patched 0x4020A0 (post-decryption-loop) with `EB FE` (infinite loop trap)
5. Ran with `max_instructions=10000` — the decryption loop completed all 33
   iterations (EDI reached 0x21)
6. Read 33 bytes from `[EBP-0x28]` → `144C9DEFAC04969C7BFAD8EFAA8EA194`
7. Online lookup confirmed: **MD5("fake") = 144C9DEFAC04969C7BFAD8EFAA8EA194**

**Answer:** Password is **"fake"**

### Key 1 — Environment Variable (sub_401bf0) — *Manual Crypto*

The env var name is encrypted as 22 wide characters using XOR(0xAA5E) + INC +
ROL13. This algorithm was simple enough to compute by hand from the disassembly.

**Decryption** (per wchar): `ROL13((XOR(encrypted, 0xAA5E) + 1) & 0xFFFF)`

Result: **`PROCESOR_ARCHITECTURE`** (single S — intentional misspelling!)

**Answer:** Set `PROCESOR_ARCHITECTURE=AMD64 ` (with trailing space)

### Key 2 — NTFS Alternate Data Stream (sub_401910)

Opens `CrackMeZ3S.exe:Z3S.txt`, reads the content, reverses it via `_strrev`,
and compares against `"\n\r70.6102"`.

**Answer:** Create ADS with content `"2016.07\r\n"`

### Key 3 — Clipboard Content (sub_401710)

Opens the Windows clipboard via `OpenClipboard` + `GetClipboardData(CF_TEXT)`
and compares against a hardcoded string.

**Answer:** Copy **"Boom Boom - Lip Lock - Song"** to clipboard

### Key 4 — Windows Version (sub_401560)

Calls `GetVersionExW` and checks `dwMajorVersion == 6 && dwMinorVersion == 0`.

**Answer:** Run in **Windows Vista compatibility mode**

### Key 5 — Ctrl-C Console Event

Intercepts a console Ctrl-C event via `SetConsoleCtrlHandler`.

**Answer:** Press **Ctrl-C** during execution

---

## Flag Assembly

The collector (sub_401180) waits on all 6 events, then copies specific bytes
from each key's output buffer into `g_4084f8`:

```
Position:  0  1  2  3  4  5  6  7  8  9  10
Character: P  E  L  o  c  k     v  2  .  0
Source:    K5 K5 K3 K3 K3 K3 K1 K4 K2 K2 K2
```

**Final flag: `PELock v2.0`**

Verified against: `MD5("#flag4poprawna PELock v2.0 \n123458s3cr3t _+=-=-=") == 4ED28DA4AAE4F2D58BF52EB0FE09F40B`

---

## Debugger Techniques Developed

This analysis established several reusable patterns for Arkana's interactive
debugger:

### 1. IAT Patching for Unresolved Imports

Qiling may fail to resolve MSVCRT CRT functions, leaving IAT entries pointing
to invalid addresses (0x5xxx range). The fix:

```
1. Write a "xor eax, eax; ret" stub (31 C0 C3) to a code cave
2. Read the IAT region to identify unresolved entries (low addresses)
3. Overwrite all unresolved IAT entries with the stub address
4. Restore any accidentally overwritten null terminators or resolved entries
```

### 2. Code Patching for Execution Redirection

Unicorn's `emu_start()` does not honour EIP changes via `debug_write_register`.
Instead of changing EIP, patch the binary code:

```
1. Calculate JMP offset: target - (patch_addr + 5)
2. Write E9 <offset_le32> at the desired redirect point
3. Execution naturally flows through the patched JMP
```

### 3. Infinite Loop Trap for Memory Extraction

When breakpoints are unreliable after code patches, use a trap:

```
1. Write EB FE (jmp self) at the desired stop point
2. Run with max_instructions high enough for the target code to complete
3. Emulator stops when instruction limit is reached (stuck in loop)
4. Read decrypted/computed data from memory at leisure
```

### 4. API Stubbing Strategy

For multi-threaded binaries under Qiling:

```
- CreateThread → return fake handle (0x1337)
- CreateEventW → return fake handle (0x100)
- WaitForMultipleObjects → return 0 (WAIT_OBJECT_0)
- SetEvent → return 1 (success)
- IsDebuggerPresent → return 0 (not debugged)
- srand → void (prevent PRNG-based corruption)
```

---

## Anti-Analysis Protections

| Technique | Implementation | Bypass |
|-----------|---------------|--------|
| Timing check | 4× QueryPerformanceCounter, >5s = corruption | CRT stub returns instant values |
| Debugger detection | IsDebuggerPresent | Stubbed to return 0 |
| PEB NtGlobalFlag | Direct PEB access | Not triggered under emulation |
| OutputDebugStringW | SEH-based detection | Stubbed to no-op |
| Pointer encryption | EncodePointer with -100 offset | CRT stub returns identity |
| Red herrings | 18 Polish fake error messages | Ignored (static analysis identified them) |
| Random corruption | memset on event/thread/data buffers | srand stubbed, timing bypassed |

---

## Tool Usage Summary

| Category | Tools | Invocations |
|----------|-------|-------------|
| Debug lifecycle | debug_start, debug_stop, debug_status | 15 |
| Debug execution | debug_continue, debug_step, debug_run_until | 18 |
| Debug memory | debug_read_memory, debug_write_memory, debug_write_register | 40 |
| Debug stubs | debug_stub_api, debug_set_breakpoint, debug_remove_breakpoint | 42 |
| Static analysis | decompile, disassemble, triage, capa, strings, imports | 25 |
| Notes & reporting | add_note, generate_report | 11 |
| **Total** | | **151** |
