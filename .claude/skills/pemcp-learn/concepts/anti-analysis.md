# Concept Reference: Anti-Analysis Techniques

Advanced tier reference for Module 3.3. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

Anti-analysis techniques are code constructs deliberately added to hinder
reverse engineering, debugging, and automated analysis. They fall into three
broad categories: anti-debug (detect/prevent debuggers), anti-VM (detect virtual
machines and sandboxes), and obfuscation (make code harder to understand even
when you can see it). Understanding these techniques is necessary for bypassing
them during analysis.

**Critical distinction — intentional vs incidental**: The mere presence of an
API in the import table does not constitute an anti-analysis technique. Many
APIs flagged by analysis tools have entirely legitimate uses in compiler
runtimes, standard libraries, and application frameworks. An anti-analysis
technique requires **deliberate code** that checks a condition and **alters
execution flow** based on the result (e.g., "if debugger detected, exit" or
"if timing delta exceeds threshold, decrypt with wrong key"). An API that
simply appears in the IAT because the language runtime uses it is not
anti-analysis — it is a normal import. See the "False Positives from Compiler
Runtimes" section below for common examples.

## Anti-Debug Techniques

### API-Based Detection

The simplest checks call Windows APIs that reveal debugger presence:

- **IsDebuggerPresent()** — reads the PEB.BeingDebugged flag. Returns TRUE if
  a user-mode debugger is attached. The most common anti-debug check.
- **CheckRemoteDebuggerPresent()** — similar but checks for debuggers attached
  to the process from another process.
- **NtQueryInformationProcess(ProcessDebugPort)** — queries the kernel for the
  debug port. Returns non-zero if a debugger is attached. Harder to hook than
  IsDebuggerPresent because it goes through ntdll directly.
- **NtQueryInformationProcess(ProcessDebugFlags)** — returns 0 when being
  debugged (inverted logic catches analysts who patch for non-zero).
- **NtQueryInformationProcess(ProcessDebugObjectHandle)** — checks whether a
  debug object handle exists for the process.

### PEB Flag Checks

Instead of calling APIs, malware can read the Process Environment Block directly:

```
; Direct PEB.BeingDebugged check (no API call to hook)
mov eax, fs:[0x30]      ; PEB address (32-bit) or gs:[0x60] (64-bit)
movzx eax, byte [eax+2] ; BeingDebugged flag
test eax, eax
jnz debugger_detected
```

Also checked: `PEB.NtGlobalFlag` (0x70 offset) — set to 0x70 when a debugger
creates the process (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK |
FLG_HEAP_VALIDATE_PARAMETERS). And `PEB.ProcessHeap.Flags` / `ForceFlags`.

### Timing Checks

Debuggers introduce delays. Malware measures execution time to detect this:

- **RDTSC** — read timestamp counter. Execute a code block, read RDTSC before
  and after, check if delta exceeds a threshold (typically ~100,000 cycles for
  a simple block; debugging makes this millions).
- **GetTickCount()** — millisecond-resolution system timer. Same delta approach.
- **QueryPerformanceCounter()** — high-resolution timer. Most accurate.
- **timeGetTime()** — multimedia timer, less commonly hooked.

### Exception-Based Techniques

Debuggers intercept exceptions, changing execution flow:

- **INT 2D** — breakpoint exception. Under a debugger, the debugger may swallow
  it and skip the next byte, causing misaligned execution. Without a debugger,
  the SEH handler runs normally.
- **INT 3 (0xCC)** — software breakpoint. If the SEH handler is set up, the
  binary detects whether the handler ran (no debugger) or was intercepted.
- **Single-step exception** — set the trap flag, execute an instruction. Without
  a debugger, the SEH handler fires. Under a debugger, the debugger catches it.
- **Guard pages** — mark a page as guard. Accessing it fires an exception.
  Debuggers handle this differently from normal execution.

### TLS Callbacks

TLS (Thread Local Storage) callbacks execute before the program's main entry
point. Many debuggers break at the entry point, missing TLS callbacks entirely.
Malware uses TLS callbacks to perform anti-debug checks before the analyst's
breakpoint is hit.

```
Tool: find_anti_debug_comprehensive()

Example output:
  Anti-debug techniques detected:
    [HIGH] IsDebuggerPresent at 0x00401050 (called in TLS callback)
    [HIGH] NtQueryInformationProcess(ProcessDebugPort) at 0x00401120
    [MED]  RDTSC timing check at 0x00401200 (delta threshold: 0xFFFF)
    [MED]  PEB.BeingDebugged direct read at 0x004010A0
    [LOW]  INT 2D at 0x00401300 (exception-based)
  TLS callbacks found: 1 at 0x00401000
```

## Anti-VM Techniques

Virtual machine detection aims to identify analysis sandboxes. Malware that
detects a VM may exit cleanly, display benign behaviour, or corrupt its own
analysis artefacts.

### CPU-Level Detection

- **CPUID** — the hypervisor present bit (CPUID leaf 1, ECX bit 31) is set in
  most VMs. CPUID leaf 0x40000000 returns the hypervisor vendor string
  ("VMwareVMware", "Microsoft Hv", "KVMKVMKVM").
- **IN instruction** — `in eax, dx` with specific magic values communicates
  with VMware's backdoor interface. Crashes on real hardware.

### Registry and File System Artifacts

- Registry keys: `HKLM\SOFTWARE\VMware, Inc.`, `HKLM\SOFTWARE\Oracle\VirtualBox`
- File paths: `C:\Windows\System32\drivers\vmci.sys`, `C:\Windows\System32\vboxdisp.dll`
- Service names: VMTools, VBoxService, vmhgfs

### Hardware Fingerprinting

- **MAC address prefixes**: VMware (00:0C:29, 00:50:56), VirtualBox (08:00:27),
  Hyper-V (00:15:5D). Checking the first 3 bytes of the MAC address.
- **Disk size**: sandboxes often have small disks (<80GB).
- **RAM size**: sandboxes often have minimal RAM (<2GB or 4GB).
- **Screen resolution**: sandboxes may use unusual/default resolutions.
- **CPU core count**: single core is suspicious in a modern environment.

### Process and Service Enumeration

Malware enumerates running processes looking for analysis tool names:

- VM tools: `vmtoolsd.exe`, `vmwaretray.exe`, `VBoxService.exe`, `VBoxTray.exe`
- Sandbox agents: `SbieSvc.exe` (Sandboxie), `joeboxcontrol.exe`, `cuckoomon.dll`
- Analysis tools: `procmon.exe`, `wireshark.exe`, `x64dbg.exe`, `IDA*.exe`

## Obfuscation Techniques

### Control Flow Flattening

The original program's structured control flow (if/else, loops) is replaced
with a dispatcher pattern: all basic blocks are placed at the same nesting
level, and a state variable + switch statement controls which block executes
next.

```
Original:
  if (x > 0) { do_a(); } else { do_b(); }
  do_c();

Flattened:
  state = INIT;
  while (1) {
    switch (state) {
      case INIT:  state = (x > 0) ? DO_A : DO_B; break;
      case DO_A:  do_a(); state = DO_C; break;
      case DO_B:  do_b(); state = DO_C; break;
      case DO_C:  do_c(); state = EXIT; break;
      case EXIT:  return;
    }
  }
```

In the CFG, this appears as a central dispatcher node with edges to many blocks,
all of which loop back to the dispatcher. The function complexity is artificially
inflated.

### Opaque Predicates

Conditional branches where the outcome is always the same but is not obvious
from local inspection. Used to insert dead code paths and confuse analysis.

```
; Always true: x^2 + x is always even (x*(x+1) is always even)
mov eax, [var_x]
imul eax, eax        ; x^2
add eax, [var_x]     ; x^2 + x
test eax, 1          ; check if odd
jnz fake_path        ; never taken, but decompiler doesn't know
```

`propagate_constants` can sometimes resolve these when the input values are
known constants.

### Junk Code Insertion

Instructions that have no net effect on program state, inserted to increase
code size and confuse pattern matching:

```
push eax / pop eax           ; no-op pair
xor eax, 0x12345678          ; will be undone later
; ... real code ...
xor eax, 0x12345678          ; undo the earlier xor
```

### String Encryption

Strings are not stored in plaintext. Instead, encrypted bytes are stored in the
binary, and a decryption stub runs at load time or first use to produce the
cleartext on the stack or in a heap buffer. After use, the cleartext may be
zeroed.

Pattern to recognise in decompiled code:
```c
char buf[64];
for (int i = 0; i < len; i++)
    buf[i] = encrypted[i] ^ key[i % key_len];
// buf now contains the decrypted string
CreateFileA(buf, ...);
memset(buf, 0, sizeof(buf));  // wipe after use
```

```
Tool: find_and_decode_encoded_strings()

Attempts to identify and decode string encryption patterns, reporting both
the encryption method and the decoded cleartext strings.
```

### API Hashing

Instead of importing functions by name (which analysts can read), malware
resolves APIs at runtime by walking the PEB's module list, hashing each
export name, and comparing against a hardcoded hash value.

```c
// Typical API hash resolution loop
HMODULE mod = get_module_by_hash(0x6A4ABC5B);  // kernel32.dll
FARPROC fn = get_proc_by_hash(mod, 0x91AFCA54); // VirtualAlloc
fn(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

Common hash algorithms: CRC32, djb2, FNV-1a, ROR13, sdbm. The algorithm choice
is itself a family identifier — different malware families use different hashes.

```
Tool: scan_for_api_hashes()

Detects API hash resolution patterns and attempts to resolve the hash values
to known API names using common hashing algorithms.
```

## False Positives from Compiler Runtimes

Analysis tools (capa, YARA, import classifiers) flag APIs by capability — what
they *can* be used for. But many flagged APIs appear in binaries for completely
benign reasons. Before labelling any API as "anti-analysis", verify that the
binary contains **deliberate detection code** (a check + conditional branch),
not just a runtime import.

### Common false positives

| API | Flagged as | Benign explanation |
|-----|-----------|-------------------|
| `IsDebuggerPresent` | anti-debug | **Rust** stdlib (`std::panicking`) checks this to decide whether to break into debugger or print a backtrace on panic. **Delphi** VCL and **.NET** CLR use it similarly. Present in the IAT of virtually every Rust/Delphi/.NET Windows binary. |
| `QueryPerformanceCounter` | timing anti-debug | **Rust** `std::time::Instant` on Windows. **Go** `time.Now()`. Used by async runtimes (tokio, .NET ThreadPool) for scheduling. Present in any binary that measures elapsed time. |
| `GetTickCount` / `GetTickCount64` | timing anti-debug | Standard timer API. Used by HTTP clients for timeouts, by GUI frameworks for animation, by logging for timestamps. |
| `NtTerminateProcess` | anti-analysis / evasion | Reflective loaders hook this to intercept process exit and clean up loaded payloads. Commercial packers (EMERITA, Themida) use it for graceful teardown. Also used by crash reporters. |
| `VirtualProtect` | self-modifying code | Required by any loader that maps PE sections — code sections need PAGE_EXECUTE_READ, data sections need PAGE_READWRITE. Standard runtime behavior, not self-modification. |
| `VirtualAlloc` | injection / shellcode | Required for any dynamic memory allocation beyond the heap. Used by JIT compilers (.NET, Java), memory-mapped I/O, large buffer allocation. |
| `CreateProcessW` | execution | Used by any application that launches subprocesses — build tools, archive extractors (7z), package managers, shell utilities. |

### How to distinguish intentional anti-debug from incidental imports

An API import alone is never sufficient evidence. Look for the **usage pattern**:

**Intentional anti-debug** (real technique):
```c
if (IsDebuggerPresent()) {
    ExitProcess(0);  // or: decrypt with wrong key, or: jump to decoy code
}
```
The API result is checked and execution flow changes based on it. The code is
in user-written functions, not deep inside runtime initialization.

**Incidental import** (false positive):
```c
// Language runtimes — these are NOT anti-debug, they are developer tooling:

// Rust std::panicking — decides debugger break vs backtrace on panic
if (IsDebuggerPresent()) { DebugBreak(); } else { print_backtrace(); }

// Delphi VCL — raises debug notification on exception
if (IsDebuggerPresent()) { OutputDebugString(exception_info); }

// .NET CLR — managed debugger attach detection during startup
// Go runtime — similar panic/crash handling logic

// C/C++ with MSVC CRT — _CrtDbgReport checks debugger presence
if (IsDebuggerPresent()) { __debugbreak(); }
```
The API is called by the language runtime or standard library for developer
convenience. It does not alter the program's functional behavior or evade
analysis. This applies to **any language and runtime**, not just the examples
above — always check whether a flagged API is in user code or runtime code.

**Key questions to ask**:
1. Is the API called in user code or in a compiler/runtime library function?
2. Does the result control a branch that changes the program's core behavior?
3. Are there multiple layered checks (API + PEB + timing) suggesting deliberate
   anti-analysis? A single runtime import is not a "technique".

### YARA rule false positives

YARA rules that match on byte patterns (instruction sequences, constants) rather
than strings can produce false positives on compiled code. Common examples:
- Behavioral rules (e.g., `android_meterpreter`, `antisb_threatExpert`) matching
  coincidental byte sequences in compiled binaries of any language
- Crypto-detection rules matching legitimate TLS/crypto libraries (ChaCha20 in
  rustls/BoringSSL, AES-NI in OpenSSL/mbedTLS/WolfSSL, RC4 in legacy HTTP stacks)
- Network capability rules matching standard HTTP client libraries (hyper,
  WinHTTP, libcurl, Boost.Beast)

Always verify YARA matches by checking the matched offset — is it in user code
or in a known library? If the match is inside a crypto library, TLS
implementation, or HTTP framework, it is infrastructure code, not malware.
This applies regardless of the language the binary was written in.

## Detection and Bypass Strategies

| Technique | Detection tool | Bypass strategy |
|---|---|---|
| API anti-debug | `find_anti_debug_comprehensive` | Hook the API in emulation to return "not debugged" |
| PEB flag checks | Decompile + pattern match | Patch the PEB read or use emulation with clean PEB |
| Timing checks | `find_anti_debug_comprehensive` | Emulation runs at consistent speed (no timing delta) |
| Anti-VM checks | Decompile + string search | Emulation is not a VM — or hook the check APIs |
| Control flow flattening | `get_function_cfg` (dispatcher pattern) | Trace state variable transitions manually |
| Opaque predicates | `propagate_constants` | Resolve the constant and eliminate dead paths |
| String encryption | `find_and_decode_encoded_strings` | Or: emulate to the decryption point and read memory |
| API hashing | `scan_for_api_hashes` | Resolve hashes to names, then treat as normal imports |

## Socratic Questions

- "This function checks IsDebuggerPresent at the very start. If you were the
  malware author, why would you put it there and not somewhere else?"
  (Leads to: early checks prevent analysts from setting breakpoints deeper in)
- "The binary runs a timing check. How would you expect the measured time to
  differ between normal execution and debugging?"
  (Leads to: debugger single-stepping adds orders of magnitude to the delta)
- "The CFG shows a function with one huge central node and 30 edges going out
  and coming back. What does that pattern suggest?"
  (Leads to: control flow flattening with a dispatcher)
- "We found IsDebuggerPresent in the import table but also see direct PEB
  access. Why would the author use both?"
  (Leads to: defence in depth — API hooking bypasses one, direct PEB access
  catches the other)
- "This Rust binary imports IsDebuggerPresent. Is that anti-debug?"
  (Leads to: not necessarily — Rust's panic handler imports it to decide
  whether to break into a debugger or print a backtrace. Check whether the
  call site is in user code with a defensive branch, or in the stdlib. An
  import alone is not a technique.)

## Common Mistakes

### Assuming anti-analysis means the binary is malicious

Some commercial software uses anti-debug and anti-VM for DRM and license
enforcement. Commercial packers and protectors (Themida, VMProtect, EMERITA,
ASProtect) employ techniques that look identical to malware anti-analysis
when viewed through automated tooling. And as described in "False Positives
from Compiler Runtimes" above, many APIs flagged as anti-analysis are simply
part of the language runtime. A confirmed anti-analysis technique is a data
point, not a verdict — consider the full picture.

### Parroting tool labels without verification

When `get_focused_imports()` categorises an API as "anti_analysis" or a YARA
rule matches "anti_debug", these are **classification hints**, not confirmed
findings. The tools categorise by capability (what an API *can* do), not by
intent (what the developer *meant* it to do). Before reporting any API or
YARA match as an anti-analysis technique, verify the usage: decompile the
calling function, check whether the result controls a defensive branch, and
determine whether the code is in user-written logic or a runtime library.
Reporting `IsDebuggerPresent` as "anti-debug" in a Rust binary without
checking is a false positive — and undermines the credibility of the analysis.

### Focusing on bypass before understanding

Students often want to immediately bypass anti-debug. Teach them to first
understand what the check does and what happens if it succeeds. The anti-debug
code itself is intelligence — it reveals the author's sophistication and may
indicate the malware family.

### Missing chained checks

Malware often layers multiple anti-analysis checks. Bypassing IsDebuggerPresent
is insufficient if there is also a timing check and a PEB flag read. Use
`find_anti_debug_comprehensive` to get the full picture before attempting bypass.

### Confusing obfuscation with encryption

Obfuscation makes code hard to read but does not hide data — the instructions
are all there, just rearranged. Encryption transforms data into an unreadable
form that requires a key to reverse. String encryption is encryption applied
to data within obfuscated code. The distinction matters for choosing tools:
obfuscation is addressed with CFG analysis and constant propagation, encryption
requires key recovery and decryption tools.
