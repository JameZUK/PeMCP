# Search Patterns for Decompilation & Disassembly

Quick reference for the `search`, `context_lines`, and `case_sensitive` parameters on
`decompile_function_with_angr`, `batch_decompile`, and `get_annotated_disassembly`.

---

## When to Search vs Read Full Output

| Situation | Approach | Why |
|-----------|----------|-----|
| First look at unknown function | Full decompile | Need complete picture |
| Verifying a hypothesis | `search="pattern"` | Targeted check, saves ~90% tokens |
| Finding specific API calls in large function | `search="APIName"` | Jump to relevant lines |
| Tracing a variable through a function | Full decompile + rename | Search can't show data flow |
| Scanning many functions for a pattern | `batch_decompile(..., search="...")` | Only matching functions returned |
| Understanding small function (<30 lines) | Full decompile | Search overhead not worth it |
| Locating crypto loop in large function | `search="xor\|shr\|shl"` | Find crypto without reading setup |
| Need full control flow understanding | Full decompile | Search fragments lose structure |
| Cross-referencing decompile vs disassembly | Search both with same pattern | Compare at same point |

**Rule of thumb**: Search when you have a hypothesis; full output when building
understanding from scratch.

---

## Regex Pattern Reference

### Crypto & Encoding Operations

| Goal | Pattern | Tool | ctx |
|------|---------|------|-----|
| XOR operations | `xor\|XOR` | decompile, disasm | 2 |
| Bitwise crypto | `shr\|shl\|ror\|rol\|>>\|<<` | decompile, disasm | 3 |
| AES/RC4/DES | `aes\|rc4\|des\|crypt\|rijndael\|blowfish` | decompile | 2 |
| Crypto APIs | `Crypt[A-Z]\|BCrypt\|NCrypt` | decompile | 3 |
| Key/IV setup | `key\|iv\|nonce\|salt\|seed` | decompile | 3 |
| Byte array init | `\[.*\]\s*=\s*\{` | decompile | 5 |

### Network & C2 Communication

| Goal | Pattern | Tool | ctx |
|------|---------|------|-----|
| Socket ops | `socket\|connect\|send\|recv\|bind\|listen\|accept` | decompile | 3 |
| WinSock | `WSA\|Winsock\|ws2` | decompile, disasm | 2 |
| HTTP | `http\|InternetOpen\|HttpSend\|WinHttp\|urlmon` | decompile | 3 |
| URL/domain | `https?://\|www\.\|port` | decompile | 2 |
| DNS | `getaddrinfo\|gethostbyname\|DnsQuery` | decompile | 2 |

### Process Injection & Execution

| Goal | Pattern | Tool | ctx |
|------|---------|------|-----|
| Classic injection | `VirtualAlloc\|WriteProcess\|CreateRemoteThread` | decompile | 3 |
| Process creation | `CreateProcess\|ShellExecute\|WinExec\|system` | decompile | 3 |
| Memory mapping | `NtMap\|ZwMap\|MapViewOfFile\|VirtualProtect` | decompile | 3 |
| Thread manipulation | `CreateThread\|ResumeThread\|SuspendThread` | decompile | 2 |
| APC injection | `QueueUserAPC\|NtQueueApc` | decompile | 3 |

### Persistence & Evasion

| Goal | Pattern | Tool | ctx |
|------|---------|------|-----|
| Registry | `Reg[A-Z]\|RegSet\|RegCreate\|HKEY_` | decompile | 3 |
| Services | `CreateService\|StartService\|OpenSCManager` | decompile | 3 |
| Scheduled tasks | `schtask\|ITaskScheduler` | decompile | 2 |
| Startup | `\\\\Run\|\\\\RunOnce\|Startup\|CurrentVersion` | decompile | 3 |
| Anti-debug (code) | `IsDebugger\|CheckRemote\|NtQueryInformation` | decompile | 3 |
| Anti-debug (asm) | `rdtsc\|cpuid\|int 0x2d\|int3` | disasm | 3 |
| Anti-VM | `vmware\|vbox\|qemu\|hyperv\|xen` | decompile | 2 |

### File & Resource Operations

| Goal | Pattern | Tool | ctx |
|------|---------|------|-----|
| File I/O | `CreateFile\|WriteFile\|ReadFile\|DeleteFile` | decompile | 3 |
| File paths | `C:\|%[A-Z]+%\|AppData\|Temp\|System32` | decompile | 2 |
| Resources | `FindResource\|LoadResource\|LockResource` | decompile | 3 |

### String & Memory Operations

| Goal | Pattern | Tool | ctx |
|------|---------|------|-----|
| String funcs | `strcmp\|strcat\|sprintf\|strlen\|memcpy\|wcs` | decompile | 2 |
| Unsafe patterns | `sprintf\|strcpy\|strcat\|gets\|scanf` | decompile | 3 |
| Buffer ops | `malloc\|calloc\|HeapAlloc\|VirtualAlloc` | decompile | 2 |

### Control Flow

| Goal | Pattern | Tool | ctx |
|------|---------|------|-----|
| Switch dispatch (C2 handlers) | `case\|switch\|== 0x` | decompile | 5 |
| Loop bodies | `while\|for\s*\(\|do\s*\{` | decompile | 5 |
| Error handling | `GetLastError\|SetLastError\|FAILED\|SUCCEEDED` | decompile | 2 |

---

## Workflow Recipes

### 1. Triage Sweep — Find Suspicious Code Across Many Functions

1. `get_function_map(limit=20)` — top-ranked addresses
2. `batch_decompile(addresses, search="VirtualAlloc|WriteProcess|CreateRemote")`
   — only injection functions returned
3. Full decompile matching functions for context

Token savings: ~20 functions x ~100 lines = ~2000 lines → search returns ~15-30 lines

### 2. Crypto Hunt

1. `batch_decompile(addresses, search="xor|shr|shl|rc4|aes|crypt")`
2. Full decompile matches to understand algorithm
3. `get_annotated_disassembly(addr, search="xor|shr|shl|rol|ror")`
   — verify in assembly (decompiler may miss bitwise detail)

### 3. C2 Extraction

1. `batch_decompile(addresses, search="socket|connect|http|send|recv|Internet")`
2. Full decompile networking function
3. `get_function_xrefs(addr)` — trace callers
4. Decompile callers with `search="http|url|://|port"`

### 4. Anti-Debug Discovery

1. `batch_decompile(addresses, search="IsDebugger|CheckRemote|NtQuery|OutputDebug")`
2. `get_annotated_disassembly(addr, search="rdtsc|cpuid|int 0x2d|int3")`
   — assembly-level checks the decompiler may optimize away

### 5. Vulnerability Audit

1. `batch_decompile(addresses, search="sprintf|strcpy|strcat|gets|scanf")`
2. Full decompile matches to check if input is user-controlled
3. `get_backward_slice(addr, variable)` on the buffer argument

---

## Context Lines Guide

| Scenario | context_lines | Rationale |
|----------|---------------|-----------|
| Quick existence check | 1-2 | Just confirm presence |
| How an API is called (arguments) | 2-3 (default) | See assignments before the call |
| Crypto loop analysis | 5-8 | Loop setup, body, iteration together |
| Switch/case dispatch | 5-10 | Cases are multi-line |
| Buffer overflow audit | 3-5 | Declaration + size + unsafe call |

Default: 2. Maximum: 20. Max matches per search: 500.

---

## When NOT to Search

- **Full function understanding**: First encounter, need overall purpose
- **Data flow tracing**: Use `get_reaching_definitions` or `get_backward_slice`
- **Type recovery**: Struct layouts need all field accesses together
- **Control flow comprehension**: All branches, loop conditions, early returns
- **Small functions (<30 lines)**: Full output is already compact
- **Rename-heavy workflows**: Need all usages visible for renaming
