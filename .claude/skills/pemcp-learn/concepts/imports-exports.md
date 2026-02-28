# Concept Reference: Imports & Exports

Foundation tier reference for Module 1.4. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

Imports and exports are the mechanism by which binaries interact with the
operating system and with each other. An import is a function the binary needs
from an external library (DLL). An export is a function the binary makes
available for others to call. Together, they form the binary's interface with
the outside world.

### The Shopping List Analogy

"Think of a binary like a chef preparing a meal. The chef has their own skills
(the code in .text), but they need ingredients from the grocery store (the OS
and its DLLs). The import table is the shopping list — it says exactly which
ingredients are needed and from which store (DLL) to get them. If the chef
needs flour from the bakery aisle (kernel32.dll) and spices from the spice
shop (advapi32.dll), those are separate entries on the list."

Extend:
- **The Import Address Table (IAT)** = the shopping list with blank price tags.
  When the binary loads, the OS "fills in" the actual memory addresses of each
  function. The IAT starts as a list of names and becomes a list of addresses.
- **Exports** = the menu board at a restaurant. If the binary is a DLL, its
  export table advertises what functions it offers to callers.

## Dynamic Linking Explained Simply

When a binary calls `CreateFileW`, it does not contain the code for
`CreateFileW`. Instead:

1. The import table says: "I need `CreateFileW` from `kernel32.dll`"
2. When Windows loads the binary, it also loads `kernel32.dll` into memory
3. Windows looks up the address of `CreateFileW` in kernel32's export table
4. Windows writes that address into the binary's IAT
5. When the binary calls `CreateFileW`, it reads the address from the IAT and
   jumps there

This process is called **dynamic linking** because the connection between the
binary and its dependencies is made at load time, not at compile time.

### Runtime Resolution (LoadLibrary + GetProcAddress)

Some binaries do not list all their imports statically. Instead, they:

1. Call `LoadLibrary("suspicious.dll")` to load a library at runtime
2. Call `GetProcAddress(handle, "HiddenFunction")` to get the function address
3. Call the function through the returned pointer

This is **runtime API resolution**. It is used legitimately (plugin systems,
optional features) but is also a key malware technique for hiding imports from
static analysis. If a binary has very few static imports but calls LoadLibrary
and GetProcAddress, it is likely resolving additional APIs at runtime.

Teaching point: "If the shopping list is suspiciously short, the chef might be
buying ingredients on the way to the kitchen — one at a time, so nobody sees
the full list."

### DLL Search Order

When a binary requests a DLL, Windows searches for it in a specific order:
1. The directory containing the executable
2. The system directory (C:\Windows\System32)
3. The 16-bit system directory
4. The Windows directory
5. The current directory
6. Directories in the PATH environment variable

**DLL sideloading** exploits this: an attacker places a malicious DLL with a
legitimate name in the application's directory, and Windows loads it before
finding the real one. This is a common technique in APT campaigns.

## Suspicious Import Combinations

Teach the learner to recognise these functional groupings. The key insight is
that individual imports are not suspicious — it is the combination that reveals
behaviour.

### Process Injection

| API | Purpose |
|-----|---------|
| `OpenProcess` | Get handle to target process |
| `VirtualAllocEx` | Allocate memory in remote process |
| `WriteProcessMemory` | Write code into allocated memory |
| `CreateRemoteThread` | Execute the written code |

This combination enables classic DLL/code injection.

### Networking

| API | Purpose |
|-----|---------|
| `WSAStartup` / `socket` / `connect` | Raw socket communication |
| `InternetOpenA/W` / `HttpOpenRequest` | HTTP/HTTPS communication |
| `URLDownloadToFile` | Download a file from a URL |
| `WinHttpOpen` / `WinHttpSendRequest` | Modern HTTP client |

### Persistence

| API | Purpose |
|-----|---------|
| `RegSetValueExA/W` | Write registry values (Run keys, services) |
| `CreateServiceA/W` | Install a Windows service |
| `CopyFileA/W` + path to startup folder | Drop copy to auto-start location |

### Crypto

| API | Purpose |
|-----|---------|
| `CryptAcquireContext` | Initialise crypto provider |
| `CryptEncrypt` / `CryptDecrypt` | Encrypt/decrypt data |
| `CryptImportKey` | Import a crypto key |
| `BCryptEncrypt` / `BCryptDecrypt` | Modern crypto API |

### Anti-Analysis

| API | Purpose |
|-----|---------|
| `IsDebuggerPresent` | Check for attached debugger |
| `NtQueryInformationProcess` | Check debug flags |
| `GetTickCount` / `QueryPerformanceCounter` | Timing-based anti-debug |
| `CheckRemoteDebuggerPresent` | Remote debugger detection |

### Imphash

The import hash (imphash) is an MD5 hash of the binary's import table
(DLL names + function names, normalised and ordered). Binaries compiled from
the same source with the same compiler settings produce the same imphash, even
if the code changes slightly. This makes imphash valuable for clustering
related samples and identifying malware families.

## Key PeMCP Tools

- **`get_focused_imports()`** — The primary tool. Returns security-relevant
  imports categorised by threat behaviour (networking, process manipulation,
  crypto, persistence, anti-analysis, etc.) with risk ratings. Always start
  here rather than reading the full import table.
- **`get_pe_data(key='imports')`** — Full unfiltered import table listing every
  DLL and every imported function. Use when you need the complete picture or
  want to examine non-security-relevant imports (e.g., UI libraries, math
  functions).
- **`get_pe_data(key='exports')`** — Export table for DLLs. Shows function
  names, ordinals, and forwarded exports. Use when analysing a DLL to understand
  its interface.
- **`get_import_hash_analysis()`** — Generates the imphash and compares it
  against known families. Use to check for family matches and cluster samples.

### Teaching Moment: get_focused_imports Output

When the learner first sees `get_focused_imports()` output, walk through:
- The behavioural categories and what each means
- The risk levels (CRITICAL, HIGH, MEDIUM) and how they are assigned
- The difference between "this API exists in the imports" and "this API is
  actually called in a malicious way" — imports show capability, not proof

## Socratic Questions

- "If a binary imports VirtualAllocEx and WriteProcessMemory together, what
  behaviour might that enable?"
  (Expected insight: writing data into another process's memory — a core step
  in process injection)
- "Why does this binary have only 3 imports?"
  (Expected insight: likely packed — the real imports are resolved after
  unpacking; or it uses LoadLibrary/GetProcAddress for runtime resolution)
- "This DLL exports a function called 'ServiceMain'. What does that tell you?"
  (Expected insight: the DLL is designed to run as a Windows service)
- "We see both CreateFileA and CreateFileW imported. Why both?"
  (Expected insight: A suffix = ANSI, W suffix = Wide/Unicode. The program
  handles both string types, or different code paths use different variants)
- "The imphash matches a known malware family. Does that prove this binary is
  malicious?"
  (Expected insight: imphash shows the import structure is identical, which
  strongly suggests a relationship, but the binary could also be a legitimate
  tool that happens to import the same functions. Corroborate with other
  evidence.)
- "If an attacker wanted to hide their imports, how might they do it?"
  (Expected insight: use LoadLibrary/GetProcAddress for runtime resolution,
  use API hashing to obscure function names, or pack the binary so the
  real import table is only visible after unpacking)

## Common Misconceptions

### "Imports prove malicious intent"

Importing VirtualAllocEx does not make a binary malicious. Legitimate software
(debuggers, profilers, process managers, anti-virus) uses these same APIs.
Imports show what a binary CAN do — not what it DOES do or WHY. Malicious
intent is established by analysing HOW the APIs are used in context, not by
their mere presence. Teach the difference between capability and intent.

### "More imports = more suspicious"

The opposite is often true. A binary with a rich, diverse import table is likely
a normal application that uses many OS features. A binary with suspiciously few
imports (e.g., only LoadLibrary, GetProcAddress, and VirtualProtect) is more
concerning — it suggests the real functionality is hidden through runtime
resolution or packing.

### "If an import is not in the table, the binary cannot use that function"

Runtime API resolution via LoadLibrary/GetProcAddress lets a binary call any
function from any DLL without it appearing in the static import table. API
hashing takes this further — the function names themselves are replaced with
hash values, resolved at runtime. Always consider that the static import
table shows the minimum set of capabilities, not the complete set.

### "Export names always match function purposes"

Export names can be anything. Malware authors deliberately use misleading
export names (e.g., exporting `ServiceMain` or `DllRegisterServer` to appear
legitimate). Export forwarding can also redirect calls to unexpected locations.
The export name is a label, not a guarantee.

### "DLLs are always library code"

DLLs can contain any code, including complete malware functionality. Many
malware families are distributed as DLLs that are loaded via rundll32.exe,
regsvr32.exe, or DLL sideloading. A DLL is just a binary format — it does not
imply the code is a benign library.

## When to Teach This

- **After PE structure**: Understanding that the import and export tables are
  data directories within the PE headers provides necessary context.
- **During triage**: When `get_focused_imports()` output is on screen, explain
  each category and what the risk levels mean.
- **When import count is anomalous**: Very few imports (< 10) is a natural
  bridge to the packing concept. Many security-relevant imports bridge to
  capability analysis (Module 2.5).
- **When analysing a DLL**: The export table becomes the focus. Explain how
  exports define the DLL's interface and how they can be misleading.
- **When LoadLibrary/GetProcAddress appear**: This is the natural teaching
  moment for runtime API resolution and why it is used to hide imports.
