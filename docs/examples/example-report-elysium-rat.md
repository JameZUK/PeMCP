# Malware Analysis Report: Elysium RAT (SheetRAT) Plugin-Based .NET RAT

**Analyst:** Arkana Automated Analysis
**Date:** 2026-03-29
**Classification:** Remote Access Trojan (RAT) / Plugin Framework / .NET
**Risk Level:** CRITICAL (43/100)
**Source:** MalwareBazaar (same-day upload, signature: SheetRAT)

---

## 1. Executive Summary

This report documents the analysis of a **same-day MalwareBazaar sample** classified as "SheetRAT" -- a fully-featured **.NET 4.0 plugin-based Remote Access Trojan** whose internal name is **Elysium**. The binary was uploaded to MalwareBazaar hours before analysis began and had no prior public reverse engineering.

The sample uses a **custom two-alphabet substitution cipher** to encrypt over 400 string constants (API names, C2 addresses, registry paths, DLL names), combined with **control flow flattening** (numeric state-machine obfuscation) and **Math.\* constant hiding** (e.g., `2.0 * 3.0` instead of `6`). The obfuscation is custom-built -- de4dot identifies it as "Unknown Obfuscator."

Full ILSpy decompilation recovered **313 C# source files** across 310 classes. Breaking the substitution cipher revealed the complete C2 infrastructure: a **primary IP server** (`185.73.126.186:8808`) and a **dynamic DNS backup** (`fzotnmreqj.localto.net:2699`), with support for a **Dead Drop Resolver** mode ("PASTEMODE") that fetches C2 addresses from an external URL at runtime.

The RAT's architecture is a **plugin framework** -- the core binary handles C2 communication, persistence, and anti-analysis, while all heavy capabilities (file browser, keylogger, reverse shell, webcam capture) are loaded as **.NET DLL plugins stored in the Windows Registry** and invoked via reflection. Eight core commands were decoded: SaveInvoke, Invoke, Update, Uninstall, Restart, Pong, Exit, and Disconnect.

Defense evasion is comprehensive: **AMSI bypass** (patches `AmsiScanBuffer` with `mov eax, E_INVALIDARG; ret`), **ETW bypass** (patches `EtwEventWrite` with `xor rax, rax; ret`), **Windows Defender exclusion** via WMI, **sandbox detection** (Sandboxie, Avast, Comodo), and **process killing** (Task Manager, Process Hacker, Process Explorer). The sample disguises itself as **Paint.NET** and persists via scheduled tasks with mixed-case `schtASks` commands to evade string-based detection.

---

## 2. Sample Information

| Property | Value |
|----------|-------|
| **Filename** | sheetrat.exe |
| **SHA-256** | `285eeaf46e455ad7a4405c71c404750a6882e7718e31cf2ba9636ad79d147384` |
| **MD5** | `06a1882cfb40365ca45ad2bbd9dac240` |
| **ssdeep** | `6144:vv2yBCYf1VoGfExk1sYJe6VlWT8b9ho7XQfNbwKCrHJ3KtEBibwulsctNqL:vv2NgVoCLJPVle8twKCrHyEQ5Q` |
| **File Size** | 561,664 bytes (549 KB) |
| **Format** | PE32 (.NET CIL), Windows GUI |
| **Runtime** | CLR v2.5, metadata v4.0.30319 (.NET Framework 4.0) |
| **Signed** | No |
| **Sections** | 3 (.text, .rsrc, .reloc) |
| **Imports** | 1 function from 1 DLL (mscoree.dll `_CorExeMain`) |
| **GUID** | `a7805e28-c8db-482c-8b04-06c0ca884f7d` |
| **Assembly Title** | "Client" |
| **Copyright** | "Copyright (C) 2022" |
| **Internal Name** | Elysium |
| **Disguise** | Paint.NET |
| **MalwareBazaar Signature** | SheetRAT |

### PEiD False Positive

PEiD matched "fasm ->Tomasz Grysztar" (flat assembler) on the entry point bytes. This is a **false positive** -- the sole import of `_CorExeMain` from `mscoree.dll` confirms this is a standard .NET assembly. YARA correctly identified .NET signatures (11 rules matched), and `dotnet_analyze` confirmed CLR metadata with 50+ type definitions.

---

## 3. Obfuscation

### 3.1 String Encryption: Two-Alphabet Substitution Cipher

All 400+ sensitive strings are encrypted using a **character substitution cipher** with two 95-character lookup tables stored as static methods in class `WeIVPzHHkmljT`:

| Role | Method | Characters |
|------|--------|------------|
| Input alphabet | `UrtMCZaZZKsXJcc()` | `,"VjM29Y_G50e+oTXf}Jzq^tr~6d&;QwL1%RcW'sx...` |
| Output alphabet | `KvFnFRAE()` | `eVH$8}~]gsqXB0k?IODA.bmK i^!9d[pf27P|Y3W1z...` |

The decoder `mDWVIIga.ZOVcwRvrRPQdH()` iterates each input character, finds its position in the input alphabet, and returns the character at the same position in the output alphabet.

**Example decryptions:**

| Encoded | Decoded |
|---------|---------|
| `o,8\,ux%z;uu` | `kernel32.dll` |
| `c8.D,GGx%g~8G7` | `Process32First` |
| `J^G~\nD]\eU11,8` | `AmsiScanBuffer` |
| `Z\~\G7]uu` | `Uninstall` |
| `AM*zRxzA%:zAM:PMM+M ...` | `185.73.126.186:8808 fzotnmreqj.localto.net:2699` |

### 3.2 Control Flow Flattening

Every method uses numeric state-machine obfuscation -- genuine logic is wrapped in `while(true)` loops dispatching on an integer/double state variable:

```csharp
int num = 5990;
do {
    if (num == 5990) { num = 5998; }
} while (num != 5998);
// actual code here
```

### 3.3 Numeric Constant Obfuscation

Literal constants are replaced with `Math.*` expressions:

| Expression | Value | Purpose |
|-----------|-------|---------|
| `2.0 * 3.0` | 6 | `ProtocolType.Tcp` |
| `1.0 + 1.0` | 2 | `AddressFamily.InterNetwork` |
| `65.0 - Math.Tanh(32.0)` | ~64 | `PAGE_EXECUTE_READWRITE` (0x40) |
| `0x3CF0255F ^ 0x3CF0ED5F` | 51200 | Socket receive buffer size |

### 3.4 Class/Method Obfuscation

All 310 classes use randomised names within namespace `miaqwOWlv`. de4dot classifies the obfuscator as "Unknown" -- this is a custom protection, not ConfuserEx, .NET Reactor, or any recognised framework.

---

## 4. C2 Infrastructure

### 4.1 Connection Architecture

| Property | Value |
|----------|-------|
| **Protocol** | Raw TCP socket (IPv4, stream) |
| **Primary C2** | `185.73.126.186:8808` |
| **Backup C2** | `fzotnmreqj.localto.net:2699` |
| **DNS Provider** | localto.net (dynamic DNS) |
| **Wire Format** | 4-byte LE length header + GZip-compressed UTF-8 payload |
| **Message Separator** | `<@>` |
| **Encryption** | **None** -- only GZip compression (significant OPSEC weakness) |
| **C2 Selection** | Random choice from space-separated address list |
| **Keepalive** | Timer-based with randomised intervals (12-16s / 33-44s) |

### 4.2 Dead Drop Resolver

The RAT supports two C2 modes configured at build time:
- **IPMODE** (this sample): C2 addresses hardcoded in the binary
- **PASTEMODE**: C2 fetched at runtime from an external URL via `WebClient.DownloadString()`, split on `:` (char 58) -- designed for Google Sheets, Pastebin, or similar services

### 4.3 Registration Beacon

On successful connection, the client sends a **39-field registration packet** including:
- Base64-encoded screenshot thumbnail (50x50 JPEG)
- Machine name, processor count, total RAM
- Installed AV products (WMI query)
- Admin/user privilege status
- Client HWID (hardware fingerprint)
- Binary creation timestamp
- Connected webcam device name (COM enumeration)
- External IP address (fetched via 4 HTTP services)

---

## 5. Command Set

Eight commands decoded from the substitution cipher:

| Command | Handler | Action |
|---------|---------|--------|
| **SaveInvoke** | `xtlwrpJcAg` | Store plugin DLL in registry as binary blob + load via `AppDomain.Load` |
| **Invoke** | `OtvcbgmbLB` | Request plugin by name; if not cached, sends `getDLL<@>name` to server |
| **Update** | `IGUtExGqem` | Receive base64 payload → write temp .exe → uninstall old → install new |
| **Uninstall** | `maAKhqdSXrKRS` | Remove persistence → create `.bat` self-delete → `Environment.Exit()` |
| **Restart** | `fwvOxNyM` | `cmd.exe /k timeout 5 > NUL && "path"` (hidden window, re-execute) |
| **Pong** | `UsRGfcoLL` | Keepalive response -- sends idle counter back, resets to 0 |
| **Exit** | `KwgHTyhJW` | `Environment.Exit()` with random exit code |
| **Disconnect** | `cdPSZShH` | Close socket, triggers reconnection loop |

---

## 6. Plugin Architecture

The most significant finding: **Elysium is a plugin framework**, not a monolithic RAT. The core binary handles only C2, persistence, and anti-analysis. All heavy capabilities are loaded on demand as .NET DLL plugins.

### 6.1 Plugin Lifecycle

1. C2 server sends **Invoke** command with plugin name
2. Client checks registry cache (`HKCU\Software\{HWID}\{name}`)
3. If not cached, opens sub-connection and requests: `getDLL<@>{name}`
4. Server responds with **SaveInvoke**: name + base64-encoded DLL bytes
5. Plugin stored in **Windows Registry** as binary value (survives reboots)
6. Loaded via `AppDomain.CurrentDomain.Load(bytes)` (Assembly.Load)
7. Entry point: dynamically invokes `Run(c2_address, client_hwid, parameter)` via C# `CallSite` binder
8. Fallback: if `Run` method signature doesn't match, tries alternate signature with base64-decoded parameter

### 6.2 Registry-Based Plugin Storage

Plugins persist in `HKCU\Software\{HWID}\{plugin_name}` as `REG_BINARY` values. This means:
- Plugins survive system reboots without touching the filesystem
- No DLL files on disk for AV to scan
- Plugin cache tied to the specific hardware fingerprint

---

## 7. Defense Evasion

### 7.1 AMSI Bypass

Patches `AmsiScanBuffer` in `amsi.dll` with architecture-specific shellcode:

| Architecture | Patch Bytes | Assembly | Effect |
|-------------|-------------|----------|--------|
| x86 (32-bit) | `B8 57 00 07 80 C2 18 00` | `mov eax, 0x80070057; ret 0x18` | Return `E_INVALIDARG` |
| x64 (64-bit) | `B8 57 00 07 80 C3` | `mov eax, 0x80070057; ret` | Return `E_INVALIDARG` |

Patch bytes found at PE offset **0x250**. Uses `VirtualProtect` with `PAGE_EXECUTE_READWRITE` (0x40) to make the target writable before patching.

### 7.2 ETW Bypass

Patches `EtwEventWrite` in `ntdll.dll`:

| Architecture | Patch Bytes | Assembly | Effect |
|-------------|-------------|----------|--------|
| x86 (32-bit) | `33 C0 C2 14 00` | `xor eax, eax; ret 0x14` | Return success (0) |
| x64 (64-bit) | `48 33 C0 C3` | `xor rax, rax; ret` | Return success (0) |

Patch bytes found at PE offset **0x258** (x64) and **0x268** (x86).

### 7.3 Windows Defender Evasion

- WMI query `SELECT * FROM MSFT_MpPreference` on `root\Microsoft\Windows\Defender`
- Adds **ExclusionPath** for the binary's directory
- Adds **Windows Firewall exclusion** via WMI `SetSecurityDescriptor`

### 7.4 Anti-Analysis Process Killing

Continuously enumerates running processes via `CreateToolhelp32Snapshot` / `Process32First` / `Process32Next` and terminates:

| Process | Purpose |
|---------|---------|
| `Taskmgr.exe` | Windows Task Manager |
| `ProcessHacker.exe` | Process Hacker analysis tool |
| `procexp.exe` | Sysinternals Process Explorer |

Uses `OpenProcess` + `TerminateProcess` or `Environment.Exit(0)` depending on configuration.

### 7.5 Sandbox Detection

Checks for analysis environment DLLs loaded in the current process:

| DLL | Product |
|-----|---------|
| `SbieDll.dll` | Sandboxie |
| `snxhk.dll` | Avast sandbox hook |
| `cmdvrt32.dll` | Comodo sandbox |

### 7.6 Anti-VM Detection (Disabled)

The sample includes WMI-based VM detection (disabled in this build via `IvNzzdZT = "false"`):
- `Select * from Win32_CacheMemory` -- empty in most VMs
- `Select * from CIM_Memory` -- returns fewer entries in VMs
- `Win32_DiskDrive` → Manufacturer/Name/Model -- checks for "VMware", "VBOX", "Virtual"

### 7.7 Mixed-Case Command Evasion

Scheduled task commands use deliberate mixed case to evade string-based detection rules:
- `schtASks /deLeTe /F /Tn`
- `scHTaSks /Run /I /TN`

---

## 8. Persistence

### 8.1 Scheduled Task

| Property | Value |
|----------|-------|
| Task name | `Sheet_nbszmiyxtax` |
| Create command | `cmd /c scHTaSks /Run /I /TN "Sheet_nbszmiyxtax"` |
| Delete command | `cmd /c schtASks /deLeTe /F /Tn "Sheet_nbszmiyxtax"` |

### 8.2 Registry Run Keys

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` -- standard user persistence
- `Userinit` key modification for admin-level persistence
- `DelegateExecute` value manipulation

### 8.3 Install Logic

- **Admin path**: Firewall exclusion → copy binary to install directory → create scheduled task + registry Run key
- **Non-admin path**: Copy binary → registry Run key only
- Install directory disguised as **Paint.NET** in user AppData
- MD5 hash comparison prevents re-installing identical binary
- Uninstall creates `.bat` file: `@echo off / timeout 5 > NUL` → self-delete via `cmd.exe`

---

## 9. Additional Capabilities

### 9.1 Screenshot Capture

`rCFLLTJqX.rTLGxNPG()` captures the primary screen using `Graphics.CopyFromScreen()`, resizes to a 50x50 JPEG thumbnail, and includes it in the registration beacon. Full-resolution screenshots are likely handled by a server-side plugin.

### 9.2 Webcam/Microphone Enumeration

Uses COM `ICreateDevEnum` interface to enumerate DirectShow filter categories:

| GUID | Category |
|------|----------|
| `{860BB310-5D01-11d0-BD3B-00A0C911CE86}` | Video Input Devices (webcams) |
| `{62BE5D10-60EB-11d0-BD3B-00A0C911CE86}` | Audio Input Devices |
| `{55272A00-42CB-11CE-8135-00AA004BB851}` | Audio Capture Devices (microphones) |

Reads `FriendlyName` property for each device and sends the list to C2 in the registration beacon.

### 9.3 System Fingerprinting

| Source | Data Collected |
|--------|---------------|
| `Environment.MachineName` | Computer name |
| `Environment.ProcessorCount` | CPU core count |
| `ComputerInfo.TotalPhysicalMemory` | Total RAM |
| `WindowsIdentity.GetCurrent()` | Admin/user status |
| `PerformanceCounter` | CPU usage monitoring |
| WMI `Win32_DiskDrive` | Disk manufacturer/model |
| WMI antivirus query | Installed AV products |
| 4 HTTP services | External IP address |

### 9.4 External IP Discovery

The RAT attempts to resolve its external IP via four web services in sequence, using a custom User-Agent and 5-second timeout. If all fail, returns a default value.

---

## 10. Security Mitigations

| Feature | Status |
|---------|--------|
| ASLR | Enabled |
| DEP/NX | Enabled |
| No SEH | True |
| High Entropy ASLR | Disabled |
| Control Flow Guard | Disabled |
| Code Integrity | Disabled |

Standard .NET defaults -- ASLR/DEP enabled by the compiler.

---

## 11. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| **Command and Scripting Interpreter** | T1059.003 | `cmd.exe /k timeout 5 > NUL && "path"` for restart/delete |
| **Scheduled Task/Job** | T1053.005 | `schtasks` create/run/delete with mixed-case evasion |
| **Registry Run Keys** | T1547.001 | HKCU Run key, Userinit key modification |
| **Masquerading** | T1036.005 | Disguised as "Paint.NET" in AppData |
| **Impair Defenses: Disable or Modify Tools** | T1562.001 | AMSI bypass (AmsiScanBuffer patch), ETW bypass (EtwEventWrite patch) |
| **Impair Defenses: Disable Windows Event Logging** | T1562.002 | EtwEventWrite patched to return 0 |
| **Modify Registry** | T1112 | Plugin DLLs stored as registry binary values |
| **Process Discovery** | T1057 | CreateToolhelp32Snapshot process enumeration |
| **Security Software Discovery** | T1518.001 | WMI antivirus query, Defender preference check |
| **Virtualization/Sandbox Evasion** | T1497.001 | SbieDll.dll, snxhk.dll, cmdvrt32.dll checks |
| **Debugger Evasion** | T1622 | RDTSC x5, CPUID x2 byte patterns in .text section |
| **Application Layer Protocol** | T1071 | Raw TCP socket C2 with GZip compression |
| **Dynamic Resolution: Dead Drop Resolver** | T1568.002 | PASTEMODE fetches C2 from external URL |
| **Ingress Tool Transfer** | T1105 | Plugin DLLs downloaded from C2 |
| **Reflective Code Loading** | T1620 | `AppDomain.CurrentDomain.Load()` for plugin execution |
| **Screen Capture** | T1113 | `Graphics.CopyFromScreen()` screenshot in beacon |
| **Video Capture** | T1125 | COM ICreateDevEnum webcam enumeration |
| **Audio Capture** | T1123 | COM AudioInputDeviceCategory enumeration |
| **System Information Discovery** | T1082 | Machine name, CPU count, RAM, disk info |
| **File and Directory Discovery** | T1083 | MD5 hash file comparison for install dedup |
| **Exfiltration Over C2 Channel** | T1041 | All data exfiltrated over primary TCP socket |

---

## 12. Indicators of Compromise

### 12.1 File Hashes

| Hash | Value |
|------|-------|
| SHA-256 | `285eeaf46e455ad7a4405c71c404750a6882e7718e31cf2ba9636ad79d147384` |
| MD5 | `06a1882cfb40365ca45ad2bbd9dac240` |
| ssdeep | `6144:vv2yBCYf1VoGfExk1sYJe6VlWT8b9ho7XQfNbwKCrHJ3KtEBibwulsctNqL:vv2NgVoCLJPVle8twKCrHyEQ5Q` |

### 12.2 Network

| Type | Value |
|------|-------|
| C2 IP | `185.73.126.186:8808` |
| C2 Domain | `fzotnmreqj.localto.net:2699` |
| DNS Provider | localto.net (dynamic DNS) |

### 12.3 Registry

| Key | Purpose |
|-----|---------|
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Persistence |
| `HKCU\Software\{HWID}\*` | Plugin DLL cache (binary blobs) |

### 12.4 File System

| Path | Purpose |
|------|---------|
| `%AppData%\Paint.NET\` | Install directory (disguised) |
| `%TEMP%\*.exe` | Update staging |
| `%TEMP%\*.bat` | Self-deletion script |

### 12.5 Scheduled Task

| Property | Value |
|----------|-------|
| Task name | `Sheet_nbszmiyxtax` |

### 12.6 AMSI/ETW Patch Signatures

| Target | Architecture | Patch Bytes |
|--------|-------------|-------------|
| `AmsiScanBuffer` | x86 | `B8 57 00 07 80 C2 18 00` |
| `AmsiScanBuffer` | x64 | `B8 57 00 07 80 C3` |
| `EtwEventWrite` | x64 | `48 33 C0 C3` |
| `EtwEventWrite` | x86 | `33 C0 C2 14 00` |

### 12.7 Anti-Analysis Indicators

| Check | Target |
|-------|--------|
| DLL load check | `SbieDll.dll` (Sandboxie) |
| DLL load check | `snxhk.dll` (Avast sandbox) |
| DLL load check | `cmdvrt32.dll` (Comodo sandbox) |
| Process kill | `Taskmgr.exe`, `ProcessHacker.exe`, `procexp.exe` |
| WMI query | `Select * from Win32_CacheMemory` |
| WMI query | `Select * from CIM_Memory` |

### 12.8 Obfuscation Fingerprints

| Indicator | Value |
|-----------|-------|
| .NET namespace | `miaqwOWlv` |
| Assembly GUID | `a7805e28-c8db-482c-8b04-06c0ca884f7d` |
| Assembly title | "Client" |
| Cipher class | `WeIVPzHHkmljT` (2229 lines, 400+ encoded strings) |
| Decoder method | `mDWVIIga.ZOVcwRvrRPQdH()` |

---

## 13. Conclusion

**Elysium** (tracked by MalwareBazaar as "SheetRAT") is a **plugin-based .NET RAT framework** with a deceptively simple core -- only 8 built-in commands -- that serves as a delivery platform for unlimited server-side plugin capabilities. The plugin architecture, combined with **registry-based DLL storage**, means the RAT's full capability set is invisible to static analysis of the core binary alone.

The custom obfuscation (substitution cipher + control flow flattening + Math.\* constant hiding) successfully defeated de4dot's obfuscator identification, but the underlying protection is straightforward once the two alphabet arrays are extracted. A critical OPSEC failure is the **complete absence of C2 encryption** -- traffic is only GZip compressed, making all communications trivially interceptable with network monitoring.

This analysis demonstrates Arkana's ability to perform **end-to-end reverse engineering of an unknown .NET RAT** -- from initial triage of an unclassified MalwareBazaar sample through .NET decompilation, custom cipher breaking, C2 infrastructure extraction, AMSI/ETW patch byte recovery, full command set enumeration, and plugin architecture reconstruction. The complete decompiled source (313 C# files) and detection artifacts (YARA, Sigma, ATT&CK Navigator layer) were generated in a single automated session.

---

*Report generated from Arkana .NET decompilation, custom cipher decryption, and deep-dive analysis across 313 recovered source files.*
