# Malware Analysis Report: SalatStealer 3-Layer Info Stealer

**Analyst:** Arkana Automated Analysis (multi-session)
**Date:** 2026-03-28
**Classification:** Information Stealer / Loader / Credential Harvester
**Risk Level:** CRITICAL (70/100)
**Source:** Malware Bazaar (uploaded 2026-03-27, same day as analysis)
**Attribution:** SalatStealer family, dropped by GCleaner

---

## 1. Executive Summary

This report documents the **complete 3-layer reverse engineering of SalatStealer** — a previously unanalysed Go-based information stealer obtained from Malware Bazaar within hours of its first appearance. The analysis demonstrates Arkana's ability to peel through multiple protection layers: AES-256-CBC encryption, UPX 5.02 LZMA packing, and Go binary analysis — all from a single starting point.

The sample is a **PE32+ (x64) console application** (4.8 MB) acting as a **cryptographic loader**: it checks for administrator privileges, disables Windows Defender via dual-method exclusion (direct registry + PowerShell fallback), then AES-256-CBC decrypts a 3.6 MB payload from its `.data` section, drops it as a temporary `.exe`, and executes it with `CREATE_NO_WINDOW`. The dropped payload is itself **UPX 5.02 packed** (LZMA compression) wrapping a **12.9 MB Go-compiled stealer**.

**Key findings:**
- **3-layer matryoshka architecture**: MSVC x64 loader → UPX 5.02 LZMA wrapper → Go stealer (internal package name `salat/`)
- **Dual-method Defender evasion**: Direct registry write to `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` (stealthy, no telemetry) with PowerShell `Add-MpPreference` fallback (reliable but noisy)
- **AES-256-CBC decryption fully reversed**: Key, IV, and encrypted payload extracted from decompiled pseudocode; payload successfully decrypted using Binary Refinery
- **UPX 5.02 LZMA manually decompressed**: UPX stub reverse-engineered to extract compression parameters (lc=3, lp=0, pb=2, dict=2^24); LZMA header reconstructed for native decompression
- **Comprehensive stealer targeting**: 12+ Chromium browsers, 4 Firefox variants, 23+ crypto wallets, Telegram, Discord, Steam, plus LSASS credential dump and screenshot capture
- **Advanced C2**: DNS-over-HTTPS (Cloudflare, Google) for stealthy domain resolution, multipart HTTP upload for encrypted data exfiltration
- **Task Scheduler persistence** via `capnspacehook/taskmaster` Go library

---

## 2. Sample Information

| Property | Value |
|----------|-------|
| **Filename** | `file` (Malware Bazaar) / `salat_stealer.exe` (analysis) |
| **SHA-256** | `f8a26bce0b29bfaa0351133aff6b85e31dfa7c46280c8b9559829857b6ca7681` |
| **MD5** | `a568678f0be3be4a088fbd64d4f008d0` |
| **SHA-1** | `a5493e0fa353f14e9a652ed27f9c6302a34f39b9` |
| **ssdeep** | `98304:n12xIZT5pBqSwqgK6dP6UfQbUxK6I/X0x7D8Y9MzwnTYDMnyzj:nYIFBqSwI0YcK6u0x7IYKKWxH` |
| **TLSH** | `T18B26339B36F0B2F6C427427EE053AA42F371703206485B6F038543976F67616FE396A9` |
| **Imphash** | `bfee7c7e234d73184f6b414fec537224` |
| **File Size** | 4,786,176 bytes (4.8 MB) |
| **Format** | PE32+ (x64), Windows Console subsystem |
| **Compiler** | MSVC + Delphi (Rich header: 11 entries, 7 unique product IDs) |
| **Compiled** | 2026-03-27 00:10:31 UTC (same day as Malware Bazaar upload) |
| **Signed** | No |
| **Sections** | 6 (`.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc`) |
| **Imports** | 3 DLLs (ADVAPI32, KERNEL32, SHELL32), 99 functions |
| **Origin** | Dropped by GCleaner campaign |
| **Malware Bazaar Tags** | `SalatStealer`, `dropped-by-gcleaner`, `UNIQ.file` |
| **First Seen** | 2026-03-27 18:46:31 UTC |

---

## 3. Acquisition

The sample was obtained programmatically from [Malware Bazaar](https://bazaar.abuse.ch/) via its authenticated API, selected for its combination of:
- **SalatStealer** family tag (new, previously unanalysed stealer family)
- **UNIQ** tag (unique file, not seen before in other campaigns)
- **GCleaner** delivery chain (known pay-per-install distribution)
- **Same-day upload** (first seen hours before analysis)

The AES-encrypted zip was extracted using `pyzipper` and the standard Malware Bazaar password (`infected`).

---

## 4. Architecture Overview

SalatStealer uses a **3-layer matryoshka design** to protect the actual stealer from static analysis:

```
Layer 1: Outer Loader (PE32+ x64, 4.8 MB, MSVC)
  ├── Admin check → UAC elevation
  ├── Dual-method Defender exclusion
  ├── AES-256-CBC decrypt .data section (4.6 MB, entropy 8.0)
  ├── Drop to %LOCALAPPDATA%\temp\*.exe
  └── CreateProcessA(CREATE_NO_WINDOW)

Layer 2: UPX Wrapper (PE32 x86, 3.6 MB, UPX 5.02 LZMA)
  └── Decompresses to 12.9 MB

Layer 3: Go Stealer (12.9 MB, package "salat/")
  ├── salat/main.go       — entry point
  ├── salat/init.go       — initialisation
  ├── salat/funcs.go      — core stealing functions
  ├── salat/sets.go       — target configuration
  ├── salat/task.go       — Task Scheduler persistence
  └── salat/screenshot/   — screen capture module
```

---

## 5. Layer 1: Outer Loader Analysis

### 5.1 Entry Point and Admin Check

The entry point at `0x140002640` (`_start`) initialises the security cookie, performs CRT setup, then calls the main loader function `sub_140001000`.

Before any payload work, `sub_140002020` checks for administrator privileges:

```c
// sub_140002020 — Administrator group membership check
AllocateAndInitializeSid(&SIA, 2,
    SECURITY_BUILTIN_DOMAIN_RID,    // 32
    DOMAIN_ALIAS_RID_ADMINS,        // 544
    0, 0, 0, 0, 0, 0, &pSid);
CheckTokenMembership(NULL, pSid, &isMember);
FreeSid(pSid);
return isMember;
```

If **not admin**, `sub_1400020d0` re-launches itself with elevation:

```c
// sub_1400020d0 — UAC elevation via "runas"
GetModuleFileNameA(NULL, &path, 260);
sei.lpVerb = "runas";
sei.lpFile = path;
sei.nShow  = SW_SHOWNORMAL;
ShellExecuteExA(&sei);
ExitProcess(0);
```

### 5.2 Dual-Method Defender Exclusion

If running as admin, the loader iterates over four target paths (`LOCALAPPDATA`, `APPDATA`, `C:\Program Files`, `C:\Program Files (x86)`) and applies **two exclusion methods** per path:

**Method 1 — Direct Registry Write** (`sub_140001e20`, stealthier):
```c
// Enable backup/restore/ownership privileges
sub_1400021a0("SeBackupPrivilege");
sub_1400021a0("SeRestorePrivilege");
sub_1400021a0("SeTakeOwnershipPrivilege");

// Write exclusion directly to Defender's registry key
RegCreateKeyExA(HKEY_LOCAL_MACHINE,
    "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
    0, NULL, REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,  // falls back to KEY_WRITE if denied
    NULL, &hKey, &disposition);
RegSetValueExA(hKey, path, 0, REG_DWORD, &zero, 4);
RegFlushKey(hKey);
```

**Method 2 — PowerShell Fallback** (`sub_140001cc0`, reliable but detectable):
```
cmd.exe /c powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden
  -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath '%s'
  -Force -ErrorAction SilentlyContinue" >nul 2>&1
```

The PowerShell command spawns with `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`, waits up to 10 seconds (`WaitForSingleObject`), and force-kills the process if it hangs (`TerminateProcess`). Each path exclusion is followed by a 1-second `Sleep`.

### 5.3 AES-256-CBC Payload Decryption

After Defender exclusions, the loader decrypts the embedded payload:

```c
// sub_140001000 — main loader function (simplified)
Sleep(1500);  // evasion delay

LPVOID buffer = VirtualAlloc(NULL, g_payloadSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// sub_140001bd0 — decryption orchestrator
memcpy(buffer, &g_encryptedData, g_payloadSize);     // copy to RW buffer
aes256_key_expand(&keySchedule, &g_aesKey);           // sub_1400019d0
aes256_cbc_decrypt(&keySchedule, buffer, g_payloadSize); // sub_140001430

DWORD actualSize = pkcs7_unpad(buffer, g_payloadSize);  // sub_140001c60
```

**Crypto parameters extracted from decompilation:**

| Parameter | Value | Location |
|-----------|-------|----------|
| **Algorithm** | AES-256-CBC with PKCS7 padding | Confirmed by S-box at `0x15c60`, inv S-box at `0x15d60`, 60-round key expansion |
| **Key** (32 bytes) | `efd1828c56012a7c84d42d88fc9206f925a1fadbf323b926dc8ccad0ec3986f7` | File offset `0x20800` |
| **IV** (16 bytes) | `480ec48e3ac99d80cc7f1da90a72dc14` | File offset `0x20820` |
| **Encrypted data** | 3,593,232 bytes | File offset `0x20840` |
| **Payload size** | Stored at file offset `0x38DC50` as DWORD LE: `0x0036D410` |

The payload was **successfully decrypted** using Binary Refinery:
```
refinery_pipeline(file_offset=0x20840, length=3593232,
    steps=["aes:<key>:CBC:<iv>:padding=pkcs7"],
    output_path="/output/salat_stealer_decrypted.exe")
```

Result: a valid **PE32 (x86) executable**, 3,593,216 bytes — identified as **UPX 5.02 packed** (sections: UPX0, UPX1, UPX2).

### 5.4 Drop and Execute

After decryption, the loader writes the payload to disk and executes it:

```c
GetEnvironmentVariableA("LOCALAPPDATA", &tempDir, 260);
GetTempFileNameA(tempDir, "tmp", 0, &tempName);
// Replace extension with ".exe" (0x656E652E in little-endian)
MoveFileA(tempName, exePath);

HANDLE hFile = CreateFileA(exePath, GENERIC_WRITE, 0, NULL,
    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
WriteFile(hFile, buffer, actualSize, &written, NULL);
CloseHandle(hFile);

CreateProcessA(exePath, NULL, NULL, NULL, FALSE,
    CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);

// Self-clean: mark for deletion on reboot
MoveFileExA(exePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
VirtualFree(buffer, 0, MEM_RELEASE);
```

---

## 6. Layer 2: UPX 5.02 LZMA Unpacking

### 6.1 UPX Header Analysis

The decrypted PE contains standard UPX sections with a pack header at file offset `0x1F5`:

| Field | Value |
|-------|-------|
| **Magic** | `UPX!` |
| **Version** | 5.02 |
| **Format** | PE32 (0x09) |
| **Method** | LZMA (0x0E) |
| **Level** | 10 |

### 6.2 Stub Reverse Engineering

The UPX decompression stub at entry point `0xC52250` was disassembled to extract compression parameters:

```asm
mov esi, 0x00CE6015     ; source: compressed data in UPX1
lea edi, [esi-0x8E5015] ; destination: UPX0 at 0x401000
inc esi                  ; skip 2-byte header
inc esi
push 0x00C5038D          ; sz_unc = 12,911,501 bytes
push 0x0036C239          ; sz_cpr = 3,588,665 bytes
mov dword [ebx], 0x00020003  ; LZMA props: lc=3, lp=0, pb=2
```

### 6.3 Manual LZMA Decompression

Standard tools (Unipacker, Qiling, Speakeasy, refinery) failed because UPX 5.02 stores LZMA properties in the stub code rather than inline with the data stream. The decompression was achieved by **manually reconstructing a standard LZMA header**:

```python
# Construct LZMA header: props=0x5D (lc=3,lp=0,pb=2), dict=2^24, size=12911501
header = b'\x5d' + (1 << 24).to_bytes(4, 'little') + (12911501).to_bytes(8, 'little')
result = lzma.decompress(header + compressed_data, format=lzma.FORMAT_ALONE)
# Result: 12,911,501 bytes — exact match with sz_unc
```

The decompressed output is raw section data (no PE headers — UPX rebuilds those at runtime) containing the **Go stealer binary**.

---

## 7. Layer 3: Go Stealer Deep Dive

### 7.1 Identification

| Property | Value |
|----------|-------|
| **Go Build ID** | `sCTzxNPHRWG7nzVI1GNn/tcp_9B6bqJ7O5oWBMtYP/wjjYy9bRgH6mK34FgDt_/Mj-fvSl9wHlyAVgTX440` |
| **Internal Package** | `salat/` |
| **Source Files** | `main.go`, `init.go`, `funcs.go`, `sets.go`, `task.go` |
| **Modules** | `salat/screenshot/` (screen capture) |
| **Key Dependency** | `github.com/capnspacehook/taskmaster` (Task Scheduler persistence) |
| **Crypto** | `pbkdf2.go` (Chrome DPAPI decryption) |
| **Database** | SQLite3 (`go-sqlite3` with vtab support) |

### 7.2 Browser Credential Theft

SalatStealer targets **16 browsers** across two engine families:

**Chromium-based (12):** Chrome, Chromium, Microsoft Edge, Brave (BraveSoftware), Opera, CocCoc, Coowon, QIP Surf, Elements Browser, Catalina, BlackHaw, K-Meleon

**Firefox-based (4):** Mozilla Firefox, Waterfox, Cyberfox, IceDragon

**Stolen database files:**

| Database | Engine | Data Extracted |
|----------|--------|----------------|
| `Login Data` | Chromium | `SELECT origin_url, ... FROM logins` |
| `Web Data` | Chromium | Autofill and payment data |
| `Cookies` | Chromium | `SELECT name, encrypted_value FROM cookies` |
| `Local State` | Chromium | DPAPI master key for decryption |
| `logins.json` | Firefox | Stored credentials (Extensions path) |
| `cookies.sqlite` | Firefox | Session cookies |
| `key4.db` | Firefox | `SELECT a11, a102 FROM nssPrivate` (NSS private keys) |

**Process killing:** Before accessing locked SQLite databases, the stealer runs `taskkill /F /PID` to force-terminate browser processes.

**Decryption:** Chrome credentials are decrypted using PBKDF2 key derivation (`pbkdf2.go`) against the DPAPI master key from `Local State`. Firefox credentials are extracted from the NSS database using direct SQLite queries against `nssPrivate`.

### 7.3 Cryptocurrency Wallet Theft

**23+ wallets targeted:**

Exodus, Electrum, Ethereum, Metamask, Phantom, Coinbase, Crocobit, Starcoin, Guarda, Bitapp, Coin98, Fewcha, Finnie, Coinomi, Binance, Martian, Safepal, Solfare, iWallet, Enkrypt, MyMonero, Bytecoin, Armory

### 7.4 Messaging and Gaming Platforms

| Platform | Target Path | Data Stolen |
|----------|-------------|-------------|
| **Telegram** | `Local\Packages\TelegramDesktop` | `tdata` session files |
| **Discord** | `Clients\DiscordTokens.txt` | Authentication tokens |
| **Steam** | `Valve\Steam\users`, `config.vdf` | Session data, account config |

### 7.5 Advanced Credential Harvesting

- **LSASS process dump**: `"failed to find LSASS process"`, `"failed to impersonate SYSTEM"` — attempts to dump LSASS for credential extraction with SYSTEM impersonation
- **Microsoft Cryptography registry**: Accesses `Microsoft\Cryptography` for machine GUID / DPAPI keys
- **WMI reconnaissance**: `Win32_Processor` query for hardware fingerprinting

### 7.6 Screenshot Capture

The dedicated `salat/screenshot` package provides multi-monitor screen capture:

| Function | Purpose |
|----------|---------|
| `screenshot.CaptureRect` | Capture a specific screen region |
| `screenshot.CaptureWindow` | Capture a specific window |
| `screenshot.CreateImage` | Create image buffer |
| `screenshot.GetMonitors` | Enumerate all monitors |

Screenshots are encoded as JPEG (`image/jpeg`) for upload.

### 7.7 C2 Communication

**DNS-over-HTTPS for domain resolution:**

| Resolver | URL |
|----------|-----|
| Cloudflare | `https://cloudflare-dns.com/dns-query?name=` |
| Google | `https://dns.google/resolve?name=` |
| Cloudflare (IP) | `https://1.1.1.1/dns-query?name=` |

The actual C2 domain is resolved at runtime via DoH, evading traditional DNS monitoring. No hardcoded C2 URLs appear in the binary.

**Command protocol:**

| Command | Action |
|---------|--------|
| `post` | HTTP POST data to C2 |
| `open` | Open URL or file |
| `taskkill` | Kill a process |
| `postOpen` | POST data then open URL |
| `/config/` | Retrieve configuration |

**Exfiltration:** Stolen data is packaged as `mime/multipart` uploads over HTTPS with AES+TLS encryption.

### 7.8 Persistence

The stealer uses the `github.com/capnspacehook/taskmaster` Go library to create Windows Task Scheduler entries for persistence. The library supports `Week`, `Month`, `Action`, and `Trigger` scheduling patterns.

---

## 8. Anti-Analysis Techniques

| Technique | Layer | Evidence |
|-----------|-------|----------|
| AES-256-CBC encrypted payload | Loader | 4.6 MB `.data` section at entropy 8.0 |
| UPX 5.02 LZMA packing | Wrapper | Defeats Unipacker, Qiling, Speakeasy automated unpackers |
| CPUID VM detection | Loader | 6 locations checking hypervisor bit |
| IsDebuggerPresent | Loader | In CRT exception handler |
| Hidden window execution | Loader | `CREATE_NO_WINDOW`, `wShowWindow=0` |
| Sleep delays | Loader | 500ms–1500ms between operations |
| Self-deletion on reboot | Loader | `MoveFileExA(MOVEFILE_DELAY_UNTIL_REBOOT)` |
| DNS-over-HTTPS | Stealer | C2 domain resolved via encrypted DNS |
| No static C2 IOCs | Stealer | All C2 infrastructure resolved at runtime |

---

## 9. MITRE ATT&CK Mapping

| ID | Technique | Tactic | Evidence |
|----|-----------|--------|----------|
| T1134 | Access Token Manipulation | Privilege Escalation | `AdjustTokenPrivileges`, `OpenProcessToken` |
| T1548.002 | Bypass UAC | Privilege Escalation | `ShellExecuteExA("runas")` |
| T1562.001 | Disable/Modify Tools | Defense Evasion | Defender exclusions via registry + PowerShell |
| T1027 | Obfuscated Files | Defense Evasion | AES-256 encryption + UPX 5.02 LZMA packing |
| T1059.001 | PowerShell | Execution | Hidden PowerShell for Defender exclusion |
| T1036.005 | Match Legitimate Name | Defense Evasion | Drops as temp file with `.exe` extension |
| T1070.004 | File Deletion | Defense Evasion | `MoveFileExA(MOVEFILE_DELAY_UNTIL_REBOOT)` |
| T1555.003 | Credentials from Web Browsers | Credential Access | SQLite queries on Login Data, Cookies, key4.db |
| T1539 | Steal Web Session Cookie | Credential Access | Chrome/Firefox cookie extraction |
| T1005 | Data from Local System | Collection | Wallets, Telegram, Discord, Steam |
| T1113 | Screen Capture | Collection | `salat/screenshot` Go package |
| T1071.001 | Web Protocols | Command and Control | HTTPS multipart upload |
| T1568.002 | Domain Generation / DoH | Command and Control | DNS-over-HTTPS for C2 resolution |
| T1053.005 | Scheduled Task | Persistence | `capnspacehook/taskmaster` library |
| T1003.001 | LSASS Memory | Credential Access | LSASS process dump attempt |

*15 techniques across 7 tactics*

---

## 10. Indicators of Compromise

### 10.1 File Hashes

| Layer | SHA-256 |
|-------|---------|
| **Outer loader** | `f8a26bce0b29bfaa0351133aff6b85e31dfa7c46280c8b9559829857b6ca7681` |
| **Inner payload (UPX)** | `2df39940a0268440f6652632c1a08841d869b3f8b08193b01afb000f8b3762d2` |

### 10.2 Network Indicators

| Type | Value | Purpose |
|------|-------|---------|
| DoH Resolver | `cloudflare-dns.com/dns-query` | C2 domain resolution |
| DoH Resolver | `dns.google/resolve` | C2 domain resolution |
| DoH Resolver | `1.1.1.1/dns-query` | C2 domain resolution |

### 10.3 Host Indicators

| Type | Value |
|------|-------|
| Registry | `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` |
| Privileges | `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege` |
| Process | `cmd.exe /c powershell.exe ... Add-MpPreference -ExclusionPath` |
| Process | `taskkill /F /PID` (browser process termination) |
| File drop | `%LOCALAPPDATA%\temp\*.exe` |
| Persistence | Windows Task Scheduler (via `taskmaster` library) |

### 10.4 Crypto Material

| Parameter | Value |
|-----------|-------|
| AES-256 Key | `efd1828c56012a7c84d42d88fc9206f925a1fadbf323b926dc8ccad0ec3986f7` |
| AES IV | `480ec48e3ac99d80cc7f1da90a72dc14` |
| Go Build ID | `sCTzxNPHRWG7nzVI1GNn/tcp_9B6bqJ7O5oWBMtYP/wjjYy9bRgH6mK34FgDt_/Mj-fvSl9wHlyAVgTX440` |
| Imphash | `bfee7c7e234d73184f6b414fec537224` |

---

## 11. Why This Example

This analysis showcases several Arkana capabilities that are difficult or impossible with traditional tools:

1. **Automated payload decryption** — AES key, IV, and data boundaries extracted from decompiled pseudocode, then decrypted via Binary Refinery pipeline in a single tool call
2. **Multi-layer unpacking** — Peeled through AES encryption → UPX 5.02 LZMA packing → Go binary, with each layer requiring different analysis techniques
3. **UPX stub reverse engineering** — Disassembled the UPX decompression stub to extract LZMA parameters when all automated unpackers failed
4. **Go binary string analysis** — Extracted stealer targets, C2 infrastructure, and module structure from raw decompressed Go binary sections
5. **Evidence-first methodology** — Every finding grounded in specific tool output: decompiled functions, hex patterns, crypto constants, SQL queries found in the binary
6. **Same-day analysis** — Sample obtained and fully analysed within hours of its first appearance on Malware Bazaar
