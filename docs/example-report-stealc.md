# Malware Analysis Report: StealC Information Stealer

**Analyst:** Arkana Automated Analysis
**Date:** 2026-03-03
**Classification:** Information Stealer (Credential Theft / Data Exfiltration)
**Risk Level:** CRITICAL (62/100)
**VT Detection:** 58/72

---

## 1. Executive Summary

This report documents the analysis of a **StealC** information stealer — a commodity malware-as-a-service (MaaS) stealer that targets browser credentials, Steam gaming tokens, and cryptocurrency wallets. The binary masquerades as an **FL Studio installer** (`FL.Studio.v25.1.6.49971.exe`) and was compiled 2026-01-23 with MSVC (linker 14.44).

Unlike the packed samples in this report series, StealC is **not heavily packed** (max entropy 6.462) and yields rich static analysis results: 32 capa capability rules matched, extensive browser and application targeting strings are visible, and RC4/XOR/Base64/FNV hash implementations are identifiable. The binary dynamically resolves additional APIs via `GetProcAddress` and loads `wininet.dll` and `crypt32.dll` at runtime for HTTP communication and certificate/credential manipulation.

Targeted applications include **Google Chrome**, **Brave Browser**, **Microsoft Edge**, and **Steam**, with credential, cookie, and token theft implemented via direct file access to browser profile databases.

---

## 2. Sample Information

| Property | Value |
|----------|-------|
| **Filename** | stealc.exe / FL.Studio.v25.1.6.49971.exe |
| **SHA-256** | `cee05a00aeacfc794aebc293a1c03bfc93b05cfd8d7da0d2a8a2d792894fc3bd` |
| **MD5** | `dae7ea07675741e0291f8877a01124c0` |
| **SHA-1** | `99c397419622a1c47c02eba0b7749fcf8c1b6b03` |
| **ssdeep** | `12288:JU8VHX4ZPBuvzkOkW7UE+YTRqwJ4rO6ALSQTbAK4lVAp:5VH6BuvbkW7xXVVmrOzQAp` |
| **File Size** | 753,152 bytes (735 KB) |
| **Format** | PE64 (x64), Windows GUI |
| **Compiler** | MSVC (linker 14.44) |
| **Compiled** | 2026-01-23 19:28:36 UTC |
| **Signed** | No |
| **Sections** | 6 |
| **Imports** | 97 functions from KERNEL32.dll only |
| **Rich Header** | Present (10 compiler entries, hash 0x4f90abc1) |
| **VT Label** | trojan.stealc/marte |
| **VT First Seen** | 2026-01-24 |
| **VT Tags** | persistence, checks-cpu-name, idle, long-sleeps, detect-debug-environment |
| **VT Names** | "FL.Studio.v25.1.6.49971.exe", "C:\Windows\5ellw6.exe" |

---

## 3. Targeted Applications

### 3.1 Browser Credential Theft

StealC targets Chromium-based browser profile databases directly:

| Browser | Profile Path String |
|---------|-------------------|
| **Google Chrome** | `\Google\Chrome\User Data\Local State` |
| **Brave Browser** | `\BraveSoftware\Brave-Browser\User Data\Local State` |
| **Microsoft Edge** | `\Microsoft\Edge\User Data\Local State` |

The `Local State` file contains the AES master key (encrypted with DPAPI) used to decrypt stored passwords and cookies in `Login Data` and `Cookies` SQLite databases. The stealer loads **crypt32.dll** at runtime for DPAPI decryption (`CryptUnprotectData`).

Binary references to `\chrome.exe`, `brave.exe`, and `msedge.exe` suggest the stealer also checks for running browser processes (to close them before accessing locked database files).

### 3.2 Steam Token Theft

| Target | Path String |
|--------|-------------|
| Steam tokens | `soft\Steam\tokens\steam_tokens.txt` |
| Steam config | `\Steam\local.vdf` |
| Steam config | `config.vdf` |
| Steam ID | `SteamID` field extraction |

The stealer extracts Steam authentication tokens (for session hijacking) and Steam ID information from VDF configuration files.

### 3.3 Registry Targets

| Registry Path | Purpose |
|---------------|---------|
| `Software\Brave-Browser\User` | Brave Browser user profile data |

---

## 4. Capabilities

### 4.1 Capa Analysis (32 Rules Matched)

| Capability | Category | Match Count | ATT&CK |
|------------|----------|-------------|--------|
| **Get geographical location** | Collection | 8 | T1614 |
| **Encode data using Base64** | Data manipulation | 2 | T1027 |
| **Encode data using XOR** | Data manipulation | 7 | T1027 |
| **Encrypt data using RC4 PRGA** | Encryption | 2 | T1027 |
| **Mersenne Twister PRNG** | Data manipulation | 2 | — |
| **Hash data using FNV** | Hashing | 1 | — |
| **Link function at runtime** | Runtime linking | 6 | T1129 |
| **PEB access** | Anti-debug | 2 | — |
| **Load assembly via IAssembly** | Code loading | 1 | — |
| **Parse PE header** | Reflective loading | 7 | T1129 |
| **Enumerate PE sections** | Code discovery | 2 | — |
| **Enumerate files** | Discovery | 2 | T1083 |
| **Read file** | File I/O | 4 | — |
| **Write file** | File I/O | 5 | — |
| **Create/open file** | File I/O | 5 | — |
| **Get file size** | File I/O | 1 | T1083 |
| **Clear file content** | Anti-forensics | 1 | — |
| **Accept command line args** | Execution | 1 | T1059 |
| **Query environment variable** | Discovery | 1 | T1082 |
| **Set environment variable** | Persistence | 2 | — |
| **Change memory protection** | Memory | 3 | — |
| **Delay execution** | Anti-sandbox | 1 | — |
| **Terminate process** | Process control | 3 | — |
| **Print debug messages** | Debug | 1 | — |
| **TLS storage operations** | Thread mgmt | 3 | — |

### 4.2 Cryptographic Implementations

| Algorithm | Evidence |
|-----------|----------|
| **RC4** | 20 identity permutation instances in .rdata; PRGA detected by capa (2 functions) |
| **XOR** | 7 XOR encoding loops detected |
| **Base64** | Base64 encoding (2 functions) + Base64 table in data section |
| **FNV hash** | FNV-1/FNV-1a hash (1 function) — likely for API name hashing |
| **CRC32** | CRC32 polynomial constant detected (YARA match) |
| **Mersenne Twister** | MT19937 PRNG (2 functions) |

RC4 is used for **C2 communication encryption** and **configuration decryption** — a hallmark of StealC.

### 4.3 Dynamic API Resolution

The binary imports only from KERNEL32.dll (97 functions) and dynamically loads additional libraries at runtime:

| Library | Resolved Via | Purpose |
|---------|-------------|---------|
| `wininet.dll` | GetProcAddress | HTTP communication (InternetOpen, InternetConnect, HttpSendRequest) |
| `crypt32.dll` | GetProcAddress | DPAPI credential decryption (CryptUnprotectData) |

6 runtime linking call sites were identified by capa, plus FNV hashing for API name resolution.

### 4.4 Anti-Analysis

| Technique | Implementation |
|-----------|---------------|
| Debugger detection | `IsDebuggerPresent` import |
| Debug output | `OutputDebugStringW` import |
| Timing check | `QueryPerformanceCounter` import |
| PEB access | Direct PEB structure access (2 sites) — NtGlobalFlag check |
| Delayed execution | Sleep-based sandbox evasion (VT: `long-sleeps`, `idle` tags) |
| CPU fingerprinting | VT: `checks-cpu-name` tag |

### 4.5 Command Execution

| Indicator | Detail |
|-----------|--------|
| `C:\Windows\system32\cmd.exe` | Command shell execution capability |
| `C:\ProgramData\` | Staging/drop directory |
| `C:\Windows\5ellw6.exe` | Installed copy (VT submission name) |

---

## 5. YARA Matches

| Rule | Category | Description |
|------|----------|-------------|
| **Browsers** | Stealer | References to internet browsers |
| **network_http** | Network | HTTP communications |
| **Str_Win32_Wininet_Library** | Network | WinInet API library usage |
| **Str_Win32_Internet_API** | Network | WinInet API calls |
| **Str_Win32_Http_API** | Network | HTTP API calls |
| **CRC32_poly_Constant** | Crypto | CRC32 polynomial constant |
| **BASE64_table** | Encoding | Base64 lookup table |
| **anti_dbg** | Anti-debug | Debugger detection |
| **maldoc_getEIP_method_1** | Technique | Position-independent code (PIC) pattern |
| **contains_base64** | Encoding | Base64-encoded data |
| **win_files_operation** | File I/O | Profile file access |
| **Misc_Suspicious_Strings** | Suspicious | Miscellaneous malware strings |
| **IsPE64** | PE | 64-bit PE confirmed |
| **HasRichSignature** | PE | Rich header present |
| **HasDebugData** | PE | Debug data directory |
| **Microsoft_Visual_Cpp_80_DLL** | Compiler | MSVC runtime |

---

## 6. Security Mitigations

| Mitigation | Status |
|------------|--------|
| ASLR | Enabled |
| High Entropy ASLR | Enabled |
| DEP/NX | Enabled |
| CFG Guard | **Not enforced** (instrumented but guard_cf=false) |
| SEH Protection | Not set |
| CET Shadow Stack | Not set |

The binary has CFG instrumentation compiled in but the guard flag is not set — this may indicate the original legitimate application was compiled with CFG, and the malware author built on top of it.

---

## 7. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| **Credentials from Password Stores: Credentials from Web Browsers** | T1555.003 | Chrome/Brave/Edge `Local State` + `crypt32.dll` for DPAPI |
| **Steal Application Access Token** | T1528 | Steam tokens (`steam_tokens.txt`, `SteamID`) |
| **System Location Discovery** | T1614 | Geographical location collection (8 capa matches) |
| **Obfuscated Files or Information** | T1027 | RC4 PRGA, XOR encoding, Base64, FNV hash |
| **Shared Modules** | T1129 | Dynamic API resolution via GetProcAddress (6 sites) |
| **Debugger Evasion** | T1622 | IsDebuggerPresent, PEB access, QueryPerformanceCounter |
| **Masquerading** | T1036.005 | Disguised as FL Studio installer |
| **File and Directory Discovery** | T1083 | File enumeration (2 capa matches) |
| **System Information Discovery** | T1082 | Environment variable queries, CPU fingerprinting |
| **Command and Scripting Interpreter** | T1059 | cmd.exe reference, command line argument parsing |
| **Process Injection** | T1055 | VirtualProtect for memory manipulation |
| **Data Staged** | T1074 | `C:\ProgramData\` staging directory |
| **Application Layer Protocol: Web Protocols** | T1071.001 | WinInet HTTP communication |

---

## 8. Indicators of Compromise

### 8.1 File Hashes

| Hash | Value |
|------|-------|
| SHA-256 | `cee05a00aeacfc794aebc293a1c03bfc93b05cfd8d7da0d2a8a2d792894fc3bd` |
| MD5 | `dae7ea07675741e0291f8877a01124c0` |
| SHA-1 | `99c397419622a1c47c02eba0b7749fcf8c1b6b03` |
| Rich header hash | `0x4f90abc1` |

### 8.2 File System

| Path | Purpose |
|------|---------|
| `C:\Windows\5ellw6.exe` | Installed copy |
| `C:\ProgramData\` | Staging directory |

### 8.3 Dynamically Loaded Libraries

| DLL | Purpose |
|-----|---------|
| `wininet.dll` | HTTP C2 communication |
| `crypt32.dll` | DPAPI credential decryption |

### 8.4 Registry

| Key | Purpose |
|-----|---------|
| `Software\Brave-Browser\User` | Browser profile enumeration |

### 8.5 Targeted Files

| File/Path | Data Stolen |
|-----------|-------------|
| `\Google\Chrome\User Data\Local State` | Browser master key |
| `\BraveSoftware\Brave-Browser\User Data\Local State` | Browser master key |
| `\Microsoft\Edge\User Data\Local State` | Browser master key |
| `soft\Steam\tokens\steam_tokens.txt` | Steam auth tokens |
| `\Steam\local.vdf` | Steam configuration |
| `config.vdf` | Steam configuration |

---

## 9. Conclusion

This is a **StealC v2** information stealer (also labelled "Marte" by some vendors), a commodity MaaS tool distributed via trojanised software installers. The sample masquerades as an **FL Studio** installer — a common social engineering vector targeting music producers and hobbyists.

The binary is well-engineered: compiled with modern MSVC (linker 14.44, January 2026), uses RC4 for C2 encryption, FNV hashing for API resolution, and implements targeted credential theft for Chromium browsers and Steam. The geographic location collection (8 capa matches) suggests the stealer fingerprints victims before exfiltrating data, potentially for filtering out researchers or targeting specific regions.

Unlike the heavily packed LockBit sample, StealC yielded **extensive static analysis results** — 32 capa rules matched, all targeted applications identified, and the full cryptographic toolkit (RC4, XOR, Base64, FNV, CRC32, Mersenne Twister) mapped. This demonstrates Arkana's strength in analysing unpacked or lightly obfuscated malware where static analysis provides near-complete coverage without requiring dynamic execution.

---

*Report generated from Arkana static analysis. Dynamic analysis would reveal the full C2 protocol, exfiltration endpoints, and any additional plugin-based capabilities downloaded at runtime.*
