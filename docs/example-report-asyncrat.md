# Malware Analysis Report: AsyncRAT .NET Remote Access Trojan

**Analyst:** Arkana Automated Analysis
**Date:** 2026-03-03
**Classification:** Remote Access Trojan (RAT) / .NET
**Risk Level:** CRITICAL (57/100)
**VT Detection:** 43/72

---

## 1. Executive Summary

This report documents the analysis of an **AsyncRAT** client built from the open-source AsyncRAT C# framework. The binary is a **.NET assembly** (CLR v4.0.30319) with obfuscated metadata — type and method definitions are stripped, but string tables and member references remain readable, providing extensive visibility into its capabilities.

The sample connects to C2 server **cveutb.sa.com**, uses **AES-256 + HMACSHA256** for encrypted communications via the **MessagePack** serialisation protocol, and implements comprehensive anti-analysis (VMware, VirtualBox, Sandboxie, debugger detection). It persists via the Windows **Run registry key** and drops itself to `C:\Windows\ett1h.exe`.

The PDB path reveals the threat actor's project structure in **Vietnamese** ("Cong Viec" = "Work"), suggesting a **Vietnamese-speaking operator** who renamed the output assembly to "MalwareRAT."

Debug strings left in the binary (`[DEBUG] Sandbox detected`, `[DEBUG] Extreme persistence added`, `[DEBUG] InitializeSettings called - Using plaintext config`) suggest an **unsophisticated operator** testing a custom build of the AsyncRAT framework.

---

## 2. Sample Information

| Property | Value |
|----------|-------|
| **Filename** | asyncrat.exe / MalwareRAT.exe |
| **SHA-256** | `86e642bd08f372c81982c022ff3f8e70f535f2b56fc438eb196983d4995bab2c` |
| **MD5** | `bccd380228cc0709c50b6be1b06411c2` |
| **SHA-1** | `0fe8c6ffaed90ba4ad3f17e8375dc62ba32f91c9` |
| **ssdeep** | `384:YMT5XY+17Ng15KhElE1bdcWOebX093bayseHQxnC7O+WmlIuufGfrfCvWWWwEQ+j:Yi5XHRNg1IhT1hV4RbJwB+WWHLQ+j` |
| **File Size** | 34,816 bytes (34 KB) |
| **Format** | PE32 (.NET CIL), Windows GUI |
| **Runtime** | CLR v4.0.30319 (.NET Framework 4.x) |
| **Signed** | No |
| **Sections** | 3 |
| **Imports** | 1 function from 1 DLL (mscoree.dll — .NET loader stub) |
| **VT Label** | trojan.msil/asyncrat |
| **VT First Seen** | 2026-03-01 |
| **VT Tags** | long-sleeps, assembly, detect-debug-environment |

### PDB Path (Attribution)

```
D:\Cong Viec\malware\AsyncRAT-C-Sharp\malware chuan 2\AsyncRAT-C-Sharp-master\AsyncRAT-C#\Client\obj\Debug\MalwareRAT.pdb
```

- **"Cong Viec"** = Vietnamese for "Work"
- **"malware chuan 2"** = Vietnamese for "standard malware 2" (second iteration)
- Built from the public `AsyncRAT-C-Sharp` repository
- Output renamed to `MalwareRAT.exe`

---

## 3. .NET Assembly Analysis

### 3.1 Metadata Obfuscation

The .NET metadata has been stripped/obfuscated:

| Category | Count | Notes |
|----------|-------|-------|
| Type definitions | **0** | All types stripped |
| Method definitions | **0** | All methods stripped |
| User strings | **0** | User string heap cleared |
| Assembly references | **10** | Intact — reveals dependencies |
| Member references | **30** | Intact — reveals API usage |

Despite metadata stripping, the string tables (FLOSS-extracted) and member references provide full visibility.

### 3.2 Assembly References

| Assembly | Version | Purpose |
|----------|---------|---------|
| mscorlib | 4.0.0.0 | .NET core library |
| System | 4.0.0.0 | Base class library |
| **System.Net.Http** | 4.2.0.0 | HTTP communication |
| **MessagePackLib** | 1.0.0.0 | AsyncRAT C2 protocol serialisation |
| **System.Management** | 4.0.0.0 | WMI queries (AV detection) |
| **System.Drawing** | 4.0.0.0 | Screenshot capture |
| System.Core | 4.0.0.0 | LINQ/extensions |
| **Microsoft.VisualBasic** | 10.0.0.0 | ComputerInfo (system fingerprinting) |
| **System.Windows.Forms** | 4.0.0.0 | GUI/clipboard access |
| Microsoft.CSharp | 4.0.0.0 | Dynamic type support |

### 3.3 Key Member References

| Method | Class | Capability |
|--------|-------|------------|
| `Sleep` | Thread | Long-sleep anti-sandbox |
| `FromBase64String` | Convert | Config/payload decoding |
| `get_UTF8` / `GetString` | Encoding | String processing |
| `get_TotalPhysicalMemory` | ComputerInfo | System fingerprinting |
| `get_ProcessorCount` | Environment | VM detection (low CPU count) |
| `get_UserName` | Environment | Victim identification |

---

## 4. Capabilities

### 4.1 C2 Communication

| Component | Detail |
|-----------|--------|
| **C2 Domain** | `cveutb.sa.com` |
| **Protocol** | MessagePack over TCP (MessagePackLib 1.0.0.0) |
| **Encryption** | AES-256 (AesCryptoServiceProvider) + HMACSHA256 |
| **User-Agent** | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36` |
| **Connectivity check** | `https://www.google.com/` |

### 4.2 Cryptographic Keys

Two 64-character hex strings (SHA-256 hashes) are embedded — likely the **server certificate hash** and **encryption key derivative**:

| Role | Value |
|------|-------|
| Key 1 | `E65CA7C06AE3E9BACD16F6D87026D2FD51447F87F8771676568AF93C6313D707` |
| Key 2 | `1DB2A1F9902B35F8F880EF1692CE9947A193D5A698D8F568BDA721658ED4C58B` |

### 4.3 Anti-Analysis Suite

| Technique | Implementation |
|-----------|---------------|
| VMware detection | Check for `C:\WINDOWS\system32\Drivers\Vmmouse.sys`, `vmhgfs.sys` |
| VirtualBox detection | Check for `VBoxGuest.sys`, `VBoxSF.sys` |
| Sandboxie detection | Check for `SbieDll.dll` (`DetectSandboxie`) |
| Generic sandbox | `IsSandbox` check |
| Debugger detection | `CheckRemoteDebuggerPresent`, `isDebuggerPresent` |
| Debug mode | `EnterDebugMode` (SeDebugPrivilege) |
| AV enumeration | WMI `Select * from AntivirusProduct` |
| Sandbox evasion | On detection: "[DEBUG] Sandbox detected - sending heavy suspicious traffic" |
| Long sleeps | `Thread.Sleep` — VT tagged `long-sleeps` |

### 4.4 Persistence

| Mechanism | Detail |
|-----------|--------|
| Run key | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| Install path | `C:\Windows\ett1h.exe` (random name) |
| Startup class | `NormalStartup` |
| Install class | `Client.Install` with `InstallFile` / `InstallFolder` methods |
| Mutex | `MutexControl` — `CreateMutex` / `CloseMutex` for single-instance |

### 4.5 Web Panel / Payload Paths

Embedded URL paths suggest a web-based C2 panel or secondary payload staging:

| Path | Purpose |
|------|---------|
| `/adminer.php` | Database management interface |
| `/phpmyadmin/index.php` | MySQL admin panel |
| `/wp-login.php` | WordPress login (compromised site?) |
| `/config.bin` | Configuration download |
| `/keylog.txt` | Keylogger data upload |
| `/backup.sql` | Database exfiltration |
| `/malware.exe` | Payload download |
| `/update.bin` | Update/second-stage download |
| `/payload.dll` | DLL payload download |

### 4.6 System Fingerprinting

| Data Collected | Method |
|----------------|--------|
| Username | `Environment.UserName` |
| CPU count | `Environment.ProcessorCount` |
| Total RAM | `ComputerInfo.TotalPhysicalMemory` |
| Installed AV | WMI `AntivirusProduct` query |
| OS info | .NET Framework APIs |

---

## 5. YARA Matches

| Rule | Category | Description |
|------|----------|-------------|
| Njrat | RAT | RAT detection (generic .NET RAT pattern) |
| VMWare_Detection | AntiVM | VMware driver string references |
| VirtualBox_Detection | AntiVM | VirtualBox driver string references |
| Sandboxie_Detection | AntiVM | Sandboxie DLL references |
| DebuggerCheck__RemoteAPI | AntiDebug | Remote debugger check API |
| anti_dbg | AntiDebug | Debugger detection |
| win_mutex | Mutex | Mutex creation for single instance |
| Dropper_Strings | Dropper | File dropping capability |
| WMI_strings | WMI | WMI access (AV product query) |
| contains_base64 | Encoding | Base64-encoded data present |
| IsNET_EXE | PECheck | .NET assembly confirmed |
| Big_Numbers3 | Crypto | 64-character hex strings (crypto keys) |

---

## 6. Security Mitigations

| Mitigation | Status |
|------------|--------|
| ASLR | Enabled |
| High Entropy ASLR | Enabled |
| DEP/NX | Enabled |
| No SEH | Set (uses .NET exception handling) |
| Control Flow Guard | Not set |

Standard .NET security flags — ASLR/DEP are enabled by default by the .NET compiler.

---

## 7. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| **System Information Discovery** | T1082 | ProcessorCount, TotalPhysicalMemory, UserName |
| **Security Software Discovery** | T1518.001 | WMI `Select * from AntivirusProduct` |
| **Virtualization/Sandbox Evasion** | T1497.001 | VMware/VirtualBox driver checks, SbieDll.dll |
| **Debugger Evasion** | T1622 | CheckRemoteDebuggerPresent, isDebuggerPresent |
| **Encrypted Channel** | T1573.001 | AES-256 + HMACSHA256 C2 encryption |
| **Application Layer Protocol** | T1071.001 | HTTP with Chrome User-Agent spoofing |
| **Registry Run Keys** | T1547.001 | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| **Masquerading** | T1036.005 | Drop to `C:\Windows\ett1h.exe` (system directory) |
| **Input Capture: Keylogging** | T1056.001 | `/keylog.txt` upload path |
| **Screen Capture** | T1113 | System.Drawing reference |
| **Data Encoding** | T1132.001 | Base64 encoding (`Convert.FromBase64String`) |
| **Ingress Tool Transfer** | T1105 | `/malware.exe`, `/update.bin`, `/payload.dll` download paths |

---

## 8. Indicators of Compromise

### 8.1 File Hashes

| Hash | Value |
|------|-------|
| SHA-256 | `86e642bd08f372c81982c022ff3f8e70f535f2b56fc438eb196983d4995bab2c` |
| MD5 | `bccd380228cc0709c50b6be1b06411c2` |
| SHA-1 | `0fe8c6ffaed90ba4ad3f17e8375dc62ba32f91c9` |

### 8.2 Network

| Type | Value |
|------|-------|
| C2 Domain | `cveutb.sa.com` |
| Connectivity Check | `https://www.google.com/` |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36` |

### 8.3 File System

| Path | Purpose |
|------|---------|
| `C:\Windows\ett1h.exe` | Installed copy |
| `MalwareRAT.exe` | Original filename |
| `AsyncRAT.exe` | Framework name reference |

### 8.4 Registry

| Key | Purpose |
|-----|---------|
| `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Persistence |

### 8.5 Crypto Material

| Type | Value |
|------|-------|
| Key/cert hash 1 | `E65CA7C06AE3E9BACD16F6D87026D2FD51447F87F8771676568AF93C6313D707` |
| Key/cert hash 2 | `1DB2A1F9902B35F8F880EF1692CE9947A193D5A698D8F568BDA721658ED4C58B` |

### 8.6 Anti-Analysis Indicators

| Check | Target |
|-------|--------|
| Driver path | `C:\WINDOWS\system32\Drivers\Vmmouse.sys` |
| Driver path | `C:\WINDOWS\system32\Drivers\vmhgfs.sys` |
| Driver path | `C:\WINDOWS\system32\Drivers\VBoxGuest.sys` |
| Driver path | `C:\WINDOWS\system32\Drivers\VBoxSF.sys` |
| DLL load | `SbieDll.dll` (Sandboxie) |
| DLL load | `ntdll.dll` (direct NT API) |

---

## 9. Conclusion

This is a **minimally customised AsyncRAT build** compiled by a Vietnamese-speaking operator from the public AsyncRAT C# repository. The operator renamed the output to "MalwareRAT" but left extensive debug strings and the full PDB path in the binary, indicating **low operational security maturity**.

Despite the operator's inexperience, the AsyncRAT framework itself provides substantial capabilities: AES-256 encrypted C2 communications, comprehensive anti-analysis evasion (VM, sandbox, debugger), keylogging, screenshot capture, system fingerprinting, multi-stage payload delivery, and registry-based persistence.

This analysis demonstrates Arkana's **.NET analysis capabilities** — even with stripped metadata (0 types, 0 methods, 0 user strings), the combination of assembly references, member references, FLOSS string extraction, StringSifter ML ranking, and YARA rule matching provided full visibility into the RAT's configuration, C2 infrastructure, and anti-analysis techniques without requiring .NET decompilation.

---

*Report generated from Arkana triage analysis. .NET method-level disassembly available via `dotnet_disassemble_method()` for deeper investigation.*
