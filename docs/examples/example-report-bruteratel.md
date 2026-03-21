# Malware Analysis Report: Brute Ratel C4 Badger Implant

**Analyst:** Arkana Automated Analysis (multi-session)
**Date:** 2026-03-21
**Classification:** Command & Control Implant (Post-Exploitation / Adversary Simulation)
**Risk Level:** CRITICAL (27/100)
**Attribution:** Commercial tool (Brute Ratel C4 by Chetan Nayak / Dark Vortex)

---

## 1. Executive Summary

This report documents the **complete unpacking and C2 configuration extraction** of a Brute Ratel C4 (BRc4) "badger" implant — a commercial adversary simulation framework increasingly observed in real-world intrusions. The analysis required reversing a **two-stage packed loader** with RC4 encryption, reflective DLL injection, and a custom PIC (position-independent code) shellcode bootstrap, followed by deep-dive analysis of the unpacked implant to extract the embedded C2 configuration.

The execution chain proceeds through: DllMain self-injection → PIC shellcode stage 1/2 → RC4 payload decryption (8-byte key) → reflective PE loading with MZ magic zeroing → badger initialisation → RC4 config decryption (separate 8-byte key derived from payload tail) → WSA networking → C2 beacon loop.

The unpacked badger resolves **all APIs dynamically** via a custom hash function and GetProcAddress — only 3 functions appear in the import table (FreeConsole, GetModuleHandleW, GetProcAddress). This near-total absence of static imports defeated automated triage tools and emulation engines, requiring manual static analysis to trace the complete execution flow and identify the config decryption routine.

**C2 Infrastructure:** 5 domains across 2 Tyk API gateways (AWS US-East-1, EU-Central-1) and 3 direct domains, communicating over HTTPS/443 with JSON-formatted beacons.

---

## 2. Sample Information

### 2.1 Packed Loader

| Property | Value |
|----------|-------|
| **Filename** | `bruteratel.exe` |
| **SHA-256** | `7d30c01dcb8bb19069f96f84ee4b693f4540783f5ccae37eeb1cd3d3f71bc939` |
| **MD5** | `3325325e80e3c0e3d3a5d9b7ba5f4916` |
| **File Size** | 265,216 bytes (259 KB) |
| **Format** | PE64 (x64) DLL |
| **Export Name** | `badger_x64_wait.bin.packed.dll` |
| **Sections** | 5 (.text, .rdata, .data, .pdata, .reloc) |
| **Imports** | 4 DLLs (KERNEL32, ntdll, VCRUNTIME140, api-ms-win-crt-runtime) |
| **Signed** | No |

### 2.2 Unpacked Badger Implant

| Property | Value |
|----------|-------|
| **Filename** | `bruteratel_unpacked.dll` |
| **SHA-256** | `6066cf700a0b6ae31c2bb3547917b7ec241fafbda8fff654ad566dec5f2c2a39` |
| **MD5** | `8a706319c518905cc47730528d2dd22b` |
| **File Size** | 244,752 bytes (239 KB) |
| **Format** | PE64 (x64) DLL |
| **Sections** | 9 (.text, .rdata, .data, .pdata, .tls, .gfids, .00cfg, .rsrc, .reloc) |
| **Imports** | FreeConsole, GetModuleHandleW, GetProcAddress + CRT functions only |
| **Functions** | 936 identified |
| **Risk Score** | 27/100 (CRITICAL — low score due to dynamic API resolution evading static analysis) |

---

## 3. Execution Chain

### 3.1 Stage 1 — DllMain Self-Injection

The packed loader's DllMain performs **self-injection** into its own process:

1. `VirtualAllocEx` with handle `-1` (current process) — allocates RWX memory
2. `WriteProcessMemory` — copies the .data section payload to new allocation
3. `CreateRemoteThread` — spawns a thread at the PIC shellcode entry point

This self-injection pattern uses the process's own handle (`-1`) rather than targeting a remote process, avoiding the cross-process injection heuristics of many EDR products.

### 3.2 Stage 2 — PIC Shellcode Bootstrap

The .data section (file offset `0x1A00`, raw size `0x3D600`) contains the complete payload structure:

```
Offset 0x000-0x00F:  Header (DWORD flag=1, zeros)
Offset 0x010-0x02D:  PIC Stage 1 (30 bytes)
Offset 0x02E-0x1C0:  Encrypted config blob (403 bytes)
Offset 0x1C1-0x1D9:  PIC Stage 2 (25 bytes)
Offset 0x1DA-0x3BDE9: Encrypted payload (244,752 bytes)
Offset 0x3BDEA-0x3D3AD: PIC decryptor/reflective loader (~5,572 bytes)
Offset 0x3D3B0:       Config globals (payload_size=0x3D39D, sleep=0x78)
```

**PIC Stage 1** (`sub rsp, 0x28; and rsp, -0x10; push 0x193; call Stage2`):
Aligns the stack and pushes the config blob size (403 bytes) as a parameter.

**PIC Stage 2** (`call $+5; pop rcx`):
Classic position-independent code technique — uses the `call`/`pop` pair to determine its own address in memory, then computes relative offsets to the decryptor and payload.

### 3.3 Stage 3 — RC4 Payload Decryption

The PIC decryptor at `.data+0x3BDEA` performs:

1. `HeapAlloc` + `memcpy` — copies the 244,752-byte encrypted payload to a new buffer
2. `HeapAlloc` + `memcpy` — copies the 403-byte encrypted config blob
3. **RC4 decryption** of the payload:
   - Key: last 8 bytes of the encrypted payload (`7124702c7d70613f`)
   - KSA uses `AND EAX, 7` for 8-byte key wrapping
   - Standard PRGA with XOR

**Critical detail:** After decryption, the instruction `LEA RAX, [R11 + RBX - 0x10]` saves a pointer to the **last 16 bytes of the decrypted payload** (offset `0x3BC00`). The first 8 bytes of these 16 bytes become the RC4 key for config decryption — a second, separate key (`7a3e24647a292175`) appended to the payload by the BRc4 packer.

### 3.4 Stage 4 — Reflective PE Loading

The decrypted payload is a valid PE64 DLL with **intentionally zeroed MZ magic bytes** (bytes 0-1 set to `0x00` instead of `0x4D5A`). The reflective loader:

1. Parses PE headers via `e_lfanew` at offset +60
2. Maps sections into memory with correct permissions
3. Processes relocations for ASLR
4. Resolves imports dynamically
5. Calls the entry point

The MZ magic zeroing is an anti-forensics technique — memory scanners searching for `MZ` headers will not detect the loaded implant. This required manual patching to `0x4D5A` before the unpacked DLL could be analysed as a standalone PE.

### 3.5 Stage 5 — Badger Initialisation

The badger entry point (`0x100071b0`) performs:

```c
FreeConsole();                              // Detach from console
sub_10024ce0(&g_10040380, 0, 240);         // Zero state struct
sub_10002950(&g_10040380, 0, 240);         // Initialise state
sub_10034ff0(v2, sub_10007bf0, ptr, 0, v0); // CreateThread → worker
g_100434f8(ptr->field_10, INFINITE);        // WaitForSingleObject
```

The worker thread (`0x10007bf0`) then:
1. Copies the 8-byte RC4 key from the loader's struct (`field_18`)
2. Decrypts the config via `sub_10007f70` (RC4 + pipe-delimiter parser)
3. Initialises state with JSON beacon templates via `sub_10008ed0`
4. Calls `WSAStartup(MAKEWORD(2,2))` for networking
5. Enters the main C2 beacon loop: heartbeat → process commands → dispatch → send response

---

## 4. C2 Configuration

### 4.1 Config Encryption

| Parameter | Value |
|-----------|-------|
| **Algorithm** | RC4 |
| **Config key** | `7a3e24647a292175` (8 bytes) |
| **Key source** | First 8 bytes of last 16 bytes of decrypted payload |
| **Default key** | `{-l," +r3/#~&;v_` (16-byte hardcoded fallback in `sub_10004b10`) |
| **Config format** | Pipe-delimited (`|`), 27 fields |
| **Secure erase** | Config buffer zeroed after parsing |

### 4.2 Decrypted Configuration

```
||0|5|5|100||||||||||||0|1|
ridiculous-breakpoint-gw.aws-use1.cloud-ara.tyk.io,
anikvan.com,boriz400.com,
uncertain-kitten-gw.aws-euc1.cloud-ara.tyk.io,
altynbe.com|443|
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36|
6J1D1M4P9A57JGC2|LDTPTF78OUCCVQ0I|
/api/azure,/content.php||
d0cf9d2be1473579e729382f5c2e22c6c79fa039137f4fb854afb298916fef71
```

### 4.3 Parsed Config Fields

| Field | Value | Purpose |
|-------|-------|---------|
| **Sleep** | 5 seconds | Beacon interval |
| **Jitter** | 5 | Randomisation factor |
| **Max retry** | 100 | Connection retry limit |
| **C2 domains** | 5 (see below) | Comma-separated, round-robin |
| **Port** | 443 | HTTPS |
| **User-Agent** | Chrome 90 on Win10 x64 | Mimics legitimate browser |
| **Auth token 1** | `6J1D1M4P9A57JGC2` | Beacon authentication |
| **Auth token 2** | `LDTPTF78OUCCVQ0I` | Secondary auth token |
| **URI paths** | `/api/azure`, `/content.php` | C2 callback endpoints |
| **License hash** | `d0cf9d2be...16fef71` | BRc4 license verification |

### 4.4 C2 Infrastructure

| Domain | Infrastructure | Region |
|--------|---------------|--------|
| `ridiculous-breakpoint-gw.aws-use1.cloud-ara.tyk.io` | Tyk API Gateway | AWS US-East-1 |
| `uncertain-kitten-gw.aws-euc1.cloud-ara.tyk.io` | Tyk API Gateway | AWS EU-Central-1 |
| `anikvan.com` | Direct domain | — |
| `boriz400.com` | Direct domain | — |
| `altynbe.com` | Direct domain | — |

Two of the five C2 domains use **Tyk API gateway** infrastructure (`cloud-ara.tyk.io`), providing traffic proxying and blending C2 communications with legitimate API traffic. The URI path `/api/azure` further masquerades as cloud API activity.

### 4.5 C2 Protocol

The beacon uses a JSON format with stack-string-constructed field names (built character-by-character via `sub_10033de0` to avoid static string detection):

| JSON Field | Purpose |
|------------|---------|
| `cs` | Checksum / message type |
| `ud` | User data |
| `pd` | Process data |
| `dnm` | Domain / hostname |
| `dsz` | Data size |

---

## 5. Capabilities

### 5.1 Capa Analysis (14 Rules Matched)

| Capability | Category | ATT&CK |
|------------|----------|--------|
| **Encrypt data using RC4 KSA** | Crypto | T1027 |
| **Prepare HTTP request** | Communication | T1071.001 |
| **Check HTTP status code** | Communication | T1071.001 |
| **Check for software breakpoints** | Anti-debug | T1622 |
| **Anti-VM: VMware detection** | Anti-analysis | T1497.001 |
| **Link function at runtime** | Runtime linking | T1129 |
| **Parse PE header** | Reflective loading | T1620 |
| **Enumerate PE sections** | Code discovery | — |
| **Read/write file** | File I/O | — |
| **Create/manage threads** | Execution | T1106 |
| **Network socket operations** | Communication | T1095 |

The low capa rule count (14 vs typical 30-40) is characteristic of BRc4 — by resolving all APIs dynamically via hash-based resolution, the binary presents almost no static indicators for signature-based tools.

### 5.2 Dynamic API Resolution

BRc4 resolves APIs at runtime using a multi-step process:

1. **PEB walking** (`gs:[0x60]`) — traverses loaded module list to find ntdll and kernel32
2. **Custom hash function** — hashes export names from each DLL's export table
3. **GetProcAddress** — resolves remaining APIs by name at runtime
4. **Indirect syscalls** — extracts syscall numbers from ntdll stubs to bypass user-mode hooks

This results in an import table containing only 3 meaningful functions:
- `FreeConsole` (KERNEL32)
- `GetModuleHandleW` (KERNEL32)
- `GetProcAddress` (KERNEL32)

All other API calls (networking, crypto, process management, file I/O) are resolved dynamically and invisible to static analysis.

### 5.3 Anti-Analysis Techniques

| Technique | Implementation |
|-----------|---------------|
| **Dynamic API resolution** | Custom hash function + PEB walking (only 3 imports visible) |
| **Indirect syscalls** | Extracts syscall numbers from ntdll stubs, bypasses user-mode hooks |
| **NtGlobalFlag anti-debug** | Checks PEB+0xBC for debugger flags `0x70` |
| **Software breakpoint detection** | Scans for `0xCC` (INT3) bytes in code |
| **VMware detection** | String `RO\CMV` (reversed "VMC\OR") built via stack strings |
| **MZ magic zeroing** | Erases bytes 0-1 of loaded PE to evade memory scanners |
| **Stack string construction** | `sub_10033de0` builds strings char-by-char (JSON templates, detection strings) |
| **Config secure erase** | Config buffer zeroed immediately after parsing |
| **RC4 encrypted config** | Config only exists in plaintext briefly during initialisation |
| **Minimal static imports** | 3 functions in IAT; all else resolved dynamically |

### 5.4 Emulation Resistance

Both **Speakeasy** and **Qiling** emulation engines returned 0 API calls when attempting dynamic analysis of the packed loader:

- Speakeasy's API hooks are bypassed by the PEB-walking API resolution (the shellcode never calls `GetProcAddress` through the IAT)
- Qiling's syscall hooking is defeated by the indirect syscall technique (the implant extracts raw syscall numbers and issues them directly)

This demonstrates a fundamental limitation of user-mode emulation against implants designed for EDR evasion — the same techniques that bypass real endpoint security also defeat analysis emulators.

---

## 6. YARA Matches

| Rule | Category | Description |
|------|----------|-------------|
| **IsPE64** | PE | 64-bit PE confirmed |
| **HasRichSignature** | PE | Rich header present |

Only 2 generic YARA rules matched — no behavioural or capability rules triggered. This is a direct consequence of the near-total dynamic API resolution: without static import references, string-based detection rules have nothing to match.

---

## 7. Security Mitigations

| Mitigation | Status |
|------------|--------|
| ASLR | Enabled |
| High Entropy ASLR | **Not set** |
| DEP/NX | Enabled |
| CFG Guard | **Not enforced** |
| SEH Protection | Not set |
| CET Shadow Stack | Not set |

---

## 8. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| **DLL Injection** | T1055.001 | Self-injection via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread (handle -1) |
| **Reflective Code Loading** | T1620 | Reflective DLL loader: PE header parsing, section mapping, relocation processing |
| **Native API** | T1106 | All APIs resolved dynamically via GetProcAddress and custom hash resolution |
| **Software Packing** | T1027.002 | Custom PIC loader with two-stage shellcode bootstrap and RC4 encryption |
| **Obfuscated Files or Information** | T1027 | RC4-encrypted payload and config, stack-string construction |
| **Deobfuscate/Decode Files** | T1140 | RC4 decryption of payload (8-byte key) and config (separate 8-byte key) |
| **Debugger Evasion** | T1622 | NtGlobalFlag check (PEB+0xBC, flags 0x70), software breakpoint detection |
| **Virtualization/Sandbox Evasion: System Checks** | T1497.001 | VMware detection string "RO\CMV" |
| **Indicator Removal** | T1070.006 | MZ magic byte zeroing post-load, config secure erase after parsing |
| **Disable or Modify Tools** | T1562.001 | PEB walking and indirect syscalls bypass user-mode API hooks |
| **Application Layer Protocol: Web Protocols** | T1071.001 | HTTPS C2 over port 443 with JSON beacon format |
| **Encrypted Channel: Symmetric Cryptography** | T1573.001 | RC4 encryption for C2 communications |
| **Data Encoding: Standard Encoding** | T1132.001 | JSON-formatted beacon (cs, ud, pd, dnm, dsz fields) |
| **Proxy** | T1090 | 2 of 5 C2 domains use Tyk API gateway infrastructure as proxy/redirector |
| **Fallback Channels** | T1008 | 5 C2 domains with comma-separated round-robin failover |
| **System Information Discovery** | T1082 | Hostname/domain name collection (dnm field in beacon) |
| **Process Discovery** | T1057 | Process data collection (pd field in beacon) |

---

## 9. Key Functions (Unpacked Badger)

| Address | Role | Details |
|---------|------|---------|
| `0x100071b0` | Entry point | FreeConsole, state init, create worker thread |
| `0x10007bf0` | Worker thread | Config decrypt, WSA init, C2 beacon loop (248 lines) |
| `0x10007f70` | Config parser | RC4 decrypt, pipe-split by ASCII 124, 27 fields (487 lines) |
| `0x10004b10` | RC4 implementation | Standard KSA + PRGA, default 16-byte key, 8-byte override |
| `0x10008ed0` | State initialisation | JSON beacon templates built via stack strings |
| `0x10033de0` | Stack string builder | Constructs strings char-by-char to evade static detection |
| `0x10013d90` | C2 heartbeat | Beacon check-in with sleep/jitter |
| `0x10008bc0` | Command processor | Parses incoming C2 commands |
| `0x10018c60` | Command dispatcher | Routes commands to appropriate handlers |
| `0x10014700` | Response sender | Sends command output back to C2 |
| `0x10002950` | State struct init | Initialises the 240-byte global state structure |
| `0x10018bd0` | PE header processor | Processes PE headers for reflective loading |
| `0x10034ff0` | CreateThread wrapper | Dynamically-resolved thread creation |
| `0x1002b4c0` | HeapAlloc wrapper | Dynamically-resolved heap allocation |
| `0x100244a0` | memcpy wrapper | Memory copy utility |
| `0x10025560` | String split | Splits buffer by delimiter (used for pipe-delimited config) |

---

## 10. Indicators of Compromise

### 10.1 File Hashes

| Stage | Hash | Value |
|-------|------|-------|
| Packed loader | SHA-256 | `7d30c01dcb8bb19069f96f84ee4b693f4540783f5ccae37eeb1cd3d3f71bc939` |
| Packed loader | MD5 | `3325325e80e3c0e3d3a5d9b7ba5f4916` |
| Unpacked badger | SHA-256 | `6066cf700a0b6ae31c2bb3547917b7ec241fafbda8fff654ad566dec5f2c2a39` |
| Unpacked badger | MD5 | `8a706319c518905cc47730528d2dd22b` |

### 10.2 Network

| Indicator | Type | Detail |
|-----------|------|--------|
| `ridiculous-breakpoint-gw.aws-use1.cloud-ara.tyk.io` | Domain | C2 (Tyk gateway, US-East-1) |
| `uncertain-kitten-gw.aws-euc1.cloud-ara.tyk.io` | Domain | C2 (Tyk gateway, EU-Central-1) |
| `anikvan.com` | Domain | C2 (direct) |
| `boriz400.com` | Domain | C2 (direct) |
| `altynbe.com` | Domain | C2 (direct) |
| `443` | Port | HTTPS C2 communication |
| `/api/azure` | URI | C2 callback endpoint |
| `/content.php` | URI | C2 callback endpoint |

### 10.3 Authentication & Licensing

| Indicator | Type | Detail |
|-----------|------|--------|
| `6J1D1M4P9A57JGC2` | Auth token | Beacon authentication token 1 |
| `LDTPTF78OUCCVQ0I` | Auth token | Beacon authentication token 2 |
| `d0cf9d2be1473579e729382f5c2e22c6c79fa039137f4fb854afb298916fef71` | Hash | BRc4 license hash |

### 10.4 Strings & Artefacts

| String | Location | Purpose |
|--------|----------|---------|
| `badger_x64_wait.bin.packed.dll` | Export name | BRc4 packed badger identifier |
| `{-l," +r3/#~&;v_` | RC4 function | Default RC4 key (16 bytes) |
| `RO\CMV` | Stack string | VMware detection (reversed) |
| `{"cs":"t":` | Stack string | JSON beacon template |
| `Chrome/90.0.4430.93` | Config | User-Agent version string |

### 10.5 Decryption Keys

| Parameter | Value | Usage |
|-----------|-------|-------|
| Payload RC4 key | `7124702c7d70613f` | Decrypts packed payload (8 bytes, from tail of encrypted data) |
| Config RC4 key | `7a3e24647a292175` | Decrypts C2 config (8 bytes, from tail of decrypted payload) |
| Default RC4 key | `{-l," +r3/#~&;v_` | Hardcoded fallback (16 bytes, in RC4 function) |

---

## 11. Analysis Challenges

This sample presented several challenges that required manual analysis beyond automated tooling:

| Challenge | Impact | Resolution |
|-----------|--------|------------|
| **Dynamic API resolution** | 0 suspicious APIs detected by automated triage | Decompiled entry point chain manually to trace execution flow |
| **FLOSS found 0 strings** | No decoded/stack/tight strings for IOC extraction | Stack strings identified through decompilation of `sub_10008ed0` |
| **Emulation returned 0 API calls** | Speakeasy and Qiling both defeated | Pivoted to pure static analysis with angr decompilation |
| **MZ magic zeroed** | Unpacked payload not recognised as PE | Manually patched bytes 0-1 to `0x4D5A` |
| **Config key not in binary** | RC4 key derived from decrypted payload, not stored statically | Traced PIC shellcode disassembly to find `LEA RAX, [R11+RBX-0x10]` key derivation |
| **extract_config_automated failed** | All config data encrypted, no static patterns | Manual decompilation of config parser (`sub_10007f70`) revealed pipe-delimited format |
| **Dual-file analysis** | Config blob in packed binary, parser in unpacked binary | Used Python on host to read packed .data section while Arkana analysed unpacked badger |

---

## 12. Conclusion

This is a **Brute Ratel C4 "badger" implant** — a commercial adversary simulation framework that has become increasingly popular among threat actors due to its advanced EDR evasion capabilities. The sample demonstrates why BRc4 is considered more difficult to detect than Cobalt Strike: dynamic API resolution via hash functions, indirect syscalls that bypass user-mode hooks, stack-string construction that defeats FLOSS, and MZ magic zeroing that evades memory scanners.

The analysis required a multi-session approach spanning three phases: (1) packed loader analysis to understand the self-injection and PIC shellcode bootstrap, (2) manual RC4 decryption and reflective loading reversal to extract the badger payload, and (3) deep-dive decompilation of the badger to extract the C2 configuration. Automated extraction tools (`extract_config_automated`, `extract_config_for_family`) failed due to the complete absence of static indicators — the config exists in plaintext only briefly during runtime initialisation and is immediately zeroed after parsing.

The C2 infrastructure reveals operational sophistication: 5 domains across two Tyk API gateways and three direct domains provide redundancy and traffic blending with legitimate cloud API traffic. The URI path `/api/azure` is designed to appear as normal cloud service communication. The presence of a license hash (`d0cf9d...`) suggests this is either a legitimately purchased BRc4 licence repurposed for malicious activity, or a cracked version — both scenarios have been observed in the wild.

This report demonstrates Arkana's capability for **deep manual-assisted analysis** of heavily obfuscated implants — combining angr decompilation for function-level understanding, raw byte disassembly for PIC shellcode analysis, hex dump inspection for memory layout mapping, and host-side Python scripting for cross-binary data extraction when the loaded-file-at-a-time constraint requires working with multiple binaries simultaneously.

---

*Report generated across multiple Arkana analysis sessions. The config RC4 key derivation was traced through PIC shellcode disassembly (disassemble_raw_bytes) and confirmed by successful decryption of the 403-byte config blob. All 5 C2 domains, auth tokens, URI paths, and the license hash were extracted from the decrypted pipe-delimited configuration.*
