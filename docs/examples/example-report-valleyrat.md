# Malware Analysis Report: ValleyRAT Multi-Stage Loader

**Analyst:** Arkana Automated Analysis (multi-session)
**Date:** 2026-03-21
**Classification:** Remote Access Trojan (RAT) / Loader / Process Injector
**Risk Level:** CRITICAL (81/100)
**Attribution:** Chinese-origin (Silver Fox APT / ValleyRAT family)

---

## 1. Executive Summary

This report documents the **complete multi-stage unpacking and C2 extraction** of a ValleyRAT sample — a Chinese-origin remote access trojan associated with the Silver Fox APT group. The analysis required reversing **5 layers of encryption and encoding** to reach the final implant and extract its C2 configuration.

The execution chain proceeds through: UPX unpacking → RC4-encrypted PE64 DLL extraction → custom config decryption pipeline (delimiter removal → Base64 → XOR → subtract) → shellcode with PEB-walking reflective loader and AMSI/ETW/WLDP bypasses → custom ARX block cipher in CTR mode → final PE64 RAT implant.

The inner PE is a full-featured RAT with process hollowing (via `CreateProcessA` suspended + `VirtualAllocEx` + `WriteProcessMemory`), registry persistence, raw TCP/UDP C2 communication, and modular capabilities (screenshot, keylogging, process management). The C2 configuration uses **reversed-string obfuscation** with pinyin-abbreviated field names.

**C2 Server:** `8.136.41.104:3323` (Alibaba Cloud, China)

---

## 2. Sample Information

### 2.1 Outer Sample (UPX-Packed Loader)

| Property | Value |
|----------|-------|
| **Filename** | `valleyrat_d4c7157d.exe` |
| **SHA-256** | `d4c7157d593e6ac6c4afc9a466f731d577caee271a29ca8ef0bc9acd12322c4e` |
| **Format** | PE64 (x64), UPX-packed |

### 2.2 Stage 2 — PE64 DLL Payload

| Property | Value |
|----------|-------|
| **Filename** | `valleyrat_payload_full.exe` |
| **File Size** | 530,944 bytes (518 KB) |
| **Format** | PE64 (x64) DLL |
| **Image Base** | `0x20FB30000` |
| **Sections** | 10 |
| **Imports** | 3 DLLs, 120 functions |

### 2.3 Stage 5 — Inner PE (Final RAT Implant)

| Property | Value |
|----------|-------|
| **Filename** | `valleyrat_inner_pe.bin` |
| **SHA-256** | `2842a9c07da8706c2e5c1441313d00d5528a7f1e07c8f01046745f113e7df9a6` |
| **MD5** | `3846180eb7f12b7b90abf9201e778b3a` |
| **File Size** | 134,968 bytes (132 KB) |
| **Format** | PE64 (x64), MSVC |
| **Image Base** | `0x140000000` |
| **Entry Point** | RVA `0x9A74` |
| **Sections** | 6 |
| **Imports** | 5 DLLs, 130 functions |
| **Compiler** | Microsoft Visual C++ 8.0 |
| **Signed** | No |
| **Risk Score** | 81/100 (CRITICAL) |

---

## 3. Execution Chain (5 Stages)

### 3.1 Stage 1 — UPX Unpacking

The outer executable is UPX-packed. Standard `upx -d` decompression yields the PE64 DLL payload.

### 3.2 Stage 2 — PE64 DLL Config Extraction

The DLL reads an embedded encrypted config blob and applies a 4-step decryption pipeline:

| Step | Operation | Detail |
|------|-----------|--------|
| 1 | Delimiter removal | Strip non-Base64 delimiter characters |
| 2 | Base64 decode | Standard Base64 decoding |
| 3 | XOR | Single-byte XOR with key `0xBE` |
| 4 | Subtract | Subtract `9` from each byte |

The output is **164,939 bytes of shellcode** containing an encrypted data structure and a reflective loader.

### 3.3 Stage 3 — Shellcode Structure

The shellcode is laid out as:

```
Offset 0x000: CALL +0x221C0          (5 bytes — jumps over data to code)
Offset 0x005: Data structure          (139,712 bytes — encrypted)
Offset 0x221E5: Reflective loader     (~25,222 bytes — PEB-walking code)
```

#### Shellcode Data Structure Layout

```
Offset 0x000: uint32  total_size     = 0x000221C0 (139,712)
Offset 0x004: byte[16] cipher_key    = 1C 07 5F 65 50 9C DB 0A 56 01 D8 65 1D 7C 40 D9
Offset 0x014: byte[16] cipher_ctr    = 7B 11 5D 50 F2 CA 33 07 02 5D FD 30 CB 19 2D DC
Offset 0x028: uint64  hash_param     (module search base)
Offset 0x048: uint64  api_hash_1     (VirtualAlloc)
Offset 0x050: uint64  api_hash_2     (VirtualFree)
Offset 0x1E8: uint64  api_hash_3     (ExitThread)
Offset 0x234: uint32  decrypt_flag   = 3 (triggers ARX-CTR decryption)
Offset 0x238: uint32  exec_flag      = 0 (0=synchronous, non-zero=threaded)
Offset 0x23C: byte[]  encrypted_data (139,140 bytes)
```

#### Reflective Loader (sub_221E5)

The loader performs classic PEB module walking:
1. `gs:[0x30]` → TEB → PEB → `Ldr` → `InLoadOrderModuleList`
2. Resolves APIs by hash via `sub_25055` (PEB walker) + `sub_22B61` (export resolver)
3. Allocates memory with `VirtualAlloc` and copies the data structure
4. Checks `decrypt_flag` at `[rdi+0x234]`: if `== 3`, calls the ARX-CTR decryption function
5. Checks `exec_flag` at `[rdi+0x238]`: if `== 0`, calls the thread entry directly (synchronous)

**Anti-disassembly trick:** `xor eax, eax; js target` — the Sign Flag is always 0 after XOR, so the jump is never taken, but static disassemblers may follow the false branch.

### 3.4 Stage 4 — ARX-CTR Block Cipher

The decryption function (`sub_25255`) implements a **custom ARX (Add-Rotate-XOR) block cipher in CTR mode**:

#### Cipher Parameters
- **Block size:** 16 bytes (4 × 32-bit words)
- **Key:** 16 bytes at structure offset `0x004`
- **Counter/Nonce:** 16 bytes at structure offset `0x014`
- **Rounds:** 16

#### Round Function (per round)
```
a1 = b + a
c1 = c + d
b1 = ROL32(b, 5)  XOR a1
d1 = ROL32(d, 8)  XOR c1
c2 = c1 + b1
b2 = ROL32(b1, 7) XOR c2
c3 = ROR32(c2, 16)
a2 = ROL32(a1, 16) + d1
d2 = ROL32(d1, 13) XOR a2
→ output: (a2, b2, c3, d2)
```

#### Cipher Mode
1. Load 16-byte counter block
2. Pre-XOR counter with key (whitening)
3. Apply 16 ARX rounds
4. Post-XOR result with key (whitening)
5. XOR keystream block with ciphertext → plaintext
6. Increment counter (big-endian byte order)
7. Repeat for each 16-byte block

#### Integrity Verification
After decryption, `sub_250C9` computes a hash over the decrypted data at `[rdi+0xC2C]` and compares it with the expected value at `[rdi+0xD30]`. The hash processes 16-byte blocks with `0x80` padding (MD5-style).

### 3.5 Stage 5 — Decrypted Payload

Decryption produces **139,140 bytes** containing:

| Region | Offset | Size | Content |
|--------|--------|------|---------|
| Config blob | `0x000` | 4,172 bytes | AMSI/ETW bypass targets, DLL names, campaign marker |
| Inner PE | `0x104C` | 134,968 bytes | The final ValleyRAT implant (PE64, AMD64) |

---

## 4. Pre-PE Configuration Blob (AMSI/ETW/WLDP Bypass)

The first 4,172 bytes of decrypted data contain the shellcode's defense evasion configuration:

### 4.1 DLL Preload List

```
ole32;oleaut32;wininet;mscoree;shell32
```

### 4.2 Bypass Targets

| Category | API Function | Purpose |
|----------|-------------|---------|
| **AMSI** | `AmsiInitialize` | Disable AMSI scanning |
| **AMSI** | `AmsiScanBuffer` | Patch buffer scanning |
| **AMSI** | `AmsiScanString` | Patch string scanning |
| **WLDP** | `WldpQueryDynamicCodeTrust` | Bypass dynamic code trust |
| **WLDP** | `WldpIsClassInApprovedList` | Bypass class approval |
| **ETW** | `EtwEventWrite` | Suppress event tracing |
| **ETW** | `EtwEventUnregister` | Unregister trace providers |

### 4.3 Module Targets

| Module | Purpose |
|--------|---------|
| `amsi` | AMSI DLL for patching |
| `clr` | CLR runtime (AMSI host) |
| `wldp` | Windows Lockdown Policy |
| `ntdll` | Direct syscall / bypass targets |

### 4.4 Campaign Marker

```
RF77CTMM
```

The shellcode patches these API functions in memory before loading the inner PE, effectively blinding Windows Defender (AMSI), application whitelisting (WLDP), and event tracing (ETW).

---

## 5. C2 Configuration

### 5.1 Config Location & Encoding

The C2 configuration is stored as a **UTF-16LE wide string** at file offset `0x1DE40` within the inner PE's data section. The obfuscation scheme reverses both key names and values:

```
|0:db|0:lk|0:hs|0:ld|0:ll|0:hb|0:pj|4 .21.5202:zb|0.1:bb|默认:zf|
1:lc|1:dd|1:3t|08:3o|1.0.0.721:3p|1:2t|3233:2o|401.14.631.8:2p|
1:1t|3233:1o|401.14.631.8:1p|
```

### 5.2 Decoded Configuration

| Key | Pinyin | Meaning | Raw (Reversed) | Decoded |
|-----|--------|---------|----------------|---------|
| `p1` | — | C2 Server 1 IP | `401.14.631.8` | **`8.136.41.104`** |
| `o1` | — | C2 Server 1 Port | `3233` | **`3323`** |
| `t1` | — | C2 Server 1 Type | `1` | `1` (TCP) |
| `p2` | — | C2 Server 2 IP | `401.14.631.8` | **`8.136.41.104`** |
| `o2` | — | C2 Server 2 Port | `3233` | **`3323`** |
| `t2` | — | C2 Server 2 Type | `1` | `1` (TCP) |
| `p3` | — | C2 Server 3 IP | `1.0.0.721` | **`127.0.0.1`** |
| `o3` | — | C2 Server 3 Port | `08` | **`80`** |
| `t3` | — | C2 Server 3 Type | `1` | `1` |
| `fz` | 分组 (fēnzǔ) | Group/Campaign | `认默` | **`默认`** ("default") |
| `bb` | 版本 (bǎnběn) | Version | `0.1` | **`1.0`** |
| `bz` | 编制 (biānzhì) | Build Date | `4 .21.5202` | **`2025.12.4`** |
| `jp` | 截屏 (jiépíng) | Screenshot | `0` | Disabled |
| `bh` | 保活 (bǎohuó) | Heartbeat | `0` | Disabled |
| `kl` | 键盘 (jiànpán) | Keylogger | `0` | Disabled |
| `bd` | 本地 (běndì) | Debug/Local | `0` | Disabled |
| `dd` | — | Flag | `1` | Enabled |
| `cl` | — | Flag | `1` | Enabled |

### 5.3 Config Key Templates

The config parser uses key templates stored at file offset `0x19690`:

```
p1: o1: t1: p2: o2: t2: p3: o3: t3:
dd: cl: fz: bb: bz: jp: sx: bh: ll: dl: sh: kl: bd:
```

The key names are **pinyin abbreviations** of Chinese words, confirming Chinese-language development.

---

## 6. Capabilities

### 6.1 Capa Analysis (40 Rules Matched)

| Capability | Namespace | ATT&CK |
|------------|-----------|--------|
| **Write process memory** | — | T1055 |
| **Allocate or change RWX memory** | `host-interaction/process/inject` | T1055 |
| **Use process replacement** | `host-interaction/process/inject` | T1055.012 |
| **Create process suspended** | `host-interaction/process/create` | T1055.012 |
| **Resume thread** | `host-interaction/thread/resume` | T1055.012 |
| **Execute shellcode via indirect call** | `load-code/shellcode` | T1620 |
| **Spawn thread to RWX shellcode** | `load-code/shellcode` | T1055.003 |
| **Create TCP socket** | `communication/socket/tcp` | T1095 |
| **Create UDP socket** | `communication/socket/udp/send` | T1095 |
| **Act as TCP client** | `communication/tcp/client` | T1095 |
| **Connect TCP/UDP socket** | `communication/socket` | T1095 |
| **Resolve DNS** | `communication/dns` | T1071 |
| **Send/receive data** | `communication` | T1095 |
| **Encode data using XOR** | `data-manipulation/encoding/xor` | T1027 |
| **Set/delete registry value** | `host-interaction/registry` | T1112 |
| **Enumerate PE sections** | `load-code/pe` | T1129 |
| **Resolve function by parsing PE exports** | `load-code/pe` | T1129 |
| **Create process on Windows** | `host-interaction/process/create` | T1106 |
| **Link many functions at runtime** | `linking/runtime-linking` | T1129 |
| **Terminate process** | `host-interaction/process/terminate` | T1489 |

### 6.2 Process Injection (Process Hollowing)

The RAT implements classic **process hollowing** (T1055.012):

1. `CreateProcessA` with `CREATE_SUSPENDED` flag
2. `VirtualAllocEx` in the remote process
3. `WriteProcessMemory` to inject payload
4. `ResumeThread` to execute

### 6.3 Network Communication

The RAT uses **raw TCP/UDP sockets** (not HTTP) for C2 communication:
- WSA initialization (`initialize Winsock library`)
- TCP client with socket configuration
- DNS resolution for C2 domain fallback
- Send/receive data on socket
- XOR encoding for data in transit

### 6.4 Anti-Analysis

| Technique | Implementation |
|-----------|---------------|
| **Debugger detection** | `IsDebuggerPresent` API import |
| **Timing checks** | `GetTickCount`, `QueryPerformanceCounter` |
| **AMSI bypass** | Patches AmsiInitialize/ScanBuffer/ScanString in memory |
| **ETW bypass** | Patches EtwEventWrite/EtwEventUnregister |
| **WLDP bypass** | Patches WldpQueryDynamicCodeTrust/IsClassInApprovedList |
| **Anti-disassembly** | `xor eax,eax; js target` (dead branch trick) |
| **String reversal** | C2 config values stored reversed |
| **PEB walking** | API resolution via PEB→Ldr→InLoadOrderModuleList (no imports) |

---

## 7. YARA Matches

| Rule | Category | Description |
|------|----------|-------------|
| **ThreadControl__Context** | Anti-debug | Thread context manipulation (AntiDebug) |
| **anti_dbg** | Anti-debug | Debugger detection checks |
| **inject_thread** | Injection | CreateRemoteThread code injection |
| **win_registry** | Persistence | Registry manipulation |
| **win_files_operation** | File I/O | Private profile file access |

---

## 8. Security Mitigations

| Mitigation | Status |
|------------|--------|
| ASLR | Enabled |
| High Entropy ASLR | **Not set** |
| DEP/NX | Enabled |
| CFG Guard | **Not enforced** |
| SEH Protection | Not set |
| Force Integrity | Not set |

---

## 9. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| **Process Hollowing** | T1055.012 | CreateProcessA (suspended) + VirtualAllocEx + WriteProcessMemory + ResumeThread |
| **Thread Execution Hijacking** | T1055.003 | Spawn thread to RWX shellcode |
| **Reflective Code Loading** | T1620 | PEB-walking shellcode, PE export resolution |
| **Non-Application Layer Protocol** | T1095 | Raw TCP/UDP socket C2 (port 3323) |
| **Obfuscated Files or Information** | T1027 | 5-stage encryption chain, XOR encoding, string reversal |
| **Deobfuscate/Decode Files** | T1140 | Multi-layer decryption at runtime |
| **Modify Registry** | T1112 | `HKLM\SOFTWARE\IpDates_info` persistence |
| **Masquerading: Match Legitimate Name** | T1036.005 | DLL sideloading via `tracerpt.exe` (LOLBin) |
| **Disable or Modify Tools** | T1562.001 | AMSI, ETW, WLDP runtime patching |
| **Debugger Evasion** | T1622 | IsDebuggerPresent, timing checks |
| **Shared Modules** | T1129 | Runtime API linking via PE export parsing |
| **Native API** | T1106 | Direct PEB access, ntdll targeting |

---

## 10. Indicators of Compromise

### 10.1 File Hashes

| Stage | Hash Type | Value |
|-------|-----------|-------|
| Outer (packed) | SHA-256 | `d4c7157d593e6ac6c4afc9a466f731d577caee271a29ca8ef0bc9acd12322c4e` |
| Inner PE (implant) | SHA-256 | `2842a9c07da8706c2e5c1441313d00d5528a7f1e07c8f01046745f113e7df9a6` |
| Inner PE (implant) | MD5 | `3846180eb7f12b7b90abf9201e778b3a` |

### 10.2 Network

| Indicator | Type | Detail |
|-----------|------|--------|
| `8.136.41.104` | IP Address | C2 server (Alibaba Cloud, China) |
| `3323` | Port | C2 communication port (TCP) |

### 10.3 Host-Based

| Indicator | Type | Detail |
|-----------|------|--------|
| `d33f351a4aeea5e608853d1a56661059` | Mutex | Process mutex (MD5 hash format) |
| `HKLM\SOFTWARE\IpDates_info` | Registry Key | Persistence / C2 IP storage |
| `IpDate` | Registry Value | C2 IP storage value name |
| `Console\1` | Registry Path | Configuration storage |
| `Windows\System32\tracerpt.exe` | LOLBin | DLL sideloading vector |
| `RF77CTMM` | Campaign Marker | In shellcode config blob |

### 10.4 Strings

| String | Location | Purpose |
|--------|----------|---------|
| `denglupeizhi` | Inner PE `0x195F8` | Pinyin for 登录配置 ("login configuration") |
| `CKernelManager` | Inner PE `0x1DE20` | Kernel management class name |
| `MiniDumpWriteDump` | Inner PE `0x19780` | Crash dump capability |
| `%s-%04d%02d%02d-%02d%02d%02d.dmp` | Inner PE `0x197B0` | Dump filename format |

### 10.5 Decryption Keys

| Parameter | Value | Usage |
|-----------|-------|-------|
| Config XOR key | `0xBE` | Stage 2 config decryption |
| Config subtract | `9` | Stage 2 config decryption |
| ARX cipher key | `1c075f65509cdb0a5601d8651d7c40d9` | Stage 4 inner PE decryption |
| ARX cipher CTR | `7b115d50f2ca330702 5dfd30cb192ddc` | Stage 4 counter/nonce |

---

## 11. Attribution

| Evidence | Detail |
|----------|--------|
| **Language** | Chinese pinyin config keys (fz=分组, bb=版本, bz=编制, kl=键盘, jp=截屏, bh=保活) |
| **String** | `denglupeizhi` = 登录配置 ("login configuration") |
| **Campaign name** | 默认 (mòrèn = "default" in Chinese) |
| **Infrastructure** | Alibaba Cloud hosting (`8.136.41.104`) |
| **Family** | ValleyRAT — associated with Silver Fox APT |
| **TTPs** | Consistent with known ValleyRAT: `tracerpt.exe` sideloading, multi-stage shellcode, AMSI/ETW patching, reversed-string C2 config |

---

## 12. Conclusion

This is a **ValleyRAT** implant — a Chinese-origin RAT associated with the Silver Fox APT group. The sample demonstrates sophisticated multi-stage loading with 5 layers of encryption/encoding, a custom ARX block cipher implementation, and comprehensive defense evasion (AMSI, ETW, WLDP, and anti-debug bypasses).

The analysis required reversing each stage sequentially: UPX → RC4 → custom config pipeline → reflective shellcode → ARX-CTR cipher → inner PE extraction. The final implant communicates over raw TCP sockets to `8.136.41.104:3323` (Alibaba Cloud, China) and supports process hollowing, registry persistence, and modular capabilities including screenshot capture and keylogging.

This report demonstrates Arkana's capability for **deep multi-stage malware unpacking** — combining angr decompilation of the custom ARX cipher, PEB-walking shellcode analysis, hex pattern searching for encrypted payloads, and automated triage/capa/YARA analysis of the extracted inner PE. The entire analysis was conducted through Arkana's MCP tools with minimal custom code (only the ARX cipher decryption required a Python implementation, as the cipher is non-standard).

---

*Report generated across multiple Arkana analysis sessions. The custom ARX block cipher was reversed from angr decompilation of the shellcode loader. C2 configuration was extracted from the inner PE's data section using Arkana's wide string extraction and hex dump tools.*
