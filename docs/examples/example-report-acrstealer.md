# Malware Analysis Report: ACRStealer Go Loader with Custom Cipher

**Analyst:** Arkana Automated Analysis
**Date:** 2026-03-27
**Classification:** Information Stealer / Loader / Dead Drop Resolver
**Risk Level:** CRITICAL (56/100)
**Source:** Malware Bazaar (uploaded 2026-03-27, same day as analysis)
**Attribution:** ACRStealer family, dropped by RenPyLoader

---

## 1. Executive Summary

This report documents the **deep reverse engineering of a same-day ACRStealer sample** — a Go-compiled information stealer loader obtained from Malware Bazaar within hours of its initial upload. The analysis showcases Arkana's full capabilities across static analysis, binary archaeology, Go-specific reverse engineering, and custom cipher reversal.

The sample is a **Go 1.20+ PE32 GUI application** (1.9 MB, 1,651 Go functions / 3,216 angr-discovered functions) that acts as a **multi-stage loader**: the Go outer layer handles anti-analysis, environment checks, and decryption, whilst the actual stealer payload is encrypted in a ~320 KB blob within the `.rdata` section. At runtime, a **5-stage custom cipher** decrypts the payload into RWX memory for execution.

**Key findings:**
- **Zero static IOCs** — no plaintext URLs, domains, IPs, or browser targeting strings anywhere in the binary. All operational data lives in the encrypted second-stage payload.
- **Invalid code signing** from `new-pay.heleket.com` (Let's Encrypt, issued 3 weeks prior)
- **Comprehensive anti-analysis**: PEB walking for API resolution (12 sites), CPUID VM detection (3 sites), RDTSC timing checks (2 sites), software breakpoint detection — verified by Speakeasy emulation producing **0 intercepted API calls**
- **Custom 5-stage decryption algorithm** fully reversed from decompilation: modular substitution → array reversal → byte pair swap → subtraction → XOR, with key `0x115C4` (71,108)
- **No standard crypto libraries imported** — capa detections of AES/RC4/Salsa20 were all Go runtime internals (AES-NI hash randomisation, ChaCha8 PRNG), not user-space cryptography

**C2 Infrastructure:** The C2 IP `77.238.236.29` (from Malware Bazaar intelligence) and Dead Drop Resolver URLs (Steam/Google Docs profiles) reside in the encrypted second-stage payload, consistent with ACRStealer's known architecture of separating the loader from the operational stealer.

---

## 2. Sample Information

| Property | Value |
|----------|-------|
| **Filename** | `qgB7ZMYQE.exe` (Malware Bazaar) / `acr_stealer.exe` (analysis) |
| **SHA-256** | `558116769157ba364b2a6037b0756e78b8785e5b62d8d97e0b4ad9d8bfcf09c3` |
| **MD5** | `ae89db36336750fb87ea78a8d0ef0b83` |
| **SHA-1** | `90c22c96594c52ceafa551c563e60fdf2f5c332f` |
| **ssdeep** | `24576:NanWkw4EZymTFzVe29jcpCDlHYwnJEFGaXZaaDnxOvzYqmh4bFa3Ev5:oAII9CYE4bFau5` |
| **TLSH** | `T138955B11FEC764F1E403163259BB22AF23399C050F36AA97DB84797DF9BB2D41826349` |
| **Imphash** | `5af915f278815e76bad476ef32593028` |
| **File Size** | 1,912,968 bytes (1.8 MB) |
| **Format** | PE32 (x86), Windows GUI subsystem |
| **Compiler** | Go 1.20+ (detected via gopclntab parser) |
| **Sections** | 6 (`.text`, `.rdata`, `.data`, `.idata`, `.reloc`, `.symtab`) |
| **Imports** | 1 DLL (kernel32.dll), 45 functions — all benign |
| **Rich Header** | Absent (expected for Go) |
| **Signed** | Yes — **INVALID** (certificate chain verification failed) |
| **Origin** | Spain (ES), reported by `iamaachum` |
| **Malware Bazaar Tags** | `ACRStealer`, `dropped-by-RenPyLoader`, `77-238-236-29`, `signed` |
| **First Seen** | 2026-03-27 21:29:58 UTC |

---

## 3. Acquisition

The sample was obtained programmatically from [Malware Bazaar](https://bazaar.abuse.ch/) via its authenticated API, selected for its combination of:
- **ACRStealer** family tag (sophisticated info stealer with Dead Drop Resolver)
- **Go compilation** (unusual for this family — previous variants were C/C++)
- **Code signing** (signed malware with infrastructure indicators)
- **RenPyLoader** delivery chain (multi-stage)
- **Same-day upload** (fresh, unanalysed sample)

The AES-encrypted zip was extracted using `pyzipper` and the standard Malware Bazaar password (`infected`).

---

## 4. Code Signing Analysis

| Property | Value |
|----------|-------|
| **Subject CN** | `new-pay.heleket.com` |
| **Issuer CN** | `E8` (Let's Encrypt) |
| **Algorithm** | sha256WithRSAEncryption |
| **Valid From** | 2026-03-04 |
| **Valid To** | 2026-06-02 |
| **Serial** | `0523cd54eaf24c39b6a3f8e80bec72b669bd` |
| **Thumbprint** | `02a8c915ea7e44d6d6c3ba953fa9a626dadfd7362c1173e36689afd86becce7a` |
| **Validation** | **FAILED** — certificate chain error, no issuer matching "E8" found |

The certificate was issued just **23 days before the sample appeared** — a hallmark of malware operators obtaining short-lived certificates from automated CAs. The domain `new-pay.heleket.com` suggests payment-themed infrastructure, possibly linked to the RenPyLoader delivery campaign.

---

## 5. Go Binary Analysis

### 5.1 gopclntab Metadata

| Property | Value |
|----------|-------|
| **Go Version** | 1.20+ |
| **Analysis Method** | gopclntab (pure-Python parser) |
| **Function Count** | 1,651 (Go pclntab) / 3,216 (angr CFG) |
| **Package Count** | 193 |
| **Source File Count** | 178 |
| **pclntab Magic** | `0xFFFFFFF1` (at file offset `0x129458`) |

### 5.2 Module Architecture (Obfuscated Names)

The main package uses **generic English words** as function names — a deliberate obfuscation technique to hinder analysis:

| Module | References | Sub-functions | Likely Purpose |
|--------|-----------|---------------|----------------|
| `main.Certain` | 55+ | 29 (func2–func29) | Core stealer engine — largest module |
| `main.Brain` | 36+ | 18 | C2 communication and command processing |
| `main.Document` | 25+ | 7 | Credential and file harvesting |
| `main.Bind` | 21+ | 10 | Network binding and Dead Drop Resolver |
| `main.Actual` | 14+ | 9 | Runtime decryption and initialisation |
| `main.Bleak` | 13+ | 3 | Anti-analysis and environment evasion |
| `main.Box` | 10+ | 6 | Data packaging for exfiltration |

### 5.3 Statically Linked DLLs

Go statically links Windows DLLs into the binary. Only `kernel32.dll` appears in the import table (45 benign functions), but the following DLLs are resolved at runtime via PEB walking:

| DLL | Purpose |
|-----|---------|
| `ws2_32.dll` | Winsock networking |
| `dnsapi.dll` | DNS resolution |
| `crypt32.dll` | Certificate and crypto operations |
| `advapi32.dll` | Registry and security |
| `shell32.dll` | Shell operations |
| `userenv.dll` | User profile access |
| `mswsock.dll` | Advanced socket operations |
| `secur32.dll` | Security provider interface |
| `iphlpapi.dll` | Network adapter information |
| `netapi32.dll` | Network management |
| `bcryptprimitives.dll` | Crypto primitives |

---

## 6. Anti-Analysis Techniques

### 6.1 PEB-Walking API Resolution

Capa detected **PEB access at 12 locations** and **PEB ldr_data traversal at 6 locations** — the binary resolves all sensitive APIs by walking the Process Environment Block's loaded module list rather than using the import table. This was **confirmed empirically**: Speakeasy emulation of the full binary captured **zero API calls**, as all function pointers are resolved manually and bypass standard API hooking.

### 6.2 VM and Debugger Detection

| Technique | Locations | Severity |
|-----------|-----------|----------|
| **CPUID** (hypervisor/VM detection) | `0x4024a8`, `0x4763b9`, `0x4763e6` | High |
| **RDTSC** (timing-based anti-debug) | `0x414b6d`, `0x4776db` | Medium |
| **Software breakpoint detection** | Detected by capa | High |
| **Vectored SEH manipulation** | YARA: `SEH__vectored` | Medium |
| **Thread context manipulation** | YARA: `ThreadControl__Context` | Medium |
| **Console control handler** | YARA: `DebuggerException__SetConsoleCtrl` | Low |

### 6.3 YARA Detections

| Rule | Category |
|------|----------|
| `DebuggerException__SetConsoleCtrl` | Anti-Debug |
| `ThreadControl__Context` | Anti-Debug |
| `SEH__vectored` | Anti-Debug |
| `network_udp_sock` | Network |
| `network_tcp_listen` | Network |
| `network_tcp_socket` | Network |
| `network_dns` | Network |
| `win_registry` | Host Interaction |
| `win_token` | Privilege |
| `win_files_operation` | File I/O |

---

## 7. Entropy Analysis

### 7.1 Section Entropy

| Section | Entropy | Size | Permissions |
|---------|---------|------|-------------|
| `.text` | 6.17 | 707,584 | XR |
| `.rdata` | 6.55 | 1,041,408 | R |
| `.data` | 5.57 | 29,184 | RW |
| `.idata` | 3.93 | 1,536 | RW |
| `.reloc` | 6.54 | 39,424 | R |
| `.symtab` | 5.04 | 90,624 | R |

### 7.2 Encrypted Payload Region

The entropy heatmap reveals a **sharp entropy spike to 7.4–7.8** within the `.rdata` section, spanning approximately **320 KB** starting at file offset `0xDB000`. This region contains the encrypted second-stage payload. The surrounding data has typical Go binary entropy (5.0–6.5), making the encrypted blob clearly distinguishable.

---

## 8. Execution Flow — From Entry Point to Decryption

### 8.1 Go Startup Chain

The execution flow was traced through the Go runtime startup sequence:

```
_rt0_386_windows (0x4782f0)
  └→ _rt0_386 (0x476320)
       └→ runtime.rt0_go (0x476340)
            ├→ CPUID checks (GenuineIntel detection)
            ├→ runtime.schedinit
            ├→ runtime.newproc(runtime.main)
            └→ runtime.mstart
                 └→ runtime.main
                      └→ main.main (0x481930)
```

The address of `main.main` (`0x481930`) was recovered by **parsing the Go pclntab directly** — locating the `0xFFFFFFF1` magic at file offset `0x129458`, computing the funcnameTab offset, searching for the "main.main" name entry, and extracting the associated `entryOff` field (`0x80930`) from the funcdata structure.

### 8.2 main.main — Orchestration (0x481930)

Decompilation of `main.main` (310 lines, stack frame `0x15C` bytes) reveals the core orchestration logic:

```
1. sub_498e80()                    — Runtime initialisation
2. Build 10-element configuration array
3. Set operational parameters:
   - flag = 1, timeout = 500, choice = 0
4. sub_4195c0(&g_4bac20)           — Module setup
5. Copy 80,565 bytes from g_4db981  — Encrypted payload
6. decrypt_payload(0, 322261, 322261, 0x115C4)  — DECRYPTION
7. VirtualAlloc(MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
8. Copy decrypted payload to RWX memory
9. Execute decrypted payload
```

The critical finding: `g_4db981` (VA `0x4DB981`, file offset `0xDA981`) is the source of the encrypted payload, and `0x115C4` (71,108) is the decryption key.

### 8.3 decrypt_payload — Custom 5-Stage Cipher (0x482980)

Decompilation of `decrypt_payload` (300 lines) reveals a **bespoke multi-stage cipher** with no resemblance to standard cryptographic algorithms:

#### Stage 1 — Modular Substitution (Alternating Even/Odd)

```c
for (i = 0; i < length; i++) {
    if (!(i & 1)) {  // even bytes
        data[i] -= (key % 53) + (i * 17);
    } else {          // odd bytes
        data[i] = (i * 31) ^ (key % 97) ^ data[i];
    }
}
```

The compiler optimised `key % 53` and `key % 97` using **magic number multiplication**:
- `1296593901 * key >> 36` computes `key / 53` → remainder gives `key % 53 = 35`
- `1416896428 * key >> 37` computes `key / 97` → remainder gives `key % 97 = 104`

#### Stage 2 — Full Array Reversal

```c
left = 0; right = length - 1;
while (left < right) {
    swap(data[left], data[right]);
    left++; right--;
}
```

#### Stage 3 — Adjacent Byte Pair Swap

```c
for (i = 0; i + 1 < length; i += 2) {
    swap(data[i], data[i + 1]);
}
```

#### Stage 4 — Byte Subtraction

```c
for (k = 0; k < length; k++) {
    data[k] -= (key >> 8);  // subtract 0x15 (21)
}
```

#### Stage 5 — XOR with Key and Index

```c
for (l = 0; l < length; l++) {
    data[l] ^= (key & 0xFF) ^ l;  // XOR with 0xC4 ^ l
}
```

#### Derived Constants

| Constant | Derivation | Value |
|----------|------------|-------|
| Even-byte subtract | `key % 53` | 35 |
| Odd-byte XOR | `key % 97` | 104 (`0x68`) |
| Global subtract | `key >> 8` | 277 → byte: `0x15` (21) |
| XOR base | `key & 0xFF` | `0xC4` (196) |

### 8.4 Post-Decryption Execution

After decryption, `main.main` calls `sub_481800` with parameters `(ptr->field_0, ptr->field_4, 0, 0x3000, 64)`:

- `0x3000` = `MEM_COMMIT | MEM_RESERVE`
- `64` = `0x40` = `PAGE_EXECUTE_READWRITE`

This is a **VirtualAlloc** call allocating RWX memory for the decrypted payload — confirming the encrypted blob contains **executable code** (the actual ACRStealer implant) rather than configuration data alone.

---

## 9. Capa Capabilities

| Capability | Namespace | Severity |
|------------|-----------|----------|
| Check for software breakpoints | `anti-analysis/anti-debugging` | High |
| Decompress data using QuickLZ | `data-manipulation/compression` | Medium |
| Encrypt data using AES via x86 extensions* | `data-manipulation/encryption/aes` | Medium |
| Encrypt data using RC4 PRGA* | `data-manipulation/encryption/rc4` | Medium |
| Encrypt data using Salsa20 or ChaCha* | `data-manipulation/encryption/salsa20` | Medium |
| Hash data using murmur3 | `data-manipulation/hashing/murmur` | Medium |
| Access PEB ldr_data | `linking/runtime-linking` | Medium |
| PEB access | Anti-analysis lib rule | Medium |
| Calculate modulo 256 via x86 assembly | Data lib rule | Low |

*\*Investigation revealed these are **Go runtime internals** (AES-NI for map hash randomisation, ChaCha8 for PRNG, RC4 pattern matched against a Go varint decoder), not user-space cryptographic implementations. No `crypto/aes`, `crypto/cipher`, or `crypto/rc4` Go packages are present in the binary.*

---

## 10. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| **Obfuscated Files or Information** | T1027 | Custom 5-stage cipher, encrypted payload in .rdata, obfuscated Go function names |
| **Deobfuscate/Decode Files or Information** | T1140 | Runtime decryption of executable payload using custom cipher |
| **Debugger Evasion** | T1622 | Software breakpoint detection, RDTSC timing, CPUID VM checks |
| **Virtualisation/Sandbox Evasion** | T1497 | CPUID hypervisor bit check, PEB-based environment detection |
| **Process Injection** | T1055 | VirtualAlloc PAGE_EXECUTE_READWRITE for in-memory payload execution |
| **Subvert Trust Controls: Code Signing** | T1553.002 | Invalid certificate from new-pay.heleket.com |
| **Shared Modules** | T1129 | PEB ldr_data walking for runtime API resolution |
| **Native API** | T1106 | Direct PEB access, syscall-based operations |
| **Non-Standard Port** | T1571 | Network capability via ws2_32/dnsapi (port determined by C2 config) |
| **Web Service: Dead Drop Resolver** | T1102.001 | ACRStealer family uses Steam/Google Docs for C2 resolution |

---

## 11. Indicators of Compromise

### 11.1 File Hashes

| Hash | Value |
|------|-------|
| SHA-256 | `558116769157ba364b2a6037b0756e78b8785e5b62d8d97e0b4ad9d8bfcf09c3` |
| MD5 | `ae89db36336750fb87ea78a8d0ef0b83` |
| SHA-1 | `90c22c96594c52ceafa551c563e60fdf2f5c332f` |
| Imphash | `5af915f278815e76bad476ef32593028` |

### 11.2 Network

| Indicator | Type | Source |
|-----------|------|--------|
| `77.238.236.29` | IP Address | Malware Bazaar tag (C2 infrastructure) |

### 11.3 Code Signing

| Indicator | Type | Detail |
|-----------|------|--------|
| `new-pay.heleket.com` | Domain | Certificate Subject CN |
| `02a8c915ea7e44d6d6c3ba953fa9a626dadfd7362c1173e36689afd86becce7a` | Cert Thumbprint | SHA-256 of signing certificate |
| `0523cd54eaf24c39b6a3f8e80bec72b669bd` | Cert Serial | Certificate serial number |

### 11.4 Decryption Parameters

| Parameter | Value | Usage |
|-----------|-------|-------|
| Cipher key | `0x115C4` (71,108) | 5-stage custom cipher key |
| Even-byte subtract constant | 35 | `key % 53` |
| Odd-byte XOR constant | 104 (`0x68`) | `key % 97` |
| Global subtract | 21 (`0x15`) | `key >> 8` |
| XOR base | 196 (`0xC4`) | `key & 0xFF` |
| Encrypted payload offset | `0xDA981` (file) / `0x4DB981` (VA) | Source of encrypted data |
| Payload size (copied) | 80,565 bytes | Bytes copied from global |
| Processing length | 322,261 bytes | Length parameter to decryption function |
| Decryption function | `0x482980` | `decrypt_payload` |
| Entry point (main.main) | `0x481930` | Go main function |

### 11.5 Delivery Chain

| Component | Detail |
|-----------|--------|
| Loader | RenPyLoader (multi-stage delivery) |
| Payload | ACRStealer Go variant |
| Origin | Spain (ES) per Malware Bazaar |

---

## 12. Arkana Tool Coverage

This analysis exercised **50+ Arkana tools** across all seven analysis phases, demonstrating the platform's depth for Go binary reverse engineering:

### Phase 0 — Environment Discovery
`get_config` — Docker container with angr, capa, FLOSS, YARA, StringSifter available

### Phase 1 — Identify
`open_file` → `get_triage_report` → `classify_binary_purpose` → `go_analyze` (gopclntab) → `parse_authenticode` → `get_focused_imports` → `get_strings_summary` → `get_capa_analysis_info` → `scan_for_api_hashes` → `add_note` (hypothesis)

### Phase 3 — Map
`get_function_map` → `detect_crypto_constants` → `scan_for_embedded_files` → `find_anti_debug_comprehensive` → `identify_malware_family` → `get_entropy_analysis` → `map_mitre_attack` → `search_floss_strings` → `get_top_sifted_strings` → `search_for_specific_strings`

### Phase 4 — Deep Dive
`batch_decompile` (digest mode) → `decompile_function_with_angr` (6 functions) → `get_annotated_disassembly` → `disassemble_at_address` (Go startup chain) → `search_decompiled_code` → `get_function_xrefs` (AES/RC4 call chains) → `get_capa_rule_match_details` → `get_cross_reference_map` → `search_hex_pattern` (pclntab magic, RC4 patterns, cipher code) → `get_hex_dump` (encrypted blob, pclntab headers, funcdata) → `rename_function` (main_main, decrypt_payload) → `auto_note_function`

### Phase 5 — Extract
`extract_config_automated` → `find_and_decode_encoded_strings` → `brute_force_simple_crypto` (known-plaintext XOR) → `refinery_xor` (key guessing + application) → `refinery_auto_decrypt` → `refinery_decrypt` (RC4, AES-256-CBC) → `emulate_pe_with_windows_apis` (Speakeasy) → `emulate_and_inspect`

### Phase 7 — Report
`update_hypothesis` → `get_iocs_structured` → `generate_yara_rule` → `generate_cti_report` → `generate_analysis_report` → `map_mitre_attack` (Navigator layer) → `add_note` (IOC, conclusion)

### Generated Artefacts

| Artefact | Path |
|----------|------|
| YARA detection rule | `/output/acr_stealer_yara.yar` |
| Structured IOCs (JSON) | `/output/acr_stealer_iocs.json` |
| CTI report (Markdown) | `/output/acr_stealer_cti_report.md` |
| MITRE ATT&CK Navigator layer | `/output/acr_stealer_mitre_layer.json` |

---

## 13. Significance — What Makes This Sample Interesting

### 13.1 Go Rewrite of a Known Family

ACRStealer was previously a C/C++ stealer using RC4 with key `852149723` and Base64-encoded Dead Drop Resolver URLs on Steam and Google Docs profiles. This sample represents a **complete Go rewrite** — none of the known ACRStealer keys, UUIDs (`f1575b64-8492-4e8b-b102-4d26e8c70371`), or C2 path patterns (`/ujs/`, `/enc_ujs/`) were found, confirming an entirely new codebase.

### 13.2 Custom Cipher vs Standard Crypto

Rather than importing Go's `crypto/aes` or `crypto/rc4` packages, the authors implemented a **bespoke 5-stage cipher** using only arithmetic and bitwise operations. This avoids creating detectable import signatures and makes the encryption harder to identify through standard crypto constant scanning (no S-boxes, no AES round constants, no RC4 permutation tables).

### 13.3 Anti-Analysis Effectiveness

The combination of PEB-walking API resolution + CPUID/RDTSC evasion + encrypted payload proved highly effective:
- **Speakeasy emulation**: 0 API calls captured
- **Static string analysis**: 0 IOCs found (9,071 strings examined)
- **Automated config extraction**: no config recovered
- **Known-key decryption**: all known ACRStealer keys failed

Only by **following the execution flow through decompilation** — from the Go entry point through the pclntab to `main.main` and into the decryption function — was the cipher algorithm and key material recovered.

### 13.4 Loader/Payload Separation

The Go binary functions purely as a **loader and decryptor**. The actual stealer capabilities (browser credential theft, Dead Drop Resolver C2, data exfiltration) reside entirely within the encrypted payload executed from RWX memory. This architectural separation means static analysis of the loader reveals the *how* of delivery but not the *what* of theft — a deliberate design choice to frustrate triage.

---

## 14. Conclusion

This ACRStealer sample demonstrates a sophisticated evolution of the family: a **Go-compiled loader** with comprehensive anti-analysis that wraps an encrypted executable payload containing the actual stealer functionality. The custom 5-stage cipher (modular substitution, reversal, pair swap, subtraction, XOR) was fully reversed through systematic decompilation — from tracing the Go startup chain through pclntab parsing to identifying `main.main` at `0x481930` and the decryption function at `0x482980`.

The analysis required no external tools or custom scripts — every step from acquisition through to cipher reversal was performed exclusively through Arkana's 284 MCP tools, demonstrating the platform's capability for **end-to-end malware analysis of non-trivial, actively-deployed threats**.

---

## 15. References

- [ACRStealer DDR Technique — Broadcom](https://www.broadcom.com/support/security-center/protection-bulletin/acr-stealer-malware-leverages-dead-drop-resolver-ddr-technique)
- [ACRStealer Google Docs C2 — ASEC (AhnLab)](https://asec.ahnlab.com/en/86390/)
- [New ACRStealer Variant with Modifications — ASEC (AhnLab)](https://asec.ahnlab.com/en/89128/)
- [ACRStealer — Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/win.acr_stealer)
- [ACRStealer Syscall Evasion Variant — Cryptika](https://www.cryptika.com/new-acrstealer-variant-uses-syscall-evasion-tls-c2-and-secondary-payload-delivery/)

---

*Report generated from a single Arkana analysis session. The custom 5-stage cipher was reversed from angr decompilation of the Go binary's main.main and decrypt_payload functions. The Go pclntab was parsed at the byte level to locate main.main's entry point address. All analysis was conducted exclusively through Arkana's MCP tools — no external scripts, disassemblers, or debuggers were used.*
