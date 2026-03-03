# Malware Analysis Report: LockBit 3.0 Ransomware

**Analyst:** Arkana Automated Analysis
**Date:** 2026-03-03
**Classification:** Ransomware (Packed)
**Risk Level:** CRITICAL (36/100 static — understated due to packing)
**VT Detection:** 63/72

---

## 1. Executive Summary

This report documents the triage-level analysis of a **LockBit 3.0 / BlackMatter ransomware** sample. The binary is **heavily packed** with near-maximum entropy (7.998) across all executable sections, a self-modifying `.text` section (RWX), and an unconventional entry point in `.itext`. Packing effectively conceals the ransomware payload from static analysis — no ransom note strings, no encryption routine identifiers, and no meaningful IOCs are visible without unpacking.

Despite the packing, Arkana identified **RC4 KSA** and **XOR encoding** routines in the unpacking stub, dynamic API resolution via `GetProcAddress`/`GetModuleHandleA`, and a **screenshot capture capability** (`BitBlt`). The domain `z.pw` was recovered from static strings.

Full behavioral analysis would require dynamic execution or unpacking to reveal the ransomware payload.

---

## 2. Sample Information

| Property | Value |
|----------|-------|
| **Filename** | lockbit.exe |
| **SHA-256** | `a61687dca6e71baa451a3ba677299af8c0b8d576f7e348609aa43162ca550dc3` |
| **MD5** | `9698c2af88de2ca817dd83f394a2be5d` |
| **SHA-1** | `6644e6e6e57ec05e0919cd7de2306b3800a272fb` |
| **ssdeep** | `3072:l7iU6uq8updgvFD8KzN/lyGeNOvCnkvxj5RaPUdQeSuDN4esFnhvQXQlm1Y:l7i3p80gvZ5lkOR9ccdQbuDN4plhImmK` |
| **File Size** | 148,480 bytes (145 KB) |
| **Format** | PE32 (x86), Windows GUI |
| **Compiler** | MSVC (linker 14.12) |
| **Compiled** | 2022-09-13 23:30:57 UTC |
| **Signed** | No |
| **Sections** | 5 (.text, .itext, .rdata, .data, .pdata) |
| **Imports** | 25 functions from 3 DLLs (KERNEL32, USER32, GDI32) |
| **Rich Header** | Absent (stripped) |
| **VT Label** | ransomware.lockbit/blackmatter |
| **VT First Seen** | 2025-12-19 |
| **VT Names** | "LB3_pass.exe", "x815bbhoz.exe" |

---

## 3. Packing Analysis

### 3.1 Packing Verdict: Likely Packed (Confidence 6/10)

The binary is heavily packed/encrypted. Multiple independent indicators confirm this:

| Indicator | Detail | Severity |
|-----------|--------|----------|
| .text entropy | **7.998** (max is 8.0) | HIGH |
| .data entropy | **7.995** | HIGH |
| .pdata entropy | **7.968** | HIGH |
| .text permissions | **RWX** (writable + executable) | HIGH |
| Entry point | In `.itext` section (0x41946f), not `.text` | MEDIUM |
| PEiD signatures | FSG v1.10, ASProtect v1.32, TINYPROG v3.6 | Multiple matches |

### 3.2 Section Layout

| Section | VA | Virtual Size | Raw Size | Permissions | Entropy |
|---------|-----|-------------|----------|-------------|---------|
| .text | 0x1000 | 97,606 | 97,792 | **RWX** | 7.998 |
| .itext | 0x19000 | 1,385 | 1,536 | R-X | — |
| .rdata | 0x1a000 | 1,202 | 1,536 | R-- | — |
| .data | 0x1b000 | 44,488 | 40,960 | RW- | 7.995 |
| .pdata | 0x26000 | 5,304 | 5,632 | RW- | 7.968 |

The `.text` section being both writable and executable is a strong packing indicator — the unpacking stub decrypts the payload into this section at runtime.

### 3.3 Implications

- Static string analysis yields almost no readable content (1,822 strings extracted, nearly all encrypted garbage)
- No ransomware note text, .onion URLs, or crypto wallet addresses are visible
- No meaningful crypto constants detected (encrypted within the packed payload)
- Capa and YARA analysis is limited to the unpacking stub
- MITRE ATT&CK auto-mapping returned 0 techniques (packing defeats static behavioral analysis)

---

## 4. Capabilities Detected (Unpacking Stub)

Despite heavy packing, the following capabilities were identified in the unpacking/loader stub:

### 4.1 Capa Rules Matched

| Capability | Namespace | Matches | ATT&CK |
|------------|-----------|---------|--------|
| Encode data using XOR | data-manipulation/encoding/xor | 2 addresses | T1027 |
| Encrypt data using RC4 KSA | data-manipulation/encryption/rc4 | 1 address | T1027 |
| Contain loop | (library rule) | 10 functions | — |

### 4.2 Dynamic API Resolution

The unpacking stub resolves APIs at runtime to avoid static import detection:

| API | Purpose |
|-----|---------|
| `GetProcAddress` | Resolve function addresses dynamically |
| `GetModuleHandleA` | Get module base for API resolution |
| `FreeLibrary` | Unload libraries after use |
| `BitBlt` | **Screenshot capture** (GDI32) |

The minimal import table (25 functions) combined with `GetProcAddress` is a classic indicator of packed malware that dynamically resolves its full API surface after unpacking.

### 4.3 YARA Matches

| Rule | Description |
|------|-------------|
| screenshot | Take screenshot capability |
| IsPacked | Entropy-based packing detection |
| contains_base64 | Base64-encoded data present |
| domain | Domain name detected |
| HasDebugData | Debug data directory present |

---

## 5. Security Posture

| Mitigation | Status |
|------------|--------|
| ASLR | **Disabled** |
| High Entropy ASLR | **Disabled** |
| DEP/NX | Enabled |
| SEH Protection | Not set |
| Control Flow Guard | **Disabled** |
| Force Integrity | Not set |

The lack of ASLR and CFG is typical for malware — these protections benefit defenders and are intentionally omitted.

---

## 6. Indicators of Compromise

### 6.1 File Hashes

| Hash | Value |
|------|-------|
| SHA-256 | `a61687dca6e71baa451a3ba677299af8c0b8d576f7e348609aa43162ca550dc3` |
| MD5 | `9698c2af88de2ca817dd83f394a2be5d` |
| SHA-1 | `6644e6e6e57ec05e0919cd7de2306b3800a272fb` |
| ssdeep | `3072:l7iU6uq8updgvFD8KzN/lyGeNOvCnkvxj5RaPUdQeSuDN4esFnhvQXQlm1Y:l7i3p80gvZ5lkOR9ccdQbuDN4plhImmK` |

### 6.2 Network

| Type | Value | Notes |
|------|-------|-------|
| Domain | `z.pw` | Short domain, possible C2/exfil relay |

### 6.3 File System

| Indicator | Value |
|-----------|-------|
| Known VT filename | `x815bbhoz.exe` (random name, dropped to `C:\Windows\`) |
| Known VT filename | `LB3_pass.exe` (password-protected LockBit 3.0 variant) |

---

## 7. MITRE ATT&CK Mapping (Manual)

Static analysis of the packed stub provides limited ATT&CK coverage. The following techniques are inferred from the unpacking stub and known LockBit 3.0 behaviour:

| Technique | ID | Evidence |
|-----------|----|----------|
| **Obfuscated Files or Information** | T1027 | RC4 KSA + XOR encoding in unpacking stub |
| **Software Packing** | T1027.002 | Entropy 7.998, RWX .text, PEiD matches |
| **Dynamic API Resolution** | T1106 | GetProcAddress + GetModuleHandleA + FreeLibrary |
| **Screen Capture** | T1113 | BitBlt (GDI32) import |
| **Data Encrypted for Impact** | T1486 | VT classification: ransomware.lockbit |

*Note: Full ATT&CK mapping would require dynamic analysis of the unpacked payload.*

---

## 8. Analysis Limitations

This analysis is **triage-level only** due to the heavy packing:

1. **No ransomware payload analysis** — the encryption routines, ransom note, and file targeting logic are hidden within the packed .text section
2. **No C2 infrastructure** — beyond the `z.pw` domain, all network IOCs are encrypted
3. **No YARA rule generated** — byte patterns from the packed stub would produce high false-positive rates
4. **Capa coverage minimal** — only 3 rules matched against the unpacking stub vs the full payload

### Recommended Next Steps

| Action | Tool |
|--------|------|
| Automated unpacking | `auto_unpack_pe()` — attempt UPX/ASPack/PEtite/FSG unpacking |
| Manual unpacking | `emulate_pe_with_windows_apis()` — run in Speakeasy emulator |
| Shellcode emulation | `emulate_shellcode_with_speakeasy()` — if unpacking stub is shellcode-like |
| Similarity clustering | `compute_similarity_hashes()` — ssdeep/TLSH against known LockBit variants |
| Dynamic analysis | Execute in sandbox (ANY.RUN, CAPE, Joe Sandbox) for full behavioral trace |

---

## 9. Conclusion

This is a **LockBit 3.0** ransomware sample (also labelled BlackMatter by some vendors) with professional-grade packing that defeats static analysis. The packed stub uses RC4 and XOR to decrypt the payload at runtime, dynamically resolves APIs via `GetProcAddress`, and includes a screenshot capture capability (`BitBlt`).

The binary's characteristics — stripped Rich header, disabled ASLR/CFG, RWX .text section with near-maximum entropy, and entry point in a separate `.itext` section — are consistent with the LockBit 3.0 builder output. The filename `LB3_pass.exe` on VirusTotal suggests this is a password-protected variant that requires a command-line password to execute.

Static analysis alone provides limited visibility into packed samples. This report demonstrates that Arkana can still extract valuable intelligence from the unpacking stub (crypto primitives, API resolution, imported capabilities) and integrate external threat intelligence (VirusTotal) to contextualise the sample, even when the primary payload is inaccessible.

---

*Report generated from Arkana triage analysis. Full analysis would require dynamic execution or unpacking.*
