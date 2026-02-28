# Unpacking Guide

Strategies for identifying and unpacking packed, encrypted, or obfuscated binaries.

---

## Identifying Packed Binaries

### Automated Detection
```
get_triage_report(compact=True)    → check packing_assessment section
detect_packing()                   → dedicated packing detection
analyze_entropy_by_offset()        → entropy visualization
```

### Key Indicators

| Indicator | Threshold | Meaning |
|-----------|-----------|---------|
| `max_section_entropy` | > 7.2 in executable sections | Almost certainly packed |
| `total_import_functions` | < 10 | Likely packed (real binaries import dozens) |
| `peid_matches` | Any match | Known packer identified |
| `packer_section_names` | UPX0/UPX1, .aspack, .themida, etc. | Named packer sections |
| Section `virtual_size >> raw_size` | Virtual 10x+ larger than raw | Unpacking stub expands |
| Section with W+X permissions | Any | Self-modifying code (unpacking) |
| Very few strings | < 20 readable strings | Content is encrypted |
| Single large section | > 90% of file in one section | Packed payload |

### Common Packer Signatures

| Packer | Section Names | PEiD Signature | Notes |
|--------|---------------|----------------|-------|
| UPX | UPX0, UPX1, UPX2 | UPX 3.x+ | Most common, easily unpacked |
| ASPack | .aspack, .adata | ASPack 2.x | |
| PECompact | PEC2, PECompact2 | PECompact 2.x | |
| Themida/WinLicense | .themida | Themida/WinLicense | VM-based, hard to unpack |
| VMProtect | .vmp0, .vmp1 | VMProtect | Code virtualization |
| Obsidium | .obsidium | Obsidium | Anti-debug heavy |
| MPRESS | .MPRESS1, .MPRESS2 | MPRESS | |
| Enigma | .enigma1, .enigma2 | Enigma Protector | |
| Petite | .petite | Petite | |
| NSPack | .nsp0, .nsp1 | NSPack | |
| .NET Reactor | — | .NET Reactor | .NET obfuscator |
| ConfuserEx | — | ConfuserEx | .NET obfuscator |
| Dotfuscator | — | Dotfuscator | .NET obfuscator |

---

## Unpacking Methods

### Method 1: auto_unpack_pe() — Known Packers

**Best for**: UPX, ASPack, PECompact, MPRESS, and other well-known packers
identified by PEiD or section names.

```
auto_unpack_pe()
```

- Automatically identifies the packer and applies the appropriate unpacking algorithm
- Handles most common commercial and open-source packers
- Returns the unpacked binary ready for analysis
- If it fails, falls through to Method 2

**After success**: Re-run `open_file()` on the unpacked binary, then Phase 1.

### Method 2: try_all_unpackers() — Orchestrated Attempt

**Best for**: When the packer is unknown or auto_unpack_pe() failed.

```
try_all_unpackers()
```

- Orchestrates multiple unpacking strategies in sequence
- Tries known unpackers, then generic/heuristic approaches
- Reports which method succeeded (or all failures)
- More thorough but slower than Method 1

**After success**: Re-run Phase 1 on the result.

### Method 3: qiling_dump_unpacked_binary() — Emulation-Based

**Best for**: Custom packers, unknown packers, heavily obfuscated stubs where
static unpacking fails.

```
qiling_setup_check()                       → verify rootfs is available
qiling_dump_unpacked_binary()              → emulate until OEP, dump
```

- Emulates the packer stub execution using Qiling Framework
- Detects when the original entry point is reached
- Dumps the unpacked binary image from memory
- Works on packers that are resistant to static analysis
- Requires Qiling rootfs (check with `qiling_setup_check()`)

**Troubleshooting**:
- If emulation hangs: packer may have anti-emulation. Try with hooks.
- If dump is corrupt: OEP detection may be wrong. Try Method 4.

### Method 4: Manual OEP Recovery + Reconstruction

**Best for**: When all automated methods fail. Requires more analyst guidance.

#### Step 1: Find the OEP
```
find_oep_heuristic()                       → heuristic OEP detection
```

If heuristic fails, manual approach:
```
decompile_function_with_angr(entry_point)  → understand the unpacking stub
get_function_cfg(entry_point)              → map the stub's control flow
```

Look for:
- A tail jump (jmp eax, jmp [esp], push+ret) after the unpacking loop
- The target of that jump is the OEP
- Common pattern: loop decrypting sections → restore registers → jump to OEP

#### Step 2: Emulate to OEP
```
emulate_with_watchpoints(                  → set watchpoint on suspected OEP
    address=entry_point,
    watchpoints=[{address: oep_candidate, type: "execute"}]
)
```

Or use Qiling with specific breakpoints:
```
emulate_binary_with_qiling(timeout=30)     → let it run through unpacking
qiling_memory_search(pattern=<MZ header>)  → find unpacked PE in memory
```

#### Step 3: Reconstruct PE
```
reconstruct_pe_from_dump(dump_data, oep)   → rebuild valid PE from dump
```

- Fixes section alignment, imports, and PE headers
- The OEP becomes the new entry point
- May need import reconstruction if IAT was destroyed

---

## Special Cases

### Multi-Layer Packing
Some malware is packed multiple times (e.g., custom packer wrapping UPX).

```
Strategy:
1. Unpack outer layer with appropriate method
2. Check if result is still packed: detect_packing() or get_triage_report()
3. If yes, repeat unpacking for inner layer
4. Track and document each layer: add_note("Layer N: <packer> removed")
5. Continue until no packing indicators remain
```

### Encrypted Overlay / Appended Data
Payload stored after the PE boundary, decrypted at runtime.

```
1. refinery_pe_operations(operation="overlay")     → extract overlay data
2. analyze_entropy_by_offset()                     → confirm encryption
3. Decompile the overlay-reading function
4. Recover key from code → refinery_decrypt() or refinery_xor()
5. refinery_carve() on decrypted overlay          → extract embedded PE/payload
```

### .NET Obfuscators (ConfuserEx, .NET Reactor, Dotfuscator)
These don't pack in the traditional sense — they obfuscate IL code, encrypt
strings, and hide control flow.

```
1. dotnet_analyze()                                → assess obfuscation level
2. refinery_dotnet(operation="deobfuscate")        → attempt deobfuscation
3. dotnet_disassemble_method()                     → check specific methods
4. find_and_decode_encoded_strings()               → decode obfuscated strings
5. For string encryption: identify decryption method in .cctor,
   then refinery_decrypt() with recovered key
```

### Shellcode Extraction from Loaders
Packed binary that decrypts and executes shellcode in memory.

```
1. Decompile the entry function → identify allocation + decryption + execution
2. Get encrypted shellcode: get_hex_dump(offset, length)
3. Identify encryption: get_reaching_definitions() on decryption routine
4. Decrypt: refinery_xor() or refinery_decrypt()
5. Analyze shellcode: emulate_shellcode_with_qiling() or emulate_shellcode_with_speakeasy()
6. Search shellcode memory: qiling_memory_search() for next-stage URLs/IPs
```

### VirtualAlloc + WriteProcessMemory (Process Hollowing)
Malware that unpacks into another process's memory space.

```
1. get_focused_imports() → look for VirtualAllocEx, WriteProcessMemory,
   NtUnmapViewOfSection, SetThreadContext, ResumeThread
2. Decompile the injection routine
3. Identify the payload source (encrypted buffer, resource, overlay)
4. Extract and decrypt the payload buffer
5. The payload is the real malware — analyze it separately
```

---

## Post-Unpacking Checklist

After successfully unpacking:

- [ ] Run `open_file()` on the unpacked binary
- [ ] Run `get_triage_report()` — should show more imports, lower entropy
- [ ] Verify the unpacked binary has a valid PE structure
- [ ] Check import count is reasonable (dozens to hundreds, not <10)
- [ ] Check strings are now readable and meaningful
- [ ] Note the packer(s) removed: `add_note("Unpacked from: <packer>", category="tool_result")`
- [ ] Proceed to Phase 3 (Map) with the unpacked binary
