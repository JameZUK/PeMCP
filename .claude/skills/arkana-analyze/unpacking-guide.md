# Unpacking Guide

Strategies for identifying and unpacking packed, encrypted, or obfuscated binaries.

---

## Phase 2 Anti-Pattern Warning

**ACTUALLY CALL THE UNPACKING TOOLS**: Do not just think about which unpacking
tool to use — call it. The most common failure mode is recognizing the binary
is packed, identifying the right tool in your reasoning, but then trying
something else instead (hex dumps, refinery operations, manual stub analysis).
The method cascade below exists for a reason: call `auto_unpack_pe()` first,
then `try_all_unpackers()`, then `qiling_dump_unpacked_binary()`. Only attempt
manual stub analysis (Method 4) after all three automated methods have been
tried and have returned explicit failure results.

**Do NOT decompile or decrypt while packed**: The packing stub is designed to
defeat static analysis — angr's CFG builder will stall or produce useless
results on obfuscated/encrypted code. The resources, strings, and encrypted
blobs inside a packed binary are there to be processed by the UNPACKED code.
You cannot understand the decryption without first understanding the code that
performs it, and you cannot understand that code until the binary is unpacked.

If ALL unpacking and emulation methods fail: Report what IS known (packer ID,
entropy, import count, any VT results, any strings or IOCs extracted from the
packed binary) and clearly state that deeper analysis was blocked by packing. Do
not guess at the payload's nature.

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
- **Known limitation**: FSG-packed binaries may fail with Unipacker. Use Method 3 (Qiling emulation) as fallback

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
static unpacking fails. Especially effective for packers that VirtualAlloc +
decrypt + execute (e.g. TA505).

```
qiling_setup_check()                       → verify rootfs is available
qiling_dump_unpacked_binary()              → emulate, track VirtualAlloc, scan for PE headers
qiling_dump_unpacked_binary(smart_unpack=False)  → fallback: dump largest mapped region
```

- `smart_unpack` (default True) hooks VirtualAlloc/VirtualAllocEx to track all
  allocations during emulation, then scans tracked regions for MZ + PE signature
  headers. Dumps the best PE candidate found. This is much more reliable than
  the fallback largest-region heuristic for most real-world packers.
- Falls back to dumping the largest mapped region if no PE found in allocations,
  or if `smart_unpack=False`.
- Response includes `dump_source` ("virtualalloc_pe_detection" or "largest_region_fallback"),
  `tracked_allocations` count, and `pe_header_detected` flag.
- Works on packers that are resistant to static analysis
- Requires Qiling rootfs (check with `qiling_setup_check()`)
- `_MAX_TRACKED_ALLOCS` (1000) caps tracked allocations to prevent memory issues

**Troubleshooting**:
- If emulation hangs: packer may have anti-emulation. Use the debugger with
  `debug_stub_api(set_last_error="0x578")` to bypass GetLastError() checks.
- If smart_unpack finds wrong PE: try `smart_unpack=False` or specify `dump_address`.
- If dump is corrupt: OEP detection may be wrong. Try Method 4.

### Method 4: Manual OEP Recovery + Reconstruction

**Best for**: When all automated methods fail. Requires more analyst guidance.

#### Step 1: Find the OEP
```
find_oep_heuristic()                       → heuristic OEP detection
```

If heuristic fails, manual approach:

**Note**: Angr CFG analysis typically stalls on packed binaries because the code
is encrypted/obfuscated. If angr is stuck, try `disassemble_raw_bytes()` on
specific hex regions, or prefer Method 3 (Qiling emulation) which executes the
stub dynamically rather than analyzing it statically.

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

### Deep Multi-Layer Delivery Chains (5+ layers)
Complex malware (StealC, DarkGate, ValleyRAT loaders) may have 5-7+ layers
combining multiple techniques: SFX archives, batch scripts, PE fragment
reassembly, PRNG encryption, script interpreters, process hollowing, and
compressed payloads.

**Workflow for deep chains:**
```
1. At EACH layer transition:
   - add_note(category='tool_result', content='Layer N: description + key findings')
   - Save the extracted payload: output_path="/output/layer_N_payload.bin"
   - Record cryptographic materials (keys, algorithms, offsets)

2. When you extract a NEW binary (PE, script, shellcode):
   - open_file() on the extracted payload to start a fresh analysis pass
   - get_triage_report(compact=True) to quickly assess the next layer
   - Do NOT attempt to analyze an extracted payload without loading it first

3. When you encounter an encrypted/encoded blob inside a script:
   - Trace the variable assignment chain to find ALL chunks (search_hex_pattern)
   - Identify the encryption key from adjacent code (often in the same function)
   - Decrypt with refinery tools, then check for compression headers:
     * LZNT1: first 2 bytes, (header >> 12) & 0xF == 0xB
     * LZSS/AutoIt: first 4 bytes == "EA05" or "EA06"
     * Zlib: first byte == 0x78
   - Decompress, then open_file() on the result

4. The C2 address is typically in the INNERMOST layer (the final payload PE),
   NOT in intermediate loaders/scripts. Keep peeling layers until you reach
   a PE with imports for networking (WinHTTP, WinInet, ws2_32).
```

### Encrypted Overlay / Appended Data
Payload stored after the PE boundary, decrypted at runtime.

```
1. refinery_pe_operations(operation="overlay")     → extract overlay data
2. analyze_entropy_by_offset()                     → confirm encryption
3. Decompile the overlay-reading function
4. Recover key from code → decrypt directly from file offset:
   refinery_xor(file_offset="0x...", length=N, key_hex="...",
     output_path="/output/decrypted_overlay.bin")
5. refinery_carve(output_path="/output/carved_payload.bin")
   → carve embedded PE/payload and save as artifact
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
2. Identify encryption: get_reaching_definitions() on decryption routine
3. Decrypt and save directly from file:
   refinery_xor(file_offset="0x...", length=N, key_hex="...",
     output_path="/output/shellcode.bin")
   → reads from file, decrypts, saves to disk as artifact
4. Analyze shellcode: emulate_shellcode_with_qiling() or emulate_shellcode_with_speakeasy()
5. Search shellcode memory: qiling_memory_search() for next-stage URLs/IPs
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

### AutoIt3 Compiled Scripts (.a3x)
AutoIt3 compiled scripts are protected by PRNG-based stream encryption.
Modified AutoIt3 builds (DarkGate, StealC, AsgardProtector, CyberGate) may use
**RanRot PRNG** instead of the standard Mersenne Twister. Standard decompilers
(autoit-ripper, Exe2Aut, refinery) fail on RanRot-encrypted scripts.

**Detection**: Search for `AU3!EA06` or `AU3!EA05` magic in strings/hex. Also
search for EA05_MAGIC bytes: `A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D`.

```
1. autoit_decrypt(prng_type="auto")          → auto-detect MT vs RanRot, decrypt
2. If auto fails, check the binary:
   search_hex_pattern("FB B4 A9 53")         → RanRot LCG multiplier 0x53A9B4FB
   If found: autoit_decrypt(prng_type="ranrot")
   If not:   autoit_decrypt(prng_type="mt")
3. If standard key fails, find modified key:
   search_hex_pattern("EE 18 00 00")         → standard EA06 key (0x18EE)
   If NOT found, the key was changed. Compare .text section with original
   AutoIt3 stub to find the modified value:
   autoit_decrypt(custom_key=0x1234)
```

**How RanRot differs from MT**: RanRot uses `rotl32(state[p1], 9) + rotl32(state[p2], 13)`
with a 17-element circular buffer. Seeded via LCG: `state[i] = 1 - prev * 0x53A9B4FB`.
The binary can contain BOTH RanRot (for decrypt) and MT (for AutoIt3's `Random()`
function). Auto-detection scans for the RanRot multiplier; if found, uses RanRot.

**Multi-layer AutoIt3 delivery** (common in malware):
```
IExpress SFX → obfuscated batch script → PE fragment reassembly → AutoIt3.exe
→ 8-byte XOR outer encryption → RanRot/MT inner encryption → LZSS compression
```
The outer XOR key can be derived from the `AU3!EA06` known plaintext (first 8 bytes).
The inner encryption uses the au3_ResType key (0x18EE for EA06, 0x16FA for EA05).
`autoit_decrypt()` handles the inner layer; use `refinery_xor` for the outer if needed.

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
