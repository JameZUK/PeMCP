# Concept Reference: Advanced Unpacking

Expert tier reference for Module 4.1. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

When `auto_unpack_pe` and `try_all_unpackers` fail, the analyst must unpack
manually. This requires understanding how packers work at a structural level:
they compress or encrypt the original binary, prepend a stub that reverses the
transformation at runtime, and transfer control to the Original Entry Point
(OEP) of the now-restored binary. Manual unpacking means finding the OEP,
letting the stub run (via emulation), dumping the restored binary from memory,
and reconstructing a valid PE from the dump.

This module covers the techniques needed when automated methods are insufficient:
custom packers, multi-layer packing, process hollowing, .NET-specific
obfuscators, and PE reconstruction.

## Manual OEP Recovery

The OEP is the address where the packer stub finishes and transfers control to
the original binary's code. Finding it is the critical first step.

### Heuristic Detection

```
Tool: find_oep_heuristic()

Uses multiple heuristics to suggest OEP candidates:
- Section permission changes (stub makes .text writable, then restores RX)
- Tail jump pattern (jmp to a distant address outside the stub's section)
- Stack frame signatures (the real entry point has a standard prologue)
- Cross-section transfer (execution moves from the packer section to .text)

Example output:
  OEP candidates (ranked by confidence):
    [HIGH]  0x00401000 — tail jump from stub at 0x00406F80
    [MED]   0x00401030 — standard prologue after VirtualProtect sequence
    [LOW]   0x00401100 — cross-section jump target
```

### Emulation to OEP

Use emulation to execute the packer stub and stop at the OEP:

```
Tool: emulate_with_watchpoints(watchpoints=[
    {"type": "execute", "address": 0x00401000}
])

The watchpoint fires when the OEP candidate is about to execute, confirming
it is reached and allowing a memory dump at exactly the right moment.
```

Alternative approach — watch for the decompression pattern:
```
Tool: emulate_with_watchpoints(watchpoints=[
    {"type": "write", "address_range": "0x00401000-0x00402000"}
])

Watch for writes to the .text section. The last write before execution
transfers to .text marks the end of unpacking.
```

### Stack Frame Analysis

At the OEP of a standard C/C++ binary, the runtime initialisation produces a
recognisable pattern:

- 32-bit MSVC: `call __security_init_cookie` then `jmp __tmainCRTStartup`
- 64-bit MSVC: `sub rsp, 0x28` then `call __security_init_cookie`
- MinGW: `push ebp / mov ebp, esp / and esp, -16 / sub esp, N`

When disassembling OEP candidates, look for these signatures to confirm you
have found the real entry point rather than an intermediate unpacking stage.

## Multi-Layer Packing

Some samples are packed multiple times: the outer packer unpacks to reveal an
inner packer, which unpacks to reveal the actual binary. Each layer must be
handled sequentially.

### Detection Strategy

After the first unpack, check the result:

1. Run `detect_packing()` on the dumped binary — if it still shows packed
   indicators, there is another layer
2. Check entropy — if still uniformly high (>7.0), likely still packed
3. Check import count — if still minimal (<10 imports), likely still packed
4. Attempt to decompile the entry point — if it is another unpacking stub
   rather than meaningful application code, there is another layer

### Tracking Layers

Maintain a mental model (or notes) of each layer:

```
Layer 0 (on disk): UPX-packed, detected by signature
  -> auto_unpack_pe() succeeds
Layer 1 (after UPX): Custom packer, no signature match
  -> find_oep_heuristic() identifies OEP at 0x00401000
  -> emulate to OEP, dump memory
Layer 2 (after custom): Clean binary, normal entropy and imports
  -> Analysis can proceed
```

```
Tool: add_note(content="Unpacking layers: ...", category="tool_result")

Document each layer as you go. Multi-layer unpacking is error-prone, and
notes prevent you from losing track of which layer you are working on.
```

## Process Hollowing Analysis

Process hollowing is not packing in the traditional sense — it is a runtime
technique where malware creates a legitimate process in a suspended state,
replaces its memory with a malicious payload, and resumes execution. The
"unpacking" happens in a different process.

### The Hollowing Sequence

```
1. CreateProcess("svchost.exe", ..., CREATE_SUSPENDED)
   — creates a legitimate process, paused before it runs
2. NtUnmapViewOfSection(hProcess, imageBase)
   — removes the original svchost code from memory
3. VirtualAllocEx(hProcess, imageBase, payloadSize, ...)
   — allocates space for the payload at the same base address
4. WriteProcessMemory(hProcess, imageBase, payloadBuffer, ...)
   — writes the malicious PE into the hollowed process
5. SetThreadContext(hThread, &ctx)  [ctx.Eax = new entry point]
   — redirects execution to the payload's entry point
6. ResumeThread(hThread)
   — the process runs the malicious code as svchost.exe
```

### Analysis Approach

The payload written in step 4 is the binary you want to analyse. To extract it:

```
Tool: decompile_function_with_angr(hollowing_function)

Read the function that performs the hollowing. Identify the source buffer
for WriteProcessMemory — this is where the payload lives before injection.
```

```
Tool: get_backward_slice(write_call_address, source_buffer_param)

Trace the source buffer backwards to find where the payload is decrypted
or unpacked before being written into the hollow process.
```

If the payload is decrypted in memory before writing:
```
Tool: emulate_binary_with_qiling()  or  emulate_pe_with_windows_apis()

Emulate up to the WriteProcessMemory call. Hook the call to capture the
payload buffer contents. Then analyse the captured PE separately.
```

## .NET-Specific Obfuscators

.NET binaries are packed/obfuscated differently because they contain managed IL
code rather than native machine code. The .NET runtime is the execution
environment, and obfuscators work within its constraints.

### ConfuserEx

The most common open-source .NET obfuscator. Features:
- **Anti-tamper**: integrity checks that crash the binary if modified
- **Anti-debug**: managed debugger detection
- **String encryption**: runtime decryption of all string literals
- **Control flow obfuscation**: switch-based dispatch in IL
- **Resource encryption**: embedded resources are encrypted

```
Tool: dotnet_analyze()

Detects .NET obfuscator signatures and reports which protections are present.
```

### .NET Reactor

Commercial obfuscator. Adds a native stub that decrypts the .NET assembly
at runtime. The on-disk binary contains an encrypted blob and a native
loader — the actual .NET code only exists in memory after the loader runs.

### Babel Obfuscator

Renames all symbols to meaningless names, encrypts strings, and can merge
assemblies. Less aggressive than ConfuserEx but still impedes analysis.

### .NET Deobfuscation Approach

```
Tool: refinery_dotnet()

Applies .NET-specific deobfuscation operations: string decryption, resource
decryption, control flow restoration. Start here before attempting manual
analysis.
```

For cases where automated tools fail:
1. Use `dotnet_analyze()` to identify which protections are applied
2. Use `dotnet_disassemble_method(token)` to read the IL code
3. Identify the string decryption method (usually called from static constructors)
4. Emulate or replicate the decryption to recover cleartext strings

## PE Reconstruction from Memory Dumps

After emulation-based unpacking, the memory dump is not a valid PE file — it
needs reconstruction to be loadable by analysis tools.

### What Needs Fixing

- **PE headers**: may be damaged or zeroed by the packer. Section headers need
  correct raw sizes and pointers.
- **Import table**: the in-memory IAT contains resolved function addresses (e.g.,
  0x7FFE1234) instead of the original import directory entries. These addresses
  are specific to the emulation session and meaningless on disk.
- **Relocations**: if the binary was loaded at a non-preferred base address,
  relocated pointers need adjustment.
- **Section alignment**: memory layout uses page alignment (0x1000) while disk
  layout uses file alignment (0x200 typically). Raw offsets must be recalculated.

```
Tool: reconstruct_pe_from_dump()

Automated PE reconstruction: fixes headers, rebuilds import table by matching
IAT entries to known DLL export addresses, adjusts section alignment, and
produces a valid PE file.

Example output:
  Input: memory dump from 0x00400000, size 0x15000
  Reconstruction:
    - PE header: repaired (e_lfanew corrected)
    - Sections: 4 sections remapped (virtual -> raw alignment)
    - Imports: 47 functions resolved across 6 DLLs
    - Relocations: stripped (not needed for analysis)
  Output: reconstructed.exe (valid PE, loadable in IDA/Ghidra)
```

```
Tool: qiling_dump_unpacked_binary()

Combines emulation-to-OEP with memory dumping in a single step. Emulates
the binary, detects the OEP transition, and dumps the reconstructed PE.
```

## Socratic Questions

- "The automated unpacker failed but detect_packing says it is UPX. What could
  explain a known packer that does not unpack automatically?"
  (Leads to: modified UPX — the author patched the UPX header/signature to
  break the standard unpacker while keeping the algorithm)
- "After unpacking, the import table is empty. Is the binary broken?"
  (Leads to: the packer resolved imports at runtime and stored addresses
  directly in the IAT. PE reconstruction needs to reverse-resolve them.)
- "We unpacked one layer and the result still looks packed. How do you decide
  whether to keep unpacking or analyse what you have?"
  (Leads to: check entropy, import count, and try to decompile the entry point.
  If it is another stub, there is another layer. If it is application code
  with encrypted strings, stop unpacking and work on string decryption.)

## Common Mistakes

### Dumping at the wrong moment

If you dump too early, the unpacking stub has not finished and the .text section
is still encrypted. If you dump too late, the binary may have already zeroed
the unpacking code or overwritten headers. The OEP transition is the precise
moment to dump.

### Skipping PE reconstruction

A raw memory dump will not load properly in most analysis tools. The section
alignment, import table, and header fields all need correction. Always run
`reconstruct_pe_from_dump` before attempting further analysis.

### Treating .NET packing like native packing

.NET obfuscators work at the IL level, not the native code level. Trying to
find an OEP or dump native memory misses the point — the .NET assembly is
what needs to be recovered. Use `dotnet_analyze` and `refinery_dotnet` instead
of native unpacking tools.

### Giving up after one failed method

Manual unpacking often requires trying multiple approaches. If OEP heuristics
fail, try emulation with watchpoints. If Qiling fails, try Speakeasy. If
static analysis cannot find the decryption, try searching memory after partial
emulation. Persistence and methodical elimination of approaches is key.

**Reference**: See [unpacking-guide.md](../pemcp-analyze/unpacking-guide.md)
in the pemcp-analyze skill for additional unpacking workflows and packer-specific
recipes.
