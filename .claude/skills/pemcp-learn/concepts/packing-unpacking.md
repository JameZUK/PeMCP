# Packing and Unpacking

Reference material for Module 2.3. Builds on Foundation knowledge of PE sections,
entry points, and the import address table. This concept teaches learners to identify
packed binaries and use PeMCP's unpacking tools to get past the protection layer.

---

## Core Concepts

### Why Packing Exists

Packing serves both legitimate and malicious purposes:

**Legitimate uses**:
- Reducing binary size for distribution (UPX was originally a compression tool)
- Protecting intellectual property (commercial software protectors like Themida)
- Preventing casual reverse engineering of proprietary algorithms

**Malicious uses**:
- Evading antivirus signature detection (the real code is hidden until runtime)
- Slowing down reverse engineering (analysts must unpack before they can analyse)
- Defeating static analysis tools (imports, strings, and code are all obscured)

### How Packers Work

At a high level, every packer follows the same pattern:

1. **Build time**: The packer takes the original binary, compresses or encrypts its
   code and data sections, and prepends a small "stub" — the unpacking routine.

2. **Runtime**: When the packed binary executes, the stub runs first. It
   decompresses or decrypts the original code into memory, reconstructs the import
   table (resolves API addresses), and then jumps to the Original Entry Point (OEP)
   where the real program begins.

The packed binary is essentially a self-extracting container. The stub is the only
code that exists in cleartext. Everything else — the real code, the real strings,
the real imports — is hidden inside the compressed/encrypted payload.

### Identifying Packed Binaries

Several indicators signal packing. No single indicator is conclusive, but multiple
indicators together are strong evidence.

**High entropy (> 7.0 in executable sections)**: Compressed or encrypted data has
near-random byte distribution, which produces high entropy. Normal compiled code has
entropy around 5.5-6.5. A `.text` section with entropy above 7.0 is almost certainly
packed. Use `analyze_entropy_by_offset()` to visualise entropy across the file.

**Low import count (< 10 functions)**: Normal binaries import dozens to hundreds of
API functions. Packed binaries only need a handful — typically `LoadLibrary`,
`GetProcAddress`, `VirtualAlloc`, and `VirtualProtect` — because the stub resolves
the real imports dynamically at runtime.

**Suspicious section names**: Packers often create distinctive section names:
UPX0/UPX1 (UPX), .aspack (ASPack), .themida (Themida), .vmp0 (VMProtect),
.MPRESS1 (MPRESS). These are strong identifiers.

**Virtual size much larger than raw size**: The unpacking stub needs room to expand
the compressed data. A section with `virtual_size` ten times larger than `raw_size`
has reserved space for decompression.

**Sections with write + execute permissions**: Normal code sections are read+execute.
A section that is also writable is set up for self-modification — the stub writes
the decompressed code into it.

**PEiD signatures**: PEiD-style signature databases match known packer byte patterns
at the entry point. `detect_packing()` checks these signatures.

### The Original Entry Point (OEP)

The OEP is where the real program's execution begins — the entry point of the
original binary before it was packed. The packed binary's actual entry point is the
start of the unpacking stub. After the stub finishes its work, it transfers control
to the OEP.

Finding the OEP is the key to successful unpacking. Once you know where the real
code starts, you can dump the unpacked binary from memory and reconstruct a valid
PE with the OEP as its entry point.

Common OEP transfer patterns:
- `jmp eax` — the OEP address was computed and stored in a register
- `push <addr>` / `ret` — push the OEP and "return" to it
- `jmp <far address>` — direct jump to a different section (the decompressed code)

### PeMCP's Unpacking Cascade

PeMCP provides a graduated set of unpacking tools, ordered from simplest to most
manual:

**Step 1: `auto_unpack_pe()`** — Handles known packers identified by PEiD signatures.
Fast and reliable for UPX, ASPack, PECompact, MPRESS, and others. Try this first.

**Step 2: `try_all_unpackers()`** — Orchestrates multiple unpacking methods
automatically. Tries known unpackers first, then heuristic approaches. More thorough
but slower.

**Step 3: `qiling_dump_unpacked_binary()`** — Emulates the binary with Qiling
Framework, lets the unpacking stub run, detects when the OEP is reached, and dumps
the unpacked image from memory. Works for custom or unknown packers.

**Step 4: Manual OEP recovery** — When automated methods fail, use
`find_oep_heuristic()` to locate candidates, `emulate_with_watchpoints()` to verify,
and `reconstruct_pe_from_dump()` to rebuild the PE. This is an Advanced (Tier 3)
skill covered in Module 4.1.

### What Changes After Unpacking

After successful unpacking, the binary transforms dramatically:

- **Imports appear**: The IAT is populated with real API calls — dozens or hundreds
  instead of fewer than 10. `get_focused_imports()` now reveals the binary's true
  capabilities.
- **Strings become readable**: URLs, file paths, registry keys, mutex names, error
  messages, and other operational strings are now visible.
- **Entropy drops**: Code sections return to normal entropy (5.5-6.5) as the
  compressed/encrypted payload is replaced with cleartext code.
- **Functions become analysable**: `get_function_map()` finds real functions instead
  of just the packer stub. Decompilation produces meaningful pseudocode.
- **Capa rules match**: Capability analysis can now identify behaviors that were
  hidden inside the packed payload.

---

## Key PeMCP Tools

| Tool | Purpose |
|------|---------|
| `detect_packing()` | Packing detection with PEiD signatures, entropy, section analysis |
| `analyze_entropy_by_offset()` | Entropy distribution across the binary — visualise packed regions |
| `auto_unpack_pe()` | Automated unpacking for known packers |
| `try_all_unpackers()` | Orchestrated multi-method unpacking attempt |
| `qiling_dump_unpacked_binary()` | Emulation-based memory dump for unknown packers |

---

## Teaching Moments During Guided Analysis

**When triage detects packing**: Explain why the triage report flagged this binary.
Walk through the indicators: entropy values, import count, section names, PEiD
matches. Show how multiple weak indicators combine into strong evidence.

**When the learner sees very few imports**: Ask them to think about what a real
program needs from the operating system. Opening files, creating windows, networking,
memory management — all require imports. A binary that imports only `LoadLibrary`
and `GetProcAddress` is resolving everything else at runtime.

**After successful unpacking**: This is a key "before and after" teaching moment. Run
`get_strings_summary()` and `get_focused_imports()` on the unpacked binary and
compare with the packed version. The contrast demonstrates exactly what packing hides.

**When unpacking fails**: Do not let the learner give up. Explain the cascade: try
the next method. If all methods fail, explain what IS still possible — VT lookup,
emulation-based behavior observation, whatever strings or IOCs can be extracted from
the packed binary.

---

## Socratic Questions

- "Why do packed binaries have so few imports?"
  *Expected direction*: The real imports are hidden inside the encrypted payload.
  The packer stub only needs enough API access to decompress and load the real code.
  It uses `LoadLibrary`/`GetProcAddress` to resolve the real imports at runtime.

- "After unpacking, what is the first thing you would check?"
  *Expected direction*: Re-run triage to confirm the binary is actually unpacked
  (lower entropy, more imports). Then check strings and imports — they are the
  fastest way to understand what the now-visible code actually does.

- "This binary has entropy of 7.8 but only in one section. What does that tell you?"
  *Expected direction*: That specific section contains the packed payload. Other
  sections may be in cleartext (e.g., the packer stub in a low-entropy section).
  The high-entropy section is where the real code is compressed or encrypted.

- "Is packing the same as encryption?"
  *Expected direction*: Not exactly. Packing can be compression (reversible without
  a key), encryption (requires a key), or both. UPX is pure compression. Themida
  uses encryption. Many packers combine both: compress first, then encrypt.

---

## Common Mistakes

**Assuming packed means malicious**: Many legitimate commercial applications use
packers and protectors. UPX is widely used for size reduction. Themida and VMProtect
protect commercial software. Packing is a red flag that warrants investigation, but
it is not evidence of malicious intent on its own.

**Stopping analysis when packing is detected**: "It is packed, therefore I cannot
analyse it" is not an acceptable conclusion. PeMCP provides multiple unpacking
methods. If static unpacking fails, emulation-based approaches can still reveal
runtime behavior. Even without unpacking, the packed binary's strings, metadata,
and VT reputation may provide useful intelligence.

**Not re-analysing after unpacking**: Unpacking produces a new binary that must be
analysed from scratch. The triage results, import analysis, string analysis, and
capability mapping from the packed binary are largely meaningless — they describe
the packer stub, not the real payload. Always run full Phase 1 and Phase 3 on the
unpacked result.

**Confusing the packer stub with the payload**: The entry point of a packed binary
is the unpacking stub, not the malware. Decompiling it shows the decompression
routine — the packer's code, not the attacker's.
