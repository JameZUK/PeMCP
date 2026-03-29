# Extraction Guide

Operational detail for Phase 5 extraction operations. The main SKILL.md contains
the evidence-first gate and automated extraction tools; this file covers manual
refinery operations, batch mode, and extraction chain documentation.

## Speculative Decryption Safety Gate

"Concrete evidence" means you decompiled the function that performs the operation
and can cite: the specific algorithm (e.g., "sub_401830 calls CryptDecrypt with
CALG_RC4"), the key source (e.g., "16-byte key loaded from .rdata+0x5000"), and
the data location (e.g., "reads 54KB from RCDATA/202").

Specifically forbidden without decompilation evidence:
- Guessing XOR keys or trying `brute_force_simple_crypto` (this tool produces
  false positives — a coincidental "MZ" match does NOT mean you found the right
  key; it means 2 bytes out of thousands happened to align)
- Trying random decompression algorithms on high-entropy data
- Chaining speculative `refinery_pipeline` operations hoping something works
- Trying multiple RC4/AES/XOR key combinations from different resources
- Deriving keys from known-plaintext XOR and assuming they repeat

The ONLY exceptions:
- `extract_config_automated()` and `extract_config_for_family()`, which use
  validated family-specific logic internally
- `brute_force_simple_crypto()` AFTER decompilation reveals the algorithm is
  simple XOR but the key can't be traced statically — and even then, validate
  results thoroughly (a valid PE needs more than just "MZ at offset 0"; check
  e_lfanew, section count, import table)

## Binary Refinery Operations

For manual decoding when automated extraction fails. Key tools now support
`file_offset` (hex offset into loaded file, e.g. `"0x3B80"`), `length` (bytes
to read), and `output_path` (save decoded output to disk as a session artifact):

- `refinery_xor(operation, key_hex, file_offset, length, output_path)` — XOR
  decryption with known key; `file_offset`/`length` read directly from the loaded
  binary, `output_path` saves the result and registers it as a session artifact
- `refinery_decrypt(data, algorithm, key)` — AES/RC4/DES/ChaCha20 decryption
- `refinery_auto_decrypt(data)` — auto-detect and decrypt XOR/SUB patterns
- `refinery_decompress(data, algorithm)` — gzip/bzip2/lz4/zlib decompression
- `refinery_pipeline(steps, file_offset, length, output_path)` — chain multiple
  refinery operations including encoding (b64, hex), compression (zl, lzma),
  crypto (xor, rc4, aes), slicing (snip, chop, pick), bitwise (ror, rol, shl,
  shr, and, or, not, add, sub), padding (pad, terminate), and utility (nop);
  accepts file offset input, saves final output as artifact, supports batch mode
  via `data_hex_list` (up to 100 items)
- `refinery_carve(data, pattern, output_path)` — carve out embedded files/payloads;
  `output_path` saves all carved items to disk as artifacts
- `refinery_regex_extract(data, pattern)` — regex-based data extraction
- `refinery_codec(data, operation, codec)` — encoding/decoding (base64, hex, etc.)

**Prefer `file_offset`/`length` over `get_hex_dump()` + `data_hex`** when working
with embedded payloads — it's a single step instead of two, avoids hex-encoding
large blobs, and produces cleaner tool history.

## Incremental Pipeline Construction

When using `refinery_pipeline` with more than 2 steps, build and verify
stage-by-stage rather than constructing the full pipeline at once.

**Methodology:**
1. Start with the first 1-2 steps and inspect the output
2. Verify the intermediate result matches expectations (correct encoding, expected
   byte patterns, plausible size)
3. Add the next step and inspect again
4. Repeat until the full pipeline is complete

**When to use this pattern:**
- More than 2 pipeline steps
- Unfamiliar data format or unknown encoding layers
- Complex transforms (e.g., b64 decode → XOR → decompress → carve)
- Any time a pipeline produces unexpected output

**Example — multi-stage config extraction:**
```
# Step 1: Verify the base64 layer
refinery_pipeline(file_offset="0x3B80", length=512, steps=[{"op": "b64"}])
# → Inspect: should be raw bytes, not still ASCII

# Step 2: Add XOR decryption
refinery_pipeline(file_offset="0x3B80", length=512,
    steps=[{"op": "b64"}, {"op": "xor", "key": "5A"}])
# → Inspect: should show structure (MZ header, JSON, URL patterns)

# Step 3: Add decompression if needed
refinery_pipeline(file_offset="0x3B80", length=512,
    steps=[{"op": "b64"}, {"op": "xor", "key": "5A"}, {"op": "zl"}],
    output_path="/output/config.bin")
```

## Pipeline Debugging

When a pipeline produces wrong or empty output:

1. **Bisect**: Run progressively fewer steps to isolate the failure. If a 4-step
   pipeline fails, try steps 1-3, then 1-2, then step 1 alone.

2. **Preview input**: Before transforming, inspect the raw bytes with
   `get_hex_dump(offset, length=64)` or `refinery_pretty_print(data, format="hex")`.
   Wrong input (wrong offset, wrong length, already-decoded data) is the #1 cause
   of pipeline failures.

3. **Discover operations**: Call `refinery_list_units(category)` to confirm the exact
   operation name and verify it exists. Operation names must match exactly — `"zlib"`
   is not the same as `"zl"`, and `"base64"` is not the same as `"b64"`.

4. **Common pitfalls:**
   - Wrong hex encoding in `data_hex` (odd length, non-hex chars) — prefer
     `file_offset`+`length` instead
   - Operation name mismatch — always verify with `refinery_list_units`
   - Wrong step order — decoding layers must be unwrapped in the reverse order
     they were applied (outermost first)
   - Data already decoded — the blob you're targeting may have already been
     processed by a previous tool call

## Artifact Management

**Always use `output_path`** when extracting payloads, decrypted configs, or carved
files that need further analysis. The file is written to disk AND registered as a
session artifact with hashes and file type detection. Artifacts are:
- Included in `export_project()` archives (up to 50 MB total)
- Persisted in cache — restored on next `open_file()` of the same binary
- Tracked in session state — use `get_artifacts()` to list them

## Batch Operations

Several tools support batch mode to avoid repeated single-item calls:

| Tool | Batch Parameter | Cap | Use Case |
|------|----------------|-----|----------|
| `refinery_pipeline` | `data_hex_list` | 100 | Decrypt/decode many blobs with the same pipeline (e.g., 95 Base64+RC4 config entries) |
| `get_string_at_va` | `virtual_addresses` | 50 | Extract strings at multiple VAs or file offsets from decompilation/disassembly output. Use `address_type='file_offset'` when FLOSS gives file offsets instead of VAs |
| `batch_decompile` | `addresses` | 20 | Decompile many functions in one call (per-function 60s timeout) |
| `auto_note_function` | `function_addresses` | 20 | Auto-note many functions after batch decompilation |
| `get_capa_rule_match_details` | `rule_ids` | 20 | Get match details for multiple capa rules at once |
| `batch_rename` | `renames` | 50 | Bulk apply function/variable/label renames |

Batch results include per-item error isolation — individual failures don't fail
the batch. Each response includes `total`, `succeeded`, and `failed` counts.

## Multi-Layer Delivery Chain Techniques

### IExpress SFX Resource Decoding
IExpress self-extracting archives store execution commands in RCDATA resources.
Extract and decode these to understand the full attack chain:

```
1. extract_resources()  → find RCDATA entries (RUNPROGRAM, POSTRUNPROGRAM, TITLE, etc.)
2. Read resource values — they're plain ASCII strings:
   - RUNPROGRAM: primary command executed after extraction
   - POSTRUNPROGRAM: secondary command (often the real payload trigger)
   - ADMQCMD/USRQCMD: admin/user-mode commands
   - TITLE: SFX window title (often random words in malware)
3. The cabinet (MSCF magic) is in RT_RCDATA/CABINET
   search_hex_pattern("4D 53 43 46 00 00 00 00")  → find cabinet offset
   refinery_pipeline(file_offset, length, steps=["nop"], output_path=...)  → extract cabinet
   refinery_extract(operation='archive', sub_operation='cab')  → extract contents
```

### Batch Script `type | %comspec%` Piping
Fileless batch execution: `type malicious.flv | %comspec%` pipes a file's contents
through cmd.exe as commands. The file doesn't need a .bat extension. Common in
IExpress-based malware with `POSTRUNPROGRAM` set to this pattern.

To deobfuscate variable-substitution batch scripts:
```
1. Extract the batch file from the cabinet
2. Identify Set commands (they define single characters: Set Folk=/)
3. Lines NOT starting with "Set" and NOT containing only junk words are the real commands
4. Substitute all %VarName% patterns with their values
5. The decoded commands reveal the actual execution chain
```

### PE Fragment Reassembly
Malware splits a PE across multiple files to evade AV scanning:
```
cmd /c set /p ="MZ" > target.exe <nul        ← Write 2-byte MZ header
cmd /c findstr /V "marker" Fragment1 >> target.exe  ← Append fragment (skip marker line)
cmd /c copy /b /y target.exe + Fragment2 + Fragment3 target.exe  ← Binary concatenate
```

To reconstruct: replicate the exact commands. The fragments are typically in a
cabinet or dropped files. The reassembled PE often has a valid Authenticode
signature (in the overlay) despite being fragmented.

### LZNT1 Compressed Payloads
Malware using `RtlDecompressFragment` stores payloads in LZNT1 format.

**Detection**: First 2 bytes are a chunk header. Signature nibble = `0xB` (bits 15-12):
```
get_hex_dump(offset, length=4)  → check if (header >> 12) & 0xF == 0xB
refinery_decompress(algorithm='lznt1', output_path=...)  → decompress
```

Common pattern: RC4 decrypt → LZNT1 decompress → valid PE.

### AutoIt3 Post-Decryption Workflow
After `autoit_decrypt()` recovers the script source:

1. **Decode REVEALS() strings**: `REVEALS("85R118R...", offset)` — subtract offset from each R-separated number to get ASCII
2. **Extract DllCall targets**: Search for `DllCall(REVEALS(...)` patterns — decode DLL name, return type, and function name
3. **Find embedded payloads**: Search for large hex assignments (`$VAR = "0x..."` + `$VAR = $VAR & "..."` concatenation chains). Assemble all chunks.
4. **Recover RC4 keys**: Look for `Binary(REVEALS(...))` adjacent to the payload variable — this is typically the RC4 decryption key
5. **Decrypt and decompress**: `refinery_xor(key_hex=...)` for RC4, then `refinery_decompress(algorithm='lznt1')` for the inner PE
6. **Open the extracted PE**: `open_file()` on the result for full triage + analysis

## .NET-Specific Extraction

- `refinery_dotnet(data, operation)` — .NET resource/metadata extraction
- `dotnet_analyze()` — .NET assembly structure and method listing
- `dotnet_disassemble_method(method)` — CIL disassembly of specific methods

## Payload & Container Extraction

- `extract_resources()` — PE resource extraction
- `extract_steganography()` — detect data hidden after image EOF markers
- `parse_custom_container()` — parse custom malware container formats
- `refinery_extract(data, format)` — extract from archives/containers
- `refinery_executable(data, operation)` — executable-level analysis via refinery

## C2 Attribution Before Extraction

Before extracting a C2 config, **always verify the family attribution**:

1. `identify_malware_family()` with all available evidence (hash algorithm, seed,
   hash constants, config encryption, compiler, constants, matched strings)
2. `verify_malware_attribution(family=<top candidate>)` to confirm the match
3. Only then follow the family-specific extraction recipe
4. Use `extract_config_for_family(family=<confirmed>)` for automated KB-driven
   extraction, or follow the manual recipe in config-extraction.md
5. Parse decrypted config structures with `parse_binary_struct(schema=[...])`
   when the config is a binary struct (not plaintext)

**Why this matters**: Different C2 frameworks share techniques (e.g., DJB2
hashing used by both Havoc and AdaptixC2, ROR13 used by both Cobalt Strike and
BRc4). Without checking discriminating indicators like hash seeds and specific
constants, you will misattribute. The `verify_malware_attribution()` tool catches
these errors before they propagate into your report.

## Documenting the Extraction Chain

Whenever you extract a C2 config, decryption key, encoded payload, or any derived
artefact, **record the full chain of evidence** so your workings can be verified.
Use `add_note()` to document each step. The note should answer:

1. **Where** the encrypted/encoded data was found (section, offset, resource name,
   .NET field, overlay — be specific)
2. **How** you identified the algorithm (which function was decompiled, what crypto
   constants were matched, what pattern was recognised)
3. **Where** the key/IV came from (hardcoded at address X, derived via PBKDF2 from
   field Y with salt Z, first N bytes of the blob, etc.)
4. **What tools** you called in what order to perform the decryption/decoding
5. **What the output was** and how you validated it (plausible IPs/domains, correct
   struct size, re-encryption produces the original, etc.)

Example note:
```
add_note(content="""C2 config extraction chain:
- Encrypted blob: 256 bytes at .data+0x4020 (identified via analyze_entropy_by_offset)
- Algorithm: RC4 (identified by decompiling sub_401830 which calls CryptDecrypt
  with CALG_RC4, confirmed by identify_crypto_algorithm matching RC4 init loop)
- Key: 16-byte value at .rdata+0x5000 (traced via get_reaching_definitions on
  the CryptImportKey call in sub_401830)
- Decrypted with: refinery_decrypt(algorithm="rc4", key=<hex>)
- Result: 4 C2 URLs, validated as syntactically correct with plausible TLDs
- Artifact: saved to /output/decrypted_config.bin (artifact_id: art_1709300000_1)
""", category="ioc")
```
