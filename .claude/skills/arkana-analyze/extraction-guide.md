# Extraction Guide

Operational detail for Phase 5 extraction operations. The main SKILL.md contains
the evidence-first gate and automated extraction tools; this file covers manual
refinery operations, batch mode, and extraction chain documentation.

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
