# Concept Reference: Malware Configuration Extraction

Advanced tier reference for Module 3.4. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

Command-and-control (C2) configuration is the data a malware sample needs to
communicate with its operator: server addresses, ports, encryption keys,
campaign identifiers, sleep timers, and protocol parameters. Extracting this
configuration is one of the highest-value analysis outcomes — it produces
actionable intelligence (IOCs for blocking, infrastructure for tracking, keys
for decrypting captured traffic).

C2 configs are almost always protected in some way. If the config were plaintext,
automated tools and even basic string extraction would trivially find it. The
analyst's job is to locate the encrypted data, identify the protection scheme,
recover the key, decrypt, and validate the result.

## Common Config Storage Patterns

### XOR-Encrypted Blob in .data Section

The most common pattern. A contiguous block of encrypted bytes is stored in the
.data or .rdata section. At runtime, a decryption function XORs the blob with a
key (single-byte, multi-byte, or rolling) and writes the result to a buffer.

Indicators:
- High-entropy region in an otherwise low-entropy .data section
- XOR loop in decompiled code referencing a data section address
- Fixed-size buffer allocation followed by a decryption loop

### .NET String Fields or Resources

.NET malware often stores configs as encrypted strings in class fields,
embedded resources, or base64-encoded constants. The decryption is typically a
simple method called during static construction or Form_Load.

```
Tool: dotnet_analyze()
Tool: refinery_dotnet()

.NET configs are often extractable by examining managed resources and tracing
the decryption method in the IL disassembly.
```

### PE Resource Entries

Config data embedded as a named or numbered resource in the PE resource table.
Common resource types: RCDATA, custom types (type 10+), or bitmap resources
that contain non-image data.

```
Tool: extract_resources()

Lists all embedded resources with sizes and entropy. A small RCDATA resource
with high entropy is a strong indicator of an encrypted config.
```

### Structs at Fixed Offsets

Some families store the config as a C struct at a fixed offset from the binary's
base or at a known position within a specific section. The struct layout is
fixed per version: first 4 bytes = C2 address length, next N bytes = encrypted
C2 address, next 2 bytes = port, etc.

```
Tool: parse_binary_struct(schema=[
    {"name": "c2_addr_len", "type": "uint32_le"},
    {"name": "c2_addr", "type": "bytes:64"},
    {"name": "port", "type": "uint16_le"},
    {"name": "server_ip", "type": "ipv4"}
], file_offset="0x5000", length=128)

Parses binary data according to typed field definitions. Supports: uint8-64
(LE/BE), cstring, wstring, ipv4, bytes:N, padding:N.
```

### Runtime-Only (Memory-Only Configs)

The config is never stored as a discrete blob. Instead, individual values are
computed or decrypted inline throughout the code:

```c
char c2_host[64];
c2_host[0] = 'e' ^ 0x33;  // each character individually XORed
c2_host[1] = 'v' ^ 0x33;
c2_host[2] = 'i' ^ 0x33;
// ... etc.
```

These are the hardest to extract statically. Emulation is often the most
practical approach — let the binary build the config in memory, then search
for it.

### Steganography (Image Overlays)

Config data hidden in image files — either appended to the image (overlay) or
encoded in pixel values (LSB steganography). The binary loads the image,
extracts the hidden data from a known offset or using a known algorithm, and
decrypts it.

```
Tool: extract_steganography()
Tool: scan_for_embedded_files()

Look for image loading APIs (LoadImage, GdipCreateBitmapFromFile) combined
with byte-level data extraction patterns.
```

## Extraction Methodology

Follow this sequence. Each step informs the next.

### Step 1: Locate the Encrypted Data

Start with automated detection, then fall back to manual methods:

```
Tool: extract_config_automated()

Attempts family-specific and generic extraction patterns. If this succeeds,
validate the output and you may be done. If it fails or returns incomplete
results, proceed to manual extraction.
```

If family is known, try the knowledge-base-driven extractor:

```
Tool: extract_config_for_family(family="<confirmed family>")

Handles algorithm selection, key recovery, decryption, and parsing automatically
using recipes from the malware signatures knowledge base. Falls back to generic
extraction if no family-specific extractor exists.
```

Manual approaches:
- Check resources for high-entropy entries (`extract_resources`)
- Look for high-entropy regions in .data section (`analyze_entropy_by_offset`)
- Search for XOR decryption patterns in capa results (`get_capa_analysis_info`)
- Trace references to data section addresses from crypto-flagged functions

### Step 2: Identify the Algorithm

Once you have located the encrypted data, find the function that decrypts it:

```
Tool: decompile_function_with_angr(decrypt_function_address)

Look for:
- XOR loops (single-byte, multi-byte, rolling key)
- RC4 pattern (KSA: 256-iteration init loop, PRGA: swap-and-index loop)
- AES (SubBytes table reference, or calls to crypto APIs)
- Base64 + XOR (decode first, then decrypt)
- Custom algorithms (less common but present in sophisticated families)
```

### Step 3: Find the Key

The key must be somewhere the binary can access it. Common locations:

- Hardcoded bytes adjacent to or near the encrypted blob
- Derived from a hardcoded passphrase via a KDF (MD5, SHA256)
- Embedded in the binary's own metadata (PE timestamp, section name hash)
- First N bytes of the encrypted blob itself (key prepended to ciphertext)

```
Tool: get_backward_slice(decrypt_function_address, key_parameter)

Trace the key parameter backwards from the decryption call to its origin.
This is the single most valuable data flow analysis for C2 extraction.
```

### Step 4: Decrypt

Use refinery tools to perform the actual decryption:

```
Tool: refinery_xor(data, key)          — for XOR-encrypted configs
Tool: refinery_decrypt(data, algo, key) — for AES, RC4, DES, etc.
Tool: refinery_auto_decrypt(data)      — attempt automatic detection
Tool: refinery_pipeline(steps)         — chain operations: base64 decode
                                         then XOR then decompress
```

Example pipeline for a common pattern (base64 → XOR → config):
```
refinery_pipeline(steps=["b64", "xor:4D", "zl"])
```

### Step 5: Validate

Decrypted configs should contain plausible data:

- **IP addresses/domains**: syntactically valid, resolvable or at least
  plausible TLD
- **Ports**: reasonable range (80, 443, 8080, 4444 common for C2)
- **Strings**: readable, consistent encoding (not garbled mixed bytes)
- **Struct alignment**: if you are parsing a struct, field sizes should be
  consistent and total size should match the blob size

```
Tool: get_iocs_structured()

Aggregates all extracted IOCs (IPs, domains, URLs, hashes, mutexes) from
all analysis passes. Use this to validate and collect final results.
```

If the output is garbled, re-examine the algorithm and key. Common errors:
wrong key length, wrong byte order (little-endian vs big-endian key), wrong
offset into the blob (skipping a length header or key prefix).

## Worked Example Pattern

This illustrates the sequence an analyst would follow:

```
1. extract_config_automated()           -> "No known family detected"
2. get_capa_analysis_info()             -> "encrypt data using XOR" matched
3. get_capa_rule_match_details("encrypt data using XOR")
                                        -> function at 0x00401A00
4. decompile_function_with_angr(0x00401A00)
                                        -> XOR loop, key from [ebp+8], data from [ebp+C]
5. get_function_xrefs(0x00401A00)       -> called from 0x004021B0
6. decompile_function_with_angr(0x004021B0)
                                        -> loads data from 0x00405000, key = first 4 bytes
7. get_hex_dump(0x00405000, 256)        -> see the encrypted blob
8. refinery_xor(offset=0x00405004, length=200, key="0x00405000:4")
                                        -> decrypted: "192.168.1.50|443|campaign_2024"
9. get_iocs_structured()                -> confirms IP and port extraction
```

## Socratic Questions

- "We found a function that XORs a data buffer with a key. How can we find
  out what key the binary actually uses at runtime?"
  (Leads to: backward slice from the key parameter, or emulate and inspect)
- "The automated extractor did not find anything. Does that mean there is no
  config?" (Leads to: no — it means the family is not in the signature database.
  Manual extraction is required.)
- "The decrypted output looks almost right but has some garbled bytes at the
  start. What might cause that?"
  (Leads to: key offset error — the first N bytes might be the key itself or a
  length prefix that should be skipped)
- "Two samples from the same family use different C2 servers but the same
  encryption key. What does that tell us about how the operator builds samples?"
  (Leads to: builder tool with configurable C2 but static crypto — common in
  commodity malware)

## Common Mistakes

### Jumping to decryption before understanding the algorithm

Students often try `refinery_auto_decrypt` immediately. If the algorithm is not
a standard one, auto-detection fails. Always decompile the decryption function
first to understand exactly what operations are performed and in what order.

### Wrong key scope

The key used for config encryption may not be a simple byte string. It could be
the MD5 hash of a passphrase, the first N bytes of the encrypted blob itself
(key-prepended ciphertext), or a derived value. Backward slicing reveals the
full key derivation chain.

### Confusing encoding with encryption

Base64 is not encryption — it is encoding. Many configs are base64-encoded AND
then encrypted (or vice versa). The order of operations matters. If you XOR
first and get garbled base64, try base64-decoding first and then XORing.

### Not validating results

A successful decryption operation that produces random-looking bytes is not a
successful extraction. Always validate: are the domains plausible? Are the ports
reasonable? Does the struct parse cleanly? If not, revisit the algorithm or key.

**Reference**: See [config-extraction.md](../arkana-analyze/config-extraction.md) in the
arkana-analyze skill for family-specific extraction recipes and worked examples
for known malware families.
