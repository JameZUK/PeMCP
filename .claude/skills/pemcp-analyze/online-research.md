# Online Research Methodology

Guide for safely researching malware families and translating public decoders
into PeMCP tool calls.

---

## When to Research

Research online when:
- A malware family is identified (VT, YARA, behavioral match) but you lack
  extraction knowledge for its config format
- Static analysis reveals an unfamiliar encoding/encryption scheme
- You need to understand a specific technique or algorithm spotted in the binary
- The automated `extract_config_automated()` failed and you need a manual approach

Do NOT research when:
- Standard PeMCP tools can handle the task directly
- The binary is entirely novel (no public intel will exist)
- You already have enough information to proceed

## Family Identification Sources

Use these to identify the malware family before searching for decoders:

| Source | Tool | What It Reveals |
|--------|------|-----------------|
| VirusTotal | `get_virustotal_report_for_loaded_file()` | Family labels from 70+ engines |
| YARA | `search_yara_custom(rule)` or triage YARA results | Rule-based family matching |
| Capa | `get_capa_analysis_info()` | Behavioral capabilities mapped to ATT&CK |
| Strings | `get_strings_summary()` | Mutex names, PDB paths, unique strings |
| Import hash | `get_import_hash_analysis()` | Imphash clusters known families |
| Similarity | `compute_similarity_hashes()` | ssdeep/TLSH for fuzzy matching |

## Search Query Patterns

Once a family is identified, search for decoder information:

### Config Extraction
```
"<family_name> config extractor"
"<family_name> C2 extraction python"
"<family_name> decryption routine analysis"
"<family_name> configuration structure"
```

### Encryption/Encoding Schemes
```
"<family_name> encryption algorithm"
"<family_name> string decryption"
"<family_name> XOR key derivation"
"<family_name> AES key extraction"
```

### Technical Analysis Reports
```
"<family_name> malware analysis report"
"<family_name> reverse engineering deep dive"
"<family_name> technical analysis" (append the current year)
```

### Preferred Sources
Prioritize results from:
- Vendor blogs: Elastic, CrowdStrike, Mandiant, SentinelOne, Check Point, Zscaler
- Research blogs: MalwareBazaar, Any.Run, OALabs, Hasherezade
- Repositories: CAPE, MWCP, RATDecoders, MalwareConfigExtract
- Academic / DFIR: SANS, VirusBulletin

## Read-and-Understand Methodology

When you find a public decoder or analysis report, extract three things:

### 1. Algorithm
What encryption/encoding is used?
- XOR (single-byte, multi-byte, rolling)
- AES (which mode: ECB, CBC, CTR? key size?)
- RC4, ChaCha20, DES, 3DES, Blowfish
- Base64, hex encoding, custom alphabet
- Compression (zlib, gzip, LZMA, aPLib)
- Multi-layer (e.g., Base64 → AES → XOR)

### 2. Data Location
Where is the encrypted config stored?
- PE section (.data, .rdata, .rsrc, overlay)
- .NET resource, field, or embedded assembly
- Specific offset from section start
- PE resource by name or type ID
- Registry key or dropped file (runtime only)

### 3. Key Source
Where does the decryption key come from?
- Hardcoded bytes at known offset
- Derived from PE metadata (timestamp, checksum)
- .NET field value or constructor parameter
- First N bytes of the encrypted blob
- Password-based derivation (PBKDF2, SHA256 of string)

## Translation Table: Decoder Operations → PeMCP Tools

| Decoder Operation | PeMCP Tool |
|-------------------|------------|
| `open(file, 'rb').read()[offset:offset+length]` | `refinery_xor(file_offset="0x...", length=N)` or `get_hex_dump(offset, length)` |
| `xor(data, key)` | `refinery_xor(file_offset=..., key_hex=..., output_path=...)` |
| `AES.new(key, mode, iv).decrypt()` | `refinery_decrypt(algorithm="aes-cbc", key, iv)` |
| `RC4(key).decrypt(data)` | `refinery_decrypt(algorithm="rc4", key)` |
| `base64.b64decode()` | `refinery_codec(operation="decode", codec="b64")` |
| `zlib.decompress()` | `refinery_decompress(algorithm="zlib")` |
| `struct.unpack()` | Parse hex dump output manually |
| `re.findall(pattern, data)` | `refinery_regex_extract(pattern)` |
| `hashlib.sha256(password)` | `refinery_hash(algorithm="sha256")` or `refinery_key_derive()` |
| `PBKDF2(password, salt, iter)` | `refinery_key_derive(algorithm="pbkdf2")` |
| Read PE resource | `extract_resources(resource_type)` |
| Read .NET field | `dotnet_analyze()` + `dotnet_disassemble_method()` |
| Read PE overlay | `refinery_pe_operations(operation="overlay")` |
| Regex replace in string | `refinery_regex_replace(pattern, replacement)` |
| Decompress aPLib | `refinery_decompress(algorithm="aplib")` |
| Carve embedded PE | `refinery_carve(pattern="MZ", output_path="/output/carved.bin")` |
| Multi-step pipeline | `refinery_pipeline(steps=["b64", "aes:KEY", "xor:KEY2"], output_path=...)` |
| Save decoded output | Use `output_path` param on `refinery_xor`/`pipeline`/`carve` |

## Workflow Example

Suppose VT identifies the sample as "AsyncRAT" and `extract_config_automated()` failed:

1. **Search**: "AsyncRAT config extraction python decryption"
2. **Find**: Blog post describing AES-256-CBC with PBKDF2-derived key
3. **Read**: Decoder shows:
   - Key derived from: `PBKDF2(password_field, salt_field, 50000, 32)`
   - Config encrypted with: `AES-256-CBC(derived_key, iv=salt[:16])`
   - Config stored in: `Settings` class static fields as Base64 strings
4. **Translate to PeMCP**:
   ```
   dotnet_analyze()                              → find Settings class
   dotnet_disassemble_method("Settings::.cctor") → get field values
   refinery_codec(operation="decode", codec="b64") → decode Base64
   refinery_key_derive(algorithm="pbkdf2",
       password=<from .cctor>, salt=<from .cctor>, iterations=50000)
   refinery_decrypt(algorithm="aes256-cbc",
       key=<derived>, iv=<salt[:16]>)            → decrypt config
   ```
5. **Execute** the PeMCP tool sequence
6. **Validate**: Check results match expected format (hosts, ports, mutex, etc.)
7. **Document**: `add_note(content="AsyncRAT config extracted: C2=...", category="ioc")`

## Safety Rules

1. **NEVER execute downloaded scripts** — read and understand the logic, then
   translate to PeMCP tool calls. Downloaded code may be malicious, backdoored,
   or destructive.

2. **NEVER write Python scripts when internal tools exist** — the entire point of
   research is to understand the algorithm, then execute it with PeMCP's built-in
   tools. If a decoder does `base64 → AES-CBC → XOR`, translate that to
   `refinery_pipeline(pipeline="b64 | aes -m cbc -k KEY | xor KEY2")` — not a
   Python script that reimplements the same logic. Internal tool calls are logged
   in tool history, reproducible, and auditable. Scripts are opaque and
   unreviewable. Only write a script when no combination of internal tools can
   accomplish the task, and document why in an `add_note()` call.

3. **Verify output** — after decryption/decoding, validate that results look like
   legitimate config data (valid IPs, URLs, port numbers). Garbage output means
   wrong key or algorithm.

4. **Cross-reference** — compare extracted config against multiple sources. If two
   independent analyses describe different algorithms, investigate which applies
   to your specific sample version.

5. **Version awareness** — malware families evolve. A decoder for AsyncRAT 0.5.7B
   may not work for 0.5.8. Check version indicators in the binary against the
   decoder's target version.

6. **Document your sources** — note which blog/report/tool informed your extraction
   approach: `add_note(content="Extraction based on: <URL>", category="manual")`

7. **Prefer PeMCP's automated tools first** — always try `extract_config_automated()`
   and `refinery_auto_decrypt()` before manual research. They may handle it without
   any external knowledge.
