# C2 Configuration Extraction Patterns

Guide for extracting command-and-control configurations from malware using PeMCP tools.

---

## Common C2 Storage Patterns

### Pattern 1: XOR-Encrypted in .data / .rdata Section
**Indicators**: High-entropy blob in data section, XOR loop in init function, config
accessed early in execution (near entry point or DllMain).

```
Detection:  analyze_entropy_by_offset() → look for high-entropy islands in .data
Extraction: get_hex_dump() → refinery_xor(key) or refinery_auto_decrypt()
Validation: refinery_extract_iocs() on decrypted output
```

### Pattern 2: .NET Fields / Static Arrays
**Indicators**: .NET assembly, config values as static string fields or byte arrays,
sometimes Base64-encoded, sometimes encrypted with hardcoded key.

```
Detection:  dotnet_analyze() → look for config classes (Settings, Config, Connection)
Extraction: dotnet_disassemble_method() on static constructor (.cctor)
            refinery_dotnet(operation="extract_resources") for embedded resources
            refinery_codec(codec="b64") then refinery_decrypt() if encrypted
```

### Pattern 3: Encrypted PE Resources
**Indicators**: Suspicious named or RT_RCDATA resources, high entropy in resources,
decryption routine called early.

```
Detection:  extract_resources() → check entropy of each resource
Extraction: extract_resources(resource_type="RT_RCDATA")
            Identify decryption from decompilation of resource-loading function
            refinery_decrypt() or refinery_xor() with recovered key
```

### Pattern 4: Config Struct at Fixed Offset
**Indicators**: Fixed-size struct appended to PE overlay, or at known offset from
section start. Common in builder-generated malware.

```
Detection:  refinery_pe_operations(operation="overlay") to check for overlay data
            analyze_entropy_by_offset() for data past PE boundary
Extraction: get_hex_dump(offset, length) → parse struct fields manually
            refinery_carve() if config has recognizable header
```

### Pattern 5: Runtime-Only (Decrypted in Memory)
**Indicators**: Config never exists in cleartext on disk. Decrypted at runtime into
heap or stack, used, then zeroed.

```
Detection:  Cannot find config statically → suspect runtime-only
Extraction: emulate_binary_with_qiling() or emulate_pe_with_windows_apis()
            qiling_memory_search(pattern="http") after init routines complete
            qiling_hook_api_calls() on connect/send to capture C2 URL
```

### Pattern 6: Steganography / Embedded in Images
**Indicators**: Image files in resources or dropped files, data appended after EOF.

```
Detection:  scan_for_embedded_files() → detect images in resources
Extraction: extract_steganography() → extract data after image EOF
            refinery_carve() for known formats within image data
```

---

## Family-Specific Extraction

### Agent Tesla / Snake Keylogger (.NET)
**Storage**: Static string fields in config class, Base64 + AES-256 encrypted.
SMTP/FTP/Telegram credentials stored separately.

```
1. dotnet_analyze() → find classes with SMTP/FTP/credential field names
2. dotnet_disassemble_method() on constructor or config initialization
3. Locate AES key (often hardcoded as string or byte array in same class)
4. refinery_codec(operation="decode", codec="b64") → refinery_decrypt(algorithm="aes256-cbc")
5. Extracted fields: SMTP host, port, user, pass; FTP host, user, pass;
   Telegram bot token, chat ID; exfil timer interval
```

### AsyncRAT / VenomRAT (.NET)
**Storage**: Encrypted strings in Settings class. AES-256-CBC with PBKDF2-derived key.
Mutex, ports, hosts, certificate hash as separate encrypted fields.

```
1. dotnet_analyze() → find "Settings" class
2. dotnet_disassemble_method("Settings::.cctor") → locate encrypted field values
3. Find Decrypt() method → extract salt, iterations, passphrase
4. refinery_key_derive(algorithm="pbkdf2", password=passphrase, salt=salt)
5. refinery_decrypt(algorithm="aes256-cbc", key=derived_key) for each field
6. Expected: Hosts, Ports, Version, Install, Mutex, Certificate, ServerSignature
```

### Quasar RAT (.NET)
**Storage**: Similar to AsyncRAT — Settings class with AES-encrypted strings.
Key derived from hardcoded password via PBKDF2.

```
1. dotnet_analyze() → find Settings class
2. dotnet_disassemble_method() on static constructor
3. Locate AES key derivation (password + salt → PBKDF2)
4. Decrypt each settings field with refinery_decrypt()
5. Expected: Tag, Hosts, ServerSignature, InstallPath, LogPath, Mutex, StartupKey
```

### Cobalt Strike Beacon
**Storage**: XOR-encrypted config block (usually 0x1000 bytes) in .data section.
Single-byte XOR key, config is a TLV (type-length-value) structure.

```
1. get_hex_dump() → search .data section for 0x1000-byte high-entropy region
2. bruteforce_xor_key() or deobfuscate_xor_single_byte() — try common keys (0x69, 0x2e)
3. Or: extract_config_automated() — has built-in Cobalt Strike parser
4. Parse TLV: type (2 bytes) + length (2 bytes) + value
5. Key fields: BeaconType (0x0001), Port (0x0002), SleepTime (0x0003),
   PublicKey (0x0007), C2Server (0x0008), UserAgent (0x0009),
   HttpPostUri (0x000a), Watermark (0x0025)
```

### Emotet
**Storage**: Encrypted C2 list as (IP, port) pairs. XOR or RC4 encrypted in .data
or .text section. Key often derived from PE timestamp or hardcoded DWORD.

```
1. get_triage_report() → note suspicious imports (networking, crypto)
2. decompile_function_with_angr() on functions near string/crypto references
3. Locate C2 decryption routine (often called early, operates on global buffer)
4. get_reaching_definitions() to trace key source
5. refinery_xor() or refinery_decrypt(algorithm="rc4") with recovered key
6. Parse as array of structs: {IP (4 bytes), port (2 bytes)}
```

### IcedID / BokBot
**Storage**: C2 domains encrypted in binary or downloaded config. Initial loader
contacts hardcoded C2, retrieves encrypted config.

```
1. get_strings_summary() → look for campaign ID strings
2. emulate_binary_with_qiling() → capture network calls
3. qiling_memory_search(pattern="http") after network init
4. Or: decompile decryption function + refinery_decrypt()
5. Expected: C2 domains, campaign ID, bot ID generation algorithm
```

### Remcos RAT
**Storage**: RC4-encrypted config in PE resource named "SETTINGS" or similar.
Key is first N bytes of the resource.

```
1. extract_resources() → find SETTINGS/RCData resource
2. Key = first byte(s) of resource (length varies by version)
3. refinery_decrypt(algorithm="rc4", key=extracted_key)
4. Parse cleartext: null-separated fields
5. Expected: C2 host:port, password, mutex, install path, keylog settings
```

### RedLine Stealer (.NET)
**Storage**: Base64 strings in .NET resources or fields. Config class with
IP, BuildID, and feature flags.

```
1. dotnet_analyze() → find config/connection class
2. refinery_dotnet(operation="extract_resources")
3. refinery_codec(operation="decode", codec="b64") on extracted strings
4. Expected: C2 IP:port, BuildID, GrabBrowsers, GrabFTP, GrabWallets flags
```

---

## Generic Approach (Unknown Family)

When the malware family is unknown, use this systematic approach:

### Step 1: Identify Config Location
```
1. extract_config_automated()          → try automated extraction first
2. get_strings_summary()               → look for URL/IP/domain patterns
3. analyze_entropy_by_offset()         → find encrypted blobs
4. get_function_map(limit=30)          → find init/config functions
5. scan_for_embedded_files()           → check for embedded configs
```

### Step 2: Identify Decryption Mechanism
```
1. identify_crypto_algorithm()         → detect crypto constants
2. decompile_function_with_angr()      → decompile suspect functions
3. get_reaching_definitions()          → trace key/IV sources
4. get_backward_slice()               → trace encrypted data source
```

### Step 3: Extract and Decrypt
```
1. get_hex_dump(offset, length)        → extract raw encrypted data
2. Apply appropriate decryption:
   - refinery_xor()                    → XOR (single or multi-byte)
   - refinery_decrypt()                → AES/RC4/DES/ChaCha20
   - refinery_auto_decrypt()           → auto-detect simple ciphers
   - refinery_decompress()             → if compressed after decryption
   - refinery_codec()                  → Base64/hex decode
3. refinery_pipeline()                 → chain operations if multi-layer
```

### Step 4: Parse and Validate
```
1. refinery_extract_iocs()             → extract IOCs from decrypted data
2. refinery_extract_domains()          → pull domains
3. Validate: do extracted IPs/domains make sense? Are ports valid?
4. add_note(content="C2 config: ...", category="ioc")
```

---

## Validation Checklist

After extraction, verify the config makes sense:

- [ ] IP addresses are valid (not 0.0.0.0, 127.x.x.x, or multicast)
- [ ] Ports are in valid range (1-65535) and plausible for C2 (80, 443, 8080, high ports)
- [ ] URLs have valid format and plausible TLD
- [ ] Mutex names look intentional (not garbage from decryption errors)
- [ ] If encryption key was recovered, re-encrypting the output produces the original
- [ ] Multiple config fields are self-consistent (e.g., HTTPS port with HTTPS URL)
- [ ] Config version/build ID matches known family patterns

If validation fails, the decryption key or algorithm may be wrong. Re-examine
the decompilation and try alternative interpretations.
