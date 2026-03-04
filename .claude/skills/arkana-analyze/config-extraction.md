# Malware Configuration Extraction Patterns

Guide for extracting configurations from malware using Arkana tools.

---

## Step 0: Identify the Malware Family First

**Before following any family-specific recipe below**, use the malware family
identification tools to confirm which family you are dealing with:

```
1. identify_malware_family(hash_algorithm=..., hash_seed=..., hash_constants=...,
     config_encryption=..., compiler=..., matched_strings=...)
   → Returns ranked candidates with confidence scores

2. verify_malware_attribution(family="<top candidate>", hash_seed=..., ...)
   → Confirms or rejects the attribution with per-check verdicts

3. list_malware_signatures(family="<name>")
   → View full fingerprint profile for extraction guidance
```

**Why**: Different frameworks share techniques (DJB2 hashing: Havoc vs AdaptixC2;
ROR13: Cobalt Strike vs BRc4; RC4 config: AdaptixC2 vs BRc4 vs Remcos). Without
checking discriminating indicators (hash seeds, specific constants), you will
follow the wrong extraction recipe and waste analysis time.

Provide as many evidence parameters as you have — the more indicators, the more
accurate the attribution. High-confidence indicators: hash algorithm + seed,
verified hash constants, YARA matches. Supporting indicators: config encryption,
compiler, DLL names, network headers, command count.

4. If the binary has minimal imports (suggesting dynamic API resolution), use
   `scan_for_api_hashes()` to find hash constants and resolve them to API names.
   The algorithm and seed are high-confidence evidence for `identify_malware_family()`.

---

## Common C2 Storage Patterns

### Pattern 1: XOR-Encrypted in .data / .rdata Section
**Indicators**: High-entropy blob in data section, XOR loop in init function, config
accessed early in execution (near entry point or DllMain).

```
Detection:  analyze_entropy_by_offset() → look for high-entropy islands in .data
Extraction: refinery_xor(file_offset="0x...", length=N, key_hex="...",
              output_path="/output/decrypted_config.bin")
            → reads directly from loaded file, decrypts, saves to disk as artifact
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
Extraction: parse_binary_struct(schema=[...], file_offset="0x...", length=N)
            Or: get_hex_dump(offset, length) → manual inspection
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
4. refinery_codec(data="<encrypted field hex>", operation="decode", codec="b64")
   → refinery_decrypt(data="<decoded bytes>", algorithm="aes256-cbc",
     key="<key from step 3>", iv="<first 16 bytes of decoded>")
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
4. refinery_key_derive(password="<passphrase string>", algorithm="pbkdf2",
   salt="<salt hex>", iterations=50000)
5. refinery_decrypt(data="<encrypted field hex>", algorithm="aes256-cbc",
   key="<derived_key hex>", iv="<from first block>") for each field
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
1. get_hex_dump(offset=<.data section start>, length=0x2000) → search for 0x1000-byte high-entropy region
2. Decompile the config decryption function to identify the XOR key.
   Cobalt Strike commonly uses single-byte XOR (0x69 or 0x2e).
   Only if key is not visible in decompiled code:
   brute_force_simple_crypto(..., known_plaintext="MZ") — but validate
   the FULL PE structure, not just the first 2 bytes
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
1. extract_resources(resource_type="RT_RCDATA") → find SETTINGS resource
2. Key = first N bytes of resource (length varies by version, typically 1-16 bytes)
3. refinery_decrypt(data="<resource bytes after key>", algorithm="rc4", key="<first N bytes as hex>")
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

### NjRAT (.NET)
**Storage**: Plaintext or lightly obfuscated static fields. C2 comms use
`|'|'|` pipe separator. Very simple config structure.

```
1. dotnet_analyze() → find main class with Host, Port, Dir fields
2. dotnet_disassemble_method() on constructor → extract plaintext values
3. search_for_specific_strings(patterns=["|'|'|", "njRAT", "njq8"])
4. Expected: Host, Port, Victim name, Directory, Registry key, Mutex, Version
```

### NanoCore (.NET)
**Storage**: Config in .NET embedded resource, DES-CBC encrypted with
PBKDF2-derived key from a GUID string.

```
1. dotnet_analyze() → find config class with PrimaryConnectionHost
2. refinery_dotnet(operation="extract_resources") → extract embedded resources
3. Locate GUID key in Decrypt method → refinery_key_derive(algorithm="pbkdf2")
4. refinery_decrypt(algorithm="des-cbc", key="<derived key>")
5. Expected: PrimaryConnectionHost, ConnectionPort, Mutex, GroupName, Version
```

### Gh0st RAT (Native)
**Storage**: Plaintext C2 strings in .data section. Identified by 5-byte magic
header ("Gh0st" or variant) in network packets, Zlib-compressed, 13-byte header.

```
1. search_yara_custom(rule="rule gh0st { strings: $m = \"Gh0st\"
   condition: uint16(0) == 0x5A4D and $m }")
2. get_strings_summary() → look for IP/domain strings near the magic
3. get_hex_dump() at .data section → search for C2 host:port strings
4. Expected: C2 host:port, Service name, Connection password
   Note: Many Gh0st variants change the 5-byte magic — search for
   any 5-byte string followed by Zlib-compressed data (78 9C header)
```

### PlugX / ShadowPad
**Storage**: Multi-layer encryption (XOR → RC4 → LZNT1 decompression).
Decrypted config starts with PLUG magic (0x504C5547). Typically loaded
via DLL side-loading.

```
1. search_yara_custom(rule="rule plugx { strings: $m = {50 4C 55 47}
   condition: uint16(0) == 0x5A4D and $m }")
2. If not found statically, check for DLL side-loading pattern:
   - identify_library_functions() → look for LoadLibrary/GetProcAddress
   - Check for accompanying .dat/.bin config file
3. get_hex_dump() → extract encrypted config blob from .data section
4. Apply XOR decryption → RC4 decryption → LZNT1 decompression
5. Verify PLUG magic (0x504C5547) at start of decrypted data
6. Expected: C2 servers (up to 4), ports, protocol, campaign ID, mutex
```

### DarkComet (Native)
**Storage**: RC4-encrypted config in PE resource named "DCDATA". Key derived
from version string (e.g., `#KCMDDC4#-890`).

```
1. extract_resources(resource_type="RT_RCDATA") → find DCDATA resource
2. Identify version from strings: search_for_specific_strings(
   patterns=["#KCMDDC", "DarkComet"])
3. RC4 key = version string (e.g., "#KCMDDC51#-890" for v5.1)
4. refinery_decrypt(data="<resource hex>", algorithm="rc4",
   key="<version string as hex>")
5. Parse as newline-separated key=value pairs
6. Expected: GENCODE, MUTEX, SID, NETDATA (C2 host:port), persistence settings
```

### QakBot / Qbot
**Storage**: RC4-encrypted config in PE resources with specific IDs
(3/311 or 118/524). Key derived from SHA1/SHA256 of hardcoded strings.

```
1. extract_resources() → look for resources with IDs "3"/"311" or "118"/"524"
2. Identify RC4 key: decompile_function_with_angr() on resource-loading func
   → key is SHA1 or SHA256 hash of a hardcoded string
3. refinery_decrypt(data="<resource hex>", algorithm="rc4", key="<sha hash>")
4. Parse C2 list as array of IP:port pairs (each entry: 1B type + 4B IP + 2B port)
5. Resource 311/524 contains campaign ID + timestamp (plaintext after decryption)
6. Expected: C2 IP:port pairs (up to 150), Campaign ID (bb, obama, azd, etc.)
```

### AdaptixC2 Beacon / Gopher
**Storage**: Two agent types with different encryption schemes.
- **Beacon** (PE: EXE/DLL/shellcode): RC4-encrypted config in `.rdata` section at
  variable offset (0x00–0x63). Structure: `size (4 bytes LE) | ciphertext | RC4 key
  (last 16 bytes of the block)`.
- **Gopher** (Go binary): AES-128-GCM encrypted + msgpack-serialized raw profile.
  Structure: `key (16 bytes) | nonce (12 bytes) | ciphertext`.

**YARA indicators**: API hash constants (`0x6363CE76` VirtualAlloc, `0xA1376764`
GetAdapters, `0x68B3D2E1` NtQueryInformationProcess), `savememory` command
comparison value `0x2321`, Go msgpack tags (`msgpack:"job_id"`, `msgpack:"acp"`).

**Agent Beacon (PE)**:
```
1. search_yara_custom(rule="rule adaptix { strings: $h1 = {76 63 CE 63}
   $h2 = {64 67 37 A1} condition: uint16(0) == 0x5A4D and all of them }")
   → confirm AdaptixC2 beacon
2. get_pe_data(key="sections") → find .rdata section offset and size
3. get_hex_dump(offset=<.rdata VA>, length=<.rdata size>) → extract .rdata content
4. Scan offsets 0x00–0x63 within .rdata for valid config:
   - Read 4-byte LE size at each offset
   - If size is plausible (< section size − 16), extract size + 16 bytes
   - RC4 key = last 16 bytes of the extracted block
5. refinery_decrypt(data="<first [size] bytes hex>", algorithm="rc4",
   key="<last 16 bytes as hex>")
6. Parse decrypted struct — first 4 bytes LE = agent_type, then type-specific:
   - HTTP: ssl (1B), server_count (4B), servers (string+port pairs), http_method,
     URI, parameter, user_agent, http_headers, kill_date, working_time, sleep, jitter
   - TCP: prepend_bytes, port, listener_type, kill_date
   - SMB: pipename (\\.\pipe\...), listener_type, kill_date
7. Expected: C2 server:port list, HTTP method + URI + User-Agent, sleep/jitter
   intervals, kill date, working time window (HH:MM-HH:MM)
```

**Agent Gopher (Go binary)**:
```
1. go_analyze() → confirm Go binary; search_for_specific_strings(
   patterns=["gopher", "msgpack:\"job_id\"", "msgpack:\"acp\""]) → confirm Gopher
2. Extract raw profile data (from embedded resource, overlay, or dumped from memory
   via emulation — the profile is a standalone encrypted blob)
3. refinery_decrypt(data="<bytes from offset 28 onwards as hex>", algorithm="aes-gcm",
   key="<first 16 bytes as hex>", iv="<bytes 16-28 as hex>")
4. Decrypted output is msgpack-serialized — decode to extract C2 config dict
5. Expected: C2 server addresses, ports, protocol settings, sleep intervals
```

Ref: [av-gantimurov/adaptixc2-extractor](https://github.com/av-gantimurov/adaptixc2-extractor)

---

## Generic Approach (Unknown Family)

When the malware family is unknown, use this systematic approach:

### Step 1: Identify the Framework
```
1. identify_malware_family()           → match any available evidence against KB
2. list_malware_signatures()           → browse known families and their fingerprints
   If a match is found with HIGH confidence, skip to Step 5 below
   and follow the family-specific recipe.
```

### Step 2: Identify Config Location
```
1. extract_config_automated()          → try automated extraction first
2. get_strings_summary()               → look for URL/IP/domain patterns
3. analyze_entropy_by_offset()         → find encrypted blobs
4. get_function_map(limit=15)          → find init/config functions
5. scan_for_embedded_files()           → check for embedded configs
```

### Step 3: Identify Decryption Mechanism
```
1. identify_crypto_algorithm()         → detect crypto constants
2. decompile_function_with_angr()      → decompile suspect functions
3. get_reaching_definitions()          → trace key/IV sources
4. get_backward_slice()               → trace encrypted data source
   After identifying the algorithm and key, re-run identify_malware_family()
   with the new evidence — you may now match a known family.
```

**IMPORTANT**: Do NOT skip step 2 (decompile) and jump to `brute_force_simple_crypto`.
Decompilation reveals the actual algorithm — brute-forcing guesses at it. Without
decompiling the decryption function, you have no evidence for which algorithm is
used, what the key size is, or whether the "encrypted" data is even encrypted
(it could be compressed, serialized, or structured data).

### Step 4: Extract and Decrypt
```
1. Use file_offset + length to read directly from the loaded binary:
   - refinery_xor(file_offset="0x...", length=N, key_hex="...",
       output_path="/output/decrypted.bin")
   - refinery_pipeline(file_offset="0x...", length=N,
       steps=["xor:41", "zl"], output_path="/output/decoded.bin")
2. Or for hex-input workflows:
   - refinery_decrypt()                → AES/RC4/DES/ChaCha20
   - refinery_auto_decrypt()           → auto-detect simple ciphers
   - refinery_decompress()             → if compressed after decryption
   - refinery_codec()                  → Base64/hex decode
3. Always use output_path to save extracted payloads as artifacts
```

### Step 5: Verify Attribution and Parse
```
1. verify_malware_attribution(family=...)   → confirm family before reporting
2. refinery_extract_iocs()             → extract IOCs from decrypted data
3. refinery_extract_domains()          → pull domains
4. Validate: do extracted IPs/domains make sense? Are ports valid?
5. add_note(content="C2 config: ...", category="ioc")
   If a family was confirmed above, try the shortcut:
6. extract_config_for_family(family=...)  → KB-driven automated extraction
7. parse_binary_struct(schema=[...])      → parse decrypted config if it's a binary struct
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
