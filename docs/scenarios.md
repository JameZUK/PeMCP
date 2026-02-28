# Real-World Scenarios & Comparisons

These scenarios demonstrate PeMCP's combined power across its tool categories. Each represents a common analysis task that traditionally requires multiple disconnected tools.

---

## Scenario 1: Triaging a Suspicious Email Attachment (2 minutes vs 30+)

**The situation:** A SOC analyst receives an alert about a suspicious `.doc` attachment. They need to determine if it's malicious and extract any IOCs.

**Traditional workflow:** Open in a sandbox VM, use `olevba` to extract macros, manually read VBA code, use CyberChef to decode Base64 payloads, use `strings` to find URLs, check hashes on VirusTotal — switching between 5+ tools.

**With PeMCP:**
```
Analyst: "Open this Office document and tell me if it's malicious"
```
PeMCP automatically:
1. `open_file("attachment.doc")` — detects OLE format
2. `get_triage_report(compact=True)` — instant risk assessment
3. `refinery_extract(operation='office', sub_operation='vba')` — extracts VBA macros
4. `refinery_deobfuscate_script(script_type='vba')` — deobfuscates the macro code
5. `refinery_extract_iocs()` — pulls URLs, IPs, domains from the deobfuscated script
6. `refinery_carve(operation='pattern', pattern='b64')` — finds and decodes Base64 payloads
7. `get_virustotal_report_for_loaded_file()` — checks community detection

The AI cross-references all findings: *"This document contains an obfuscated VBA macro that downloads a second-stage payload from hxxps://evil[.]com/payload.exe using PowerShell. The macro uses string concatenation and Chr() calls to evade static detection. Three unique C2 URLs were extracted."*

---

## Scenario 2: Extracting C2 Configuration from a Packed .NET RAT

**The situation:** A malware analyst has a .NET sample suspected to be AsyncRAT. The binary is packed and the C2 configuration is encrypted in string constants.

**Traditional workflow:** Use `de4dot` to deobfuscate, load in `dnSpy` to find the config class, manually identify the decryption routine, write a Python script to replicate the decryption, extract the C2 address — a process that can take 1-2 hours.

**With PeMCP:**
```
Analyst: "Analyse this .NET binary and extract the C2 configuration"
```
PeMCP orchestrates:
1. `open_file("sample.exe")` — detects .NET assembly
2. `dotnet_analyze()` — extracts CLR metadata, type/method definitions
3. `refinery_dotnet(operation='strings')` — extracts all .NET metadata strings
4. `refinery_dotnet(operation='fields')` — extracts constant field values (where RATs store encrypted configs)
5. `refinery_dotnet(operation='arrays')` — extracts byte array initialisers (AES keys, encrypted blobs)
6. `refinery_dotnet(operation='resources')` — checks for config stored in resources
7. `refinery_decrypt(algorithm='aes', key_hex='...', iv_hex='...')` — decrypts the config using extracted key material
8. `refinery_extract_iocs()` — extracts C2 URLs, ports, and mutex names from decrypted config

The AI correlates field names with known AsyncRAT config patterns: *"This is AsyncRAT v0.5.7B. The C2 server is 192.168.1[.]100:8808, with a backup at evil-c2[.]com:443. The mutex is 'AsyncMutex_6SI8OkPnk'. The AES-256 key was found in the Settings.Key field and the encrypted config was stored in Settings.Host, Settings.Port, and Settings.Pastebin fields."*

---

## Scenario 3: Analysing a Multi-Stage Dropper with Shellcode

**The situation:** A threat intel analyst has a PE dropper that unpacks multiple stages. Stage 1 is a packed PE, Stage 2 is XOR-encrypted shellcode in the overlay, and Stage 3 is a DLL downloaded to memory.

**With PeMCP:**
```
Analyst: "This looks like a multi-stage dropper. Help me unpack each stage."
```
PeMCP chains operations:
1. `open_file("dropper.exe")` — parses PE, background CFG starts
2. `get_triage_report()` — identifies high entropy sections, overlay data, suspicious imports (`VirtualAlloc`, `WriteProcessMemory`)
3. `detect_packing()` — confirms UPX packing on Stage 1
4. `auto_unpack_pe()` — unpacks Stage 1 via Un{i}packer
5. `refinery_pe_operations(operation='overlay')` — extracts Stage 2 from overlay
6. `refinery_xor(operation='guess_key')` — auto-detects the XOR key used on Stage 2
7. `refinery_xor(operation='apply', key_hex='...')` — decrypts Stage 2 shellcode
8. `refinery_executable(operation='disassemble')` — disassembles the decrypted shellcode
9. `emulate_shellcode_with_speakeasy()` — emulates the shellcode to capture API calls and network activity
10. `refinery_extract_iocs()` — extracts the Stage 3 download URL from emulation output

Each stage's findings are recorded with `auto_note_function()` and `add_note()`, so `get_analysis_digest()` provides a complete picture at any time.

---

## Scenario 4: Investigating a Go Binary on Linux

**The situation:** An IR team recovers a suspicious ELF binary from a compromised Linux server. It's a stripped Go binary with no symbols.

**With PeMCP:**
```
Analyst: "Analyse this Linux binary — it might be a backdoor"
```
1. `open_file("suspicious_elf")` — auto-detects ELF format
2. `elf_analyze()` — ELF headers, sections, segments, dynamic deps
3. `go_analyze()` — recovers Go compiler version, packages, and function names from `pclntab` (works on stripped binaries)
4. `get_triage_report()` — ELF-specific security checks (PIE, NX, RELRO, stack canaries)
5. `decompile_function_with_angr(address)` — decompile suspicious functions identified by package names
6. `refinery_extract_iocs()` — extract hardcoded IPs, domains, URLs
7. `get_capa_analysis_info()` — map capabilities to MITRE ATT&CK (file manipulation, process injection, network communication)

The AI recognises Go package names like `net/http`, `os/exec`, `crypto/tls` and correlates them with the decompiled functions: *"This is a Go-based reverse shell (compiled with Go 1.21.4). It establishes a TLS connection to C2 at 10.0.0[.]50:4443, receives commands via HTTP POST, and executes them via os/exec. It also has file exfiltration capabilities via the archive/zip package."*

---

## Scenario 5: Bulk IOC Extraction from a Forensic PCAP

**The situation:** An incident responder has a PCAP capture from a compromised network segment and needs to extract all malicious indicators.

**With PeMCP:**
```
Analyst: "Extract all IOCs and embedded files from this PCAP"
```
1. `refinery_forensic(operation='pcap')` — reassembles TCP streams, identifies protocols
2. `refinery_forensic(operation='pcap_http')` — extracts HTTP transactions with URLs, methods, and response bodies
3. `refinery_extract(operation='embedded')` — auto-detects embedded PE files, ZIPs, scripts in the extracted streams
4. `refinery_extract_iocs()` — extracts all URLs, IPs, domains, email addresses, hashes
5. `refinery_forensic(operation='defang')` — defangs all IOCs for safe sharing in reports

For each carved PE file, the analyst can immediately:
```
Analyst: "Open this carved PE and analyse it"
```
6. `open_file(carved_pe)` → `get_triage_report()` → `get_focused_imports()` → full analysis chain

---

## PeMCP vs Traditional Tools

### Comparison Matrix

| Capability | PeMCP | Ghidra | IDA Pro | pestudio | CyberChef | Binary Refinery CLI |
|---|---|---|---|---|---|---|
| **PE/ELF/Mach-O parsing** | 178 tools, auto-detect | Plugin-based | Plugin-based | PE only | No | No |
| **Decompilation** | Angr (auto, all archs) | Ghidra Decompiler | Hex-Rays ($$$) | No | No | No |
| **Symbolic execution** | Angr (automated) | Limited (Ghidra scripts) | No | No | No | No |
| **Data transforms** | 200+ via Binary Refinery | Manual scripting | Manual scripting | No | 300+ (manual) | 200+ (CLI) |
| **String analysis** | FLOSS + StringSifter ML ranking | Built-in (basic) | Built-in (basic) | Basic | No | Basic |
| **Signature scanning** | YARA + Capa + PEiD | YARA (plugin) | FLIRT signatures | Signatures | No | No |
| **Emulation** | Speakeasy + Qiling + Angr | Emulator (limited) | No | No | No | No |
| **AI reasoning** | Native (MCP protocol) | No | No | No | No | No |
| **Session persistence** | Notes + history + cache | Project files | IDB files | No | No | No |
| **Learning curve** | Natural language | Months | Months | Low | Moderate | Moderate |
| **Cost** | Free & open source | Free | $1,800+/year | Free | Free | Free |

### How PeMCP Complements (Not Replaces) Existing Tools

PeMCP is not meant to fully replace Ghidra or IDA Pro — those tools remain essential for deep interactive reverse engineering sessions where you need to manually rename variables, annotate code, and navigate complex control flow graphs in a visual GUI. Instead, PeMCP excels in different parts of the analysis lifecycle:

**Where PeMCP excels over Ghidra/IDA:**
- **Speed of initial triage** — PeMCP produces a comprehensive risk assessment in seconds. Ghidra takes 30+ seconds just to load and auto-analyse a binary, and IDA's auto-analysis can take minutes on large files.
- **Automated IOC extraction** — PeMCP extracts URLs, IPs, domains, hashes, and file paths automatically. In Ghidra/IDA, this requires custom scripts or manual searching.
- **Data transformation chains** — Decoding nested Base64 → XOR → zlib payloads is a single `refinery_pipeline` call. In Ghidra, you'd write a Jython script. In IDA, an IDAPython script. In CyberChef, you'd manually build a recipe.
- **Cross-tool correlation** — PeMCP's AI automatically connects findings: "The XOR key found in the .rdata section matches the key used to decrypt the config extracted from the .NET resources." No other tool does this automatically.
- **Multi-format support in one interface** — Analyse PE, ELF, Mach-O, .NET, Go, and Rust binaries without switching tools or learning different workflows.
- **Accessibility** — A junior analyst can ask "What does this function do?" and get an explanation. In Ghidra, they'd need to understand the decompiler output themselves.

**Where Ghidra/IDA still excel:**
- **Interactive visual navigation** — Ghidra's graph view, cross-reference browser, and function call trees are unmatched for manual code exploration.
- **Type reconstruction** — IDA's Hex-Rays decompiler produces higher-fidelity C pseudocode with better type propagation than Angr's decompiler.
- **Plugin ecosystems** — Ghidra has GhidraScript/Pyhidra, IDA has IDAPython — mature scripting for custom analysis workflows.
- **Debugging** — Both support live debugging. PeMCP is static/emulation-only.

**The ideal workflow combines both:**
1. **PeMCP for triage and automated analysis** — Get the risk assessment, extract IOCs, identify interesting functions, decode obfuscated data.
2. **Ghidra/IDA for targeted deep-dives** — When PeMCP identifies a critical function (e.g., "the decryption routine at 0x00401230"), open the binary in Ghidra to manually trace the algorithm and reconstruct data structures.

### PeMCP vs CyberChef / Binary Refinery CLI

CyberChef and Binary Refinery's command-line interface are powerful data transformation tools, but they require the analyst to know *which* transforms to apply and in *what order*. PeMCP wraps Binary Refinery's 200+ units behind an AI that can reason about the data:

- **CyberChef** — Browser-based, visual recipe builder. Great for known transform chains but requires manual operation selection. No binary analysis, no PE parsing, no decompilation.
- **Binary Refinery CLI** — Powerful pipe-based transforms (`data | b64 | xor[0x41] | zl`). Requires command-line expertise and knowledge of unit names. No AI reasoning.
- **PeMCP** — Wraps Binary Refinery into 23 context-efficient MCP tools, adds AI reasoning, and combines with PE parsing, decompilation, emulation, and signature scanning. The AI can look at encrypted data, hypothesise the encryption scheme, try `refinery_xor(operation='guess_key')`, and if that fails, try `refinery_auto_decrypt()`, all without the analyst knowing which specific refinery units to use.
