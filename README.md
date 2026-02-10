# PeMCP — Advanced Multi-Format Binary Analysis & MCP Server

PeMCP is a professional-grade Python toolkit for in-depth static and dynamic analysis of **PE, ELF, Mach-O, .NET, Go, and Rust** binaries, plus raw shellcode. It operates as both a powerful CLI tool for generating comprehensive reports and as a **Model Context Protocol (MCP) server**, providing AI assistants and other MCP clients with **104 specialised tools** to interactively explore, decompile, and analyse binaries across all major platforms.

PeMCP bridges the gap between high-level AI reasoning and low-level binary instrumentation, turning any MCP-compatible client into a capable malware analyst.

---

## Table of Contents

- [Key Features](#key-features)
- [Quick Start with Claude Code](#quick-start-with-claude-code)
  - [Adding PeMCP via the CLI](#adding-pemcp-via-the-cli)
  - [Adding PeMCP via JSON Configuration](#adding-pemcp-via-json-configuration)
- [Installation](#installation)
- [Modes of Operation](#modes-of-operation)
- [Configuration](#configuration)
- [MCP Tools Reference](#mcp-tools-reference)
- [Architecture & Design](#architecture--design)
- [Multi-Format Analysis](#multi-format-analysis)
- [Contributing](#contributing)
- [Licence](#licence)
- [Disclaimer](#disclaimer)

---

## Key Features

### Multi-Format Binary Support

PeMCP automatically detects and analyses binaries across all major platforms:

- **PE (Windows)** — Full parsing of DOS/NT Headers, Imports/Exports, Resources, TLS, Debug, Load Config, Rich Header, Overlay, and more.
- **ELF (Linux)** — Headers, sections, segments, symbols, dynamic dependencies, DWARF debug info.
- **Mach-O (macOS)** — Headers, load commands, segments, symbols, dynamic libraries, code signatures.
- **.NET Assemblies** — CLR headers, metadata tables, type/method definitions, CIL bytecode disassembly.
- **Go Binaries** — Compiler version, packages, function names, type definitions (works on stripped binaries via pclntab).
- **Rust Binaries** — Compiler version, crate dependencies, toolchain info, symbol demangling.
- **Raw Shellcode** — Architecture-aware loading with FLOSS string extraction.

### Advanced Binary Analysis (Powered by Angr)

36 tools powered by the **Angr** binary analysis framework, working across PE, ELF, and Mach-O:

- **Decompilation** — Convert assembly into human-readable C-like pseudocode on the fly.
- **Control Flow Graph (CFG)** — Generate and traverse function blocks and edges.
- **Symbolic Execution** — Automatically find inputs to reach specific code paths.
- **Emulation** — Execute functions with concrete arguments using the Unicorn engine.
- **Slicing & Dominators** — Perform forward/backward slicing to track data flow and identify critical code dependencies.
- **Reaching Definitions & Data Dependencies** — Track how values propagate through registers and memory.
- **Function Hooking** — Replace functions with custom SimProcedures for analysis.
- **Value Set Analysis** — Determine possible values of variables at each program point.
- **Binary Diffing** — Compare two binaries to find added/removed/modified functions.
- **Code Cave Detection** — Find unused space in binaries for patching.
- **C++ Class Recovery** — Identify vtables and class hierarchies.
- **Packing Detection** — Heuristic analysis of entropy and structure anomalies.

### Comprehensive Static Analysis

- **PE Structure** — 24 dedicated tools for every PE data directory and header.
- **Signatures** — Authenticode validation (Signify), certificate parsing (Cryptography), packer detection (PEiD), and YARA scanning.
- **Capabilities** — Integrated Capa analysis to map binary behaviours to the MITRE ATT&CK framework.
- **Strings** — FLOSS integration for extracting static, stack, tight, and decoded strings, ranked by relevance using StringSifter.
- **Crypto Analysis** — Detect crypto constants (AES S-box, DES, RC4), scan for API hashes, entropy analysis.
- **Deobfuscation** — Multi-byte XOR brute-forcing, format string detection, wide string extraction.

### Extended Library Integrations

- **LIEF** — Multi-format binary parsing and modification (PE/ELF/Mach-O section editing).
- **Capstone** — Multi-architecture standalone disassembly (x86, ARM, MIPS, etc.).
- **Keystone** — Multi-architecture assembly (generate patches from mnemonics).
- **Speakeasy** — Windows API emulation for malware analysis (full PE and shellcode).
- **Un{i}packer** — Automatic PE unpacking (UPX, ASPack, FSG, etc.).
- **Binwalk** — Embedded file and firmware detection.
- **ppdeep/TLSH** — Fuzzy hashing for sample similarity comparison.
- **dnfile/dncil** — .NET metadata parsing and CIL bytecode disassembly.
- **pygore** — Go binary reverse engineering.
- **rustbininfo** — Rust binary metadata extraction.
- **pyelftools** — ELF and DWARF debug info parsing.

### Dynamic File Loading, Caching & API Key Management

- **Auto-Detection** — `open_file` automatically detects PE/ELF/Mach-O from magic bytes. No need to specify the format.
- **No Pre-loading Required** — The MCP server starts without needing a file path. Use the `open_file` tool to load files dynamically.
- **Analysis Caching** — Results are cached to disk in `~/.pemcp/cache/`, keyed by SHA256 hash and compressed with gzip (~12x compression). Re-opening a previously analysed file loads instantly from cache.
- **Persistent Configuration** — API keys are stored securely in `~/.pemcp/config.json` and recalled automatically across sessions.
- **Progress Reporting** — File loading and analysis report progress to the MCP client in real time.

### Robust Architecture

- **Modular Package** — Clean `pemcp/` package structure with 8 tool modules, separated concerns (parsers, MCP tools, CLI, configuration).
- **Docker-First Design** — No interactive prompts. Dependencies are managed via Docker, making it container and CI/CD ready.
- **Thread-Safe State** — Centralised `AnalyzerState` class with locking for concurrent access.
- **Background Tasks** — Long-running operations (symbolic execution, Angr CFG) run asynchronously with heartbeat monitoring.
- **Smart Truncation** — MCP responses are automatically truncated to fit within 64KB limits whilst preserving structural integrity.
- **Graceful Degradation** — All 20+ optional libraries are detected at startup. Tools that require unavailable libraries return clear error messages instead of crashing.

---

## Quick Start with Claude Code

PeMCP integrates seamlessly with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) via stdio transport. You can configure PeMCP using the `claude mcp add` CLI command or by editing JSON configuration files directly.

### Adding PeMCP via the CLI

The fastest way to add PeMCP to Claude Code is with the `claude mcp add` command.

**Add to the current project (recommended):**

```bash
claude mcp add --scope project pemcp -- python /path/to/PeMCP/PeMCP.py --mcp-server
```

**Add with a VirusTotal API key:**

```bash
claude mcp add --scope project -e VT_API_KEY=your-key-here pemcp -- python /path/to/PeMCP/PeMCP.py --mcp-server
```

**Add globally for all projects (user scope):**

```bash
claude mcp add --scope user pemcp -- python /path/to/PeMCP/PeMCP.py --mcp-server
```

**Add using Docker (via `run.sh` helper):**

```bash
claude mcp add --scope project pemcp -- /path/to/PeMCP/run.sh --stdio
```

**Add using Docker with a custom samples directory:**

```bash
claude mcp add --scope project pemcp -- /path/to/PeMCP/run.sh --samples /path/to/your/samples --stdio
```

The `run.sh` helper auto-detects Docker or Podman, builds the image if needed, and handles volume mounts and environment setup. The `--samples` flag mounts any local directory into the container at `/app/samples` (read-only), so PeMCP can access your files. To pass a VirusTotal API key, set it in your environment or `.env` file:

```bash
claude mcp add --scope project -e VT_API_KEY=your-key-here pemcp -- /path/to/PeMCP/run.sh --samples ~/malware-zoo --stdio
```

**Add a remote HTTP server:**

```bash
claude mcp add --transport http --scope project pemcp http://127.0.0.1:8082/mcp
```

**Verify the server was added:**

```bash
claude mcp list
```

**Remove the server:**

```bash
claude mcp remove pemcp
```

### Adding PeMCP via JSON Configuration

Alternatively, you can configure PeMCP by editing JSON files directly.

#### 1. Project-Level Configuration (Recommended)

Add a `.mcp.json` file to your project root (an example is included in this repository):

```json
{
  "mcpServers": {
    "pemcp": {
      "type": "stdio",
      "command": "python",
      "args": ["PeMCP.py", "--mcp-server"],
      "env": {
        "VT_API_KEY": ""
      }
    }
  }
}
```

Adjust the `command` path if PeMCP is installed elsewhere:

```json
{
  "mcpServers": {
    "pemcp": {
      "type": "stdio",
      "command": "python",
      "args": ["/path/to/PeMCP/PeMCP.py", "--mcp-server"],
      "env": {
        "VT_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

#### 2. User-Level Configuration

For system-wide availability across all projects, add PeMCP to `~/.claude.json`:

```json
{
  "mcpServers": {
    "pemcp": {
      "type": "stdio",
      "command": "python",
      "args": ["/absolute/path/to/PeMCP/PeMCP.py", "--mcp-server"]
    }
  }
}
```

#### 3. Docker Configuration (via `run.sh`)

To use the Docker image with Claude Code, point the configuration at the `run.sh` helper script. Use `--samples` to specify where your binaries live on the host — they will be mounted read-only at `/app/samples` inside the container:

```json
{
  "mcpServers": {
    "pemcp": {
      "type": "stdio",
      "command": "/path/to/PeMCP/run.sh",
      "args": ["--samples", "/path/to/your/samples", "--stdio"],
      "env": {
        "VT_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Then in Claude Code, load files using the container path:

```
open_file("/app/samples/malware.exe")
```

If `--samples` is omitted, the `./samples/` directory next to `run.sh` is mounted by default. You can also set the `PEMCP_SAMPLES` environment variable instead of using the flag.

The `run.sh` helper automatically detects Docker or Podman, builds the image on first run, and persists the analysis cache and configuration in a named `pemcp-data` volume.

### Typical Workflow

Once configured, you can interact with PeMCP through Claude Code naturally:

1. **"Open this sample for analysis"** — Claude calls `open_file` with the path (auto-detects PE/ELF/Mach-O)
2. **"What format is this?"** — Claude calls `detect_binary_format` to identify format and suggest tools
3. **"What does this binary do?"** — Claude retrieves the triage report, imports, capabilities
4. **"Decompile the main function"** — Claude uses Angr tools to decompile (works on PE, ELF, Mach-O)
5. **"Is this a .NET binary?"** — Claude calls `dotnet_analyze` for CLR metadata and CIL disassembly
6. **"Analyse this Go binary"** — Claude calls `go_analyze` for packages, functions, compiler version
7. **"Check if it's on VirusTotal"** — Claude queries the VT API
8. **"Close the file"** — Claude calls `close_file` to free resources

API keys can be set interactively: *"Set my VirusTotal API key to abc123"* — Claude calls `set_api_key`, and the key persists across sessions.

---

## Installation

### Option A: Docker (Recommended)

Docker handles all complex dependencies (Angr, Unicorn, Vivisect) automatically.

#### Quick Start with `run.sh`

The included `run.sh` helper auto-detects Docker or Podman and handles image building, volume mounts, and environment setup:

```bash
# Start HTTP MCP server (builds image if needed)
./run.sh

# Start stdio MCP server (for Claude Code)
./run.sh --stdio

# Mount a custom samples directory (read-only at /app/samples)
./run.sh --samples ~/malware-zoo --stdio

# Analyse a file in CLI mode
./run.sh --analyze samples/suspicious.exe

# Open a shell in the container
./run.sh --shell

# Build/rebuild the image
./run.sh --build
```

Set environment variables as needed:

```bash
VT_API_KEY=abc123 PEMCP_PORT=9000 ./run.sh
PEMCP_SAMPLES=~/malware-zoo ./run.sh --stdio
```

Or copy `.env.example` to `.env` and fill in your values — `run.sh` loads it automatically.

#### Docker Compose

For more control, use Docker Compose directly:

```bash
# Start HTTP MCP server
docker compose up pemcp-http

# Start stdio MCP server
docker compose run --rm -i pemcp-stdio

# Build only
docker compose build
```

The `docker-compose.yml` defines two services:
- **`pemcp-http`** — Network-accessible MCP server with healthcheck and restart policy
- **`pemcp-stdio`** — For Claude Code / MCP client integration (behind the `stdio` profile)

Both services use a named `pemcp-data` volume for persistent cache and configuration.

#### Manual Docker Commands

For most use cases, the `run.sh` helper is the recommended way to run PeMCP in Docker. It handles image building, volume mounts, environment variables, and runtime detection automatically:

```bash
# Build/rebuild the image
./run.sh --build

# Start HTTP MCP server (builds image if needed)
./run.sh

# Start stdio MCP server (for Claude Code)
./run.sh --stdio

# Analyse a file in CLI mode
./run.sh --analyze samples/suspicious.exe

# Open a shell in the container
./run.sh --shell
```

If you need to run Docker directly (e.g. for custom volume mounts or networking), the equivalent commands are:

```bash
# Build the image
docker build -t pemcp-toolkit .

# Run as MCP server (streamable-http)
docker run --rm -it \
  -p 8082:8082 \
  -v "$(pwd)/samples:/app/samples" \
  -v pemcp-data:/home/pemcp/.pemcp \
  -e VT_API_KEY="your_key" \
  pemcp-toolkit \
  --mcp-server \
  --mcp-transport streamable-http \
  --mcp-host 0.0.0.0

# Run as MCP server (stdio, for Claude Code)
docker run --rm -i \
  -v "$(pwd)/samples:/app/samples" \
  -v pemcp-data:/home/pemcp/.pemcp \
  pemcp-toolkit \
  --mcp-server
```

> **Note:** The `-v pemcp-data:/home/pemcp/.pemcp` mount persists the analysis cache and API key configuration across container restarts. Without it, cached results and stored keys are lost when the container is removed. The `run.sh` helper configures this volume automatically.

### Option B: Local Installation

Requires Python 3.10+ and cmake (for building Unicorn/Angr bindings).

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libssl-dev cmake

# Install Python packages
pip install -r requirements.txt
```

### Option C: Minimal Installation

For basic PE analysis without heavy dependencies:

```bash
pip install pefile networkx "mcp[cli]"
```

Optional packages can be added individually:
- `pip install cryptography signify` — Digital signature analysis
- `pip install yara-python` — YARA scanning
- `pip install requests` — VirusTotal integration
- `pip install rapidfuzz` — Fuzzy string search
- `pip install flare-capa` — Capability detection
- `pip install flare-floss vivisect` — Advanced string extraction
- `pip install flare-stringsifter joblib numpy` — ML-based string ranking
- `pip install "angr[unicorn]"` — Decompilation, CFG, symbolic execution
- `pip install lief` — Multi-format binary parsing (PE/ELF/Mach-O)
- `pip install capstone` — Multi-architecture disassembly
- `pip install keystone-engine` — Multi-architecture assembly
- `pip install speakeasy-emulator` — Windows API emulation
- `pip install ppdeep py-tlsh` — Fuzzy hashing (ssdeep/TLSH)
- `pip install dnfile dncil` — .NET assembly analysis
- `pip install pygore` — Go binary analysis
- `pip install rustbininfo rust-demangler` — Rust binary analysis
- `pip install pyelftools` — ELF/DWARF analysis
- `pip install binwalk` — Embedded file detection
- `pip install unipacker` — Automatic PE unpacking
- `pip install dotnetfile` — .NET PE metadata

---

## Modes of Operation

### CLI Mode (One-Shot Report)

Generates a comprehensive, human-readable report. Requires `--input-file`.

```bash
python PeMCP.py --input-file malware.exe --verbose > report.txt
```

### MCP Server Mode (Interactive)

Starts the MCP server. The `--input-file` is optional — files can be loaded dynamically using the `open_file` tool.

```bash
# Start without a file (recommended for Claude Code)
python PeMCP.py --mcp-server

# Start with a pre-loaded file
python PeMCP.py --mcp-server --input-file malware.exe

# Start with streamable-http transport (for network access)
python PeMCP.py --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 --mcp-port 8082
```

#### Transport Options

| Transport | Flag | Use Case |
|---|---|---|
| **stdio** (default) | `--mcp-transport stdio` | Claude Code, local MCP clients |
| **streamable-http** | `--mcp-transport streamable-http` | Network access, Docker, remote clients |
| **sse** (deprecated) | `--mcp-transport sse` | Legacy support only; use streamable-http instead |

---

## Configuration

### API Keys

PeMCP stores API keys persistently in `~/.pemcp/config.json` with restricted file permissions (owner-only). Environment variables always take priority over stored values.

**Setting keys via MCP tools:**
- Use the `set_api_key` tool: `set_api_key("vt_api_key", "your-key-here")`
- Use the `get_config` tool to view current configuration (keys are masked)

**Setting keys via environment variables:**
- `VT_API_KEY` — VirusTotal API key (overrides stored value)

**Setting keys via `.mcp.json`:**
```json
{
  "mcpServers": {
    "pemcp": {
      "type": "stdio",
      "command": "python",
      "args": ["PeMCP.py", "--mcp-server"],
      "env": {
        "VT_API_KEY": "your-key-here"
      }
    }
  }
}
```

### Analysis Cache

PeMCP caches analysis results to disk so that re-opening a previously analysed file is near-instant. Cache entries are stored as gzip-compressed JSON in `~/.pemcp/cache/`, keyed by the SHA256 hash of the file contents.

**How it works:**

1. When `open_file` is called, PeMCP computes the SHA256 of the file.
2. If a cached result exists for that hash, it is loaded directly (typically under 10 ms).
3. If no cache exists, the full analysis runs and the result is stored for future use.
4. Cache entries are automatically invalidated when the PeMCP version changes (parser updates).
5. LRU eviction removes the oldest entries when the cache exceeds its size limit.

**Cache configuration** (via `~/.pemcp/config.json` or environment variables):

| Setting | Environment Variable | Default | Description |
|---|---|---|---|
| `cache_enabled` | `PEMCP_CACHE_ENABLED` | `true` | Set to `"false"` to disable caching entirely |
| `cache_max_size_mb` | `PEMCP_CACHE_MAX_SIZE_MB` | `500` | Maximum total cache size in MB |

**Cache management MCP tools:**

| Tool | Description |
|---|---|
| `get_cache_stats` | View cache size, entry count, and per-file details |
| `clear_analysis_cache` | Remove all cached results |
| `remove_cached_analysis` | Remove a specific entry by SHA256 hash |

**Bypassing the cache:**

```
open_file("/path/to/binary", use_cache=False)  # Force fresh analysis
```

**Docker persistence:**

In Docker, the cache lives inside the container at `/home/pemcp/.pemcp/cache/`. The `run.sh` helper automatically mounts a named `pemcp-data` volume to persist the cache and configuration across container restarts:

```bash
# run.sh handles volume mounting automatically
./run.sh --stdio

# Equivalent manual docker command (if not using run.sh)
docker run --rm -i \
  -v pemcp-data:/home/pemcp/.pemcp \
  -v "$(pwd)/samples:/app/samples" \
  pemcp-toolkit --mcp-server
```

### Command-Line Options

| Option | Description |
|---|---|
| `--input-file PATH` | File to analyse (required for CLI, optional for MCP) |
| `--mode {auto,pe,elf,macho,shellcode}` | Analysis mode (default: auto, detects from magic bytes) |
| `--mcp-server` | Start in MCP server mode |
| `--mcp-transport {stdio,streamable-http,sse}` | Transport protocol (default: stdio) |
| `--mcp-host HOST` | Server host for HTTP transports (default: 127.0.0.1) |
| `--mcp-port PORT` | Server port for HTTP transports (default: 8082) |
| `--allowed-paths PATH [PATH ...]` | Restrict `open_file` to these directories (security sandbox for HTTP mode) |
| `--skip-capa` | Skip capa capability analysis |
| `--skip-floss` | Skip FLOSS string analysis |
| `--skip-peid` | Skip PEiD signature scanning |
| `--skip-yara` | Skip YARA scanning |
| `-v, --verbose` | Enable verbose output |

---

## MCP Tools Reference

PeMCP exposes **104 tools** organised into the following categories.

### File Management

| Tool | Description |
|---|---|
| `open_file` | Load and analyse a binary (PE/ELF/Mach-O/shellcode). Auto-detects format. For PE files, returns `quick_indicators` (hashes, entropy, packing likelihood, import count, signature status, capa severity count). |
| `close_file` | Close the loaded file and clear analysis data from memory. |
| `reanalyze_loaded_pe_file` | Re-run PE analysis with different options (skip/enable specific analyses). |
| `detect_binary_format` | Auto-detect binary format and suggest appropriate analysis tools. |

### Configuration & Utilities

| Tool | Description |
|---|---|
| `set_api_key` | Store an API key persistently in `~/.pemcp/config.json`. |
| `get_config` | View current configuration, available libraries, and loaded file status. |
| `get_current_datetime` | Retrieve current UTC and local date/time. |
| `check_task_status` | Monitor progress of background tasks (e.g., Angr CFG generation). |
| `get_extended_capabilities` | List all available tools and library versions. |
| `get_cache_stats` | View analysis cache statistics (entries, size, utilization). |
| `clear_analysis_cache` | Clear the entire disk-based analysis cache. |
| `remove_cached_analysis` | Remove a specific cached analysis by SHA256 hash. |

### PE Structure Analysis (5 tools)

| Tool | Description |
|---|---|
| `get_analyzed_file_summary` | High-level summary with counts of sections, imports, matches. |
| `get_full_analysis_results` | Complete analysis data (all keys, with size guard). |
| `get_pe_data` | **Unified data retrieval** — retrieve any PE analysis key by name (e.g., `get_pe_data(key='imports')`). Use `key='list'` to discover all 25 available keys with descriptions and sizes. Supports `limit` and `offset` for pagination. Replaces 25 individual `get_*_info` tools. |

Available `get_pe_data` keys: `file_hashes`, `dos_header`, `nt_headers`, `data_directories`, `sections`, `imports`, `exports`, `resources_summary`, `version_info`, `debug_info`, `digital_signature`, `peid_matches`, `yara_matches`, `rich_header`, `delay_load_imports`, `tls_info`, `load_config`, `com_descriptor`, `overlay_data`, `base_relocations`, `bound_imports`, `exception_data`, `coff_symbols`, `checksum_verification`, `pefile_warnings`.

### PE Extended Analysis (14 tools)

| Tool | Description |
|---|---|
| `get_section_permissions` | Human-readable section permission matrix (RWX). |
| `get_pe_metadata` | Compilation timestamps, linker info, subsystem, DLL characteristics. |
| `extract_resources` | Extract and decode PE resources by type. |
| `extract_manifest` | Extract and parse embedded application manifest XML. |
| `get_load_config_details` | Extended load config (SEH, CFG, RFG, CET details). |
| `extract_wide_strings` | Extract UTF-16LE wide strings from the binary. |
| `detect_format_strings` | Detect printf/scanf format strings (format string vuln hunting). |
| `detect_compression_headers` | Detect embedded compressed data (zlib, gzip, LZMA, etc.). |
| `deobfuscate_xor_multi_byte` | Multi-byte XOR deobfuscation with known key. |
| `bruteforce_xor_key` | Brute-force single and multi-byte XOR keys against known plaintext. |
| `detect_crypto_constants` | Detect crypto constants (AES S-box, DES, SHA, RC4, etc.). |
| `analyze_entropy_by_offset` | Sliding-window entropy analysis to detect packed/encrypted regions. |
| `scan_for_api_hashes` | Detect API hashing patterns (ROR13, CRC32, DJB2, FNV). |
| `get_import_hash_analysis` | Import hash (imphash) with per-DLL analysis and anomaly detection. |

### Signature & Capability Analysis

| Tool | Description |
|---|---|
| `get_capa_analysis_info` | Capa capability rules overview with filtering. |
| `get_capa_rule_match_details` | Detailed match info for a specific Capa rule. |

> **Note:** PEiD matches and YARA matches are now accessed via `get_pe_data(key='peid_matches')` and `get_pe_data(key='yara_matches')`.

### String Analysis (10 tools)

| Tool | Description |
|---|---|
| `get_floss_analysis_info` | FLOSS results (static, stack, tight, decoded strings). |
| `extract_strings_from_binary` | Extract printable ASCII strings, optionally ranked. |
| `search_for_specific_strings` | Search for specific strings within the binary. |
| `search_floss_strings` | Regex search across FLOSS strings with score filtering. |
| `get_top_sifted_strings` | ML-ranked strings from all sources with granular filtering. |
| `get_strings_for_function` | All strings referenced by a specific function. |
| `get_string_usage_context` | Disassembly context showing where a string is used. |
| `fuzzy_search_strings` | Fuzzy matching to find similar strings. |
| `find_and_decode_encoded_strings` | Multi-layer Base64/Hex/XOR decoding with heuristics. |
| `search_binary_content` | Search for byte patterns, regex, or strings across the raw binary. |

### Triage & Forensics

| Tool | Description |
|---|---|
| `get_triage_report` | **Comprehensive automated triage** (25+ dimensions) — packing assessment, digital signatures, timestamp anomalies, Rich header fingerprint, suspicious imports & delay-load evasion, capa capabilities, network IOCs, section anomalies, overlay/appended data analysis, resource anomalies (nested PE detection), YARA matches, header corruption detection, TLS callback detection, security mitigations (ASLR/DEP/CFG/CET/XFG), version info spoofing, .NET indicators, export anomalies, high-value strings, ELF security features (PIE/NX/RELRO/canaries), Mach-O security (code signing/PIE), cumulative risk score, and format-aware tool suggestions. |
| `classify_binary_purpose` | Classify binary type (GUI app, console app, DLL, service, driver, installer, .NET assembly) from headers, imports, and resources. |
| `get_virustotal_report_for_loaded_file` | Query VirusTotal for the file hash. |

### Deobfuscation & Utilities

| Tool | Description |
|---|---|
| `deobfuscate_base64` | Decode hex-encoded Base64 data. |
| `deobfuscate_xor_single_byte` | XOR-decrypt hex data with a single byte key. |
| `is_mostly_printable_ascii` | Check if a string is mostly printable. |
| `get_hex_dump` | Hex dump of a file region. |

### Binary Analysis — Core Angr (15 tools)

| Tool | Description |
|---|---|
| `list_angr_analyses` | **Discovery tool** — lists all available angr analysis capabilities grouped by category (decompilation, CFG, symbolic, slicing, forensic, hooks, modification) with parameter descriptions. Call this first to understand available analyses. |
| `decompile_function_with_angr` | C-like pseudocode for a function at a given address. |
| `get_function_cfg` | Control flow graph (nodes and edges) for a function. |
| `find_path_to_address` | Symbolic execution to find inputs reaching a target address. |
| `emulate_function_execution` | Emulate a function with concrete arguments. |
| `analyze_binary_loops` | Detect and characterise loops in the binary. |
| `get_function_xrefs` | Cross-references (callers and callees) for a function. |
| `get_backward_slice` | All code blocks that can reach a target address. |
| `get_forward_slice` | All code reachable from a source address. |
| `get_dominators` | Dominator blocks that must execute to reach a target. |
| `get_function_complexity_list` | Functions ranked by complexity (block/edge count). |
| `extract_function_constants` | Hardcoded constants and string references in a function. |
| `get_global_data_refs` | Global memory addresses read/written by a function. |
| `scan_for_indirect_jumps` | Indirect jumps/calls (dynamic control flow) in a function. |
| `patch_binary_memory` | Patch the loaded binary in memory with new bytes. |

### Binary Analysis — Extended Angr (22 tools)

| Tool | Description |
|---|---|
| `get_reaching_definitions` | Track how values propagate through registers and memory. |
| `get_data_dependencies` | Data dependency graph for a function. |
| `hook_function` | Replace a function with a custom SimProcedure. |
| `list_hooks` | List all active function hooks. |
| `unhook_function` | Remove a previously set hook. |
| `get_calling_conventions` | Detect calling conventions for functions. |
| `get_function_variables` | Recover local variables and parameters. |
| `disassemble_at_address` | Disassemble N instructions at a given address. |
| `identify_library_functions` | Identify standard library functions (libc, etc.). |
| `get_control_dependencies` | Control dependency analysis for a function. |
| `propagate_constants` | Constant propagation analysis. |
| `diff_binaries` | Compare two binaries for added/removed/modified functions. |
| `detect_self_modifying_code` | Detect code that writes to executable memory. |
| `find_code_caves` | Find unused executable space for patching. |
| `get_call_graph` | Generate full or filtered inter-procedural call graph. |
| `find_path_with_custom_input` | Symbolic execution with custom constraints. |
| `emulate_with_watchpoints` | Emulate with memory/register watchpoints. |
| `get_annotated_disassembly` | Rich disassembly with resolved names and comments. |
| `get_value_set_analysis` | Determine possible values at program points. |
| `detect_packing` | Heuristic packing/encryption detection. |
| `save_patched_binary` | Save a patched binary to disk. |
| `identify_cpp_classes` | Recover C++ vtables and class hierarchies. |

### Extended Library Tools (13 tools)

| Tool | Description |
|---|---|
| `parse_binary_with_lief` | Multi-format binary parsing with LIEF (PE/ELF/Mach-O). |
| `modify_pe_section` | Modify PE section properties (name, characteristics). |
| `disassemble_raw_bytes` | Disassemble raw bytes with Capstone (any architecture). |
| `assemble_instruction` | Assemble mnemonics to bytes with Keystone. |
| `patch_with_assembly` | Assemble and patch instructions into the binary. |
| `compute_similarity_hashes` | Compute ssdeep and TLSH fuzzy hashes. |
| `compare_file_similarity` | Compare two files using fuzzy hash similarity. |
| `emulate_pe_with_windows_apis` | Full Windows API emulation with Speakeasy. |
| `emulate_shellcode_with_speakeasy` | Emulate shellcode with Windows API hooks. |
| `auto_unpack_pe` | Automatically unpack packed PEs (UPX, ASPack, FSG, etc.). |
| `parse_dotnet_metadata` | Parse .NET metadata with dotnetfile. |
| `scan_for_embedded_files` | Detect embedded files/firmware with Binwalk. |
| `get_extended_capabilities` | List all available tools and library versions. |

### Multi-Format Binary Analysis (9 tools)

| Tool | Description |
|---|---|
| `detect_binary_format` | Auto-detect format (PE/.NET/ELF/Mach-O/Go/Rust) from magic bytes. |
| `dotnet_analyze` | Comprehensive .NET metadata: CLR header, types, methods, assembly refs, user strings. |
| `dotnet_disassemble_method` | Disassemble .NET CIL bytecode to human-readable opcodes. |
| `go_analyze` | Go binary analysis: compiler version, packages, functions (works on stripped binaries). |
| `rust_analyze` | Rust binary metadata: compiler version, crate dependencies, toolchain. |
| `rust_demangle_symbols` | Demangle Rust symbol names to human-readable form. |
| `elf_analyze` | Comprehensive ELF analysis: headers, sections, segments, symbols, dynamic deps. |
| `elf_dwarf_info` | Extract DWARF debug info: compilation units, functions, source files. |
| `macho_analyze` | Mach-O analysis: headers, load commands, segments, symbols, dylibs, code signatures. |

---

## Architecture & Design

### Package Structure

```
PeMCP.py                        # Entry point (thin wrapper)
pemcp/
├── __init__.py                 # Package metadata
├── __main__.py                 # python -m pemcp support
├── state.py                    # Thread-safe AnalyzerState
├── config.py                   # Imports, availability flags, constants
├── cache.py                    # Disk-based analysis cache (gzip/LRU)
├── user_config.py              # Persistent API key storage (~/.pemcp/)
├── utils.py                    # Utility functions
├── hashing.py                  # ssdeep implementation
├── mock.py                     # MockPE for non-PE/shellcode mode
├── background.py               # Background task management
├── resources.py                # PEiD/capa rule downloads
├── parsers/
│   ├── pe.py                   # PE structure parsing
│   ├── capa.py                 # Capa integration
│   ├── floss.py                # FLOSS integration
│   ├── signatures.py           # PEiD/YARA scanning
│   └── strings.py              # String utilities
├── cli/
│   └── printers.py             # CLI output formatting
└── mcp/
    ├── __init__.py
    ├── server.py                — MCP server setup & validation helpers
    ├── _angr_helpers.py         — Shared angr utilities (project/CFG init, address resolution)
    ├── _format_helpers.py       — Shared binary format helpers
    ├── tools_pe.py              — File management & PE data retrieval
    ├── tools_pe_extended.py     — Extended PE analysis (resources, manifests)
    ├── tools_strings.py         — String analysis & fuzzy search
    ├── tools_angr.py            — Core angr tools (decompile, CFG, symbolic exec)
    ├── tools_angr_disasm.py     — Angr disassembly & function recovery
    ├── tools_angr_dataflow.py   — Angr data flow analysis
    ├── tools_angr_hooks.py      — Angr function hooking
    ├── tools_angr_forensic.py   — Angr forensic & advanced analysis
    ├── tools_new_libs.py        — LIEF/Capstone/Keystone/Speakeasy
    ├── tools_dotnet.py          — .NET analysis (dnfile/dncil)
    ├── tools_go.py              — Go binary analysis (pygore)
    ├── tools_rust.py            — Rust binary analysis
    ├── tools_elf.py             — ELF analysis (pyelftools)
    ├── tools_macho.py           — Mach-O analysis (LIEF)
    ├── tools_format_detect.py   — Auto binary format detection
    ├── tools_virustotal.py      — VirusTotal API integration
    ├── tools_deobfuscation.py   — Hex dump & deobfuscation tools
    ├── tools_triage.py          — Comprehensive triage report
    ├── tools_cache.py           — Analysis cache management
    ├── tools_config.py          — Configuration & utility tools
    └── tools_classification.py  — Binary purpose classification
```

### Design Principles

- **Single-File Analysis Context** — The server holds one file in memory via `AnalyzerState`. All tools operate on this shared context. Use `open_file` and `close_file` to switch between files.
- **Disk-Based Caching** — Analysis results are cached in `~/.pemcp/cache/` as gzip-compressed JSON, keyed by SHA256. Re-opening a previously analysed file loads from cache in under 10 ms. LRU eviction keeps cache size bounded.
- **Lazy Loading** — Heavy analysis (Angr CFG) runs in the background. The server is usable immediately.
- **Smart Truncation** — MCP responses exceeding 64KB are intelligently truncated (lists shortened, strings clipped) whilst preserving structure.
- **Graceful Degradation** — Optional libraries (Angr, Capa, FLOSS, etc.) are detected at startup. Tools that require unavailable libraries return clear error messages instead of crashing.

---

## Multi-Format Analysis

### Auto-Detection (Recommended)

PeMCP automatically detects the binary format from magic bytes:

```
open_file("/path/to/binary")  # Auto-detects PE, ELF, or Mach-O
```

### ELF Binaries (Linux)

```bash
# CLI mode
python PeMCP.py --input-file binary.elf --mode elf

# MCP mode — use elf_analyze, elf_dwarf_info, plus all angr tools
open_file("/path/to/binary", mode="elf")
```

### Mach-O Binaries (macOS)

```bash
# CLI mode
python PeMCP.py --input-file binary.macho --mode macho

# MCP mode — use macho_analyze, plus all angr tools
open_file("/path/to/binary", mode="macho")
```

### .NET, Go, and Rust Binaries

These format-specific tools work on any loaded binary:

```
dotnet_analyze("/path/to/assembly.exe")     # .NET CLR metadata
go_analyze("/path/to/go-binary")            # Go packages and functions
rust_analyze("/path/to/rust-binary")        # Rust crate dependencies
```

### Shellcode Analysis

PeMCP supports raw shellcode analysis:

```bash
# CLI mode
python PeMCP.py --input-file shellcode.bin --mode shellcode

# MCP server mode with architecture hint
python PeMCP.py --mcp-server --input-file shellcode.bin --mode shellcode --floss-format sc64
```

In MCP mode, you can also open shellcode dynamically:

```
open_file("/path/to/shellcode.bin", mode="shellcode")
```

Use `--floss-format sc64` (64-bit) or `--floss-format sc32` (32-bit) to provide architecture hints to FLOSS and Angr.

---

## Security

### Path Sandboxing

When running PeMCP in HTTP mode (`--mcp-transport streamable-http`), any MCP client can call `open_file` to read files on the server. Use `--allowed-paths` to restrict access:

```bash
# Only allow access to /app/samples and /tmp
python PeMCP.py --mcp-server --mcp-transport streamable-http \
  --allowed-paths /app/samples /tmp

# Docker with sandboxing (via run.sh — extra flags are passed through)
./run.sh --allowed-paths /app/samples

# Equivalent manual docker command
docker run --rm -it -p 8082:8082 \
  -v "$(pwd)/samples:/app/samples" \
  pemcp-toolkit \
  --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 \
  --allowed-paths /app/samples
```

If `--allowed-paths` is not set in HTTP mode, PeMCP logs a warning at startup.

### Other Security Measures

- **Non-root Docker**: The container runs as `pemcp` (uid 1000), not root.
- **API key storage**: Keys are stored in `~/.pemcp/config.json` with 0o600 (owner-only) permissions.
- **Zip-slip protection**: Archive extraction validates member paths against directory traversal.
- **No hardcoded secrets**: API keys are sourced from environment variables or the config file.

### Testing

Install test dependencies and run the integration test suite:

```bash
pip install -r requirements-test.txt

# Start the server in one terminal
python PeMCP.py --mcp-server --mcp-transport streamable-http

# Run tests in another terminal
pytest mcp_test_client.py -v
```

---

## Contributing

Contributions are welcome!

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-enhancement`).
3. Commit your changes.
4. Push to the branch.
5. Open a Pull Request.

---

## Licence

Distributed under the MIT Licence. See `LICENSE` for more information.

---

## Disclaimer

This toolkit is provided "as-is" for educational and research purposes only. It is capable of executing parts of analysed binaries (via Angr emulation and symbolic execution) in a sandboxed environment. Always exercise caution when analysing untrusted files. The authors accept no responsibility for misuse or damages arising from the use of this software.
