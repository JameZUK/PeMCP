# PeMCP — Advanced PE Analysis & MCP Server

PeMCP is a professional-grade Python toolkit for in-depth static and dynamic analysis of Portable Executable (PE) files and raw shellcode. It operates as both a powerful CLI tool for generating comprehensive reports and as a **Model Context Protocol (MCP) server**, providing AI assistants and other MCP clients with **60+ specialised tools** to interactively explore, decompile, and analyse binaries.

PeMCP bridges the gap between high-level AI reasoning and low-level binary instrumentation, turning any MCP-compatible client into a capable malware analyst.

---

## Table of Contents

- [Key Features](#key-features)
- [Quick Start with Claude Code](#quick-start-with-claude-code)
- [Installation](#installation)
- [Modes of Operation](#modes-of-operation)
- [Configuration](#configuration)
- [MCP Tools Reference](#mcp-tools-reference)
- [Architecture & Design](#architecture--design)
- [Shellcode Analysis](#shellcode-analysis)
- [Contributing](#contributing)
- [Licence](#licence)
- [Disclaimer](#disclaimer)

---

## Key Features

### Advanced Binary Analysis (Powered by Angr)

Beyond standard static analysis, PeMCP integrates the **Angr** binary analysis framework:

- **Decompilation** — Convert assembly into human-readable C-like pseudocode on the fly.
- **Control Flow Graph (CFG)** — Generate and traverse function blocks and edges.
- **Symbolic Execution** — Automatically find inputs to reach specific code paths.
- **Emulation** — Execute functions with concrete arguments using the Unicorn engine.
- **Slicing & Dominators** — Perform forward/backward slicing to track data flow and identify critical code dependencies.

### Comprehensive Static Analysis

- **PE Structure** — Full parsing of DOS/NT Headers, Imports/Exports, Resources, TLS, Debug, Load Config, Rich Header, Overlay, and more.
- **Signatures** — Authenticode validation (Signify), certificate parsing (Cryptography), packer detection (PEiD), and YARA scanning.
- **Capabilities** — Integrated Capa analysis to map binary behaviours to the MITRE ATT&CK framework.
- **Strings** — FLOSS integration for extracting static, stack, tight, and decoded strings, ranked by relevance using StringSifter.

### Dynamic File Loading & API Key Management

- **No Pre-loading Required** — The MCP server starts without needing a file path. Use the `open_file` tool to load files dynamically.
- **Persistent Configuration** — API keys are stored securely in `~/.pemcp/config.json` and recalled automatically across sessions.
- **Progress Reporting** — File loading and analysis report progress to the MCP client in real time.

### Robust Architecture

- **Modular Package** — Clean `pemcp/` package structure with separated concerns (parsers, MCP tools, CLI, configuration).
- **Docker-First Design** — No interactive prompts. Dependencies are managed via Docker, making it container and CI/CD ready.
- **Thread-Safe State** — Centralised `AnalyzerState` class with locking for concurrent access.
- **Background Tasks** — Long-running operations (symbolic execution, Angr CFG) run asynchronously with heartbeat monitoring.
- **Smart Truncation** — MCP responses are automatically truncated to fit within 64KB limits whilst preserving structural integrity.

---

## Quick Start with Claude Code

PeMCP integrates seamlessly with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) via stdio transport.

### 1. Project-Level Configuration (Recommended)

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

### 2. User-Level Configuration

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

### 3. Docker Configuration

To use the Docker image with Claude Code:

```json
{
  "mcpServers": {
    "pemcp": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/path/to/samples:/app/samples",
        "-e", "VT_API_KEY",
        "pemcp-toolkit",
        "--mcp-server"
      ],
      "env": {
        "VT_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Typical Workflow

Once configured, you can interact with PeMCP through Claude Code naturally:

1. **"Open this sample for analysis"** — Claude calls `open_file` with the path
2. **"What does this binary do?"** — Claude retrieves the triage report, imports, capabilities
3. **"Decompile the main function"** — Claude uses Angr tools to decompile
4. **"Check if it's on VirusTotal"** — Claude queries the VT API
5. **"Close the file"** — Claude calls `close_file` to free resources

API keys can be set interactively: *"Set my VirusTotal API key to abc123"* — Claude calls `set_api_key`, and the key persists across sessions.

---

## Installation

### Option A: Docker (Recommended)

Docker handles all complex dependencies (Angr, Unicorn, Vivisect) automatically.

```bash
# Build the image
docker build -t pemcp-toolkit .

# Run as MCP server (streamable-http)
docker run --rm -it \
  -p 8082:8082 \
  -v "$(pwd)/samples:/app/samples" \
  -e VT_API_KEY="your_key" \
  pemcp-toolkit \
  --mcp-server \
  --mcp-transport streamable-http \
  --mcp-host 0.0.0.0

# Run as MCP server (stdio, for Claude Code)
docker run --rm -i \
  -v "$(pwd)/samples:/app/samples" \
  pemcp-toolkit \
  --mcp-server
```

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
- `pip install flare-stringsifter` — ML-based string ranking
- `pip install "angr[unicorn]"` — Decompilation, CFG, symbolic execution

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

### Command-Line Options

| Option | Description |
|---|---|
| `--input-file PATH` | File to analyse (required for CLI, optional for MCP) |
| `--mode {pe,shellcode}` | Analysis mode (default: pe) |
| `--mcp-server` | Start in MCP server mode |
| `--mcp-transport {stdio,streamable-http,sse}` | Transport protocol (default: stdio) |
| `--mcp-host HOST` | Server host for HTTP transports (default: 127.0.0.1) |
| `--mcp-port PORT` | Server port for HTTP transports (default: 8082) |
| `--skip-capa` | Skip capa capability analysis |
| `--skip-floss` | Skip FLOSS string analysis |
| `--skip-peid` | Skip PEiD signature scanning |
| `--skip-yara` | Skip YARA scanning |
| `-v, --verbose` | Enable verbose output |

---

## MCP Tools Reference

PeMCP exposes 60+ tools organised into the following categories.

### File Management

| Tool | Description |
|---|---|
| `open_file` | Load and analyse a PE file or shellcode. Reports progress during analysis. |
| `close_file` | Close the loaded file and clear analysis data from memory. |
| `reanalyze_loaded_pe_file` | Re-run analysis with different options (skip/enable specific analyses). |

### Configuration & Utilities

| Tool | Description |
|---|---|
| `set_api_key` | Store an API key persistently in `~/.pemcp/config.json`. |
| `get_config` | View current configuration, available libraries, and loaded file status. |
| `get_current_datetime` | Retrieve current UTC and local date/time. |
| `check_task_status` | Monitor progress of background tasks (e.g., Angr CFG generation). |

### PE Structure Analysis

| Tool | Description |
|---|---|
| `get_analyzed_file_summary` | High-level summary with counts of sections, imports, matches. |
| `get_full_analysis_results` | Complete analysis data (all keys, with size guard). |
| `get_file_hashes_info` | MD5, SHA1, SHA256, ssdeep hashes. |
| `get_dos_header_info` | DOS header structure. |
| `get_nt_headers_info` | NT headers (File Header + Optional Header). |
| `get_data_directories_info` | Data directory entries (import, export, resource tables). |
| `get_sections_info` | Section details (entropy, hashes, characteristics). |
| `get_imports_info` | Imported DLLs and symbols. |
| `get_exports_info` | Exported symbols. |
| `get_resources_summary_info` | Resource entries (type, language, size). |
| `get_version_info_info` | Version resource data (FileVersion, ProductName). |
| `get_debug_info_info` | Debug directory (PDB paths, CodeView). |
| `get_digital_signature_info` | Authenticode signature, certificate details, validation. |
| `get_rich_header_info` | Rich header (compiler/linker versions). |
| `get_delay_load_imports_info` | Delay-loaded imports. |
| `get_tls_info_info` | TLS directory and callbacks. |
| `get_load_config_info` | Load configuration (CFG, Guard Flags). |
| `get_com_descriptor_info` | .NET COM descriptor. |
| `get_overlay_data_info` | Overlay data (offset, size, hashes). |
| `get_base_relocations_info` | Base relocation entries. |
| `get_bound_imports_info` | Bound import descriptors. |
| `get_exception_data_info` | Exception directory (RUNTIME_FUNCTION for x64). |
| `get_coff_symbols_info` | COFF symbol table entries. |
| `get_checksum_verification_info` | PE checksum verification. |
| `get_pefile_warnings_info` | Warnings from the pefile parser. |

### Signature & Capability Analysis

| Tool | Description |
|---|---|
| `get_peid_matches_info` | PEiD packer/compiler detection results. |
| `get_yara_matches_info` | YARA rule match results. |
| `get_capa_analysis_info` | Capa capability rules overview with filtering. |
| `get_capa_rule_match_details` | Detailed match info for a specific Capa rule. |

### String Analysis

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

### Triage & Forensics

| Tool | Description |
|---|---|
| `get_triage_report` | Automated summary of suspicious indicators, imports, and capabilities. |
| `get_virustotal_report_for_loaded_file` | Query VirusTotal for the file hash. |

### Deobfuscation

| Tool | Description |
|---|---|
| `deobfuscate_base64` | Decode hex-encoded Base64 data. |
| `deobfuscate_xor_single_byte` | XOR-decrypt hex data with a single byte key. |
| `is_mostly_printable_ascii` | Check if a string is mostly printable. |
| `get_hex_dump` | Hex dump of a file region. |

### Binary Analysis (Angr)

| Tool | Description |
|---|---|
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

---

## Architecture & Design

### Package Structure

```
PeMCP.py                    # Entry point (thin wrapper)
pemcp/
├── __init__.py             # Package metadata
├── __main__.py             # python -m pemcp support
├── state.py                # Thread-safe AnalyzerState
├── config.py               # Imports, availability flags, constants
├── user_config.py          # Persistent API key storage (~/.pemcp/)
├── utils.py                # Utility functions
├── hashing.py              # ssdeep implementation
├── mock.py                 # MockPE for shellcode mode
├── background.py           # Background task management
├── resources.py            # PEiD/capa rule downloads
├── parsers/
│   ├── pe.py               # PE structure parsing
│   ├── capa.py             # Capa integration
│   ├── floss.py            # FLOSS integration
│   ├── signatures.py       # PEiD/YARA scanning
│   └── strings.py          # String utilities
├── cli/
│   └── printers.py         # CLI output formatting
└── mcp/
    ├── server.py           # MCP server setup & helpers
    ├── tools_pe.py         # File management & PE data tools
    ├── tools_strings.py    # String analysis tools
    ├── tools_angr.py       # Binary analysis tools
    └── tools_misc.py       # VT, deobfuscation, triage, config tools
```

### Design Principles

- **Single-File Analysis Context** — The server holds one file in memory via `AnalyzerState`. All tools operate on this shared context. Use `open_file` and `close_file` to switch between files.
- **Lazy Loading** — Heavy analysis (Angr CFG) runs in the background. The server is usable immediately.
- **Smart Truncation** — MCP responses exceeding 64KB are intelligently truncated (lists shortened, strings clipped) whilst preserving structure.
- **Graceful Degradation** — Optional libraries (Angr, Capa, FLOSS, etc.) are detected at startup. Tools that require unavailable libraries return clear error messages instead of crashing.

---

## Shellcode Analysis

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
