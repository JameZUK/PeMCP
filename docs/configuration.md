# Configuration

Arkana's configuration covers API keys, the analysis cache, and command-line options. Settings persist in `~/.arkana/config.json` across sessions.

---

## API Keys

Arkana stores API keys persistently in `~/.arkana/config.json` with restricted file permissions (owner-only). Environment variables always take priority over stored values.

**Setting keys via MCP tools:**
- Use the `set_api_key` tool: `set_api_key("vt_api_key", "your-key-here")`
- Use the `get_config` tool to view current configuration (keys are masked)

**Setting keys via environment variables:**
- `VT_API_KEY` — VirusTotal API key (overrides stored value)

**Setting keys via `.mcp.json`:**
```json
{
  "mcpServers": {
    "arkana": {
      "type": "stdio",
      "command": "python",
      "args": ["arkana.py", "--mcp-server"],
      "env": {
        "VT_API_KEY": "your-key-here"
      }
    }
  }
}
```

---

## Analysis Cache

Arkana caches analysis results to disk so that re-opening a previously analysed file is near-instant. Cache entries are stored as gzip-compressed JSON in `~/.arkana/cache/`, keyed by the SHA256 hash of the file contents.

**How it works:**

1. When `open_file` is called, Arkana computes the SHA256 of the file.
2. If a cached result exists for that hash, it is loaded directly (typically under 10 ms).
3. If no cache exists, the full analysis runs and the result is stored for future use.
4. Cache entries are automatically invalidated when the Arkana version changes (parser updates).
5. LRU eviction removes the oldest entries when the cache exceeds its size limit.

**Cache configuration** (via `~/.arkana/config.json` or environment variables):

| Setting | Environment Variable | Default | Description |
|---|---|---|---|
| `cache_enabled` | `ARKANA_CACHE_ENABLED` | `true` | Set to `"false"` to disable caching entirely |
| `cache_max_size_mb` | `ARKANA_CACHE_MAX_SIZE_MB` | `500` | Maximum total cache size in MB |

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

In Docker, the cache lives at `/app/home/.arkana/cache/` inside the container, which is bind-mounted to `~/.arkana` on the host. The `run.sh` helper sets this up automatically (creating the directory if needed):

```bash
# run.sh handles the bind mount automatically
./run.sh --stdio

# Override cache location
./run.sh --cache /path/to/cache --stdio

# Equivalent manual docker command (if not using run.sh)
docker run --rm -i \
  --user "$(id -u):$(id -g)" \
  -e HOME=/app/home \
  -v "$HOME/.arkana:/app/home/.arkana:rw" \
  -v "$(pwd)/samples:/samples:ro" \
  arkana-toolkit --mcp-server --samples-path /samples
```

---

## Command-Line Options

| Option | Description |
|---|---|
| `--input-file PATH` | File to analyse (required for CLI, optional for MCP) |
| `--mode {auto,pe,elf,macho,shellcode}` | Analysis mode (default: auto, detects from magic bytes) |
| `--mcp-server` | Start in MCP server mode |
| `--mcp-transport {stdio,streamable-http,sse}` | Transport protocol (default: stdio) |
| `--mcp-host HOST` | Server host for HTTP transports (default: 127.0.0.1) |
| `--mcp-port PORT` | Server port for HTTP transports (default: 8082) |
| `--allowed-paths PATH [PATH ...]` | Restrict `open_file` to these directories (security sandbox for HTTP mode) |
| `--samples-path PATH` | Path to the samples directory. Enables the `list_samples` tool for AI clients to discover available files. Falls back to the `ARKANA_SAMPLES` environment variable if not set. |
| `--skip-capa` | Skip capa capability analysis |
| `--skip-floss` | Skip FLOSS string analysis |
| `--skip-peid` | Skip PEiD signature scanning |
| `-y, --yara-rules PATH` | Custom YARA rule file or directory. If not provided, uses bundled rules from ReversingLabs (MIT) and Yara-Rules Community (GPL-2.0), downloading them on first run |
| `--skip-yara` | Skip YARA scanning |
| `--floss-format {sc32,sc64}` | Shellcode architecture hint for FLOSS and Angr (32-bit or 64-bit) |
| `-v, --verbose` | Enable verbose output |
