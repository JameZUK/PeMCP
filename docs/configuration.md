# Configuration

Arkana's configuration covers API keys, the analysis cache, and command-line options. Settings persist in `~/.arkana/config.json` across sessions.

---

## API Keys

Arkana stores API keys persistently in `~/.arkana/config.json` with restricted file permissions (owner-only). Environment variables always take priority over stored values.

**Setting keys via MCP tools:**
- Use the `set_api_key` tool: `set_api_key("vt_api_key", "your-key-here")`
- Use the `get_config` tool to view current configuration (keys are masked)

**Setting keys via environment variables:**
- `VT_API_KEY`  - VirusTotal API key (overrides stored value)

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
| `cache_max_size_mb` | `ARKANA_CACHE_MAX_SIZE_MB` | `500` | Maximum total cache size in MB (clamped to 1–50,000 MB) |

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

## Environment Variables

Beyond the cache and API key settings above, Arkana supports several environment variables for tuning server behaviour:

### Response Limits

| Variable | Default | Description |
|---|---|---|
| `ARKANA_MCP_RESPONSE_LIMIT_CHARS` | `8000` | Soft character limit for MCP responses. The default 8K is tuned for Claude Code CLI compatibility. Set to `65536` to restore 64KB-only behaviour for non-Claude-Code clients. |

### Background Tasks

| Variable | Default | Description |
|---|---|---|
| `ARKANA_BACKGROUND_TASK_TIMEOUT` | `1800` | Hard timeout (seconds) for background tasks. Used as fallback when soft timeout is disabled (set to 0). |
| `ARKANA_BSIM_BACKGROUND_TIMEOUT` | `1800` | Separate timeout (seconds) for BSim function similarity background tasks (`find_similar_functions`, `build_function_signature_db`, `triage_binary_similarity`, `seed_signature_db`). |
| `ARKANA_BSIM_AUTO_INDEX` | `1` | When set to `1` (default), automatically indexes every opened binary into the BSim signature DB during enrichment. Set to `0` to disable. The DB grows organically as you work — each analyzed sample becomes available for variant detection via `triage_binary_similarity`. |
| `ARKANA_ANGR_CFG_SOFT_TIMEOUT` | `900` | Soft timeout (15 min) for CFG build. After this, the task enters OVERTIME status but keeps running. Set to `0` to disable progress-adaptive timeout and use hard timeout instead. |
| `ARKANA_BACKGROUND_TASK_SOFT_TIMEOUT` | `300` | Soft timeout (5 min) for generic background tasks. Set to `0` to fall back to hard timeout. |
| `ARKANA_OVERTIME_CHECK_INTERVAL` | `60` | How often (seconds) to check progress during overtime. |
| `ARKANA_OVERTIME_STALL_KILL` | `300` | Kill the task after this many seconds (5 min) of zero progress during overtime. |
| `ARKANA_OVERTIME_MAX_RUNTIME` | `21600` | Absolute ceiling (6 hours) — tasks are killed regardless of progress after this. |
| `ARKANA_PE_ANALYSIS_SOFT_TIMEOUT` | `300` | Soft timeout (5 min) for PE analysis in `open_file`. After this, the task enters OVERTIME status but keeps running if making progress. Set to `0` to disable and use hard timeout instead. |
| `ARKANA_PE_ANALYSIS_MAX_RUNTIME` | `3600` | Absolute ceiling (1 hour) for PE analysis — killed regardless of progress after this. |

### Concurrency

| Variable | Default | Description |
|---|---|---|
| `ARKANA_MAX_CONCURRENT_ANALYSES` | `3` | Maximum concurrent heavy analysis operations (semaphore). Prevents CPU/memory exhaustion when multiple tools run simultaneously. |
| `ARKANA_DASHBOARD_THREADS` | `4` | Number of threads in the dashboard's dedicated thread pool. Prevents dashboard requests from being starved when MCP tools or background tasks saturate the default executor. |

### Session Management

| Variable | Default | Description |
|---|---|---|
| `ARKANA_MAX_SESSIONS` | `100` | Maximum concurrent HTTP sessions. When reached, the oldest session (by last activity) is evicted. Prevents unbounded memory growth in HTTP mode. |

### File Limits

| Variable | Default | Description |
|---|---|---|
| `ARKANA_MAX_FILE_SIZE_MB` | `256` | Maximum file size (in MB) accepted by `open_file`. Parsed safely via `_safe_env_int()`. |

### Debug Sessions

| Variable | Default | Description |
|---|---|---|
| `ARKANA_MAX_DEBUG_SESSIONS` | `3` | Maximum concurrent interactive debug sessions. When reached, the oldest session is evicted. |
| `ARKANA_DEBUG_SESSION_TTL` | `1800` | Idle timeout (seconds) for debug sessions. Sessions inactive for this long are automatically cleaned up. |
| `ARKANA_DEBUG_COMMAND_TIMEOUT` | `300` | Timeout (seconds) per execution command (step, continue, run_until, step_over). When the timeout fires, the session is paused (not killed) — emulation is halted via `emu_stop()` and can be inspected and resumed. |
| `ARKANA_MAX_DEBUG_SNAPSHOTS` | `10` | Maximum saved snapshots per debug session. Each snapshot captures full CPU + memory state. |

### Emulation Inspect Sessions

These are compile-time constants in `arkana/constants.py` (not overridable via environment variables):

| Constant | Default | Description |
|---|---|---|
| `MAX_EMULATION_SESSIONS` | `3` | Maximum concurrent emulation inspect sessions. When reached, the oldest session is evicted. |
| `EMULATION_SESSION_TTL` | `1800` | Idle timeout (seconds) for emulation sessions. Sessions inactive for this long are automatically cleaned up. |
| `EMULATION_COMMAND_TIMEOUT` | `60` | Timeout (seconds) per memory inspection command (read_memory, search_memory, memory_map). |
| `EMULATION_RUN_TIMEOUT` | `300` | Timeout (seconds) for the initial emulation run. |

### Auto-Enrichment

| Variable | Default | Description |
|---|---|---|
| `ARKANA_AUTO_ENRICHMENT` | `1` | Set to `0` to disable automatic background enrichment after `open_file`. When enabled, Arkana automatically runs classification, triage, similarity hashing, MITRE mapping, IOC collection, library identification, and a decompilation sweep. |
| `ARKANA_ENRICHMENT_MAX_DECOMPILE` | `50` | Maximum number of functions to decompile during the auto-enrichment background sweep. Higher values provide more coverage but take longer. |

### Tool Descriptions

| Variable | Default | Description |
|---|---|---|
| `ARKANA_BRIEF_DESCRIPTIONS` | `0` | When set to `1`, replaces full tool descriptions with compact shorthand from `---compact:` lines in docstrings. Reduces tool listing size by ~90% (~23 KB vs ~280 KB). Useful when `ENABLE_TOOL_SEARCH` is disabled. Can also be set via `--brief-descriptions` CLI flag (takes precedence). |

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
| `--no-dashboard` | Disable the web dashboard entirely. Can also be set via `ARKANA_NO_DASHBOARD=1` env var. |
| `--allowed-paths PATH [PATH ...]` | Restrict `open_file` to these directories (security sandbox for HTTP mode) |
| `--samples-path PATH` | Path to the samples directory. Enables the `list_samples` tool for AI clients to discover available files. Falls back to the `ARKANA_SAMPLES` environment variable if not set. |
| `--brief-descriptions` | Use brief tool descriptions (first paragraph only) to reduce context window usage by ~60%. Falls back to `ARKANA_BRIEF_DESCRIPTIONS=1` env var. |
| `--skip-capa` | Skip capa capability analysis |
| `--skip-floss` | Skip FLOSS string analysis |
| `--skip-peid` | Skip PEiD signature scanning |
| `-y, --yara-rules PATH` | Custom YARA rule file or directory. If not provided, uses bundled rules from ReversingLabs (MIT) and Yara-Rules Community (GPL-2.0), downloading them on first run |
| `--skip-yara` | Skip YARA scanning |
| `--floss-format {sc32,sc64}` | Shellcode architecture hint for FLOSS and Angr (32-bit or 64-bit) |
| `-v, --verbose` | Enable verbose output |
