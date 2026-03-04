# Arkana Development Guide

## What is Arkana?

Arkana is a Model Context Protocol (MCP) server exposing 191 binary analysis tools to AI clients. It supports PE, ELF, and Mach-O formats with integrations for angr, capa, FLOSS, YARA, Binary Refinery, Qiling, and Speakeasy.

## Project Structure

```
arkana/                  # Main package
├── main.py             # Entry point, arg parsing, server startup
├── state.py            # Thread-safe AnalyzerState + StateProxy (per-session isolation)
├── config.py           # Central re-export hub (constants, imports, state, cache)
├── constants.py        # Pure constants (response limits, timeouts, URLs)
├── imports.py          # Optional library imports with *_AVAILABLE flags
├── cache.py            # Gzip-compressed LRU disk cache (~/.arkana/cache/)
├── auth.py             # Bearer token ASGI middleware
├── utils.py            # ReDoS-safe regex, safe_slice, safe_env_int
├── parsers/            # PE/FLOSS/capa/YARA/strings parsers
└── mcp/                # MCP tool modules (191 tools across 47 files)
    ├── server.py       # FastMCP instance, tool_decorator, response truncation
    ├── _*.py           # Private helpers (angr, input, format, progress, refinery)
    └── tools_*.py      # Tool modules grouped by domain
tests/                  # Unit tests (pytest)
tests/integration/      # Integration tests (requires running server)
.claude/skills/         # Claude Code analysis and learning skills
```

## Running Tests

```bash
# Unit tests (no server needed, ~2 seconds)
python -m pytest tests/ -v

# Unit tests with coverage
python -m pytest tests/ -v --cov=arkana --cov-config=.coveragerc

# Integration tests (requires running server)
./run.sh  # Start server in one terminal
python -m pytest tests/integration/mcp_test_client.py -v  # In another
```

Coverage configuration lives in `.coveragerc` (single source of truth). MCP tool modules are excluded from unit test coverage — they are tested via integration tests.

## Lint

```bash
ruff check arkana/ tests/ \
  --select=E9,F63,F7,F82,F841,W291,W292,W293,B006,B007,B018,UP031,UP032,RUF005,RUF010,RUF019,G010
```

## Key Patterns

- **Optional deps**: Every library is guarded by `*_AVAILABLE` flags in `imports.py`. Tools return actionable error messages when a dep is missing — never crash.
- **Thread safety**: All shared state uses locks. `StateProxy` + `contextvars` isolates HTTP sessions. Use `ProgressBridge` to report progress from worker threads.
- **`asyncio.to_thread()`**: CPU-intensive tool work runs in threads to avoid blocking the event loop. See `tools_angr.py` and `tools_triage.py` for examples.
- **Response truncation**: `_check_mcp_response_size()` enforces a dual-limit system — soft character limit (8K chars by default, for Claude Code CLI compatibility) plus hard byte limit (64KB backstop). The `tool_decorator` includes a safety net that auto-enforces the soft limit even for tools that don't call `_check_mcp_response_size` explicitly. Set `ARKANA_MCP_RESPONSE_LIMIT_CHARS=65536` to restore 64KB-only behavior for non-Claude-Code clients.
- **Pagination**: Large-output tools like `decompile_function_with_angr` use line-based pagination (`line_offset`/`line_limit`). Results are cached via `_ToolResultCache` so subsequent page requests don't re-execute analysis.
- **`tool_decorator`**: Wraps every MCP tool — handles session activation, heartbeat, history recording, and error enrichment.
- **Background task timeout**: All 10 angr background tools (`find_path_to_address`, `emulate_function_execution`, `analyze_binary_loops`, `get_reaching_definitions`, `get_data_dependencies`, `get_value_set_analysis`, `diff_binaries`, `find_path_with_custom_input`, `emulate_with_watchpoints`, `identify_cpp_classes`) time out automatically via `_run_background_task_wrapper(timeout=N)`. Default `BACKGROUND_TASK_TIMEOUT` is 600s, overridable via `ARKANA_BACKGROUND_TASK_TIMEOUT`. Four tools support `on_timeout` callbacks that capture partial results (steps completed, active states, captured events). `_update_progress()` records `last_progress_epoch` on every call, enabling generic stall detection in `check_task_status()`. Tasks include `created_at_epoch` for elapsed time reporting.
- **Notes system**: `add_note()` categories: `general`, `function`, `tool_result`, `ioc`, `hypothesis`, `manual`.
- **Artifacts system**: `state.register_artifact()` tracks extracted files (path, hashes, source tool, type detection). Artifacts persist via cache alongside notes/tool_history, and are included in `export_project` / `import_project` archives. Constants: `MAX_ARTIFACT_FILE_SIZE` (100 MB), `MAX_TOTAL_ARTIFACT_EXPORT_SIZE` (50 MB).

## Docker

```bash
./run.sh --stdio          # stdio mode (for Claude Code)
./run.sh                  # HTTP mode (port 8082)
./run.sh --samples ~/dir  # Mount samples directory
```

The Docker image uses 4 venvs to isolate incompatible unicorn versions (angr needs v2, Speakeasy/Unipacker/Qiling need v1).

## CI

GitHub Actions runs on every push/PR (plus manual `workflow_dispatch`): unit tests (Python 3.10-3.12), ruff lint, and smoke tests. Coverage floor is 65% with branch coverage enabled. Dependabot is configured for weekly pip dependency updates.
