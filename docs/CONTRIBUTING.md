# Contributing to PeMCP

Thank you for your interest in contributing to PeMCP. This guide covers the development workflow, coding conventions, and testing requirements.

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/JameZUK/PeMCP.git
   cd PeMCP
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements-ci.txt -r requirements-test.txt
   ```

   For the full Docker environment (with all optional libraries):
   ```bash
   docker build -t pemcp-toolkit .
   ```

## Project Structure

```
pemcp/
├── constants.py        # Pure constants (no side effects)
├── imports.py          # Optional library imports + availability flags
├── config.py           # Re-exports constants + imports, wires up state/cache
├── state.py            # Per-session state (AnalyzerState, StateProxy)
├── cache.py            # Disk-based analysis cache (gzip + LRU)
├── main.py             # CLI/MCP entry point
├── mcp/
│   ├── server.py       # MCP server setup + tool decorator
│   ├── _format_helpers.py
│   ├── _input_helpers.py
│   └── tools_*.py      # MCP tool modules (171 tools)
├── parsers/            # PE/FLOSS/capa/signature parsers
├── cli/                # CLI output formatting
└── ...
```

## Coding Conventions

- **Imports:** Import from `pemcp.config` as the single source of truth for constants, flags, and shared state. Never import directly from `pemcp.imports` or `pemcp.constants` in tool modules.
- **Tool registration:** Use `@tool_decorator` from `pemcp.mcp.server` for all MCP tools. This ensures per-session state activation, history recording, and heartbeat monitoring.
- **State access:** Always use the `state` proxy from `pemcp.config`. Never instantiate `AnalyzerState` directly in tool code.
- **Error messages:** Use `_check_pe_loaded()`, `_check_angr_ready()`, and `_check_data_key_available()` for consistent, actionable error messages.
- **Response size:** Wrap large responses with `await _check_mcp_response_size(ctx, data, tool_name)` to enforce the 64KB MCP limit.

## Testing

### Unit Tests

```bash
# Run all unit tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=pemcp --cov-config=.coveragerc --cov-fail-under=65
```

Unit tests live in `tests/` and require only `requirements-ci.txt` + `requirements-test.txt`. They do not need a running server or binary samples.

### Integration Tests

```bash
# Start the server
./run.sh

# In another terminal, run integration tests
pytest tests/integration/mcp_test_client.py -v
```

Integration tests exercise all 171 MCP tools against a running PeMCP server.

### Writing Tests

- Place unit tests in `tests/test_<module>.py`.
- Use `pytest.importorskip()` for tests that need optional libraries.
- Use `unittest.mock.patch` to mock `state` when testing tool logic.
- The coverage threshold is 65%. New code should include tests.

## Pull Request Process

1. Create a feature branch from `main`.
2. Make your changes with clear, focused commits.
3. Ensure all tests pass: `pytest tests/ -v`
4. Ensure syntax checks pass: `python -c "import py_compile; ..."`
5. Open a PR with a clear description of what changed and why.

## Architecture Notes

- **Per-session isolation:** In HTTP mode, each MCP session gets its own `AnalyzerState` via `contextvars`. The `StateProxy` in `config.py` transparently delegates to the correct session.
- **Subprocess venvs:** Speakeasy, Unipacker, and Qiling each run in isolated virtualenvs (`/app/*-venv/`) to resolve incompatible unicorn engine versions. Communication uses JSON over stdin/stdout.
- **Conditional tool registration:** Refinery tools are only registered when `binary-refinery` is installed, keeping the MCP tool catalog lean for environments without it.
