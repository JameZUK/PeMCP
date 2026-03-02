# Security & Testing

PeMCP's security model, sandboxing configuration, and testing infrastructure.

---

## Path Sandboxing

When running PeMCP in HTTP mode (`--mcp-transport streamable-http`), any MCP client can call `open_file` to read files on the server. Use `--allowed-paths` to restrict access:

```bash
# Only allow access to /samples and /tmp
python PeMCP.py --mcp-server --mcp-transport streamable-http \
  --allowed-paths /samples /tmp

# Docker with sandboxing (via run.sh — extra flags are passed through)
./run.sh --allowed-paths /samples

# Equivalent manual docker command
docker run --rm -it -p 8082:8082 \
  --user "$(id -u):$(id -g)" \
  -e HOME=/app/home \
  -v "$(pwd)/samples:/samples:ro" \
  pemcp-toolkit \
  --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 \
  --allowed-paths /samples \
  --samples-path /samples
```

If `--allowed-paths` is not set in HTTP mode, PeMCP logs a warning at startup.

---

## Other Security Measures

- **Non-root Docker**: The `run.sh` helper runs the container as your host UID/GID (`--user "$(id -u):$(id -g)"`), never as root.
- **API key storage**: Keys are stored in `~/.pemcp/config.json` with 0o600 (owner-only) permissions.
- **Zip-slip protection**: Archive extraction validates member paths against directory traversal.
- **No hardcoded secrets**: API keys are sourced from environment variables or the config file.

---

## Testing & CI/CD

PeMCP has two layers of testing, with automated CI via **GitHub Actions**:

- **Unit tests** (`tests/`) — 398 fast tests covering core modules (utils, cache, state, hashing, parsers, MCP helpers), plus parametrised edge-case tests and concurrency tests for session isolation. No server or binary samples required. Run in ~2 seconds.
- **Integration tests** (`mcp_test_client.py`) — End-to-end tests for all 190 MCP tools against a running server, organised into 19 test categories with pytest markers.
- **CI/CD** (`.github/workflows/ci.yml`) — Automated unit tests on Python 3.10/3.11/3.12, coverage enforcement (60% floor), and syntax checking on every push and PR.

```bash
# Run unit tests (no server needed)
pytest tests/ -v

# Run unit tests with coverage
pytest tests/ -v --cov=pemcp --cov-report=term-missing

# Run integration tests (requires running server)
pytest mcp_test_client.py -v
```

For detailed instructions on running tests, writing new tests, coverage, CI/CD, environment variables, test categories, markers, and troubleshooting, see **[Testing](testing.md)**.
