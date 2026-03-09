# Security & Testing

Arkana's security model, sandboxing configuration, and testing infrastructure.

---

## Path Sandboxing

When running Arkana in HTTP mode (`--mcp-transport streamable-http`), any MCP client can call `open_file` to read files on the server. Use `--allowed-paths` to restrict access:

```bash
# Only allow access to /samples and /tmp
python arkana.py --mcp-server --mcp-transport streamable-http \
  --allowed-paths /samples /tmp

# Docker with sandboxing (via run.sh  - extra flags are passed through)
./run.sh --allowed-paths /samples

# Equivalent manual docker command
docker run --rm -it -p 8082:8082 \
  --user "$(id -u):$(id -g)" \
  -e HOME=/app/home \
  -v "$(pwd)/samples:/samples:ro" \
  arkana-toolkit \
  --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 \
  --allowed-paths /samples \
  --samples-path /samples
```

If `--allowed-paths` is not set in HTTP mode, Arkana logs a warning at startup.

---

## Other Security Measures

- **Non-root Docker**: The `run.sh` helper runs the container as your host UID/GID (`--user "$(id -u):$(id -g)"`), never as root.
- **API key storage**: Keys are stored in `~/.arkana/config.json` with 0o600 (owner-only) permissions.
- **Zip-slip protection**: Archive extraction validates member paths against directory traversal.
- **No hardcoded secrets**: API keys are sourced from environment variables or the config file.
- **CSP**: Dashboard Content-Security-Policy uses `script-src 'self'` (no inline scripts) and restricts `img-src` to `'self'` only (no `data:` URIs). All event handlers use `addEventListener` or event delegation with `data-*` attributes.
- **Dashboard XSS prevention**: All dynamic values in dashboard JS (functions.js, strings.js, callgraph.js) are escaped via `escapeHtml()` before innerHTML insertion — including addresses, names, numeric counts, scores, and complexity values.
- **`Cache-Control: no-store`**: Security middleware injects `Cache-Control: no-store` on all non-static dashboard responses to prevent browser caching of sensitive API data.
- **`fetchJSON()` HTTP error checking**: All dashboard JS files use a shared `fetchJSON()` helper that checks `r.ok` before parsing JSON and throws on HTTP errors, preventing silent consumption of error responses.
- **Diff path traversal prevention**: `get_diff_data()` validates comparison file paths via `os.path.realpath()` with samples directory containment check.
- **Dashboard query bounds**: Code search queries capped at 500 chars; callgraph edges capped at 5,000; URL redirect parameters use `urllib.parse.urlencode()`.
- **Dashboard `asyncio.to_thread()`**: All API endpoints and htmx partials run data functions off the event loop via `asyncio.to_thread()`, with `try/except` fallbacks on partials.

---

## Input Validation & Safety Guards

Arkana applies defence-in-depth input validation across all layers:

- **Search regex safety**: `search` parameters on decompile/disassembly tools validate patterns via `validate_regex_pattern()` — rejects patterns longer than 1,000 chars, nested quantifiers (ReDoS), and invalid syntax. Context lines clamped to `[0, 20]`, matches capped at 500.
- **Emulation limits**: Qiling tools validate `max_instructions` (0–10M) via `_validate_max_instructions()` to prevent CPU/memory exhaustion.
- **Auth header handling**: `BearerAuthMiddleware` lowercases ASGI header keys defensively before matching.
- **Error message sanitisation**: Crypto tool errors truncate user input to 50 chars to prevent information disclosure.
- **Address validation**: Dashboard endpoints reject address parameters longer than 40 characters.
- **Content-Length parsing**: POST endpoints wrap `int(content_length)` in try/except for malformed values.
- **Delay-load imports**: PE parser bounds delay-load thunk iteration at 10,000 to prevent infinite loops on malformed binaries.
- **ThreadPool cap**: PE parser limits `ThreadPoolExecutor` workers to `min(cpu_count, 8)`.
- **IOC regex**: Domain TLD matching tightened to `{2,16}` characters.
- **Cache eviction**: CAPA and YARA rule caches use LRU (OrderedDict) instead of FIFO.
- **ELF symbol parsing**: Per-symbol error handling continues iteration on individual failures.
- **Path validation**: `_get_filepath()` always validates paths via `state.check_path_allowed()`, even when falling back to the default loaded file.
- **Recursion depth guard**: `_make_hashable()` enforces a max depth of 20 to prevent stack overflow on cyclic data structures.
- **Cache size bounds**: `ARKANA_CACHE_MAX_SIZE_MB` env var is clamped to 1–50,000 MB to prevent misconfiguration.

---

## Testing & CI/CD

Arkana has two layers of testing, with automated CI via **GitHub Actions**:

- **Unit tests** (`tests/`)  - 398 fast tests covering core modules (utils, cache, state, hashing, parsers, MCP helpers), plus parametrised edge-case tests and concurrency tests for session isolation. No server or binary samples required. Run in ~2 seconds.
- **Integration tests** (`mcp_test_client.py`)  - End-to-end tests for all 209 MCP tools against a running server, organised into 19 test categories with pytest markers.
- **CI/CD** (`.github/workflows/ci.yml`)  - Automated unit tests on Python 3.10/3.11/3.12, coverage enforcement (65% floor with branch coverage), and syntax checking on every push, PR, and manual dispatch. Dependabot monitors pip dependencies weekly.

```bash
# Run unit tests (no server needed)
pytest tests/ -v

# Run unit tests with coverage
pytest tests/ -v --cov=arkana --cov-report=term-missing

# Run integration tests (requires running server)
pytest mcp_test_client.py -v
```

For detailed instructions on running tests, writing new tests, coverage, CI/CD, environment variables, test categories, markers, and troubleshooting, see **[Testing](testing.md)**.
