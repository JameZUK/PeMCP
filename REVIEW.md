# PeMCP Project Review

## Overview

PeMCP is a comprehensive PE (Portable Executable) file analysis toolkit written in Python. It provides two operational modes: a CLI mode for generating full analysis reports, and an MCP (Model-Context-Protocol) server mode exposing 40+ tools for interactive binary exploration by AI agents. The project integrates numerous binary analysis libraries including pefile, angr, FLOSS, capa, YARA, and StringSifter.

**Reviewed files:** `PeMCP.py` (6,697 lines), `mcp_test_client.py` (420 lines), `Dockerfile`, `requirements.txt`, `FastPrompt.txt`

---

## Architecture & Design

### Strengths

1. **Graceful degradation model**: The optional dependency handling is well-designed. Each heavy library (angr, capa, FLOSS, YARA, etc.) is wrapped in try/except with availability flags, allowing the tool to function in reduced-capability mode when dependencies are missing.

2. **Centralized state management**: The `AnalyzerState` class (`PeMCP.py:73`) encapsulates global state cleanly, which is better than scattered global variables. The `close_pe()` and `reset_angr()` cleanup methods are useful.

3. **Smart response size management**: The `_check_mcp_response_size()` function (`PeMCP.py:3767`) implements intelligent truncation with a 64KB limit, using iterative heuristics to shrink responses rather than hard-failing. This is a practical solution for MCP token limits.

4. **Background task infrastructure**: The heartbeat monitoring system (`PeMCP.py:152`) and background task management with progress tracking is a thoughtful addition for long-running operations like angr CFG generation.

5. **Shellcode support**: The `MockPE` class (`PeMCP.py:510`) providing a PE-like interface for raw shellcode is a clean abstraction enabling code reuse.

6. **Dynamic tool generation**: The `_create_mcp_tool_for_key()` factory (`PeMCP.py:3909`) reduces boilerplate by generating MCP tool endpoints dynamically for each PE data key.

### Weaknesses

1. **Monolithic single-file architecture**: At 6,697 lines, `PeMCP.py` contains everything - parsing, analysis, CLI output, MCP server, utility classes, and the entry point. This makes the codebase difficult to navigate, test, and maintain. Logical modules would be:
   - `pe_parser.py` - All `_parse_*` functions
   - `cli_output.py` - All `_print_*_cli` functions
   - `mcp_tools.py` - MCP tool definitions
   - `analyzers.py` - FLOSS, capa, YARA, PEiD integration
   - `utils.py` - SSDeep, hex dump, string extraction
   - `state.py` - AnalyzerState and global configuration

2. **Pure-Python SSDeep implementation**: The `SSDeep` class (`PeMCP.py:286-508`) is a full reimplementation of ssdeep hashing. While this avoids a native dependency, it's ~220 lines of complex hashing code that would be better served by the `ssdeep` or `ppdeep` PyPI package with a fallback to this implementation.

---

## Code Quality Issues

### Critical

1. **Variable shadowing bug in `find_path_to_address`** (`PeMCP.py:5496`):
   ```python
   state = state.angr_project.factory.entry_state(add_options=stability_options)
   simgr = state.angr_project.factory.simulation_manager(state)
   ```
   The local variable `state` (angr SimState) shadows the global `state` (AnalyzerState). The second line then tries to call `.angr_project` on the angr SimState, which will fail at runtime. This is a functional bug that will cause `find_path_to_address` to crash.

2. **Duplicate imports** (`PeMCP.py:40,55` and `PeMCP.py:54,66`):
   ```python
   import re        # line 40
   import re        # line 55 (duplicate)
   import copy      # line 54
   from pathlib import Path
   import copy      # line 66 (duplicate)
   ```
   While harmless, this indicates copy-paste accumulation and lack of import hygiene.

3. **Bare `except` clauses** (multiple locations, e.g., `PeMCP.py:101`, `183`, `268`, `890`, `920`):
   ```python
   except:
       pass
   ```
   These silently swallow all exceptions including `KeyboardInterrupt` and `SystemExit`. They should at minimum be `except Exception`.

### High

4. **Thread safety concerns**: The `AnalyzerState` object is accessed from multiple threads (main thread, angr background thread, heartbeat monitor thread) without any locking mechanism. While CPython's GIL provides some protection for simple attribute reads/writes, dictionary mutations like `state.background_tasks[task_id]["status"] = "completed"` from background threads while the main thread iterates over keys (`PeMCP.py:164`) could lead to race conditions.

5. **Mutable default argument** (`PeMCP.py:5578`):
   ```python
   async def emulate_function_execution(..., args_hex: List[str] = [], ...):
   ```
   Using a mutable default argument (`[]`) is a well-known Python anti-pattern. Should be `None` with a default assignment inside the function.

6. **Inconsistent error handling in MCP tools**: Some tools raise `RuntimeError` on failures, others return error dictionaries, and some do both. For example, `decompile_function_with_angr` returns `{"error": ...}` on KeyError but raises `RuntimeError` if angr isn't available. MCP clients need to handle two different error signaling mechanisms.

### Medium

7. **Compressed/minified code blocks**: Several sections use extremely dense single-line formatting that harms readability:
   - `PeMCP.py:882`: `sym_class_file=getattr(pefile,'IMAGE_SYM_CLASS_FILE',103);sym_class_section=...`
   - `PeMCP.py:1122-1134`: Entire signature parsing logic on a few lines with semicolons
   - `PeMCP.py:3745-3746`: `"has_dos_header":'dos_header'in state.pe_data and state.pe_data['dos_header']is not None and"error"not in state.pe_data['dos_header']`

   This style makes debugging and code review significantly harder.

8. **Hardcoded VirusTotal API URL and capa rules version** (`PeMCP.py:148`, `783`):
   ```python
   VT_API_URL_FILE_REPORT = "https://www.virustotal.com/api/v3/files/"
   CAPA_RULES_ZIP_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/v9.1.0.zip"
   ```
   The capa rules URL is pinned to v9.1.0. There's no mechanism to update this without editing the source.

9. **Interactive pip install in a "Docker-compatible" tool** (`PeMCP.py:108-142`): The docstring says "Removed interactive dependency installation (Docker-compatible)" but the pefile import block still has an interactive prompt for pip install. This contradicts the stated design goal.

---

## Security Considerations

1. **VirusTotal API key in environment variable**: Using `VT_API_KEY` from the environment (`PeMCP.py:147`) is the correct approach. No hardcoded keys were found.

2. **No input validation on file paths in MCP mode**: The `--input-file` argument is resolved to an absolute path, but there's no sandboxing or path traversal prevention for MCP mode. In a networked SSE deployment, clients cannot specify arbitrary file paths (the file is pre-loaded), which mitigates this.

3. **`zipfile.extractall()` usage** (`PeMCP.py:987`): The `ensure_capa_rules_exist` function uses `zip_ref.extractall()` which is vulnerable to zip-slip attacks (path traversal via `../` in archive entries). Since the zip URL is hardcoded to a GitHub release, the practical risk is low, but defense-in-depth would call for validating member paths.

4. **HTTP download without checksum verification**: Both the PEiD database and capa rules are downloaded over HTTPS but without hash verification. If the upstream source is compromised, malicious rules could be injected.

5. **`subprocess.check_call` for pip**: The pefile install fallback (`PeMCP.py:123`) uses `subprocess.check_call` with `sys.executable`, which is acceptable. No shell injection vectors are present.

---

## Dockerfile Review

The Dockerfile (`Dockerfile:1-45`) is well-structured:

- **Good**: Uses Python 3.11 on Debian Bullseye (stable base).
- **Good**: Layer caching strategy separates heavy deps (angr, FLOSS, capa) from lighter ones.
- **Good**: Cleans apt lists to reduce image size.
- **Issue**: No non-root user is created. The container runs as root, which is acceptable for a local analysis tool but not ideal for any networked deployment.
- **Issue**: No `HEALTHCHECK` instruction for the SSE server mode.
- **Issue**: Dependencies are installed without version pinning (e.g., `pefile` instead of `pefile==2024.8.26`). This means builds are not reproducible, and a breaking upstream change could silently break the image.
- **Missing**: The `userdb.txt` and `FastPrompt.txt` files are not copied into the image.

---

## Test Suite Review (`mcp_test_client.py`)

### Strengths

- Good coverage of the MCP tool surface area with parameterized tests for PE data retrieval tools.
- Robust helper function `call_tool_and_assert_success()` with proper edge case handling (JSON vs raw text, single-item list wrapping).
- Error-path testing via `call_tool_and_expect_server_error_in_result()`.
- Fuzzy search test validates end-to-end with a prerequisite check pattern.

### Weaknesses

1. **No unit tests**: All tests are integration tests requiring a running MCP server. There are no unit tests for core parsing functions, the SSDeep implementation, hex dump formatting, or string extraction.

2. **Tests use `asyncio.run()` inside sync methods** (`PeMCP.py` test client, multiple locations): Each test creates a new event loop and a new MCP session. This is slow and creates many connections. Pytest-asyncio with a session-scoped fixture would be more efficient.

3. **Hardcoded server URL** (`mcp_test_client.py:39`): `SERVER_BASE_URL = "http://127.0.0.1:8082"` should be configurable via environment variable.

4. **Commented-out test** (`mcp_test_client.py:372-379`): The `TestReanalyzeTool` class is fully commented out with no explanation.

5. **No tests for angr-based tools**: The entire angr tool suite (decompilation, CFG, symbolic execution, emulation, slicing) has zero test coverage.

---

## Dependencies Review

The dependency set is appropriate for the tool's scope. Key observations:

- **`networkx`** is imported directly (`PeMCP.py:60`) but not listed in `requirements.txt`. It's pulled in transitively by angr, but should be listed explicitly if used directly.
- **`httpx`** is used in the test client but not in `requirements.txt`.
- **`pytest`** is used in the test client but not in `requirements.txt` (should be in a dev/test extras).
- **No version constraints** in `requirements.txt`. This is risky for reproducibility, especially with fast-moving projects like angr and capa.

---

## Recommendations (Priority Order)

1. **Fix the `state` variable shadowing bug** in `find_path_to_address` - this is a runtime crash.
2. **Replace bare `except:` with `except Exception:`** throughout.
3. **Fix the mutable default argument** `args_hex: List[str] = []`.
4. **Add threading locks** to `AnalyzerState` for background task access.
5. **Add version pins** to `requirements.txt` for reproducible builds.
6. **Split the monolith** into logical modules when the codebase grows further.
7. **Add unit tests** for core parsing and utility functions.
8. **Add a non-root user** to the Dockerfile for SSE deployments.
9. **Validate zip member paths** in `ensure_capa_rules_exist`.
10. **Make test server URL configurable** via environment variable.

---

## Summary

PeMCP is a capable and feature-rich binary analysis toolkit with a well-thought-out architecture for AI agent integration via MCP. The graceful degradation model for optional dependencies and the smart response size management are notable design decisions. The primary areas for improvement are the monolithic file structure, the `state` shadowing bug in symbolic execution, thread safety for background tasks, and the lack of unit test coverage. The codebase would also benefit from consistent code formatting throughout, as some sections are quite compressed.
