# Changelog

All notable changes to Arkana (formerly PeMCP) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added
- **Projects feature** — named multi-binary investigation containers backed by `~/.arkana/projects/`. Each project groups one or more binaries with their user-mutable analysis state (notes, artifacts, renames, custom types, triage flags, coverage, sandbox reports) in per-binary overlays. Lazy promotion: opening a binary creates an in-memory `ScratchProject` that gets promoted to disk on the first state mutation (note added, artifact registered, function renamed, etc.). Same binary can appear in multiple projects with independent overlays.
- **14 new MCP tools** for project + artifact management:
    - `tools_projects.py` (11 tools): `list_projects`, `current_project`, `create_project`, `open_project`, `close_project`, `rename_project`, `tag_project`, `delete_project`, `add_binary_to_project`, `remove_binary_from_project`, `set_primary_binary`
    - `tools_artifacts.py` (3 tools): `list_project_artifacts`, `update_artifact_metadata`, `delete_artifact`
- **PROJECTS dashboard tab** — card grid view with filter/sort/tag dropdown, "+ New project" modal, inline rename, open/tag/delete actions, active-project highlight, importable archives panel that scans `output/` for `.arkana_project.tar.gz` files and offers one-click import for both v1 (legacy single-binary) and v2 (project-level) archive formats.
- **ARTIFACTS dashboard tab** — sortable table with type icon (file/directory), name, description, size, source tool, created/modified timestamps, sha8 (click to copy), tags, expand-row for full details with inline-editable description/tags/notes, bulk select with bulk-tag/delete, download (single-file streams; directory bundles zipped on the fly), 10s auto-refresh polling.
- **Active-project indicator in nav** — when an on-disk project is bound, the global nav header shows `▶ {project_name} / {active_binary}`.
- **Persisted dashboard state per project** — `last_tab`, `hex_offset`, `last_function_address` saved into the project manifest's `dashboard_state` field. Reopening a project routes the user back to whichever tab they last visited; hexview restores its scroll position.
- **Directory artifact bundles** — `_register_artifact_directory()` helper in `_refinery_helpers.py` walks a directory tree (depth-capped, no symlinks, member/size limits enforced) and registers it as a single `kind='directory'` artifact with per-member sha256+size. Multiple multi-file output tools migrated to use it: `tools_dotnet_deobfuscate.dotnet_decompile`, `tools_refinery_extract._write_multi_file_artifacts`, `tools_refinery_dotnet`, `tools_payload.extract_steganography`, `tools_payload.parse_custom_container`.
- **Extended artifact schema**: `kind`, `original_path`, `project_relative`, `members`, `member_count`, `total_size`, `tags`, `notes`, `modified_at` fields added to `state.register_artifact()`. Backwards-compatible — existing readers see the same shape with new fields defaulting sensibly.
- **`auto_name_sample` pure helper** — `_build_sample_slug()` extracted from the existing tool. Used by `state._maybe_promote_scratch` and the cache→projects migration to give scratch promotions and migrated projects descriptive names like `stealer_packed_persistence_a3f9c211` instead of `{filename_stem}_{sha8}`.
- **Cache→projects migration** — `ProjectManager.__init__` runs a one-shot scan of `~/.arkana/cache/` on first launch under v2. For each v1 wrapper carrying user data (notes/artifacts/renames/types/triage), creates a project (tagged `migrated`) with a stub member, extracts the user state into the project's overlay, and re-writes the cache wrapper as v2 (user fields stripped). Per-entry try/except — never crashes startup. Idempotent.
- **Cache wrapper format v2** — derived analysis only (PE headers, enrichment results). User-mutable state lives in project overlays. v1 wrappers still readable by `cache.get()` for the migration path. `cache.update_session_data()` becomes a no-op on v2 wrappers but is retained for backward compat with legacy callers.
- Progress-adaptive overtime for `open_file` PE analysis (task ID `"pe-analysis"`): soft timeout (300s) → OVERTIME with stall detection → absolute ceiling (3600s). Replaces the old hard 600s timeout. Configurable via `ARKANA_PE_ANALYSIS_SOFT_TIMEOUT` and `ARKANA_PE_ANALYSIS_MAX_RUNTIME`. Set soft timeout to `0` for legacy hard-timeout behavior. Visible on dashboard and via `check_task_status("pe-analysis")`. Cancellable via `abort_background_task("pe-analysis")`
- Intermediate progress reports during PE parallel scan phase (capa/FLOSS/YARA/PEiD) for better stall detection granularity
- Pure-Python gopclntab parser (`arkana/parsers/go_pclntab.py`) for Go binary analysis. Supports Go 1.2–1.26+ (4 format versions). Slots into `go_analyze` fallback chain as tier 3: GoReSym → pygore → gopclntab → string scan. Extracts function names, addresses, and source file paths from stripped Go binaries without external tool dependencies. Based on r2gopclntabParser by Asher Davila (MIT license)
- Persistent rename/annotation layer (6 new tools, 209 total): `rename_function`, `rename_variable`, `add_label`, `list_renames`, `delete_rename`, `batch_rename`. Renames are automatically applied to decompilation and disassembly output. Persisted via cache alongside notes — restored on `open_file()`
- Custom type system (5 new tools): `create_struct`, `create_enum`, `apply_type_at_offset`, `list_custom_types`, `delete_custom_type`. Reuses `parse_binary_struct` field types. Persisted via cache
- `batch_decompile` — decompile up to 20 functions in a single call with per-function 60s timeout, result caching, and rename integration. `summary_mode` returns signature + first 5 lines only
- `search_hex_pattern` — search binary data for hex byte patterns with `??` wildcards. Optional section filter for PE binaries. Max 200 tokens, 5000 matches

### Fixed
- `macho_analyze` — LIEF returns enum objects (`MACHO_TYPES`, `CPU_TYPE`) for header, segment, and symbol fields that cannot be passed to `hex()` or serialized directly. Fixed by converting with `int()`/`str()` before JSON serialization
- `go_analyze` — pygore (last release Oct 2021) fails on modern Go binaries either by throwing on construction or by parsing successfully but returning no metadata. Added `_go_string_scan()` fallback that detects Go via 13 runtime markers and version string extraction (threshold: 2+ markers or version found)
- 5 additional tool bugs found during comprehensive 230-tool retest (tool_decorator empty errors, unify_artifact_timeline ELF guard, refinery_executable FILE_HEADER guard, refinery_pe_operations empty error, refinery_forensic empty error)
- 4 remaining tool bugs (refinery_executable virtual_read/entropy_map, diff_binaries cffi pickle, detect_self_modifying_code VEX lift)
- 11 tool bugs found during initial 230-tool audit (LIEF Builder API, DFS→BFS default, descriptive KeyErrors, FLOSS static strings, and more)
- Unified address/offset parsing: all tools now accept both hex (`0x401000`) and decimal (`4198400`) for address parameters. Previously 7 tools required hex-only input for some parameters (e.g. `unhook_function` used hex-only while `hook_function` accepted both)
- `get_strings_for_function` and `get_string_usage_context` now accept hex string addresses in addition to plain integers
- Bare `except Exception` in `server.py` response truncation now logs via `logger.debug`
- Bare `except OSError: pass` in `cache.py` LRU timestamp update now logs via `logger.debug`
- Overly broad `except Exception` in `imports.py` FLOSS import blocks narrowed to `except (ImportError, OSError, ValueError)`

### Added
- Dependabot configuration for weekly pip dependency updates
- Manual CI trigger via `workflow_dispatch`
- Branch coverage enabled in `.coveragerc`
- `get_angr_partial_functions()` - list functions discovered in angr's knowledge base even while the CFG is still building or has timed out
- BSim-inspired function similarity tools (5 new tools, 196 total): `extract_function_features`, `find_similar_functions`, `build_function_signature_db`, `query_signature_db`, `list_signature_dbs`. Architecture-independent feature extraction using 6 feature groups (CFG structural, API calls, VEX IR profile, string refs, constants, size metrics) with weighted similarity scoring. Persistent SQLite signature database at `~/.arkana/bsim/` enables cross-binary function search with two-phase query (SQL pre-filter + full scoring)
- CFG build timeout (10-minute default, configurable via `ARKANA_ANGR_CFG_TIMEOUT`) prevents indefinite hangs on packed or obfuscated binaries
- CFG stall detection monitor - `check_task_status('startup-angr')` now reports `functions_discovered_so_far` and a `stall_detection` verdict
- Background task timeout for all 10 angr background tools (default 600s, configurable via `ARKANA_BACKGROUND_TASK_TIMEOUT`). Tools that previously could hang indefinitely now time out with actionable error messages
- Generic stall detection for all background tasks — `check_task_status()` reports `stall_detection` when no progress update in 60s
- Partial results on timeout for 4 tools: `find_path_to_address`, `emulate_function_execution`, `find_path_with_custom_input` (steps completed, active states), and `emulate_with_watchpoints` (captured events)
- `BACKGROUND_TASK_TIMEOUT` constant (600s) in `arkana/constants.py`

### Enhanced
- `decompile_function_with_angr()` works without a full CFG by building a local region-scoped CFG around the target function
- `disassemble_at_address()` works without a full CFG when an angr project is loaded
- `check_task_status()` enhanced with elapsed time (`elapsed_seconds`, `elapsed_human`), generic stall detection for all background tasks, and timeout/partial result reporting for failed tasks
- `_update_progress()` now records `last_progress_epoch` on every update, enabling stall detection for all background tools
- `_run_background_task_wrapper()` supports `timeout` and `on_timeout` parameters for automatic cancellation and partial result capture

---

## [1.0.0] - 2026-03-03

Arkana v1 Launch. The project was renamed from PeMCP to Arkana on 2026-03-02.

### Changed
- **Project renamed from PeMCP to Arkana** - the tool has grown beyond PE-only analysis to support PE, ELF, Mach-O, .NET, Go, Rust, and shellcode across 190 tools. "Arkana" (Latin: hidden secrets/mysteries) better reflects the full scope.
  - Package directory: `pemcp/` → `arkana/`
  - Entry point: `PeMCP.py` → `arkana.py`
  - MCP server name: `PEFileAnalyzerMCP` → `Arkana`
  - Data directory: `~/.pemcp/` → `~/.arkana/` (auto-migrated on first run)
  - Docker image: `pemcp-toolkit` → `arkana-toolkit`
  - Environment variables: `PEMCP_*` → `ARKANA_*` (old vars still accepted as fallbacks)
  - Project archives: `.pemcp_project.tar.gz` → `.arkana_project.tar.gz` (old format still importable)
- Split `arkana/config.py` into three focused modules: `constants.py`, `imports.py`, and `config.py` (re-export hub). All existing `from arkana.config import ...` statements continue to work.
- Refactored `arkana/main.py` from a monolithic 521-line `main()` into 7 focused functions with a `_ResolvedConfig` dataclass
- Moved gzip compression in `cache.py` `put()` outside the lock to avoid blocking concurrent callers
- Moved `mcp_test_client.py` to `tests/integration/mcp_test_client.py`
- Skill directories renamed: `.claude/skills/analyze/` → `.claude/skills/arkana-analyze/` and `.claude/skills/analyse/` → `.claude/skills/arkana-analyse/`
- Raised CI coverage threshold from 60% to 65%

### Added
- 14 new tools (178 → 190 total): `generate_yara_rule`, `generate_sigma_rule`, `parse_authenticode`, `unify_artifact_timeline`, `analyze_debug_directory`, `analyze_relocations`, `analyze_seh_handlers`, `detect_dga_indicators`, `match_c2_indicators`, `analyze_kernel_driver`, `map_mitre_attack`, `analyze_batch`
- 3 malware family identification tools (`identify_malware_family`, `list_malware_signatures`, `verify_malware_attribution`) with a 123-family YAML signature knowledge base
- Soft response limit (8K chars by default) and pagination for Claude Code CLI compatibility; set `ARKANA_MCP_RESPONSE_LIMIT_CHARS=65536` to restore 64KB-only behaviour for other clients
- Animated demo recordings, example reports, and MIT licence
- Parallelized `open_file` analyses and cached compiled YARA rules
- SIGTERM graceful shutdown handler
- `arkana/constants.py` - pure constants module (no side effects, safe to import anywhere)
- `arkana/imports.py` - centralised optional dependency imports with `*_AVAILABLE` flags
- `arkana/py.typed` - PEP 561 marker for type checker support
- New unit test suites: `test_format_helpers.py` and `test_input_helpers.py`
- CI smoke-test job that verifies `--help` and core module imports
- `CHANGELOG.md` and `docs/CONTRIBUTING.md`

### Enhanced
- `find_anti_debug_comprehensive()` expanded with anti-VM detection (93 hypervisor indicators across VMware, VirtualBox, Hyper-V, QEMU, Xen, Parallels, and analysis tool fingerprints) and instruction-level scanning (RDTSC, CPUID, INT 2Dh, SIDT) in executable sections
- `emulate_binary_with_qiling()` added `trace_syscalls` parameter for syscall-level tracing with optional `syscall_filter`, and `track_memory` for memory allocation tracking (RWX detection, large allocations, protection changes)
- `brute_force_simple_crypto()` expanded with RC4, ADD, SUB, ROL, and ROR transforms plus known-plaintext XOR key detection
- `dotnet_analyze()` enhanced with user string extraction and improved type/method listing
- Consolidated duplicate tools: merged `find_anti_debug` and `detect_anti_vm` into `find_anti_debug_comprehensive`

### Fixed
- Removed duplicate `ARKANA_HOST_SAMPLES` environment variable in `run.sh`
- Replaced deprecated `asyncio.get_event_loop().run_until_complete()` with `asyncio.run()` in test helper
- Fixed `try_all_unpackers` KeyError and output key mismatch
- Fixed deprecated YARA rule warnings
- Corrected tool count across all documentation

---

## [0.11.0] - 2026-03-01

Malware Identification and Batch Analysis.

### Added
- Malware family identification tools (`identify_malware_family`, `list_malware_signatures`, `verify_malware_attribution`) with YAML signature knowledge base
- Signature knowledge base grown from 33 → 80 → 123 families across multiple iterations
- Session artifacts system: `state.register_artifact()` tracks extracted files with path, hashes, source tool, and type detection. Artifacts persist in the cache and are included in `export_project` / `import_project` archives.
- Batch mode for 4 tools: `refinery_pipeline`, `get_string_at_va`, `auto_note_function`, `get_capa_rule_match_details`
- `scan_for_api_hashes` tool for API hash resolution
- `parse_binary_struct` tool for parsing custom binary structures
- `extract_config_for_family` tool for family-specific config extraction
- Fair analysis framing added to skills: guidance to distinguish capability from intent
- `CLAUDE.md` project instructions file committed to the repository

### Changed
- Renamed C2 identification tools to malware family identification throughout all filenames and documentation references
- `refinery_pipeline` expanded with additional transform and output support

### Fixed
- `close_file` / `open_file` crash when `external_path` is `None`
- 5 tool issues found during Cobalt Strike beacon analysis
- Scoring inflation for families with minimal knowledge base data
- Null and dict-type crashes in malware family identification matchers

---

## [0.10.0] - 2026-02-28

Skills and Intelligence.

### Added
- Comprehensive binary analysis skill for Claude Code (`/arkana-analyze` and `/arkana-analyse`)
- `pemcp-learn` skill: interactive reverse engineering tutor covering concepts, quiz mode, and spaced-repetition tracking
- 20 new tools (151 → 171 total): UX improvements across 7 existing tools and net-new analysis capabilities
- Structured workflow guidance in all MCP tool docstrings
- Comprehensive project review covering architecture, security, testing, and deployment

### Changed
- Split README into focused documentation files: `tools-reference.md`, `security.md`, `testing.md`, `scenarios.md`, `CONTRIBUTING.md`
- Rewrote README intro to be concise and engaging
- Switched `.mcp.json` to Docker launcher pattern

### Fixed
- ruff lint errors in `tools_learning.py` and `mcp_test_client.py`
- Added logging to previously silent exception handlers
- Extracted timeout constants and added `safe_env_int` utility
- Removed unused variables (ruff F841) and widened test search windows

---

## [0.9.0] - 2026-02-22

Binary Refinery Integration.

### Added
- Binary Refinery integration: 23 consolidated MCP tools wrapping 200+ data transforms, including `refinery_codec`, `refinery_decrypt`, `refinery_xor`, `refinery_decompress`, `refinery_extract_iocs`, `refinery_carve`, `refinery_pe_operations`, `refinery_deobfuscate_script`, `refinery_hash`, `refinery_pipeline`, and more
- Notes system (`add_note`, `get_notes`, `update_note`, `delete_note`) with categories: `general`, `function`, `tool_result`, `ioc`, `hypothesis`, `manual`
- Tool history, session summary, and `get_analysis_digest` features
- `export_project` / `import_project` for `.pemcp_project.tar.gz` session archives
- `auto_note_function` for automatic function annotation from analysis context
- Internal/external path awareness in `open_file` and `close_file` responses
- Comprehensive "Why PeMCP" section in README with real-world scenarios and tool comparisons

### Changed
- Consolidated 56 refinery MCP tools into 23 via dispatch pattern for context efficiency

### Fixed
- Path traversal vulnerability in `import_project`
- Container mount permissions and broken HTTP startup
- Broken compact triage report and regex timeout protection
- Output directory permissions on SELinux systems
- `entropy_map` headless terminal width crash
- 10 refinery tool bugs across multiple rounds of retesting

---

## [0.8.0] - 2026-02-19

Cross-Platform Emulation and Progress Reporting.

### Added
- Qiling Framework integration for cross-platform binary emulation (PE, ELF, shellcode): `emulate_binary_with_qiling`, `emulate_shellcode_with_qiling`, `qiling_trace_execution`, `qiling_hook_api_calls`, `qiling_dump_unpacked_binary`, `qiling_resolve_api_hashes`, `qiling_memory_search`, `qiling_setup_check`
- Bundled YARA rules from ReversingLabs (MIT) and Yara-Rules Community (GPL-2.0)
- Fine-grained MCP progress reporting for approximately 50 long-running tools using push notifications via `ProgressBridge`
- Pagination and default limits documentation in README

### Changed
- Isolated unipacker in its own venv to resolve the unicorn v1/v2 dependency conflict (Docker image now uses 4 venvs)
- Bind-mount `~/.pemcp` for cache instead of a named Docker volume

### Fixed
- Qiling Windows API init errors, registry hive NK offsets, and rootfs download issues
- Qiling shellcode architecture mapping and ELF `is_driver` detection
- Unipacker stdout pollution corrupting JSON results
- Speakeasy slice error and binwalk CLI fallback
- capa version pin, PEiD ranking, and Unipacker action verb
- Surfaced capa failures in triage and normalized scores
- Podman bind mount permissions via `--userns=keep-id`
- 18 further review findings covering security, concurrency, and code quality

---

## [0.7.0] - 2026-02-17

Hardening and CI.

### Added
- CI setup with GitHub Actions: unit tests across Python 3.10-3.12, ruff lint, and smoke tests
- Coverage enforcement with 65% floor
- `.coveragerc` to scope coverage to core modules (MCP tool modules excluded from unit test coverage - tested via integration tests)
- Compiler/language detection and format-aware tool suggestions in `get_triage_report`

### Changed
- Raised CI coverage threshold from 60% to 65%

### Fixed
- 26 review findings (iterations 8-11): ReDoS protection, path sandboxing, state corruption, and race conditions
- `go_analyze` response size, Rust detection depth, and stripped binary analysis
- angr VFG by monkey-patching the `ProcedureEngine` constructor bug
- CI failures: `angr[unicorn]` downgrade loop, heavy dependency conflicts, and missing imports on Python 3.12

---

## [0.6.0] - 2026-02-15

angr Tool Reliability.

### Fixed
- 11 angr tool failures discovered during integration testing
- RDA and Propagator plugins: version-aware plugin names, removed invalid `cfg=` parameter
- Library API compatibility for `dncil`, angr FLIRT (nampa-based), and unipacker
- angr VFG by monkey-patching the `ProcedureEngine` constructor bug
- 8 remaining angr tool failures across multiple further rounds of retesting

---

## [0.5.0] - 2026-02-12

Security Hardening.

### Added
- Comprehensive unit test suite for core modules
- `DEPENDENCIES.md` documenting known conflicts and workarounds

### Changed
- Docker image uses 4 venvs to isolate incompatible unicorn versions: angr requires v2; Speakeasy, Unipacker, and Qiling require v1

### Fixed
- 6 iterations of security review fixes (C1-C3, H1-H15, M1-M30, L1-L26)
- libssl symlink crash with isolated speakeasy venv
- unicorn dependency conflicts resolved via multi-venv Docker approach
- Removed `_raise_on_error_dict` calls that converted soft errors to exceptions

---

## [0.4.0] - 2026-02-11

Reviews and Stability.

### Added
- Expanded test suite from 94 to 128 test methods with comprehensive coverage

### Changed
- Session state now inherits pre-loaded file data from default state

### Fixed
- 70+ fixes across multiple comprehensive project reviews
- Rebuilt angr project after `hook_function` / `unhook_function` to prevent stale CFG
- Suppressed `pkg_resources` deprecation warning and angr `unicorn_engine` log noise
- String extraction `TypeError` with non-standard bytes-like data

---

## [0.3.0] - 2026-02-10

Testing and Infrastructure.

### Added
- Test suite covering all 104 MCP tools
- `--samples` flag in `run.sh` and `list_samples` MCP tool for sample directory awareness
- Docker Compose support
- Path sandboxing for container security

### Changed
- Decomposed monolithic MCP tool modules into domain-focused files
- Rewrote `run.sh` helper with `--samples` flag support

### Fixed
- 52 test failures across 6 categories
- Auto-detect transport and `ExceptionGroup` handling
- Container host binding and server start configuration

---

## [0.2.0] - 2026-02-09

Major Rearchitecture.

### Added
- 47 new MCP tools: 20 angr analysis tools and 27 PE/library integration tools
- Multi-format binary analysis: .NET, Go, Rust, ELF, Mach-O support
- Dynamic file loading with streamable-http transport
- Disk-based analysis caching (`~/.pemcp/cache/`) with gzip-compressed LRU eviction
- Persistent configuration
- Docker Compose and `run.sh` helper script

### Changed
- Modularized monolithic `PeMCP.py` into `pemcp/` package with 24 modules

### Enhanced
- `get_triage_report` with comprehensive multi-format analysis
- Binary classification and auto-naming capabilities

---

## [0.1.0] - 2025-05-20

Initial Release.

### Added
- `PeMCP.py` - single-file PE analysis MCP server
- Basic PE header and section parsing via `pefile`
- Import/export table analysis
- String extraction with StringSifter ML ranking
- angr-based decompilation and disassembly
- FLOSS for obfuscated string recovery
- capa for capability detection
- YARA signature scanning
- Speakeasy for Windows API emulation
- VirusTotal hash lookup integration

---

[Unreleased]: https://github.com/JameZUK/Arkana/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/JameZUK/Arkana/compare/v0.11.0...v1.0.0
[0.11.0]: https://github.com/JameZUK/Arkana/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/JameZUK/Arkana/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/JameZUK/Arkana/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/JameZUK/Arkana/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/JameZUK/Arkana/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/JameZUK/Arkana/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/JameZUK/Arkana/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/JameZUK/Arkana/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/JameZUK/Arkana/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/JameZUK/Arkana/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/JameZUK/Arkana/releases/tag/v0.1.0
