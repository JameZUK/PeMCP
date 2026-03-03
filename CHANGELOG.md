# Changelog

All notable changes to Arkana (formerly PeMCP) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-03-03

### Changed
- **Project renamed from PeMCP to Arkana**  - the tool has grown beyond PE-only analysis to support PE, ELF, Mach-O, .NET, Go, Rust, and shellcode across 190 tools. "Arkana" (Latin: hidden secrets/mysteries) better reflects the full scope.
  - Package directory: `pemcp/` → `arkana/`
  - Entry point: `PeMCP.py` → `arkana.py`
  - MCP server name: `PEFileAnalyzerMCP` → `Arkana`
  - Data directory: `~/.pemcp/` → `~/.arkana/` (auto-migrated on first run)
  - Docker image: `pemcp-toolkit` → `arkana-toolkit`
  - Environment variables: `PEMCP_*` → `ARKANA_*` (old vars still accepted as fallbacks)
  - Project archives: `.pemcp_project.tar.gz` → `.arkana_project.tar.gz` (old format still importable)

### Added
- **14 new tools** (178 → 190 total):
  - `generate_yara_rule()`  - auto-generate YARA detection rules from analysis findings with optional `scan_after_generate` to compile and validate in one call.
  - `generate_sigma_rule()`  - generate draft Sigma detection rules (process creation, file events, registry, network).
  - `parse_authenticode()`  - PE authenticode signature parsing with certificate details, countersignature timestamps, and anomaly detection.
  - `unify_artifact_timeline()`  - correlate all temporal artifacts and detect timestomping/timestamp anomalies.
  - `analyze_debug_directory()`  - deep PDB/POGO/Rich header parsing with anomaly detection.
  - `analyze_relocations()`  - BASE_RELOC directory parsing with ASLR bypass indicators.
  - `analyze_seh_handlers()`  - SEH/x64 exception handler analysis with anti-debug detection.
  - `detect_dga_indicators()`  - DGA capability detection via API co-occurrence analysis.
  - `match_c2_indicators()`  - C2 framework indicator matching (Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel, Covenant, Mythic, PoshC2).
  - `analyze_kernel_driver()`  - kernel driver analysis (DriverEntry, IRP dispatch, IOCTL handlers, DKOM/rootkit indicators).
  - `map_mitre_attack()`  - MITRE ATT&CK mapping with optional Navigator layer output.
  - `analyze_batch()`  - multi-file batch analysis with hashing, import overlap, timestamp comparison, and ssdeep/TLSH similarity clustering.
- Three malware family identification tools: `identify_malware_family()`, `list_malware_signatures()`, `verify_malware_attribution()`  - match binary indicators against a 123-family signature knowledge base (`arkana/data/malware_signatures.yaml`) for automated malware attribution with confidence scoring.
- `arkana/constants.py`  - pure constants module (no side effects, safe to import anywhere).
- `arkana/imports.py`  - centralised optional library imports and availability flags.
- `arkana/py.typed`  - PEP 561 marker for type checker support.
- SIGTERM graceful shutdown handler in MCP server mode (reuses existing cleanup path).
- New test suites: `test_format_helpers.py` (format detection) and `test_input_helpers.py` (parsing, caching, pagination).
- CI smoke-test job that verifies CLI `--help` and core module imports.
- `CHANGELOG.md` and `docs/CONTRIBUTING.md`.

### Enhanced
- `find_anti_debug_comprehensive()`  - expanded with anti-VM detection (93 hypervisor indicators across VMware/VirtualBox/Hyper-V/QEMU/Xen/Parallels/sandbox/analysis tools) and instruction-level scanning (RDTSC, CPUID, INT 2Dh, SIDT) in executable sections.
- `emulate_binary_with_qiling()`  - added `trace_syscalls` parameter for syscall-level tracing with optional `syscall_filter`, and `track_memory` for memory allocation tracking (RWX detection, large allocations, protection changes).
- `brute_force_simple_crypto()`  - expanded with RC4, ADD, SUB, ROL, ROR transforms and known-plaintext XOR key detection.
- `dotnet_analyze()`  - enhanced with user string extraction, improved type/method listing.
- Consolidated duplicate tools: merged `find_anti_debug` into `find_anti_debug_comprehensive`, merged `detect_anti_vm` into `find_anti_debug_comprehensive`.

### Changed
- Split `arkana/config.py` into three focused modules (`constants.py`, `imports.py`, `config.py`). All existing `from arkana.config import ...` statements continue to work via re-exports.
- Refactored `arkana/main.py` from a monolithic 521-line `main()` into 7 focused functions with a `_ResolvedConfig` dataclass.
- Moved gzip compression in `cache.py` `put()` outside the lock to avoid blocking concurrent callers.
- Reduced redundant UTF-8 encoding in `_check_mcp_response_size` truncation loop.
- Removed `_format_helpers.py` from `.coveragerc` omit list (now covered by unit tests).
- Raised CI coverage threshold from 60% to 65%.
- Moved `mcp_test_client.py` to `tests/integration/mcp_test_client.py`.

### Fixed
- Removed duplicate `ARKANA_HOST_SAMPLES` environment variable in `run.sh`.
- Replaced deprecated `asyncio.get_event_loop().run_until_complete()` with `asyncio.run()` in test helper.
- Corrected tool count from 196 to 171 across all documentation (README, SKILL.md, tooling-reference.md, PROJECT_REVIEW.md).

### Renamed
- `.claude/skills/analyze/` → `.claude/skills/arkana-analyze/`
- `.claude/skills/analyse/` → `.claude/skills/arkana-analyse/`
